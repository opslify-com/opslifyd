package broker

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeKey is a clearly-fake, deterministic 32-byte KEK for tests.
func fakeKey(b byte) []byte {
	k := make([]byte, masterKeyLen)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestGenerateMasterKeyLength(t *testing.T) {
	k, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	if len(k) != masterKeyLen {
		t.Fatalf("key len %d, want %d", len(k), masterKeyLen)
	}
	k2, _ := GenerateMasterKey()
	if bytes.Equal(k, k2) {
		t.Fatal("two generated keys are identical — not random")
	}
}

// TestFileKeySourceRoundTrip: WriteKeyFile writes 0600, FileKeySource reads it back.
func TestFileKeySourceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "vault.key")
	key := fakeKey(0xAB)
	if err := WriteKeyFile(path, key); err != nil {
		t.Fatalf("WriteKeyFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file perms %#o, want 0600", perm)
	}
	got, err := FileKeySource{Path: path}.MasterKey()
	if err != nil {
		t.Fatalf("FileKeySource read: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("round-tripped key mismatch")
	}
}

// TestFileKeySourceRefusesLoosePerms: a 0644 key file is REFUSED (fail closed),
// and it is NOT reported as absent (so a chain does not silently skip a broken
// source).
func TestFileKeySourceRefusesLoosePerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(fakeKey(0x01))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := FileKeySource{Path: path}.MasterKey()
	if err == nil {
		t.Fatal("expected refusal for 0644 key file")
	}
	if errors.Is(err, ErrKeyAbsent) {
		t.Fatal("loose-perms file must fail closed, not report absent (would let a chain skip it)")
	}
}

// TestFileKeySourceMissingIsAbsent: a missing file returns ErrKeyAbsent so a chain
// falls through to the next source.
func TestFileKeySourceMissingIsAbsent(t *testing.T) {
	_, err := FileKeySource{Path: filepath.Join(t.TempDir(), "nope.key")}.MasterKey()
	if !errors.Is(err, ErrKeyAbsent) {
		t.Fatalf("missing key file must be ErrKeyAbsent, got %v", err)
	}
}

func TestWriteKeyFileRefusesClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.key")
	if err := WriteKeyFile(path, fakeKey(0x02)); err != nil {
		t.Fatal(err)
	}
	// A second write must not silently rotate the key.
	err := WriteKeyFile(path, fakeKey(0x03))
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second WriteKeyFile should refuse (ErrExists), got %v", err)
	}
}

// TestResolveChainPrecedence documents + asserts the precedence: env override beats
// file, file beats absent, and a keyring-absent (not-in-chain) box still resolves
// via the file.
func TestResolveChainPrecedence(t *testing.T) {
	const envVar = "OPSLIFY_VAULT_KEY_PREC_TEST"
	dir := t.TempDir()
	filePath := filepath.Join(dir, "vault.key")
	fileKey := fakeKey(0x11)
	envKey := fakeKey(0x22)
	if err := WriteKeyFile(filePath, fileKey); err != nil {
		t.Fatal(err)
	}

	// env set → env wins over the file (override precedence).
	t.Setenv(envVar, hex.EncodeToString(envKey))
	got, err := ResolveKeySource(envVar, filePath).MasterKey()
	if err != nil {
		t.Fatalf("resolve (env set): %v", err)
	}
	if !bytes.Equal(got, envKey) {
		t.Fatal("env override did not win over the file")
	}

	// env unset → falls through to the file (file beats absent).
	os.Unsetenv(envVar)
	got, err = ResolveKeySource(envVar, filePath).MasterKey()
	if err != nil {
		t.Fatalf("resolve (env unset): %v", err)
	}
	if !bytes.Equal(got, fileKey) {
		t.Fatal("did not fall through to the file key")
	}
}

// TestResolveChainFailClosed: with NOTHING resolvable, the chain errors (wrapping
// ErrKeyAbsent) so the daemon fatals — never a silent empty/default key.
func TestResolveChainFailClosed(t *testing.T) {
	const envVar = "OPSLIFY_VAULT_KEY_ABSENT_TEST"
	os.Unsetenv(envVar)
	_, err := ResolveKeySource(envVar, filepath.Join(t.TempDir(), "missing.key")).MasterKey()
	if !errors.Is(err, ErrKeyAbsent) {
		t.Fatalf("no source should fail closed with ErrKeyAbsent, got %v", err)
	}
}

// TestResolveChainBrokenFileStopsChain: a present-but-broken file (loose perms) is
// fail-closed even though the env is absent — the chain must NOT skip past it.
func TestResolveChainBrokenFileStopsChain(t *testing.T) {
	const envVar = "OPSLIFY_VAULT_KEY_BROKEN_TEST"
	os.Unsetenv(envVar)
	path := filepath.Join(t.TempDir(), "vault.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(fakeKey(0x44))), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ResolveKeySource(envVar, path).MasterKey()
	if err == nil || errors.Is(err, ErrKeyAbsent) {
		t.Fatalf("broken file must fail closed (not absent), got %v", err)
	}
}

// TestVaultOpensFromFileKeyEncryptsAtRest is the F5.6 regression check driven by a
// FILE key source (no env): a fresh init box starts, the vault stores a secret, and
// the value is encrypted at rest (the plaintext never appears in the db file).
func TestVaultOpensFromFileKeyEncryptsAtRest(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "vault.key")
	vaultPath := filepath.Join(dir, "vault.db")
	if err := WriteKeyFile(keyPath, fakeKey(0x55)); err != nil {
		t.Fatal(err)
	}

	v, err := OpenVault(vaultPath, ResolveKeySource("OPSLIFY_VAULT_KEY_UNSET_REG", keyPath))
	if err != nil {
		t.Fatalf("OpenVault from file key: %v", err)
	}
	const plaintext = "FAKE-super-secret-value-123"
	if err := v.Put(context.Background(), "k", []byte(plaintext), PutMeta{}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	raw, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(plaintext)) {
		t.Fatal("plaintext value found in vault db — not encrypted at rest")
	}
	// And it decrypts back through the same file-sourced KEK.
	got, _, err := v.Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != plaintext {
		t.Fatal("round-trip value mismatch")
	}
}
