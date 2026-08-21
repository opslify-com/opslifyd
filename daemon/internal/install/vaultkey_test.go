package install

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
)

// TestEnsureVaultKeyGeneratesStoresRevealsOnce: a fresh box (no env, no file) mints
// a key, writes it 0600, and reveals it EXACTLY once with the save-it warning.
func TestEnsureVaultKeyGeneratesStoresRevealsOnce(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "etc", "vault.key")
	os.Unsetenv("OPSLIFY_VAULT_KEY")

	var buf bytes.Buffer
	res, err := EnsureVaultKey(&buf, "OPSLIFY_VAULT_KEY", keyFile)
	if err != nil {
		t.Fatalf("EnsureVaultKey: %v", err)
	}
	if !res.Generated || res.FromEnv {
		t.Fatalf("expected Generated (not FromEnv), got %+v", res)
	}

	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file perms %#o, want 0600", perm)
	}

	out := buf.String()
	if !strings.Contains(out, "VAULT MASTER KEY") || !strings.Contains(strings.ToUpper(out), "ONLY COPY") {
		t.Fatalf("reveal missing the save-it warning:\n%s", out)
	}
	// The revealed hex must be the on-disk key and must appear exactly once.
	onDisk, err := broker.FileKeySource{Path: keyFile}.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	hexKey := broker.EncodeKey(onDisk)
	if n := strings.Count(out, hexKey); n != 1 {
		t.Fatalf("key revealed %d times, want exactly 1", n)
	}
}

// TestEnsureVaultKeyIdempotent: a second call does NOT regenerate or re-reveal.
func TestEnsureVaultKeyIdempotent(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "vault.key")
	os.Unsetenv("OPSLIFY_VAULT_KEY")

	var buf1 bytes.Buffer
	if _, err := EnsureVaultKey(&buf1, "OPSLIFY_VAULT_KEY", keyFile); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(keyFile)

	var buf2 bytes.Buffer
	res, err := EnsureVaultKey(&buf2, "OPSLIFY_VAULT_KEY", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if res.Generated {
		t.Fatal("second EnsureVaultKey regenerated the key")
	}
	after, _ := os.ReadFile(keyFile)
	if !bytes.Equal(before, after) {
		t.Fatal("key file changed on the idempotent second run")
	}
	if strings.Contains(buf2.String(), broker.EncodeKey(mustRead(t, keyFile))) {
		t.Fatal("second run re-revealed the key")
	}
}

// TestEnsureVaultKeyEnvOverrideSkips: with the env override set, init writes no file
// and reveals nothing (the operator already holds the key).
func TestEnsureVaultKeyEnvOverrideSkips(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "vault.key")
	t.Setenv("OPSLIFY_VAULT_KEY", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")

	var buf bytes.Buffer
	res, err := EnsureVaultKey(&buf, "OPSLIFY_VAULT_KEY", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if res.Generated || !res.FromEnv {
		t.Fatalf("expected FromEnv (no generation), got %+v", res)
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("env override must not write a key file")
	}
	if strings.Contains(buf.String(), "VAULT MASTER KEY") {
		t.Fatal("env override must not reveal a key")
	}
}

func mustRead(t *testing.T, keyFile string) []byte {
	t.Helper()
	k, err := broker.FileKeySource{Path: keyFile}.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
