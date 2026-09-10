package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testKey is a clearly-fake 32-byte master key (never a real credential).
func testKey() []byte {
	k := make([]byte, masterKeyLen)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func newTestVault(t *testing.T) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	v, err := OpenVault(path, StaticKeySource(testKey()))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	return v, path
}

func TestVaultPutGetRoundTrip(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	secret := []byte("FAKE-do-not-use-token-abc123")
	if err := v.Put(ctx, "aws/deploy", secret, PutMeta{Provider: "aws", Scope: "s3:read", TTL: "15m"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, meta, err := v.Get(ctx, "aws/deploy")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("value mismatch: got %q", got)
	}
	if meta.Provider != "aws" || meta.Scope != "s3:read" || meta.TTL != "15m" {
		t.Fatalf("meta mismatch: %+v", meta)
	}
	if meta.CreatedAt.IsZero() {
		t.Fatal("CreatedAt not stamped")
	}
}

// TestAtRestEncryption is the core security assertion: the plaintext value must be
// ABSENT from the raw on-disk file, and the file must be 0600.
func TestAtRestEncryption(t *testing.T) {
	v, path := newTestVault(t)
	ctx := context.Background()
	secret := []byte("SUPERSECRET-canary-9f8e7d6c5b4a")
	if err := v.Put(ctx, "canary", secret, PutMeta{Provider: "test"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vault file: %v", err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("SECURITY: plaintext secret present in on-disk vault file")
	}
	// The master key must not be on disk either.
	if bytes.Contains(raw, testKey()) {
		t.Fatal("SECURITY: master key present in on-disk vault file")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("vault perms = %o, want 0600", perm)
	}
}

func TestVaultWrongKeyFailsClosed(t *testing.T) {
	_, path := newTestVaultWith(t, "s", []byte("FAKE-secret-value"))
	// Reopen with a DIFFERENT master key: Get must fail (GCM auth), never return
	// garbage or the value.
	wrong := testKey()
	wrong[0] ^= 0xFF
	v2, err := OpenVault(path, StaticKeySource(wrong))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, _, err := v2.Get(context.Background(), "s"); err == nil {
		t.Fatal("SECURITY: Get with wrong master key succeeded")
	}
}

func newTestVaultWith(t *testing.T, ref string, value []byte) (*Vault, string) {
	t.Helper()
	v, path := newTestVault(t)
	if err := v.Put(context.Background(), ref, value, PutMeta{}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return v, path
}

func TestVaultPersistsAcrossReopen(t *testing.T) {
	v, path := newTestVault(t)
	ctx := context.Background()
	secret := []byte("FAKE-persist-value")
	if err := v.Put(ctx, "k", secret, PutMeta{Provider: "p"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v2, err := OpenVault(path, StaticKeySource(testKey()))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, _, err := v2.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("value mismatch after reopen: %q", got)
	}
}

func TestVaultListNoValue(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	_ = v.Put(ctx, "b", []byte("FAKE-b"), PutMeta{Provider: "pb"}, false)
	_ = v.Put(ctx, "a", []byte("FAKE-a"), PutMeta{Provider: "pa"}, false)
	metas, err := v.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("want 2 metas, got %d", len(metas))
	}
	// Sorted by ref.
	if metas[0].Ref != "a" || metas[1].Ref != "b" {
		t.Fatalf("not sorted: %+v", metas)
	}
	// SecretMeta has no value field by construction — assert the type carries none
	// by checking the JSON-relevant fields are the only descriptive data. (Compile-
	// time guarantee: SecretMeta has no Value field.)
}

func TestVaultPutNoOverwrite(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if err := v.Put(ctx, "k", []byte("FAKE-1"), PutMeta{}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Put(ctx, "k", []byte("FAKE-2"), PutMeta{}, false); err == nil {
		t.Fatal("expected ErrExists on duplicate add")
	}
	// Overwrite works and preserves CreatedAt.
	meta0, _ := v.List(ctx)
	if err := v.Put(ctx, "k", []byte("FAKE-2"), PutMeta{}, true); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, _, _ := v.Get(ctx, "k")
	if !bytes.Equal(got, []byte("FAKE-2")) {
		t.Fatalf("overwrite value = %q", got)
	}
	meta1, _ := v.List(ctx)
	if !meta0[0].CreatedAt.Equal(meta1[0].CreatedAt) {
		t.Fatal("CreatedAt changed on overwrite")
	}
}

func TestVaultDelete(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	_ = v.Put(ctx, "k", []byte("FAKE"), PutMeta{}, false)
	if err := v.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := v.Get(ctx, "k"); err == nil {
		t.Fatal("Get after Delete should fail")
	}
	if err := v.Delete(ctx, "k"); err == nil {
		t.Fatal("Delete of absent ref should error")
	}
}

func TestVaultRejectsInsecurePerms(t *testing.T) {
	v, path := newTestVault(t)
	_ = v.Put(context.Background(), "k", []byte("FAKE"), PutMeta{}, false)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := OpenVault(path, StaticKeySource(testKey())); err == nil {
		t.Fatal("SECURITY: opened vault with insecure 0644 perms")
	}
}

func TestVaultInvalidRef(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	for _, ref := range []string{"", "../escape", "a b", "x\x00y"} {
		if err := v.Put(ctx, ref, []byte("FAKE"), PutMeta{}, false); err == nil {
			t.Fatalf("expected invalid ref rejected: %q", ref)
		}
	}
}

// TestEnvelopeRotation proves the envelope primitive: re-wrapping data keys under
// a NEW master key preserves every value WITHOUT re-encrypting values, and the old
// key can no longer open the vault.
func TestEnvelopeRotation(t *testing.T) {
	v, path := newTestVault(t)
	ctx := context.Background()
	secret := []byte("FAKE-rotate-value-xyz")
	if err := v.Put(ctx, "k", secret, PutMeta{Provider: "p"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Capture the encrypted VALUE blob before rotation to prove it is unchanged.
	beforeRaw, _ := os.ReadFile(path)

	newKEK := testKey()
	for i := range newKEK {
		newKEK[i] ^= 0xAA
	}
	if err := v.RotateMasterKey(newKEK); err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}
	// Value still decrypts under the SAME vault (now using the new KEK).
	got, _, err := v.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get after rotate: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("value changed after rotate: %q", got)
	}
	// Reopen with the NEW key works, with the OLD key fails.
	if _, err := OpenVault(path, StaticKeySource(newKEK)); err != nil {
		t.Fatalf("reopen with new key: %v", err)
	}
	old, _ := OpenVault(path, StaticKeySource(testKey()))
	if _, _, err := old.Get(ctx, "k"); err == nil {
		t.Fatal("SECURITY: old master key still opens the rotated vault")
	}
	// The value ciphertext blob is byte-identical (only the wrapped DEK changed).
	afterRaw, _ := os.ReadFile(path)
	if extractValueBlob(t, beforeRaw) != extractValueBlob(t, afterRaw) {
		t.Fatal("rotation re-encrypted the value (should only re-wrap the data key)")
	}
}

// extractValueBlob pulls the base64 value ciphertext out of the raw vault JSON.
func extractValueBlob(t *testing.T, raw []byte) string {
	t.Helper()
	var f vaultFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("unmarshal vault: %v", err)
	}
	return f.Secrets["k"].Value
}

func TestEnvKeySourceDecoding(t *testing.T) {
	t.Setenv("OPSLIFY_VAULT_KEY_TEST", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	k, err := EnvKeySource{Var: "OPSLIFY_VAULT_KEY_TEST"}.MasterKey()
	if err != nil {
		t.Fatalf("MasterKey hex: %v", err)
	}
	if len(k) != masterKeyLen {
		t.Fatalf("key len %d", len(k))
	}
	// Unset => error (fail closed).
	if _, err := (EnvKeySource{Var: "OPSLIFY_UNSET_XYZ"}).MasterKey(); err == nil {
		t.Fatal("expected error for unset key env")
	}
	// Wrong length => error.
	t.Setenv("OPSLIFY_VAULT_KEY_SHORT", "abcd")
	if _, err := (EnvKeySource{Var: "OPSLIFY_VAULT_KEY_SHORT"}).MasterKey(); err == nil {
		t.Fatal("expected error for short key")
	}
}

// TestRotateMasterKeyRollsBackBothHalves pins N12. The doc promised a rotation is
// all-or-nothing, and it was not: on a persist failure only the in-memory KEK was
// restored, leaving the running vault holding DEKs re-wrapped under the NEW key
// while kek was the OLD one. Every subsequent resolve then failed to unwrap —
// every credential injection broken until a restart, from an operation that
// returned an error and claimed to have changed nothing.
func TestRotateMasterKeyRollsBackBothHalves(t *testing.T) {
	v, path := newTestVault(t)
	ctx := context.Background()
	mustPut(t, v, "tok", "the-value", "gitlab")

	// Make persist fail: the vault writes via a temp file in its own directory.
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the vault dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	newKEK := make([]byte, 32)
	for i := range newKEK {
		newKEK[i] = byte(200 - i)
	}
	if err := v.RotateMasterKey(newKEK); err == nil {
		t.Fatal("a rotation that cannot persist must return an error")
	}

	// The vault must still WORK. This is the whole claim: a failed rotation leaves
	// a usable vault, not one that has silently lost every credential.
	got, _, err := v.Get(ctx, "tok")
	if err != nil {
		t.Fatalf("after a failed rotation every resolve broke: %v", err)
	}
	if string(got) != "the-value" {
		t.Fatalf("resolved %q, want %q", got, "the-value")
	}
	// And a second attempt, once the disk recovers, must succeed.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := v.RotateMasterKey(newKEK); err != nil {
		t.Fatalf("a retry after recovery must succeed: %v", err)
	}
	if got, _, err = v.Get(ctx, "tok"); err != nil || string(got) != "the-value" {
		t.Fatalf("after a successful rotation: %q %v", got, err)
	}
}
