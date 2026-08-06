package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	want := DefaultConfig()
	want.Image = "repo@sha256:deadbeef"
	want.ToolchainDigest = "sha256:cafe"
	if err := WriteConfig(path, want); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got.Image != want.Image || got.ToolchainDigest != want.ToolchainDigest || got.Tier != want.Tier {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestLoadIdentityGood(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "identity.key")
	gen, err := GenerateIdentity(keyPath)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	got, err := LoadIdentity(keyPath)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if got.PublicKeyHex != gen.PublicKeyHex {
		t.Fatalf("public key mismatch: got %s want %s", got.PublicKeyHex, gen.PublicKeyHex)
	}
	if got.Fingerprint != gen.Fingerprint {
		t.Fatalf("fingerprint mismatch")
	}
}

func TestLoadIdentityMissing(t *testing.T) {
	if _, err := LoadIdentity(filepath.Join(t.TempDir(), "absent.key")); err == nil {
		t.Fatal("expected error for missing identity key")
	}
}

func TestLoadIdentityBadPerms(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "identity.key")
	if _, err := GenerateIdentity(keyPath); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := LoadIdentity(keyPath)
	if !errors.Is(err, ErrIdentityKeyPerms) {
		t.Fatalf("expected ErrIdentityKeyPerms, got %v", err)
	}
}

func TestLoadIdentityNotPEM(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "identity.key")
	if err := os.WriteFile(keyPath, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadIdentity(keyPath); err == nil {
		t.Fatal("expected error for non-PEM key")
	}
}
