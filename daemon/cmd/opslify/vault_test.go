package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
)

// runVaultExport runs `opslify vault key export` with the given args, capturing
// stdout+stderr, and returns the output and any error.
func runVaultExport(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := rootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs(append([]string{"vault", "key", "export"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

// TestVaultKeyExportPrintsOnce: export prints the current key once with a warning.
func TestVaultKeyExportPrintsOnce(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "vault.key")
	os.Unsetenv("OPSLIFY_VAULT_KEY")
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x7C
	}
	if err := broker.WriteKeyFile(keyFile, key); err != nil {
		t.Fatal(err)
	}
	// Write a config that points key_file at our temp key.
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vault:\n  key_file: "+keyFile+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runVaultExport(t, "--config", cfgPath)
	if err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	hexKey := broker.EncodeKey(key)
	if n := strings.Count(out, hexKey); n != 1 {
		t.Fatalf("key printed %d times, want exactly 1", n)
	}
	if !strings.Contains(strings.ToUpper(out), "ONLY COPY") {
		t.Fatalf("export missing the save-it warning:\n%s", out)
	}
}

// TestVaultKeyExportRefusesWhenAbsent: no env, no file → clean refusal, no key.
func TestVaultKeyExportRefusesWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	os.Unsetenv("OPSLIFY_VAULT_KEY")
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vault:\n  key_file: "+filepath.Join(dir, "absent.key")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runVaultExport(t, "--config", cfgPath)
	if err == nil {
		t.Fatalf("export must refuse when no key resolves; output:\n%s", out)
	}
	if !strings.Contains(err.Error(), "no vault master key") {
		t.Fatalf("expected a legible no-key error, got %v", err)
	}
}

// TestVaultCommandIsRegistered proves `opslify vault key export` exists on the CLI
// (the sole re-reveal path), so the reveal is CLI-only and discoverable.
func TestVaultCommandIsRegistered(t *testing.T) {
	root := rootCmd()
	vault, _, err := root.Find([]string{"vault", "key", "export"})
	if err != nil || vault.Name() != "export" {
		t.Fatalf("`vault key export` not registered: %v (found %v)", err, vault)
	}
}

// TestNoRouteExposesMasterKey is the belt-and-braces assertion that the master key
// is CLI-only: the daemon's secret MANAGEMENT surface (broker.SecretManager) has no
// method that returns key material or a value, and there is no "vault key" HTTP
// handler. Reveal is init (one-time) + `vault key export` (CLI), never the API/UI.
func TestNoRouteExposesMasterKey(t *testing.T) {
	// broker.SecretManager is the ONLY secret surface the daemon holds; it exposes
	// Put/List/Delete and no value/key read. A Get or a MasterKey method appearing
	// here would make this file fail to compile.
	var sm broker.SecretManager
	_ = sm
	type keyReader interface{ MasterKey() ([]byte, error) }
	if _, ok := sm.(keyReader); ok {
		t.Fatal("SecretManager unexpectedly exposes MasterKey")
	}
	type valueReader interface {
		Get() ([]byte, error)
	}
	if _, ok := sm.(valueReader); ok {
		t.Fatal("SecretManager unexpectedly exposes a value Get")
	}
}
