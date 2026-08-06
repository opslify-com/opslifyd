package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestInitCmdNonInteractive exercises the cobra wiring end-to-end with --yes so
// no TTY is needed, writing only into temp dirs (no root, no /etc).
func TestInitCmdNonInteractive(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "proj")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"init", project,
		"--yes",
		"--config", filepath.Join(root, "etc", "config.yaml"),
		"--identity-key", filepath.Join(root, "etc", "identity.key"),
		"--systemd-unit", filepath.Join(root, "etc", "opslifyd.service"),
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init command failed: %v\n%s", err, out.String())
	}

	for _, f := range []string{"opslify.env.yaml", "devbox.json", "flake.nix"} {
		if _, err := os.Stat(filepath.Join(project, f)); err != nil {
			t.Errorf("expected artifact %s", f)
		}
	}
	info, err := os.Stat(filepath.Join(root, "etc", "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("identity key perms: got %o want 0600", info.Mode().Perm())
	}
}
