package session

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// manifestManager builds a bare Manager with one live session whose workspace
// is dir — enough to exercise Manifest without a real runtime.
func manifestManager(t *testing.T, dir string) *Manager {
	t.Helper()
	m := newTestManager(t, newFakeRuntime(), newFakeClock(time.Unix(0, 0)), newMemStore())
	m.sessions["s1"] = &Session{ID: "s1", WorkspaceDir: dir}
	return m
}

func TestManifestListsFilesWithHashes(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.txt"), "hello")
	mustWrite(t, filepath.Join(dir, "sub", "b.go"), "package main")

	m := manifestManager(t, dir)
	entries, err := m.Manifest(context.Background(), "s1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	got := map[string]ManifestEntry{}
	for _, e := range entries {
		got[e.RelPath] = e
	}
	if _, ok := got["a.txt"]; !ok {
		t.Errorf("a.txt missing from manifest: %+v", entries)
	}
	if _, ok := got["sub/b.go"]; !ok {
		t.Errorf("sub/b.go missing from manifest: %+v", entries)
	}
	if got["a.txt"].Size != 5 || got["a.txt"].SHA256 == "" {
		t.Errorf("a.txt entry malformed: %+v", got["a.txt"])
	}
}

// TestManifestExcludesSecrets: a planted secret file is never listed.
func TestManifestExcludesSecrets(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "app.go"), "x")
	mustWrite(t, filepath.Join(dir, ".env"), "SECRET=abc")
	mustWrite(t, filepath.Join(dir, "tls.pem"), "----KEY----")
	mustWrite(t, filepath.Join(dir, SandboxCAFileName), "ca")

	m := manifestManager(t, dir)
	entries, err := m.Manifest(context.Background(), "s1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	for _, e := range entries {
		if e.RelPath == ".env" || e.RelPath == "tls.pem" || e.RelPath == SandboxCAFileName {
			t.Errorf("secret/excluded path leaked into manifest: %q", e.RelPath)
		}
	}
}

// TestManifestDoesNotFollowSymlinkOut: a symlink pointing outside the workspace
// is never dereferenced into the manifest (no host-path escape).
func TestManifestDoesNotFollowSymlinkOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	dir := t.TempDir()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "host-secret.txt"), "TOPSECRET")
	mustWrite(t, filepath.Join(dir, "ok.txt"), "fine")
	if err := os.Symlink(filepath.Join(outside, "host-secret.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escapedir")); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}

	m := manifestManager(t, dir)
	entries, err := m.Manifest(context.Background(), "s1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	for _, e := range entries {
		if e.RelPath == "link.txt" || e.RelPath != filepath.ToSlash(e.RelPath) {
			t.Errorf("symlink followed / escaped: %q", e.RelPath)
		}
		if e.RelPath == "escapedir/host-secret.txt" {
			t.Errorf("descended through symlinked dir: %q", e.RelPath)
		}
	}
	// The one real file is still listed.
	found := false
	for _, e := range entries {
		if e.RelPath == "ok.txt" {
			found = true
		}
	}
	if !found {
		t.Error("ok.txt should be listed")
	}
}

func TestManifestUnknownSession(t *testing.T) {
	m := newTestManager(t, newFakeRuntime(), newFakeClock(time.Unix(0, 0)), newMemStore())
	if _, err := m.Manifest(context.Background(), "nope"); err == nil {
		t.Fatal("expected error for unknown session")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
