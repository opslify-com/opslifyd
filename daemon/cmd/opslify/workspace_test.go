package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeSandbox is an in-memory /workspace served over the fake daemon: the
// manifest + file PUT/GET routes the sync engine drives, backed by a map.
type fakeSandbox struct {
	mu    sync.Mutex
	files map[string][]byte
}

func newFakeSandbox() *fakeSandbox { return &fakeSandbox{files: map[string][]byte{}} }

func (s *fakeSandbox) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions/{id}/manifest", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var out []manifestEntry
		for p, c := range s.files {
			sum := sha256.Sum256(c)
			out = append(out, manifestEntry{RelPath: p, Size: int64(len(c)), SHA256: hex.EncodeToString(sum[:])})
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("PUT /v1/sessions/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path       string `json:"path"`
			ContentB64 string `json:"content_b64"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		c, _ := base64.StdEncoding.DecodeString(body.ContentB64)
		s.mu.Lock()
		s.files[body.Path] = c
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/sessions/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("path")
		s.mu.Lock()
		c, ok := s.files[p]
		s.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(downloadFileResp{ContentB64: base64.StdEncoding.EncodeToString(c)})
	})
	return mux
}

func hashStr(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestConflictWritesSiblingNotClobber: when a file changed on BOTH sides, the
// sandbox version lands in a .opslify-conflict sibling and the operator's host
// file is left untouched.
func TestConflictWritesSiblingNotClobber(t *testing.T) {
	sb := newFakeSandbox()
	fd := newFakeDaemon(t, sb.mux())
	dir := t.TempDir()

	// A file synced at base "orig"; host now "HOST-EDIT", sandbox now "AGENT-EDIT".
	writeFile(t, filepath.Join(dir, "note.txt"), "HOST-EDIT")
	sb.files["note.txt"] = []byte("AGENT-EDIT")

	eng := newSyncEngine(newClient(fd.socketPath), "s1", dir, os.Stdout, os.Stderr)
	eng.base["note.txt"] = hashStr("orig") // both sides diverge from this base

	if err := eng.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if got, _ := os.ReadFile(filepath.Join(dir, "note.txt")); string(got) != "HOST-EDIT" {
		t.Errorf("host file clobbered: got %q, want HOST-EDIT", got)
	}
	sib, err := os.ReadFile(filepath.Join(dir, "note.txt.opslify-conflict"))
	if err != nil {
		t.Fatalf("conflict sibling not written: %v", err)
	}
	if string(sib) != "AGENT-EDIT" {
		t.Errorf("conflict sibling = %q, want AGENT-EDIT", sib)
	}
}

// TestCAFileNotSyncedBackToHost: the broker-injected .opslify-ca.pem living in
// /workspace is NOT written back to the host as a user file (F5.7 no-regression).
func TestCAFileNotSyncedBackToHost(t *testing.T) {
	sb := newFakeSandbox()
	fd := newFakeDaemon(t, sb.mux())
	dir := t.TempDir()
	sb.files[".opslify-ca.pem"] = []byte("-----BEGIN CERTIFICATE-----")
	sb.files["real.txt"] = []byte("keep me")

	eng := newSyncEngine(newClient(fd.socketPath), "s1", dir, os.Stdout, os.Stderr)
	if err := eng.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".opslify-ca.pem")); !os.IsNotExist(err) {
		t.Errorf(".opslify-ca.pem was synced back to host (must not be)")
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "real.txt")); string(got) != "keep me" {
		t.Errorf("ordinary sandbox file not pulled: %q", got)
	}
}

// TestInitialCopyInExcludesSecrets: planted secrets never enter the upload set.
func TestInitialCopyInExcludesSecrets(t *testing.T) {
	sb := newFakeSandbox()
	fd := newFakeDaemon(t, sb.mux())
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.go"), "package main")
	writeFile(t, filepath.Join(dir, ".env"), "SECRET=1")
	writeFile(t, filepath.Join(dir, "key.pem"), "PRIV")
	writeFile(t, filepath.Join(dir, "id_rsa"), "PRIV")
	writeFile(t, filepath.Join(dir, "credentials"), "AKIA...")

	eng := newSyncEngine(newClient(fd.socketPath), "s1", dir, os.Stdout, os.Stderr)
	if err := eng.initialCopyIn(context.Background()); err != nil {
		t.Fatalf("initialCopyIn: %v", err)
	}
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if _, ok := sb.files["app.go"]; !ok {
		t.Error("app.go should have been copied in")
	}
	for _, secret := range []string{".env", "key.pem", "id_rsa", "credentials"} {
		if _, ok := sb.files[secret]; ok {
			t.Errorf("secret %q was copied into the sandbox (must never be)", secret)
		}
	}
}

// TestSyncNewNoBindMount: `workspace sync --new` creates a workspace session
// WITHOUT passing the host dir into the create request — copy-not-bind. The
// create wire contract has no host-path field at all, and nothing carries the
// host dir. This asserts the invariant at the API boundary.
func TestSyncNewNoBindMount(t *testing.T) {
	sb := newFakeSandbox()
	mux := sb.mux()
	var createBody string
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		createBody = string(b)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createResp{SessionID: "s1", State: "ready"})
	})
	fd := newFakeDaemon(t, mux)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.go"), "package main")

	_, _, err := execRoot(t, "workspace", "sync", dir, "--new", "--once", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("workspace sync --new --once: %v", err)
	}
	if strings.Contains(createBody, dir) {
		t.Errorf("create request leaked host dir (would imply a bind mount): %s", createBody)
	}
	// The file crossed by explicit transfer, not a mount.
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if _, ok := sb.files["app.go"]; !ok {
		t.Error("app.go should have been transferred (copy), not mounted")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
