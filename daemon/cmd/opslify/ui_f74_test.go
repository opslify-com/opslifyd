package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- F7.4: the widened mutation routes proxy to the daemon, each behind the token ---

func TestUIWidenedRoutesReachDaemon(t *testing.T) {
	var gotExecArgv string
	var listedSecrets bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"session_id":"new1","state":"ready"}`))
	})
	mux.HandleFunc("POST /v1/sessions/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotExecArgv = string(b)
		ndjson(w, frame{Stream: "stdout", Data: "hi\n"}, frame{Exit: ptrInt(0)})
	})
	mux.HandleFunc("GET /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		listedSecrets = true
		// Metadata only — the daemon NEVER returns a value.
		w.Write([]byte(`[{"ref":"aws/deploy","provider":"aws","created_at":"2026-01-01T00:00:00Z"}]`))
	})
	mux.HandleFunc("POST /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"ref":"aws/deploy","created_at":"2026-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("DELETE /v1/secrets/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/workspaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name":"proj","snapshots":1,"latest_tag":1}]`))
	})
	mux.HandleFunc("DELETE /v1/workspaces/{name}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/policy", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"hash":"abc","strict_exec":false}`))
	})
	fd := newFakeDaemon(t, mux)

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// create
	resp := doTok(t, http.MethodPost, srv.URL+"/v1/sessions", tok, strings.NewReader(`{"mode":"scratch"}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("create via UI = %d, want 201", resp.StatusCode)
	}
	// exec — SAME daemon exec handler (F4 classifier path); no second exec route.
	resp = doTok(t, http.MethodPost, srv.URL+"/v1/sessions/s1/exec", tok, strings.NewReader(`{"argv":["ls"]}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("exec via UI = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(gotExecArgv, `"ls"`) {
		t.Errorf("exec body not forwarded to the daemon exec handler: %q", gotExecArgv)
	}
	// secrets list — names only, NO value.
	resp = doTok(t, http.MethodGet, srv.URL+"/v1/secrets", tok, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !listedSecrets {
		t.Error("secrets list did not reach the daemon")
	}
	if strings.Contains(string(body), "value") {
		t.Errorf("secrets list response leaked a value field: %q", body)
	}
	// add + remove secret
	resp = doTok(t, http.MethodPost, srv.URL+"/v1/secrets", tok, strings.NewReader(`{"ref":"aws/deploy","value_b64":"eA=="}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("add secret via UI = %d, want 201", resp.StatusCode)
	}
	resp = doTok(t, http.MethodDelete, srv.URL+"/v1/secrets/aws/deploy", tok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("remove secret via UI = %d, want 204", resp.StatusCode)
	}
	// workspaces ls/rm
	resp = doTok(t, http.MethodGet, srv.URL+"/v1/workspaces", tok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("workspaces ls via UI = %d, want 200", resp.StatusCode)
	}
	resp = doTok(t, http.MethodDelete, srv.URL+"/v1/workspaces/proj", tok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("workspaces rm via UI = %d, want 204", resp.StatusCode)
	}
	// policy view
	resp = doTok(t, http.MethodGet, srv.URL+"/v1/policy", tok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("policy view via UI = %d, want 200", resp.StatusCode)
	}
}

// --- F7.4: every NEW route is 401 tokenless and 403 with a foreign Host ---

func TestUINewRoutesTokenAndHostGuarded(t *testing.T) {
	mux := http.NewServeMux()
	daemonHit := false
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { daemonHit = true })
	fd := newFakeDaemon(t, mux)

	h, _ := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	routes := []struct{ method, path string }{
		{http.MethodPost, "/v1/sessions"},
		{http.MethodPost, "/v1/sessions/s1/exec"},
		{http.MethodGet, "/v1/secrets"},
		{http.MethodPost, "/v1/secrets"},
		{http.MethodDelete, "/v1/secrets/aws/deploy"},
		{http.MethodGet, "/v1/workspaces"},
		{http.MethodDelete, "/v1/workspaces/proj"},
		{http.MethodGet, "/v1/policy"},
		{http.MethodPost, "/ui/link"},
		{http.MethodGet, "/ui/link/status"},
	}
	for _, rt := range routes {
		// No token → 401.
		resp := doTok(t, rt.method, srv.URL+rt.path, "", strings.NewReader("{}"))
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("tokenless %s %s must be 401, got %d", rt.method, rt.path, resp.StatusCode)
		}
		// Foreign Host → 403 (checked before the token).
		req, _ := http.NewRequest(rt.method, srv.URL+rt.path, strings.NewReader("{}"))
		req.Host = "evil.com"
		fresp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", rt.method, rt.path, err)
		}
		fresp.Body.Close()
		if fresp.StatusCode != http.StatusForbidden {
			t.Errorf("foreign-Host %s %s must be 403, got %d", rt.method, rt.path, fresp.StatusCode)
		}
	}
	if daemonHit {
		t.Error("a tokenless/foreign-Host request reached the daemon")
	}
}

// --- F7.4: raw /workspace file GET stays refused from the browser (F3.6 hole closed) ---

func TestUIRawFilesGetStillRefused(t *testing.T) {
	mux := http.NewServeMux()
	daemonHit := false
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { daemonHit = true })
	fd := newFakeDaemon(t, mux)

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doTok(t, http.MethodGet, srv.URL+"/v1/sessions/s1/files?path=x", tok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("raw files GET must stay 403, got %d", resp.StatusCode)
	}
	if daemonHit {
		t.Error("a raw files GET reached the daemon — the F3.6 hole reopened")
	}
	if allowedProxyRoute(http.MethodGet, "/v1/sessions/s1/files") {
		t.Error("allowedProxyRoute permitted the raw files GET")
	}
}

// --- F7.4: /ui/link path guardrails ---

func TestValidateLinkDir(t *testing.T) {
	good := t.TempDir()
	real, err := validateLinkDir(good)
	if err != nil {
		t.Fatalf("valid dir %q rejected: %v", good, err)
	}
	if real == "" {
		t.Error("valid dir returned empty resolved path")
	}

	// A file is not a directory.
	f := filepath.Join(good, "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink whose target is a sensitive dir must be refused by its resolved target.
	link := filepath.Join(good, "escape")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}

	home, _ := os.UserHomeDir()
	bad := []struct{ name, dir string }{
		{"root", "/"},
		{"etc", "/etc"},
		{"var", "/var"},
		{"usr", "/usr"},
		{"boot", "/boot"},
		{"root-home", "/root"},
		{"home-root", home},
		{"dotdot", filepath.Join(good, "..", "x")},
		{"nonexistent", filepath.Join(good, "does-not-exist")},
		{"non-dir", f},
		{"symlink-escape", link},
		{"empty", ""},
	}
	for _, b := range bad {
		if b.dir == "" && b.name != "empty" {
			continue
		}
		if _, err := validateLinkDir(b.dir); err == nil {
			t.Errorf("validateLinkDir(%s=%q) must be refused", b.name, b.dir)
		}
	}
}

// --- F7.4: POST /ui/link starts F7.3 sync; the daemon never receives the host path ---

func TestUILinkDaemonNeverSeesHostPath(t *testing.T) {
	// Record every request path + body the daemon sees.
	var mu sync.Mutex
	var seen []string
	record := func(r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.URL.Path+"?"+r.URL.RawQuery+" "+string(b))
		mu.Unlock()
	}
	uploaded := make(chan string, 8)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/sessions/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		uploaded <- r.PathValue("id")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/sessions/{id}/manifest", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { record(r); w.WriteHeader(200) })
	fd := newFakeDaemon(t, mux)

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(linkRequest{Dir: hostDir, SessionID: "s1", On: true})
	resp := doTok(t, http.MethodPost, srv.URL+"/ui/link", tok, strings.NewReader(string(body)))
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link = %d (%s), want 200", resp.StatusCode, rb)
	}

	// Wait for the copy-in to hit the daemon.
	select {
	case id := <-uploaded:
		if id != "s1" {
			t.Errorf("upload targeted session %q, want s1", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("copy-in never reached the daemon")
	}

	// The daemon must never have received the host absolute path in any request.
	realHost, _ := validateLinkDir(hostDir)
	mu.Lock()
	defer mu.Unlock()
	for _, s := range seen {
		if strings.Contains(s, hostDir) || (realHost != "" && strings.Contains(s, realHost)) {
			t.Errorf("daemon received the host path: %q", s)
		}
	}

	// Status reports the running link.
	sresp := doTok(t, http.MethodGet, srv.URL+"/ui/link/status", tok, nil)
	var st []linkStatus
	json.NewDecoder(sresp.Body).Decode(&st)
	sresp.Body.Close()
	if len(st) != 1 || st[0].SessionID != "s1" {
		t.Fatalf("status = %+v, want one link for s1", st)
	}
	if st[0].Dir == hostDir {
		// Dir is the resolved real path; it is host-side state, fine to expose in the
		// UI's OWN status (it never crosses to the daemon).
	}

	// Unlink stops it.
	body, _ = json.Marshal(linkRequest{SessionID: "s1", On: false})
	uresp := doTok(t, http.MethodPost, srv.URL+"/ui/link", tok, strings.NewReader(string(body)))
	uresp.Body.Close()
	if uresp.StatusCode != http.StatusOK {
		t.Errorf("unlink = %d, want 200", uresp.StatusCode)
	}
}

// --- F7.4: POST /ui/link refuses a sensitive path with a clear error ---

func TestUILinkRefusesSensitiveDir(t *testing.T) {
	mux := http.NewServeMux()
	daemonHit := false
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { daemonHit = true })
	fd := newFakeDaemon(t, mux)

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, dir := range []string{"/etc", "/", filepath.Join(t.TempDir(), "..", "x"), "/does/not/exist"} {
		body, _ := json.Marshal(linkRequest{Dir: dir, SessionID: "s1", On: true})
		resp := doTok(t, http.MethodPost, srv.URL+"/ui/link", tok, strings.NewReader(string(body)))
		msg, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("link %q must be 400, got %d", dir, resp.StatusCode)
		}
		if !strings.Contains(string(msg), "refusing to link") {
			t.Errorf("link %q error not clear: %q", dir, msg)
		}
	}
	if daemonHit {
		t.Error("a refused link reached the daemon")
	}
}

func ptrInt(i int) *int { return &i }
