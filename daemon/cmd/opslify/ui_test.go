package main

import (
	"bufio"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// --- bind guard: localhost-only, enforced in code ---

func TestAssertLoopbackHost(t *testing.T) {
	ok := []string{"127.0.0.1", "::1", "localhost"}
	for _, h := range ok {
		if err := assertLoopbackHost(h); err != nil {
			t.Errorf("loopback host %q wrongly rejected: %v", h, err)
		}
	}
	bad := []string{"0.0.0.0", "192.168.1.10", "10.0.0.1", "::", "example.com", ""}
	for _, h := range bad {
		if err := assertLoopbackHost(h); err == nil {
			t.Errorf("non-loopback host %q wrongly accepted", h)
		}
	}
}

func TestAssertLoopbackAddr(t *testing.T) {
	if err := assertLoopbackAddr(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4646}); err != nil {
		t.Errorf("127.0.0.1 addr rejected: %v", err)
	}
	if err := assertLoopbackAddr(&net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 4646}); err == nil {
		t.Error("0.0.0.0 addr wrongly accepted")
	}
}

// --- embedded SPA is self-contained: no external asset references ---

func TestEmbeddedSPASelfContained(t *testing.T) {
	sub, err := fs.Sub(webuiFS, "webui")
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	// Any http(s):// URL that isn't inside an HTML/JS comment would be an external
	// fetch. We forbid ALL http(s):// literals in the served bytes to be strict.
	ext := regexp.MustCompile(`https?://[^\s"')]+`)
	// Allowlist: comments in our source reference the daemon route contract, not a
	// network host. We only allow the literal placeholder scheme-less examples, so
	// assert there is NO scheme://host anywhere.
	var files []string
	fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if len(files) == 0 {
		t.Fatal("no embedded SPA files found")
	}
	for _, f := range files {
		b, err := fs.ReadFile(sub, f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if m := ext.FindAllString(string(b), -1); len(m) > 0 {
			t.Errorf("%s references external URL(s) %v — SPA must be fully self-contained", f, m)
		}
		// Strict: no CDN-ish tokens either.
		for _, bad := range []string{"cdn.", "googleapis", "unpkg", "jsdelivr", "//fonts."} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s contains external token %q", f, bad)
			}
		}
	}
	// The entrypoint must be embedded and served.
	if _, err := fs.ReadFile(sub, "index.html"); err != nil {
		t.Errorf("index.html not embedded: %v", err)
	}
}

func TestUIServesEmbeddedIndex(t *testing.T) {
	h, err := newUIServer(filepath.Join(t.TempDir(), "unused.sock"))
	if err != nil {
		t.Fatalf("newUIServer: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("get /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("want 200 for /, got %d", resp.StatusCode)
	}
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "opslify") {
		t.Errorf("served index does not look like the SPA: %q", string(buf[:n]))
	}
}

// --- reverse proxy forwards /v1/sessions to the daemon socket ---

func TestUIProxyForwardsSessions(t *testing.T) {
	mux := http.NewServeMux()
	hit := false
	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Write([]byte(`[{"session_id":"s1","state":"ready"}]`))
	})
	fd := newFakeDaemon(t, mux)

	h, err := newUIServer(fd.socketPath)
	if err != nil {
		t.Fatalf("newUIServer: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/sessions")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if !hit {
		t.Error("proxy did not forward to the daemon socket")
	}
	if resp.StatusCode != 200 {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}

// --- proxy exposes ONLY /v1/* (no new route reaches the daemon) ---

func TestUIProxyOnlyExposesV1(t *testing.T) {
	mux := http.NewServeMux()
	daemonHit := false
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { daemonHit = true })
	fd := newFakeDaemon(t, mux)

	h, _ := newUIServer(fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// A non-/v1 path must be served by the embedded file server (404 for an
	// unknown asset), NOT proxied to the daemon.
	resp, err := http.Get(srv.URL + "/admin/secret")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if daemonHit {
		t.Error("a non-/v1 path reached the daemon — the proxy must expose only /v1/*")
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("want 404 from the file server for an unknown asset, got %d", resp.StatusCode)
	}
}

// --- Kill button path proxies to the existing DELETE endpoint ---

func TestUIProxyForwardsKill(t *testing.T) {
	var killed string
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		killed = r.PathValue("id")
		w.WriteHeader(http.StatusNoContent)
	})
	fd := newFakeDaemon(t, mux)

	h, _ := newUIServer(fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1/sessions/zz9", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp.Body.Close()
	if killed != "zz9" {
		t.Errorf("kill not proxied to existing DELETE endpoint; got %q", killed)
	}
}

// --- SSE trace stream is proxied AND streamed incrementally (not buffered) ---

func TestUIProxyStreamsSSEIncrementally(t *testing.T) {
	// The fake daemon emits one SSE frame, flushes, then holds the connection
	// open. If the proxy buffered to completion, the client would block forever;
	// a streaming proxy delivers the first frame immediately.
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions/{id}/trace", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			t.Error("proxy dropped the Accept: text/event-stream header")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl := w.(http.Flusher)
		w.Write([]byte("data: {\"seq\":0,\"type\":\"exec.output\"}\n\n"))
		fl.Flush()
		<-release // hold the stream open until the test has read the live frame
	})
	fd := newFakeDaemon(t, mux)
	defer close(release)

	h, _ := newUIServer(fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/sessions/s1/trace?from_seq=0", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get stream: %v", err)
	}
	defer resp.Body.Close()

	// Read the first frame with a deadline while the server still holds the
	// connection open — proves incremental (non-buffered) delivery.
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		br := bufio.NewReader(resp.Body)
		line, err := br.ReadString('\n')
		ch <- res{line, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("read frame: %v", r.err)
		}
		if !strings.Contains(r.line, "exec.output") {
			t.Errorf("first live frame not delivered incrementally: %q", r.line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no SSE frame within 2s — proxy buffered instead of streaming")
	}
}

// --- DNS-rebinding guard: a non-loopback Host header is refused, never proxied ---

func TestUIRefusesNonLoopbackHost(t *testing.T) {
	mux := http.NewServeMux()
	daemonHit := false
	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) { daemonHit = true })
	fd := newFakeDaemon(t, mux)

	h, _ := newUIServer(fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// A page on evil.com that rebinds DNS to 127.0.0.1 would still send Host: evil.com.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/sessions", nil)
	req.Host = "evil.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-loopback Host must be 403, got %d", resp.StatusCode)
	}
	if daemonHit {
		t.Error("request with a foreign Host header reached the daemon — DNS-rebinding guard failed")
	}

	// The unit check directly, incl. loopback names/ports that MUST pass.
	for _, ok := range []string{"127.0.0.1:4646", "localhost:4646", "[::1]:4646", "127.0.0.1"} {
		if !hostIsLoopback(ok) {
			t.Errorf("loopback Host %q wrongly refused", ok)
		}
	}
	for _, bad := range []string{"evil.com", "evil.com:4646", "10.0.0.5:4646", ""} {
		if hostIsLoopback(bad) {
			t.Errorf("non-loopback Host %q wrongly accepted", bad)
		}
	}
}

// --- proxy is read + Kill only: mutation routes are refused, never proxied ---

func TestUIProxyAllowlistBlocksMutations(t *testing.T) {
	mux := http.NewServeMux()
	daemonHit := false
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { daemonHit = true })
	fd := newFakeDaemon(t, mux)

	h, _ := newUIServer(fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// These pre-existing daemon routes must NOT be reachable through the UI bridge.
	blocked := []struct{ method, path string }{
		{http.MethodPost, "/v1/sessions"},                   // create a session
		{http.MethodPost, "/v1/sessions/s1/exec"},           // run a command
		{http.MethodPut, "/v1/sessions/s1/files"},           // upload a file
		{http.MethodDelete, "/v1/workspaces/proj"},          // delete a workspace
		{http.MethodDelete, "/v1/sessions/s1/whatever"},     // mutation sub-path
		{http.MethodPost, "/v1/sessions/s1/approvals"},      // approvals list path (not resolve) — not a POST target
		{http.MethodPost, "/v1/sessions/s1/approvals/e1/x"}, // over-long approvals path
		{http.MethodPost, "/v1/sessions/s1/files"},          // POST file path
		{http.MethodPut, "/v1/sessions/s1/approvals/e1"},    // PUT is not the resolve verb
		{http.MethodGet, "/v1/sessions/s1/files"},           // RAW /workspace download — must NOT be browser-reachable
		{http.MethodGet, "/v1/sessions/s1"},                 // single-session GET not needed by the UI — kept closed
	}
	for _, b := range blocked {
		req, _ := http.NewRequest(b.method, srv.URL+b.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", b.method, b.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s must be 403 (read+kill only), got %d", b.method, b.path, resp.StatusCode)
		}
	}
	if daemonHit {
		t.Error("a blocked mutation route reached the daemon — the UI must be read + Kill only")
	}

	// And the allowed routes pass the allowlist: the exact read + Kill +
	// history/verify GETs + the single approvals-resolve POST — nothing more.
	for _, a := range []struct{ method, path string }{
		{http.MethodGet, "/v1/sessions"},                  // live list
		{http.MethodGet, "/v1/sessions/history"},          // F3.6 history list
		{http.MethodGet, "/v1/sessions/s1/trace"},         // trace read / SSE replay
		{http.MethodGet, "/v1/sessions/s1/verify"},        // F3.6 verify verdict
		{http.MethodGet, "/v1/sessions/s1/approvals/e1"},  // F4.3 approval view poll (redacted)
		{http.MethodPost, "/v1/sessions/s1/approvals/e1"}, // F4.3 approve/deny
		{http.MethodDelete, "/v1/sessions/s1"},            // Kill
	} {
		if !allowedProxyRoute(a.method, a.path) {
			t.Errorf("allowed route %s %s wrongly blocked", a.method, a.path)
		}
	}

	// The blocked POST/PUT targets + the raw-file GET must also fail the predicate.
	for _, b := range []struct{ method, path string }{
		{http.MethodPost, "/v1/sessions"},
		{http.MethodPost, "/v1/sessions/s1/exec"},
		{http.MethodPost, "/v1/sessions/s1/approvals"},
		{http.MethodPost, "/v1/sessions/s1/approvals/e1/x"},
		{http.MethodGet, "/v1/sessions/s1/files"}, // raw workspace download — closed
	} {
		if allowedProxyRoute(b.method, b.path) {
			t.Errorf("blocked route %s %s wrongly allowed", b.method, b.path)
		}
	}
}

// --- Approve/Deny proxies to the existing F4.3 resolve endpoint ---

func TestUIProxyForwardsApprovalResolve(t *testing.T) {
	var gotSession, gotExec, gotBody string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/{id}/approvals/{exec_id}", func(w http.ResponseWriter, r *http.Request) {
		gotSession, gotExec = r.PathValue("id"), r.PathValue("exec_id")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"state":"approved"}`))
	})
	fd := newFakeDaemon(t, mux)

	h, _ := newUIServer(fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/sessions/s7/approvals/e9",
		strings.NewReader(`{"decision":"approve","comment":"lgtm"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve via UI proxy status = %d, want 200", resp.StatusCode)
	}
	if gotSession != "s7" || gotExec != "e9" {
		t.Errorf("resolve not proxied to F4.3 endpoint: session=%q exec=%q", gotSession, gotExec)
	}
	if !strings.Contains(gotBody, "approve") {
		t.Errorf("decision body not forwarded: %q", gotBody)
	}
}

// --- DNS-rebind Host-guard covers the NEW F3.6 routes too ---

func TestUIRefusesNonLoopbackHostOnNewRoutes(t *testing.T) {
	mux := http.NewServeMux()
	daemonHit := false
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { daemonHit = true })
	fd := newFakeDaemon(t, mux)

	h, _ := newUIServer(fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	routes := []struct{ method, path string }{
		{http.MethodGet, "/v1/sessions/history"},
		{http.MethodGet, "/v1/sessions/s1/verify"},
		{http.MethodPost, "/v1/sessions/s1/approvals/e1"},
	}
	for _, rt := range routes {
		req, _ := http.NewRequest(rt.method, srv.URL+rt.path, strings.NewReader("{}"))
		req.Host = "evil.com" // a rebound DNS name still carries the attacker's Host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", rt.method, rt.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s with foreign Host must be 403, got %d", rt.method, rt.path, resp.StatusCode)
		}
	}
	if daemonHit {
		t.Error("a foreign-Host request to a new route reached the daemon — Host-guard failed")
	}
}

// guard: ui + top are wired into the root command.
func TestUITopCommandsWired(t *testing.T) {
	names := map[string]bool{}
	for _, c := range rootCmd().Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"ui", "top"} {
		if !names[want] {
			t.Errorf("root missing subcommand %q", want)
		}
	}
}
