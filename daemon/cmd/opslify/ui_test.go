package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"github.com/opslify-com/opslifyd/internal/uiguard"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuf is a goroutine-safe bytes.Buffer for capturing command output that a
// background Serve goroutine writes while the test reads it.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// testToken mints a token for tests and fails hard if the CSPRNG errors.
func testToken(t *testing.T) string {
	t.Helper()
	tok, err := uiguard.MintToken()
	if err != nil {
		t.Fatalf("uiguard.MintToken: %v", err)
	}
	return tok
}

// newTestUIServer builds a UI server with a fresh token and returns both.
func newTestUIServer(t *testing.T, socketPath string) (http.Handler, string) {
	t.Helper()
	tok := testToken(t)
	h, err := newUIServer(socketPath, tok)
	if err != nil {
		t.Fatalf("newUIServer: %v", err)
	}
	return h, tok
}

// doTok performs a request with the launch token supplied via the
// X-Opslify-UI-Token header (the curl/test path).
func doTok(t *testing.T, method, url, token string, body io.Reader) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, body)
	if token != "" {
		req.Header.Set(uiguard.TokenHeader, token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// --- bind guard: localhost-only, enforced in code ---

func TestAssertLoopbackHost(t *testing.T) {
	ok := []string{"127.0.0.1", "::1", "localhost"}
	for _, h := range ok {
		if err := uiguard.AssertLoopbackHost(h); err != nil {
			t.Errorf("loopback host %q wrongly rejected: %v", h, err)
		}
	}
	bad := []string{"0.0.0.0", "192.168.1.10", "10.0.0.1", "::", "example.com", ""}
	for _, h := range bad {
		if err := uiguard.AssertLoopbackHost(h); err == nil {
			t.Errorf("non-loopback host %q wrongly accepted", h)
		}
	}
}

func TestAssertLoopbackAddr(t *testing.T) {
	if err := uiguard.AssertLoopbackAddr(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4646}); err != nil {
		t.Errorf("127.0.0.1 addr rejected: %v", err)
	}
	if err := uiguard.AssertLoopbackAddr(&net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 4646}); err == nil {
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
	h, tok := newTestUIServer(t, filepath.Join(t.TempDir(), "unused.sock"))
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doTok(t, http.MethodGet, srv.URL+"/", tok, nil)
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

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doTok(t, http.MethodGet, srv.URL+"/v1/sessions", tok, nil)
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

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// A non-/v1 path must be served by the embedded file server (404 for an
	// unknown asset), NOT proxied to the daemon.
	resp := doTok(t, http.MethodGet, srv.URL+"/admin/secret", tok, nil)
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

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doTok(t, http.MethodDelete, srv.URL+"/v1/sessions/zz9", tok, nil)
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

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/sessions/s1/trace?from_seq=0", nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set(uiguard.TokenHeader, tok)
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

	h, _ := newTestUIServer(t, fd.socketPath)
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
		if !uiguard.HostIsLoopback(ok) {
			t.Errorf("loopback Host %q wrongly refused", ok)
		}
	}
	for _, bad := range []string{"evil.com", "evil.com:4646", "10.0.0.5:4646", ""} {
		if uiguard.HostIsLoopback(bad) {
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

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// These daemon routes must NOT be reachable through the UI bridge even after
	// the F7.4 widening — the raw-file hole and every non-allowlisted verb/path.
	blocked := []struct{ method, path string }{
		{http.MethodPut, "/v1/sessions/s1/files"},           // upload a file (raw transfer)
		{http.MethodPost, "/v1/sessions/s1/files"},          // POST file path
		{http.MethodGet, "/v1/sessions/s1/files"},           // RAW /workspace download — must NOT be browser-reachable
		{http.MethodDelete, "/v1/sessions/s1/whatever"},     // mutation sub-path (not Kill)
		{http.MethodPost, "/v1/sessions/s1/approvals"},      // approvals list path (not resolve)
		{http.MethodPost, "/v1/sessions/s1/approvals/e1/x"}, // over-long approvals path
		{http.MethodPut, "/v1/sessions/s1/approvals/e1"},    // PUT is not the resolve verb
		{http.MethodPost, "/v1/sessions/s1/exec/x"},         // over-long exec path
		{http.MethodGet, "/v1/sessions/s1"},                 // single-session GET not needed by the UI — kept closed
		{http.MethodPut, "/v1/secrets/foo"},                 // PUT is not a secrets verb
		{http.MethodDelete, "/v1/secrets"},                  // DELETE needs a ref
		{http.MethodPost, "/v1/workspaces"},                 // workspaces is ls/rm only
		{http.MethodDelete, "/v1/workspaces/a/b"},           // workspace name is single-segment
		{http.MethodPost, "/v1/policy"},                     // policy is read-only
	}
	for _, b := range blocked {
		resp := doTok(t, b.method, srv.URL+b.path, tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s must be 403 (not on the F7.4 allowlist), got %d", b.method, b.path, resp.StatusCode)
		}
	}
	if daemonHit {
		t.Error("a blocked route reached the daemon — the UI allowlist must gate it")
	}

	// And the allowed routes pass the allowlist: full CLI parity behind the token.
	for _, a := range []struct{ method, path string }{
		{http.MethodGet, "/v1/sessions"},                  // live list
		{http.MethodPost, "/v1/sessions"},                 // F7.4 create
		{http.MethodGet, "/v1/sessions/history"},          // F3.6 history list
		{http.MethodGet, "/v1/sessions/s1/trace"},         // trace read / SSE replay
		{http.MethodGet, "/v1/sessions/s1/verify"},        // F3.6 verify verdict
		{http.MethodGet, "/v1/sessions/s1/approvals/e1"},  // F4.3 approval view poll (redacted)
		{http.MethodPost, "/v1/sessions/s1/approvals/e1"}, // F4.3 approve/deny
		{http.MethodPost, "/v1/sessions/s1/exec"},         // F7.4 exec (SAME F4 path as the CLI)
		{http.MethodDelete, "/v1/sessions/s1"},            // Kill
		{http.MethodGet, "/v1/secrets"},                   // F5.6 list NAMES
		{http.MethodPost, "/v1/secrets"},                  // F5.6 add
		{http.MethodDelete, "/v1/secrets/aws/deploy"},     // F5.6 remove by ref (slash in ref)
		{http.MethodGet, "/v1/workspaces"},                // F2.2 ls
		{http.MethodDelete, "/v1/workspaces/proj"},        // F2.2 rm
		{http.MethodGet, "/v1/policy"},                    // F4.1 active-policy view
	} {
		if !allowedProxyRoute(a.method, a.path) {
			t.Errorf("allowed route %s %s wrongly blocked", a.method, a.path)
		}
	}

	// The refused targets must also fail the predicate directly.
	for _, b := range []struct{ method, path string }{
		{http.MethodGet, "/v1/sessions/s1/files"}, // raw workspace download — closed
		{http.MethodPut, "/v1/sessions/s1/files"}, // raw upload — closed
		{http.MethodPost, "/v1/sessions/s1/approvals"},
		{http.MethodPost, "/v1/sessions/s1/approvals/e1/x"},
		{http.MethodPost, "/v1/sessions/s1/exec/x"},
		{http.MethodDelete, "/v1/secrets"},  // needs a ref
		{http.MethodPost, "/v1/workspaces"}, // ls/rm only
		{http.MethodPost, "/v1/policy"},     // read only
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

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/sessions/s7/approvals/e9",
		strings.NewReader(`{"decision":"approve","comment":"lgtm"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(uiguard.TokenHeader, tok)
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

	h, _ := newTestUIServer(t, fd.socketPath)
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

// --- F7.1: per-launch token mint is random and ≥256-bit ---

func TestMintUITokenRandomAndStrong(t *testing.T) {
	a := testToken(t)
	b := testToken(t)
	if a == b {
		t.Fatal("two launches minted the SAME token — the token must be per-launch random")
	}
	// hex of 32 bytes = 64 chars = 256 bits of entropy.
	if len(a) != 64 {
		t.Errorf("token length = %d hex chars, want 64 (256-bit); got %q", len(a), a)
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Errorf("token is not hex: %v", err)
	}
}

// --- F7.1: `opslify ui --no-open` prints a ?token= launch URL ---

func TestUICmdPrintsTokenURL(t *testing.T) {
	buf := &syncBuf{}
	cmd := uiCmd()
	// A random free loopback port + a definitely-unused socket; --no-open so the
	// command binds, prints, and returns as soon as we cancel the context.
	cmd.SetArgs([]string{"--no-open", "--port", "0", "--socket", filepath.Join(t.TempDir(), "unused.sock")})
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()
	// Give it a moment to bind + print, then cancel to unblock Serve.
	deadline := time.After(2 * time.Second)
	for {
		if strings.Contains(buf.String(), "?token=") {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatalf("ui did not print a ?token= URL; output:\n%s", buf.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done

	out := buf.String()
	re := regexp.MustCompile(`\?token=[0-9a-f]{64}`)
	if !re.MatchString(out) {
		t.Errorf("output missing a ?token=<64-hex> launch URL:\n%s", out)
	}
}

// --- F7.1: no token → 401 on a static path AND a /v1/* proxy path ---

func TestUIRejectsMissingToken(t *testing.T) {
	mux := http.NewServeMux()
	daemonHit := false
	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) { daemonHit = true })
	fd := newFakeDaemon(t, mux)

	h, tok := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// No token at all → 401 on both a static asset and a proxy route.
	for _, path := range []string{"/", "/app.js", "/v1/sessions"} {
		resp := doTok(t, http.MethodGet, srv.URL+path, "", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("no-token %s must be 401, got %d", path, resp.StatusCode)
		}
	}
	if daemonHit {
		t.Error("a token-less request reached the daemon — auth must gate the proxy")
	}

	// Wrong token → 401.
	wrong := strings.Repeat("0", len(tok))
	if wrong == tok {
		wrong = strings.Repeat("1", len(tok))
	}
	resp := doTok(t, http.MethodGet, srv.URL+"/v1/sessions", wrong, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong-token /v1/sessions must be 401, got %d", resp.StatusCode)
	}

	// Right token (header) → served/forwarded.
	resp = doTok(t, http.MethodGet, srv.URL+"/v1/sessions", tok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid-token /v1/sessions must be 200, got %d", resp.StatusCode)
	}
	if !daemonHit {
		t.Error("valid-token request did not reach the daemon")
	}
}

// --- F7.1: constant-time compare, verified on the exported predicate ---

func TestTokenMatchesConstantTimePath(t *testing.T) {
	tok := testToken(t)
	if !uiguard.TokenMatches(tok, tok) {
		t.Error("identical tokens must match")
	}
	if uiguard.TokenMatches(tok, "") || uiguard.TokenMatches("", tok) || uiguard.TokenMatches("", "") {
		t.Error("empty token must never match")
	}
	if uiguard.TokenMatches(tok, tok[:len(tok)-1]+"x") {
		t.Error("a one-byte-different token must not match")
	}
	// Differing lengths must not match (ConstantTimeCompare returns 0).
	if uiguard.TokenMatches(tok, tok+"a") {
		t.Error("a longer token must not match")
	}
}

// --- F7.1: ?token= index request sets the auth cookie; the cookie then serves ---

func TestUITokenCookieBootstrap(t *testing.T) {
	h, tok := newTestUIServer(t, filepath.Join(t.TempDir(), "unused.sock"))
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Load the index WITH ?token= → 200 and a Set-Cookie for the HttpOnly token.
	resp := doTok(t, http.MethodGet, srv.URL+"/?token="+tok, "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("?token= index must be 200, got %d", resp.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == uiguard.TokenCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("?token= index did not set the auth cookie")
	}
	if !cookie.HttpOnly {
		t.Error("auth cookie must be HttpOnly (keep the token out of JS)")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("auth cookie must be SameSite=Strict, got %v", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("auth cookie Path must be /, got %q", cookie.Path)
	}

	// A follow-up request carrying ONLY that cookie (no query, no header) is served.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/app.js", nil)
	req.AddCookie(cookie)
	got, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("cookie follow-up: %v", err)
	}
	got.Body.Close()
	if got.StatusCode != http.StatusOK {
		t.Errorf("cookie-authenticated /app.js must be 200, got %d", got.StatusCode)
	}
}

// --- F7.1: DNS-rebind — foreign Host is 403; loopback Host without token is 401 ---

func TestUIRebindWithoutTokenRefused(t *testing.T) {
	mux := http.NewServeMux()
	daemonHit := false
	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) { daemonHit = true })
	fd := newFakeDaemon(t, mux)

	h, _ := newTestUIServer(t, fd.socketPath)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Foreign Host → 403 (Host-guard, checked first).
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/sessions", nil)
	req.Host = "evil.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("foreign-host req: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("foreign Host must be 403 (Host-guard), got %d", resp.StatusCode)
	}

	// Loopback Host but NO token → 401 (the gap the Host-guard alone left).
	resp = doTok(t, http.MethodGet, srv.URL+"/v1/sessions", "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("loopback-Host, no-token rebind page must be 401, got %d", resp.StatusCode)
	}
	if daemonHit {
		t.Error("a rebind/no-token request reached the daemon")
	}
}

// --- F7.1: no audit-signing identity key is imported/used in the UI path ---

func TestUINoIdentityKeyImport(t *testing.T) {
	b, err := os.ReadFile("ui.go")
	if err != nil {
		t.Fatalf("read ui.go: %v", err)
	}
	src := string(b)
	for _, bad := range []string{"identity", "signing", "ed25519", "PrivateKey", "vault", "keyring"} {
		if strings.Contains(strings.ToLower(src), strings.ToLower(bad)) {
			t.Errorf("ui.go references %q — the UI path must never touch the audit-signing identity key", bad)
		}
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
