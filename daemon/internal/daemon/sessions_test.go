package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/session"
)

// fakeManager is a SessionService double so the REST layer is tested without a
// real Manager, runtime, or podman.
type fakeManager struct {
	created    *session.Session
	createErr  error
	execErr    error
	execOut    func(session.ExecSink) error
	destroyed  []string
	destroyErr error
	list       []session.View
	lastExec   session.ExecOptions
}

func (f *fakeManager) Create(_ context.Context, req session.CreateRequest) (*session.Session, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	s := &session.Session{ID: "sess-1", State: session.StateReady, Mode: req.Mode}
	f.created = s
	return s, nil
}

func (f *fakeManager) Exec(_ context.Context, id string, opts session.ExecOptions, sink session.ExecSink) error {
	f.lastExec = opts
	if f.execErr != nil {
		return f.execErr
	}
	if f.execOut != nil {
		return f.execOut(sink)
	}
	return nil
}

func (f *fakeManager) Destroy(_ context.Context, id string) error {
	f.destroyed = append(f.destroyed, id)
	return f.destroyErr
}

func (f *fakeManager) List() []session.View { return f.list }

// mustPost/mustGet issue a request and fail the test on a transport error, so
// callers can assert on the response without a repeated err check (which go vet
// otherwise flags when discarded).
func mustPost(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func mustGet(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// newTestDaemon builds a daemon wired with a fake session manager.
func newTestDaemon(t *testing.T, mgr SessionService) *Daemon {
	t.Helper()
	d, err := New(Options{
		Verifier:     okVerifier(),
		RuntimeProbe: func() error { return nil },
		Sessions:     mgr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestHTTPCreateSession(t *testing.T) {
	mgr := &fakeManager{}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/sessions", "application/json",
		strings.NewReader(`{"mode":"scratch","ttl":"10m"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	var body struct {
		SessionID string `json:"session_id"`
		State     string `json:"state"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if body.SessionID != "sess-1" || body.State != "ready" {
		t.Fatalf("body = %+v", body)
	}
}

func TestHTTPCreateBadTTL(t *testing.T) {
	d := newTestDaemon(t, &fakeManager{})
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()
	resp := mustPost(t, srv.URL+"/v1/sessions", `{"ttl":"notaduration"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// Error mapping: unavailable runtime → 503, layer "runtime" (failure legibility).
func TestHTTPCreateRuntimeUnavailable(t *testing.T) {
	mgr := &fakeManager{createErr: session.ErrRuntimeUnavailable}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()
	resp := mustPost(t, srv.URL+"/v1/sessions", `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	var e apiError
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Layer != "runtime" {
		t.Fatalf("layer = %q, want runtime", e.Layer)
	}
}

// Exec streams ndjson frames: stdout chunk(s) then an exit frame.
func TestHTTPExecStreamsFrames(t *testing.T) {
	mgr := &fakeManager{
		execOut: func(sink session.ExecSink) error {
			sink.Chunk(session.StreamStdout, []byte("hello"))
			return sink.Exit(0)
		},
	}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/sessions/sess-1/exec", "application/json",
		strings.NewReader(`{"argv":["echo","hi"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("content-type = %q", ct)
	}

	var frames []frame
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var fr frame
		if err := json.Unmarshal(sc.Bytes(), &fr); err != nil {
			t.Fatalf("bad frame %q: %v", sc.Text(), err)
		}
		frames = append(frames, fr)
	}
	if len(frames) != 2 {
		t.Fatalf("want 2 frames, got %d: %+v", len(frames), frames)
	}
	if frames[0].Stream != "stdout" || frames[0].Data != "hello" {
		t.Errorf("frame0 = %+v", frames[0])
	}
	if frames[1].Exit == nil || *frames[1].Exit != 0 {
		t.Errorf("frame1 exit = %+v", frames[1])
	}
	if !reflectEqual(mgr.lastExec.Argv, []string{"echo", "hi"}) {
		t.Errorf("argv not threaded: %+v", mgr.lastExec.Argv)
	}
}

// An exec error BEFORE any output is a clean HTTP status (not a stream).
func TestHTTPExecPreStreamError(t *testing.T) {
	mgr := &fakeManager{execErr: session.ErrNotFound}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()
	resp := mustPost(t, srv.URL+"/v1/sessions/nope/exec", `{"argv":["ls"]}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// Invalid input → 400 with layer "input".
func TestHTTPExecInvalidInput(t *testing.T) {
	mgr := &fakeManager{execErr: session.ErrInvalidInput}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()
	resp := mustPost(t, srv.URL+"/v1/sessions/s/exec", `{"argv":["ls"]}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHTTPDeleteSession(t *testing.T) {
	mgr := &fakeManager{}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1/sessions/abc", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if len(mgr.destroyed) != 1 || mgr.destroyed[0] != "abc" {
		t.Fatalf("destroyed = %v", mgr.destroyed)
	}
}

func TestHTTPListSessions(t *testing.T) {
	mgr := &fakeManager{list: []session.View{{ID: "s1", State: session.StateReady, AgeSeconds: 5, TTLRemaining: 100}}}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var views []session.View
	json.NewDecoder(resp.Body).Decode(&views)
	if len(views) != 1 || views[0].ID != "s1" {
		t.Fatalf("views = %+v", views)
	}
}

// Regression: with no session manager wired, the F1.1 surface stands and the
// session routes are simply absent (404) — they never panic on a nil manager.
func TestSessionRoutesAbsentWithoutManager(t *testing.T) {
	d, err := New(Options{Verifier: okVerifier(), RuntimeProbe: func() error { return nil }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp := mustPost(t, srv.URL+"/v1/sessions", `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no routes without a manager)", resp.StatusCode)
	}
	// Health still works.
	h := mustGet(t, srv.URL+"/v1/health")
	defer h.Body.Close()
	if h.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", h.StatusCode)
	}
}

func reflectEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// compile-time: *session.Manager satisfies SessionService (the production wiring).
var _ SessionService = (*session.Manager)(nil)
