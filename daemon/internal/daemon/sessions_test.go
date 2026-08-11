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
	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// twoStreamRuntime is a minimal real runtime.Runtime whose Exec returns an
// ExecStream with BOTH a non-empty stdout and a non-empty stderr reader, so
// driving it through session.Manager.Exec exercises streamExec's two concurrent
// pumps against a real sink. Used to reproduce the httpSink data race.
type twoStreamRuntime struct{ payload string }

func (r twoStreamRuntime) Create(context.Context, runtime.SessionSpec) (runtime.ContainerHandle, error) {
	return runtime.ContainerHandle{ID: "ctr-1", Tier: runtime.TierLocalHardened}, nil
}
func (r twoStreamRuntime) Exec(context.Context, runtime.ContainerHandle, runtime.ExecRequest) (runtime.ExecStream, error) {
	return runtime.ExecStream{
		Stdout:   strings.NewReader(r.payload),
		Stderr:   strings.NewReader(r.payload),
		ExitCode: 0,
	}, nil
}
func (r twoStreamRuntime) Destroy(context.Context, runtime.ContainerHandle) error { return nil }
func (r twoStreamRuntime) Snapshot(context.Context, runtime.ContainerHandle, string) (runtime.ImageRef, error) {
	return runtime.ImageRef{}, nil
}
func (r twoStreamRuntime) Available() error { return nil }

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
	uploaded   []byte
	downloaded []byte
	fileErr    error
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

func (f *fakeManager) WriteFile(_ context.Context, _ string, _ string, content []byte) error {
	f.uploaded = content
	return f.fileErr
}

func (f *fakeManager) ReadFile(_ context.Context, _ string, _ string) ([]byte, error) {
	if f.fileErr != nil {
		return nil, f.fileErr
	}
	return f.downloaded, nil
}

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

func TestHTTPFileUploadDownload(t *testing.T) {
	mgr := &fakeManager{downloaded: []byte("payload")}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	// Upload: base64 body decoded by the handler, forwarded to the manager.
	up := `{"path":"/workspace/f.txt","content_b64":"aGVsbG8="}` // "hello"
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/sessions/sess-1/files", strings.NewReader(up))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("upload status = %d, want 204", resp.StatusCode)
	}
	if string(mgr.uploaded) != "hello" {
		t.Fatalf("manager got %q, want hello", mgr.uploaded)
	}

	// Download: manager bytes come back base64 in the envelope.
	dresp := mustGet(t, srv.URL+"/v1/sessions/sess-1/files?path=/workspace/f.txt")
	defer dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d, want 200", dresp.StatusCode)
	}
	var db struct {
		ContentB64 string `json:"content_b64"`
	}
	json.NewDecoder(dresp.Body).Decode(&db)
	if db.ContentB64 != "cGF5bG9hZA==" { // "payload"
		t.Fatalf("content_b64 = %q", db.ContentB64)
	}
}

func TestHTTPFileUploadBadBase64(t *testing.T) {
	d := newTestDaemon(t, &fakeManager{})
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/sessions/sess-1/files",
		strings.NewReader(`{"path":"/workspace/f","content_b64":"!!!not-base64"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
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

// TestHTTPExecSinkConcurrentStreams drives the REAL streamExec (via
// session.Manager.Exec) through the REAL httpSink with a non-empty stdout AND a
// non-empty stderr reader — the two concurrent pumps that the fakeManager-based
// tests bypass. Small chunk size forces many interleaved emits. Under -race this
// FAILS against an unsynchronized httpSink and PASSES with the mutex fix. It also
// asserts frames stay well-formed (every line is a valid, non-interleaved JSON
// frame) and the exit frame arrives.
func TestHTTPExecSinkConcurrentStreams(t *testing.T) {
	payload := strings.Repeat("x", 4096)
	mgr, err := session.NewManager(session.Options{
		Config: session.ManagerConfig{
			WorkspaceRoot: t.TempDir(),
			StateDir:      t.TempDir(),
			DefaultTier:   runtime.TierLocalHardened,
			ChunkSize:     16, // force hundreds of concurrent emits per stream
		},
		Resolve: func(runtime.Tier, runtime.Location) (runtime.Runtime, error) {
			return twoStreamRuntime{payload: payload}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	s, err := mgr.Create(context.Background(), session.CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	rec := httptest.NewRecorder()
	sink := newHTTPSink(rec)
	if err := mgr.Exec(context.Background(), s.ID, session.ExecOptions{Argv: []string{"echo"}}, sink); err != nil {
		t.Fatalf("Exec: %v", err)
	}

	var stdout, stderr int
	sawExit := false
	sc := bufio.NewScanner(strings.NewReader(rec.Body.String()))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var fr frame
		if err := json.Unmarshal(sc.Bytes(), &fr); err != nil {
			t.Fatalf("interleaved/malformed frame %q: %v", sc.Text(), err)
		}
		switch {
		case fr.Exit != nil:
			sawExit = true
		case fr.Stream == "stdout":
			stdout += len(fr.Data)
		case fr.Stream == "stderr":
			stderr += len(fr.Data)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if stdout != len(payload) || stderr != len(payload) {
		t.Fatalf("stream bytes: stdout=%d stderr=%d, want %d each", stdout, stderr, len(payload))
	}
	if !sawExit {
		t.Fatal("missing exit frame")
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
