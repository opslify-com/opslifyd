package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDaemon is an httptest-style server bound to a real Unix socket in a temp
// dir, so the CLI's socket-client seam is exercised end-to-end without a real
// daemon, podman, or root.
type fakeDaemon struct {
	socketPath string
}

// newFakeDaemon starts a server with the given handler on a temp .sock.
func newFakeDaemon(t *testing.T, mux http.Handler) *fakeDaemon {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "opslifyd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return &fakeDaemon{socketPath: sock}
}

// ndjson writes frames as newline-delimited JSON with flushing, mimicking the
// daemon's chunked exec stream.
func ndjson(w http.ResponseWriter, frames ...frame) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	f, _ := w.(http.Flusher)
	for _, fr := range frames {
		enc.Encode(fr)
		if f != nil {
			f.Flush()
		}
	}
}

// frame mirrors the daemon exec frame for building fake responses.
type frame struct {
	Stream    string `json:"stream,omitempty"`
	Data      string `json:"data,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Exit      *int   `json:"exit_code,omitempty"`
	Error     string `json:"error,omitempty"`
}

func intp(i int) *int { return &i }

// execCmd runs a root command with args and captures stdout/stderr + error.
func execRoot(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := rootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), errb.String(), err
}

// --- run happy path: frames streamed, exit propagated, session deleted ---

func TestRunHappyPath(t *testing.T) {
	var gotCreate createReq
	var gotExec execReq
	deleted := false

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotCreate)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createResp{SessionID: "sess-1", State: "ready"})
	})
	mux.HandleFunc("POST /v1/sessions/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotExec)
		ndjson(w,
			frame{Stream: "stdout", Data: "hello\n"},
			frame{Stream: "stderr", Data: "warn\n"},
			frame{Exit: intp(0)},
		)
	})
	mux.HandleFunc("DELETE /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") == "sess-1" {
			deleted = true
		}
		w.WriteHeader(http.StatusNoContent)
	})
	fd := newFakeDaemon(t, mux)

	out, errb, err := execRoot(t, "run", "--socket", fd.socketPath, "echo", "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "hello") {
		t.Errorf("stdout missing frame data: %q", out)
	}
	if !strings.Contains(errb, "warn") {
		t.Errorf("stderr missing frame data: %q", errb)
	}
	if !deleted {
		t.Error("session was not deleted")
	}
	if len(gotExec.Argv) != 2 || gotExec.Argv[0] != "echo" {
		t.Errorf("argv not forwarded: %v", gotExec.Argv)
	}
	_ = gotCreate
}

func TestRunExitCodePropagatedAndKeep(t *testing.T) {
	deleted := false
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createResp{SessionID: "s2", State: "ready"})
	})
	mux.HandleFunc("POST /v1/sessions/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		ndjson(w, frame{Stream: "stdout", Data: "x"}, frame{Exit: intp(7)})
	})
	mux.HandleFunc("DELETE /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	})
	fd := newFakeDaemon(t, mux)

	// --keep must skip the delete, and exit 7 must surface as exitCodeError.
	_, _, err := execRoot(t, "run", "--socket", fd.socketPath, "--keep", "false-cmd")
	ec, ok := err.(*exitCodeError)
	if !ok {
		t.Fatalf("want exitCodeError, got %T: %v", err, err)
	}
	if ec.code != 7 {
		t.Errorf("want code 7, got %d", ec.code)
	}
	if deleted {
		t.Error("--keep should not delete the session")
	}
}

func TestRunTruncationMarker(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createResp{SessionID: "s3", State: "ready"})
	})
	mux.HandleFunc("POST /v1/sessions/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		ndjson(w, frame{Stream: "stdout", Data: "partial"}, frame{Stream: "stdout", Truncated: true}, frame{Exit: intp(0)})
	})
	mux.HandleFunc("DELETE /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	fd := newFakeDaemon(t, mux)

	_, errb, err := execRoot(t, "run", "--socket", fd.socketPath, "cat", "big")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.Contains(errb, "truncated") {
		t.Errorf("truncation marker missing from stderr: %q", errb)
	}
}

// --- session ls table ---

func TestSessionLsTable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]sessionView{
			{SessionID: "a1", Mode: "workspace", Tier: "local-hardened", State: "ready", AgeSeconds: 90, TTLRemaining: 1800},
			{SessionID: "b2", Mode: "scratch", Tier: "local-docker", State: "paused", AgeSeconds: 5, TTLRemaining: 0},
		})
	})
	fd := newFakeDaemon(t, mux)

	out, _, err := execRoot(t, "session", "ls", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	for _, want := range []string{"SESSION ID", "a1", "b2", "ready", "1m30s", "30m", "-"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
}

// --- session kill ---

func TestSessionKill(t *testing.T) {
	var killed string
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		killed = r.PathValue("id")
		w.WriteHeader(http.StatusNoContent)
	})
	fd := newFakeDaemon(t, mux)

	out, _, err := execRoot(t, "session", "kill", "zz9", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if killed != "zz9" {
		t.Errorf("want kill zz9, got %q", killed)
	}
	if !strings.Contains(out, "zz9") {
		t.Errorf("kill confirmation missing: %q", out)
	}
}

// --- session exec (existing session) ---

func TestSessionExecExisting(t *testing.T) {
	var gotID string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		gotID = r.PathValue("id")
		ndjson(w, frame{Stream: "stdout", Data: "done\n"}, frame{Exit: intp(0)})
	})
	fd := newFakeDaemon(t, mux)

	out, _, err := execRoot(t, "session", "exec", "--socket", fd.socketPath, "sX", "ls", "-la")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if gotID != "sX" {
		t.Errorf("want exec on sX, got %q", gotID)
	}
	if !strings.Contains(out, "done") {
		t.Errorf("stdout missing: %q", out)
	}
}

// --- layered error rendering: {layer:"sandbox",...} -> "[sandbox]" + non-zero ---

func TestLayeredErrorNamesLayer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"layer": "sandbox", "error": "engine unavailable"})
	})
	fd := newFakeDaemon(t, mux)

	_, _, err := execRoot(t, "run", "--socket", fd.socketPath, "true")
	le, ok := err.(*layerError)
	if !ok {
		t.Fatalf("want layerError, got %T: %v", err, err)
	}
	if le.Layer != "sandbox" {
		t.Errorf("want layer sandbox, got %q", le.Layer)
	}
	if !strings.Contains(le.Error(), "[sandbox]") {
		t.Errorf("rendered error must name the layer: %q", le.Error())
	}
}

// A mid-stream error frame (status already 200) surfaces as a runtime-layer error.
func TestMidStreamErrorFrame(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		ndjson(w, frame{Stream: "stdout", Data: "some\n"}, frame{Error: "runtime: exec drain failed"})
	})
	fd := newFakeDaemon(t, mux)

	_, _, err := execRoot(t, "session", "exec", "--socket", fd.socketPath, "s", "cmd")
	le, ok := err.(*layerError)
	if !ok {
		t.Fatalf("want layerError, got %T: %v", err, err)
	}
	if le.Layer != "runtime" {
		t.Errorf("want runtime layer, got %q", le.Layer)
	}
}

// --- socket-missing legibility ---

func TestSocketMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.sock")
	_, _, err := execRoot(t, "session", "ls", "--socket", missing)
	ce, ok := err.(*connError)
	if !ok {
		t.Fatalf("want connError, got %T: %v", err, err)
	}
	msg := ce.Error()
	if !strings.Contains(msg, "is opslifyd running?") {
		t.Errorf("missing-socket message not legible: %q", msg)
	}
	if !strings.Contains(msg, missing) {
		t.Errorf("message should name the socket path: %q", msg)
	}
}

// guard: the root still exposes init (F0.1 regression) alongside the new cmds.
func TestRootCommandsWired(t *testing.T) {
	names := map[string]bool{}
	for _, c := range rootCmd().Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"init", "run", "session"} {
		if !names[want] {
			t.Errorf("root missing subcommand %q", want)
		}
	}
}
