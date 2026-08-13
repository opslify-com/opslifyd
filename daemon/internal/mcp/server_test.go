package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeDaemon is a stdlib http.Server on a temp unix socket that mirrors the real
// internal/daemon session wire contract EXACTLY (session/exec/upload/download
// JSON shapes + the {layer,error} envelope + NDJSON exec frames). It lets the
// MCP tools be exercised with no real daemon/podman/root.
type fakeDaemon struct {
	t          *testing.T
	sockPath   string
	srv        *http.Server
	files      map[string][]byte // path -> content, per-session flattened for the test
	execFrames []string          // raw NDJSON lines the exec endpoint streams
	// forceErr, when set for a route key, makes that route reply with a layered
	// error envelope instead of the happy path.
	forceErr map[string]layeredErr
}

type layeredErr struct {
	status int
	layer  string
	msg    string
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "d.sock")
	f := &fakeDaemon{
		t:        t,
		sockPath: sock,
		files:    map[string][]byte{},
		forceErr: map[string]layeredErr{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", f.create)
	mux.HandleFunc("DELETE /v1/sessions/{id}", f.destroy)
	mux.HandleFunc("POST /v1/sessions/{id}/exec", f.exec)
	mux.HandleFunc("PUT /v1/sessions/{id}/files", f.upload)
	mux.HandleFunc("GET /v1/sessions/{id}/files", f.download)

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f.srv = &http.Server{Handler: mux}
	go f.srv.Serve(ln)
	t.Cleanup(func() { f.srv.Close() })
	return f
}

func (f *fakeDaemon) writeErr(w http.ResponseWriter, e layeredErr) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.status)
	json.NewEncoder(w).Encode(map[string]string{"layer": e.layer, "error": e.msg})
}

func (f *fakeDaemon) create(w http.ResponseWriter, r *http.Request) {
	if e, ok := f.forceErr["create"]; ok {
		f.writeErr(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"session_id": "sess-1", "state": "ready"})
}

func (f *fakeDaemon) destroy(w http.ResponseWriter, r *http.Request) {
	if e, ok := f.forceErr["destroy"]; ok {
		f.writeErr(w, e)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeDaemon) exec(w http.ResponseWriter, r *http.Request) {
	if e, ok := f.forceErr["exec"]; ok {
		f.writeErr(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	for _, line := range f.execFrames {
		io.WriteString(w, line+"\n")
	}
}

func (f *fakeDaemon) upload(w http.ResponseWriter, r *http.Request) {
	if e, ok := f.forceErr["upload"]; ok {
		f.writeErr(w, e)
		return
	}
	var body struct {
		Path       string `json:"path"`
		ContentB64 string `json:"content_b64"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	// Mirror the real daemon's /workspace confinement so path-traversal is rejected
	// by the fake exactly as the real daemon would.
	if !validWorkspacePath(body.Path) {
		f.writeErr(w, layeredErr{status: http.StatusBadRequest, layer: "input", msg: fmt.Sprintf("path %q must be under /workspace", body.Path)})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.ContentB64)
	if err != nil {
		f.writeErr(w, layeredErr{status: http.StatusBadRequest, layer: "input", msg: "invalid content_b64"})
		return
	}
	f.files[normalizeWorkspacePath(body.Path)] = raw
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeDaemon) download(w http.ResponseWriter, r *http.Request) {
	if e, ok := f.forceErr["download"]; ok {
		f.writeErr(w, e)
		return
	}
	path := r.URL.Query().Get("path")
	if !validWorkspacePath(path) {
		f.writeErr(w, layeredErr{status: http.StatusBadRequest, layer: "input", msg: fmt.Sprintf("path %q must be under /workspace", path)})
		return
	}
	raw, ok := f.files[normalizeWorkspacePath(path)]
	if !ok {
		f.writeErr(w, layeredErr{status: http.StatusBadRequest, layer: "input", msg: "no such file under /workspace"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"content_b64": base64.StdEncoding.EncodeToString(raw)})
}

// validWorkspacePath mirrors the real daemon's /workspace confinement: reject
// NUL, an absolute path not under /workspace, and any traversal.
func validWorkspacePath(p string) bool {
	if strings.Contains(p, "\x00") {
		return false
	}
	if strings.HasPrefix(p, "/") {
		clean := filepath.Clean(p)
		if clean != "/workspace" && !strings.HasPrefix(clean, "/workspace/") {
			return false
		}
	}
	rel := normalizeWorkspacePath(p)
	clean := filepath.Clean("/" + rel)
	return clean != "/" && !strings.Contains(rel, "..")
}

func normalizeWorkspacePath(p string) string {
	p = strings.TrimPrefix(p, "/workspace/")
	p = strings.TrimPrefix(p, "/workspace")
	return strings.TrimPrefix(p, "/")
}

// --- helpers to drive the MCP server over an in-memory transport ---

func connect(t *testing.T, sock string, opts Options) (*mcp.ClientSession, func()) {
	t.Helper()
	opts.Socket = sock
	srv := NewServer(opts)
	serverT, clientT := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cli := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := cli.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	return cs, func() { cs.Close() }
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args any, out any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	if out != nil && !res.IsError {
		// StructuredContent carries the typed Out value.
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("decode %s out: %v", name, err)
		}
	}
	return res
}

func resultText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// --- tests ---

func TestToolsListExposesFive(t *testing.T) {
	f := newFakeDaemon(t)
	cs, done := connect(t, f.sockPath, Options{})
	defer done()

	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	want := map[string]bool{
		"opslify_session_create": false,
		"opslify_exec":           false,
		"opslify_upload":         false,
		"opslify_download":       false,
		"opslify_session_end":    false,
	}
	for _, tool := range lt.Tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %s has nil input schema", tool.Name)
		}
	}
	if len(lt.Tools) != 5 {
		t.Errorf("want 5 tools, got %d", len(lt.Tools))
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tool %s not exposed", name)
		}
	}
}

func TestCreateExecEndRoundTrip(t *testing.T) {
	f := newFakeDaemon(t)
	f.execFrames = []string{
		`{"stream":"stdout","data":"hello\n"}`,
		`{"stream":"stderr","data":"warn\n"}`,
		`{"exit_code":0}`,
	}
	cs, done := connect(t, f.sockPath, Options{})
	defer done()

	var created sessionCreateOut
	callTool(t, cs, "opslify_session_create", map[string]any{"mode": "scratch"}, &created)
	if created.SessionID != "sess-1" || created.State != "ready" {
		t.Fatalf("create out = %+v", created)
	}

	var ex execOut
	callTool(t, cs, "opslify_exec", map[string]any{"session_id": created.SessionID, "command": []string{"echo", "hello"}}, &ex)
	if ex.Stdout != "hello\n" || ex.Stderr != "warn\n" || ex.ExitCode != 0 {
		t.Fatalf("exec out = %+v", ex)
	}

	var ended sessionEndOut
	callTool(t, cs, "opslify_session_end", map[string]any{"session_id": created.SessionID}, &ended)
	if ended.State != "ended" {
		t.Fatalf("end out = %+v", ended)
	}
}

func TestExecOutputCapTruncates(t *testing.T) {
	f := newFakeDaemon(t)
	big := strings.Repeat("A", 5000)
	f.execFrames = []string{
		fmt.Sprintf(`{"stream":"stdout","data":%q}`, big),
		`{"exit_code":0}`,
	}
	cs, done := connect(t, f.sockPath, Options{OutputCap: 1000})
	defer done()

	var ex execOut
	callTool(t, cs, "opslify_exec", map[string]any{"session_id": "sess-1", "command": []string{"cat", "big"}}, &ex)
	if len(ex.Stdout) >= 5000 {
		t.Fatalf("output not capped: %d bytes", len(ex.Stdout))
	}
	if !strings.Contains(ex.Stdout, "[truncated: 4000 bytes omitted]") {
		t.Fatalf("missing truncation marker: %q", ex.Stdout[len(ex.Stdout)-60:])
	}
}

func TestUploadDownloadRoundTrip10MB(t *testing.T) {
	f := newFakeDaemon(t)
	cs, done := connect(t, f.sockPath, Options{})
	defer done()

	payload := make([]byte, 10<<20)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	b64 := base64.StdEncoding.EncodeToString(payload)

	var up uploadOut
	res := callTool(t, cs, "opslify_upload", map[string]any{"session_id": "sess-1", "path": "/workspace/big.bin", "content_b64": b64}, &up)
	if res.IsError {
		t.Fatalf("upload errored: %s", resultText(res))
	}
	if up.Bytes != len(payload) {
		t.Fatalf("upload bytes = %d, want %d", up.Bytes, len(payload))
	}

	var down downloadOut
	callTool(t, cs, "opslify_download", map[string]any{"session_id": "sess-1", "path": "/workspace/big.bin"}, &down)
	got, err := base64.StdEncoding.DecodeString(down.ContentB64)
	if err != nil {
		t.Fatalf("decode download: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("download len = %d, want %d", len(got), len(payload))
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("byte %d differs", i)
		}
	}
}

func TestUploadPathTraversalRejected(t *testing.T) {
	f := newFakeDaemon(t)
	cs, done := connect(t, f.sockPath, Options{})
	defer done()

	res := callTool(t, cs, "opslify_upload", map[string]any{
		"session_id":  "sess-1",
		"path":        "/workspace/../../etc/passwd",
		"content_b64": base64.StdEncoding.EncodeToString([]byte("x")),
	}, nil)
	if !res.IsError {
		t.Fatalf("traversal upload should be an error")
	}
	if !strings.Contains(resultText(res), "input") {
		t.Fatalf("error should name the input layer: %q", resultText(res))
	}
}

func TestUploadOversizeRejectedLocally(t *testing.T) {
	f := newFakeDaemon(t)
	cs, done := connect(t, f.sockPath, Options{MaxFileBytes: 1024})
	defer done()

	payload := base64.StdEncoding.EncodeToString(make([]byte, 4096))
	res := callTool(t, cs, "opslify_upload", map[string]any{"session_id": "sess-1", "path": "/workspace/x", "content_b64": payload}, nil)
	if !res.IsError {
		t.Fatalf("oversize upload should be an error")
	}
	if !strings.Contains(resultText(res), "too large") {
		t.Fatalf("want too-large error, got %q", resultText(res))
	}
}

func TestLayeredErrorNaming(t *testing.T) {
	f := newFakeDaemon(t)
	f.forceErr["exec"] = layeredErr{status: http.StatusConflict, layer: "sandbox", msg: "session not ready"}
	cs, done := connect(t, f.sockPath, Options{})
	defer done()

	res := callTool(t, cs, "opslify_exec", map[string]any{"session_id": "sess-1", "command": []string{"ls"}}, nil)
	if !res.IsError {
		t.Fatalf("expected tool error")
	}
	txt := resultText(res)
	if !strings.Contains(txt, "[sandbox]") || !strings.Contains(txt, "session not ready") {
		t.Fatalf("error should name the sandbox layer: %q", txt)
	}
}

// F4.2: a policy deny surfaces through opslify_exec as a structured, non-hanging
// tool error naming the policy layer + reason — the agent gets an actionable
// message, never a silent failure.
func TestExecPolicyDenySurfacesToTool(t *testing.T) {
	f := newFakeDaemon(t)
	f.forceErr["exec"] = layeredErr{
		status: http.StatusForbidden,
		layer:  "policy",
		msg:    "session: policy denied: kubectl namespace \"prod-b\" not in allowed namespaces [rule allow.kubectl.namespaces]",
	}
	cs, done := connect(t, f.sockPath, Options{})
	defer done()

	res := callTool(t, cs, "opslify_exec", map[string]any{"session_id": "sess-1", "command": []string{"kubectl", "get", "pods", "-n", "prod-b"}}, nil)
	if !res.IsError {
		t.Fatalf("expected a tool error for a policy deny")
	}
	txt := resultText(res)
	if !strings.Contains(txt, "[policy]") || !strings.Contains(txt, "allow.kubectl.namespaces") {
		t.Fatalf("policy deny should name the policy layer + rule: %q", txt)
	}
}

func TestExecMidStreamRuntimeError(t *testing.T) {
	f := newFakeDaemon(t)
	f.execFrames = []string{
		`{"stream":"stdout","data":"partial"}`,
		`{"error":"gvisor: unsupported syscall"}`,
	}
	cs, done := connect(t, f.sockPath, Options{})
	defer done()

	res := callTool(t, cs, "opslify_exec", map[string]any{"session_id": "sess-1", "command": []string{"strace", "ls"}}, nil)
	if !res.IsError {
		t.Fatalf("expected mid-stream error surfaced")
	}
	if !strings.Contains(resultText(res), "[runtime]") {
		t.Fatalf("want runtime layer: %q", resultText(res))
	}
}

func TestSocketMissingLegible(t *testing.T) {
	// Point at a socket path that does not exist: the create tool should surface a
	// legible "cannot reach opslifyd" message rather than an opaque dial error.
	missing := filepath.Join(t.TempDir(), "nope.sock")
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("precondition: socket should not exist")
	}
	cs, done := connect(t, missing, Options{})
	defer done()

	res := callTool(t, cs, "opslify_session_create", map[string]any{"mode": "scratch"}, nil)
	if !res.IsError {
		t.Fatalf("expected socket-missing error")
	}
	txt := resultText(res)
	if !strings.Contains(txt, "cannot reach opslifyd") || !strings.Contains(txt, "nope.sock") {
		t.Fatalf("socket-missing error not legible: %q", txt)
	}
}

func TestResolveWorkspaceUnitBounds(t *testing.T) {
	// Sanity that the client cap/marker math is stable across a boundary write.
	b := &cappedBuffer{cap: 4}
	b.WriteString("ab")
	b.WriteString("cdef")
	got := b.String()
	if !strings.HasPrefix(got, "abcd") || !strings.Contains(got, "[truncated: 2 bytes omitted]") {
		t.Fatalf("capped buffer wrong: %q", got)
	}
}
