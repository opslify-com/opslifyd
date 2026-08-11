package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/session"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// SessionService is the subset of *session.Manager the REST layer drives. It is
// an interface so the HTTP handlers are unit-testable with a fake manager (no
// podman/runsc), and so the daemon never reaches past the mediated surface.
type SessionService interface {
	Create(ctx context.Context, req session.CreateRequest) (*session.Session, error)
	Exec(ctx context.Context, id string, opts session.ExecOptions, sink session.ExecSink) error
	Destroy(ctx context.Context, id string) error
	List() []session.View
	// WriteFile / ReadFile are the mediated file-transfer surface (F2.1). They
	// are confined to the session's /workspace and size-bounded in the Manager.
	WriteFile(ctx context.Context, id, path string, content []byte) error
	ReadFile(ctx context.Context, id, path string) ([]byte, error)
	// ListWorkspaces / RemoveWorkspace back the F2.2 `opslify ws ls|rm` surface.
	ListWorkspaces() ([]session.WorkspaceView, error)
	RemoveWorkspace(ctx context.Context, name string) error
}

// createRequest is the POST /v1/sessions body.
type createRequest struct {
	Mode     string `json:"mode"`
	Name     string `json:"name,omitempty"` // workspace name (workspace mode)
	Tier     string `json:"tier,omitempty"`
	Location string `json:"location,omitempty"`
	TTL      string `json:"ttl,omitempty"` // Go duration string, e.g. "30m"
}

// createResponse is the POST /v1/sessions reply.
type createResponse struct {
	SessionID string `json:"session_id"`
	State     string `json:"state"`
}

// execRequest is the POST /v1/sessions/{id}/exec body.
type execRequest struct {
	Argv     []string `json:"argv"`
	Cwd      string   `json:"cwd,omitempty"`
	Env      []string `json:"env,omitempty"`
	Stdin    string   `json:"stdin,omitempty"`
	Writable []string `json:"writable,omitempty"`
}

// apiError is the JSON error envelope. Layer names sandbox|runtime|input so the
// caller can tell a bad request from a missing engine from a lifecycle fault
// (failure legibility).
type apiError struct {
	Layer   string `json:"layer"`
	Message string `json:"error"`
}

// registerSessionRoutes adds the F1.2 session endpoints to mux. Split out so the
// F1.1 Handler stays a small composition root.
func (d *Daemon) registerSessionRoutes(mux *http.ServeMux) {
	if d.sessions == nil {
		return // no session manager wired (e.g. F1.1-only smoke); routes stay 404
	}
	mux.HandleFunc("POST /"+APIVersion+"/sessions", d.handleSessionCreate)
	mux.HandleFunc("GET /"+APIVersion+"/sessions", d.handleSessionList)
	mux.HandleFunc("POST /"+APIVersion+"/sessions/{id}/exec", d.handleSessionExec)
	mux.HandleFunc("DELETE /"+APIVersion+"/sessions/{id}", d.handleSessionDelete)
	// F2.1 mediated file transfer, confined to the session's /workspace.
	mux.HandleFunc("PUT /"+APIVersion+"/sessions/{id}/files", d.handleFileUpload)
	mux.HandleFunc("GET /"+APIVersion+"/sessions/{id}/files", d.handleFileDownload)
	// F2.2 workspace management.
	mux.HandleFunc("GET /"+APIVersion+"/workspaces", d.handleWorkspaceList)
	mux.HandleFunc("DELETE /"+APIVersion+"/workspaces/{name}", d.handleWorkspaceDelete)
}

// handleWorkspaceList backs `opslify ws ls`.
func (d *Daemon) handleWorkspaceList(w http.ResponseWriter, r *http.Request) {
	ws, err := d.sessions.ListWorkspaces()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "sandbox", err.Error())
		return
	}
	if ws == nil {
		ws = []session.WorkspaceView{}
	}
	writeJSON(w, http.StatusOK, ws)
}

// handleWorkspaceDelete backs `opslify ws rm <name>`.
func (d *Daemon) handleWorkspaceDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := d.sessions.RemoveWorkspace(r.Context(), name); err != nil {
		writeSessionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *Daemon) handleSessionCreate(w http.ResponseWriter, r *http.Request) {
	var body createRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	req := session.CreateRequest{
		Mode:     session.Mode(body.Mode),
		Name:     body.Name,
		Tier:     runtime.Tier(body.Tier),
		Location: runtime.Location(body.Location),
	}
	if body.TTL != "" {
		ttl, err := time.ParseDuration(body.TTL)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "input", "invalid ttl: "+err.Error())
			return
		}
		req.TTL = ttl
	}
	s, err := d.sessions.Create(r.Context(), req)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createResponse{SessionID: s.ID, State: string(s.State)})
}

func (d *Daemon) handleSessionList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.sessions.List())
}

func (d *Daemon) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := d.sessions.Destroy(r.Context(), id); err != nil {
		writeSessionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// uploadRequest is the PUT /v1/sessions/{id}/files body: base64 content written
// to a path confined to the session's /workspace.
type uploadRequest struct {
	Path       string `json:"path"`
	ContentB64 string `json:"content_b64"`
}

// downloadResponse is the GET /v1/sessions/{id}/files reply.
type downloadResponse struct {
	ContentB64 string `json:"content_b64"`
}

// handleFileUpload writes a base64-decoded blob to a /workspace-confined path.
// The base64 is decoded here so the daemon bounds the DECODED size (the Manager
// re-checks against session.MaxFileBytes), and traversal is rejected in the
// Manager's path resolver.
func (d *Daemon) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body uploadRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	content, err := base64.StdEncoding.DecodeString(body.ContentB64)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", "invalid content_b64: "+err.Error())
		return
	}
	if err := d.sessions.WriteFile(r.Context(), id, body.Path, content); err != nil {
		writeSessionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleFileDownload reads a /workspace-confined path and returns it base64.
func (d *Daemon) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	path := r.URL.Query().Get("path")
	content, err := d.sessions.ReadFile(r.Context(), id, path)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, downloadResponse{ContentB64: base64.StdEncoding.EncodeToString(content)})
}

// handleSessionExec streams bounded stdout/stderr frames then an exit frame as
// newline-delimited JSON (chunked transfer). Because output streams as it is
// produced, an error AFTER the first frame cannot change the status code — it is
// surfaced as a final error frame instead.
func (d *Daemon) handleSessionExec(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body execRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	opts := session.ExecOptions{
		Argv:     body.Argv,
		Cwd:      body.Cwd,
		Env:      body.Env,
		Stdin:    []byte(body.Stdin),
		Writable: body.Writable,
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	sink := newHTTPSink(w)
	err := d.sessions.Exec(r.Context(), id, opts, sink)
	if err != nil {
		if !sink.wrote {
			// Nothing streamed yet: a clean HTTP error with the right status.
			writeSessionError(w, err)
			return
		}
		// Mid-stream failure: emit a final error frame (status already sent).
		_ = sink.errorFrame(err)
	}
}

// httpSink adapts session.ExecSink to a flushing chunked HTTP response. Each
// frame is one JSON object on its own line; it flushes after every frame so the
// caller sees output as it is produced (streamed, not buffered).
//
// streamExec drives stdout and stderr through two concurrent goroutines (per the
// ExecSink contract), so every emit — the encode, the flush, and the `wrote`
// mutation — is serialized under mu. This both prevents a data race on the
// shared encoder/ResponseWriter and guarantees frames never interleave mid-write.
type httpSink struct {
	mu    sync.Mutex
	w     http.ResponseWriter
	enc   *json.Encoder
	flush func()
	wrote bool
}

func newHTTPSink(w http.ResponseWriter) *httpSink {
	s := &httpSink{w: w, enc: json.NewEncoder(w)}
	if f, ok := w.(http.Flusher); ok {
		s.flush = f.Flush
	} else {
		s.flush = func() {}
	}
	return s
}

type frame struct {
	Stream    string `json:"stream,omitempty"`
	Data      string `json:"data,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Exit      *int   `json:"exit_code,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (s *httpSink) emit(f frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrote = true
	if err := s.enc.Encode(f); err != nil {
		return err
	}
	s.flush()
	return nil
}

func (s *httpSink) Chunk(stream string, data []byte) error {
	return s.emit(frame{Stream: stream, Data: string(data)})
}
func (s *httpSink) Truncated(stream string) error {
	return s.emit(frame{Stream: stream, Truncated: true})
}
func (s *httpSink) Exit(code int) error {
	return s.emit(frame{Exit: &code})
}
func (s *httpSink) errorFrame(err error) error {
	return s.emit(frame{Error: err.Error()})
}

// decodeJSON strictly decodes an optional JSON body (empty body => zero value),
// rejecting unknown fields so a malformed request is a legible 400, not a
// silently-ignored field.
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// writeSessionError maps a manager error to an HTTP status + layered envelope.
func writeSessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, session.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "sandbox", err.Error())
	case errors.Is(err, session.ErrNotReady):
		writeAPIError(w, http.StatusConflict, "sandbox", err.Error())
	case errors.Is(err, session.ErrInvalidInput):
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
	case errors.Is(err, session.ErrRuntimeUnavailable):
		writeAPIError(w, http.StatusServiceUnavailable, "runtime", err.Error())
	case errors.Is(err, session.ErrEgress):
		writeAPIError(w, http.StatusServiceUnavailable, "egress", err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "sandbox", err.Error())
	}
}

func writeAPIError(w http.ResponseWriter, status int, layer, msg string) {
	writeJSON(w, status, apiError{Layer: layer, Message: msg})
}
