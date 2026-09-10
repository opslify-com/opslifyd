package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/project"
	"github.com/opslify-com/opslifyd/internal/session"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
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
	// Manifest is the F7.3 read-only workspace manifest: path+size+mtime+hash
	// for each /workspace file, path-guarded and secret-excluded, so the CLI
	// sync engine can diff host vs sandbox without downloading everything.
	Manifest(ctx context.Context, id string) ([]session.ManifestEntry, error)
	// ListWorkspaces / RemoveWorkspace back the F2.2 `opslify ws ls|rm` surface.
	ListWorkspaces() ([]session.WorkspaceView, error)
	RemoveWorkspace(ctx context.Context, name string) error
	// TraceExport returns a session's F3.1 trace events (chain order) + seal for
	// `opslify verify`. Absent trace => session.ErrNotFound.
	TraceExport(ctx context.Context, id string) ([]trace.Event, *trace.Signature, error)
	// TraceHistory lists PERSISTED sessions from the durable trace store (F3.2),
	// newest first, backing the F3.6 past-session browser. It reads the durable
	// directory, not the live List(), so ended (and post-restart) sessions list.
	TraceHistory(ctx context.Context) ([]trace.SessionMeta, error)
	// TraceStream opens a live SSE tail (F3.2): backfill from fromSeq + a channel
	// of subsequently-appended events + a cancel func. Requires a streamable
	// (durable) sink; otherwise session.ErrNotFound.
	TraceStream(id string, fromSeq uint64) ([]trace.Event, <-chan trace.Event, func(), error)
	// ResolveApproval / GetApproval / ListApprovals are the F4.3 human approval
	// control plane. ResolveApproval approves (runs) or denies a paused exec;
	// GetApproval is the poll the agent re-calls for its result; ListApprovals is
	// the pending queue behind `opslify approvals`.
	ResolveApproval(ctx context.Context, sessionID, execID string, decision session.ApprovalDecision, comment string) (session.ApprovalView, error)
	GetApproval(ctx context.Context, sessionID, execID string) (session.ApprovalView, error)
	ListApprovals() []session.ApprovalView
	// ActivePolicy returns the daemon's resolved baseline policy (F4.1) — the
	// read-only view behind GET /v1/policy. It carries NO secret value (creds are
	// refs/metadata only), so it is safe to surface to the F7.4 browser UI.
	ActivePolicy() policy.Resolved
	// RegistryAllowed is the F7.5 pre-install allowlist gate: it reports whether the
	// F5.5 registry proxy is configured (configured) and whether ecosystem+name is on
	// the daemon-authoritative allowlist (allowed). The operator CLI hits it BEFORE
	// running an install, so a non-allowlisted package is refused before any exec and
	// a daemon with no proxy fails closed ("install unavailable"), never open-egress.
	RegistryAllowed(ecosystem, name string) (configured, allowed bool, err error)
}

// traceResponse is the GET /v1/sessions/{id}/trace body: the event chain plus the
// seal (null until the session is sealed on close). The CLI recomputes the chain
// and checks the seal client-side, so verification never trusts the daemon's word.
type traceResponse struct {
	Events []trace.Event    `json:"events"`
	Seal   *trace.Signature `json:"seal"`
}

// createRequest is the POST /v1/sessions body.
type createRequest struct {
	Mode     string `json:"mode"`
	Name     string `json:"name,omitempty"` // workspace name (workspace mode)
	Tier     string `json:"tier,omitempty"`
	Location string `json:"location,omitempty"`
	TTL      string `json:"ttl,omitempty"` // Go duration string, e.g. "30m"
	// Project / Environment place the session in an F8.1 scope. Both omitted =>
	// the default project/environment, so every existing client keeps working.
	// Environment accepts the full id ("flight.staging") or the bare name
	// ("staging") within the project.
	Project     string `json:"project,omitempty"`
	Environment string `json:"environment,omitempty"`
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
	// F3.1 tamper-evident trace: the event chain + seal for `opslify verify`.
	mux.HandleFunc("GET /"+APIVersion+"/sessions/{id}/trace", d.handleSessionTrace)
	// F3.6 past-session browser: list PERSISTED sessions from the durable store.
	// (Literal "history" segment; no conflict with the {id} routes.)
	mux.HandleFunc("GET /"+APIVersion+"/sessions/history", d.handleSessionHistory)
	// F3.6 verify badge: the SERVER-SIDE verdict against the trusted daemon identity.
	mux.HandleFunc("GET /"+APIVersion+"/sessions/{id}/verify", d.handleSessionVerify)
	// F2.1 mediated file transfer, confined to the session's /workspace.
	mux.HandleFunc("PUT /"+APIVersion+"/sessions/{id}/files", d.handleFileUpload)
	mux.HandleFunc("GET /"+APIVersion+"/sessions/{id}/files", d.handleFileDownload)
	// F7.3 host-linked workspaces: read-only workspace manifest for host↔sandbox
	// diffing. It reuses the same /workspace path guard + secret deny-list; it
	// never lists an excluded or out-of-root path.
	mux.HandleFunc("GET /"+APIVersion+"/sessions/{id}/manifest", d.handleSessionManifest)
	// F2.2 workspace management.
	mux.HandleFunc("GET /"+APIVersion+"/workspaces", d.handleWorkspaceList)
	mux.HandleFunc("DELETE /"+APIVersion+"/workspaces/{name}", d.handleWorkspaceDelete)
	// F4.1/F7.4 active-policy view: the daemon's resolved baseline policy, read
	// only, metadata only (no secret values). Backs `opslify policy` and the F7.4
	// browser policy pane.
	mux.HandleFunc("GET /"+APIVersion+"/policy", d.handlePolicyGet)
	// F7.5 pre-install allowlist gate: the operator CLI checks a package against the
	// F5.5 registry allowlist BEFORE running an install (a non-allowlisted name is
	// refused before any exec; an unconfigured proxy fails closed). Read-only; no
	// secret. It is NOT an agent-facing MCP tool — install stays operator-only.
	mux.HandleFunc("GET /"+APIVersion+"/registry/allow", d.handleRegistryAllow)
	// F4.3 human approval gates. The resolve route is a PRIVILEGED control action:
	// it inherits the localhost/socket trust boundary (no auth in v1, like F3.5) and
	// is deliberately NOT part of the agent-facing MCP tool surface — the agent
	// cannot self-approve.
	mux.HandleFunc("GET /"+APIVersion+"/approvals", d.handleApprovalList)
	mux.HandleFunc("GET /"+APIVersion+"/sessions/{id}/approvals/{exec_id}", d.handleApprovalGet)
	mux.HandleFunc("POST /"+APIVersion+"/sessions/{id}/approvals/{exec_id}", d.handleApprovalResolve)
}

// resolveApprovalRequest is the POST /v1/sessions/{id}/approvals/{exec_id} body.
type resolveApprovalRequest struct {
	Decision string `json:"decision"` // "approve" | "deny"
	Comment  string `json:"comment,omitempty"`
}

// handleApprovalList backs `opslify approvals` — the pending queue across sessions.
func (d *Daemon) handleApprovalList(w http.ResponseWriter, r *http.Request) {
	views := d.sessions.ListApprovals()
	if views == nil {
		views = []session.ApprovalView{}
	}
	writeJSON(w, http.StatusOK, views)
}

// handleApprovalGet is the poll path: the current state of one gate (pending, or
// approved+output, or denied+reason). This is READ-ONLY — it can never approve.
func (d *Daemon) handleApprovalGet(w http.ResponseWriter, r *http.Request) {
	view, err := d.sessions.GetApproval(r.Context(), r.PathValue("id"), r.PathValue("exec_id"))
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleApprovalResolve is the human approve/deny action. approve runs the paused
// command (its output is then pollable); deny returns a structured denial. Both
// emit a chained+redacted policy.decision.
func (d *Daemon) handleApprovalResolve(w http.ResponseWriter, r *http.Request) {
	var body resolveApprovalRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	view, err := d.sessions.ResolveApproval(r.Context(), r.PathValue("id"), r.PathValue("exec_id"),
		session.ApprovalDecision(body.Decision), body.Comment)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
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

// handlePolicyGet returns the daemon's resolved baseline policy (F4.1) as JSON —
// the read-only view behind `GET /v1/policy`. The resolved policy carries only
// allow/egress/approval/cred REFERENCES and limits; no secret value is ever part
// of it, so it is safe to surface to the F7.4 browser UI.
func (d *Daemon) handlePolicyGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.sessions.ActivePolicy())
}

// registryAllowResponse is the GET /v1/registry/allow body (F7.5): whether the
// registry proxy is configured and whether the queried package is allowlisted.
type registryAllowResponse struct {
	Configured bool   `json:"configured"`
	Allowed    bool   `json:"allowed"`
	Ecosystem  string `json:"ecosystem"`
	Name       string `json:"name"`
}

// handleRegistryAllow answers the F7.5 pre-install allowlist gate. It returns
// configured=false when no F5.5 registry proxy is wired (the CLI then fails closed —
// install unavailable, never open-egress), and allowed=true only for a name on the
// daemon-authoritative allowlist. A bad/unknown ecosystem is a 400 input error.
func (d *Daemon) handleRegistryAllow(w http.ResponseWriter, r *http.Request) {
	eco := r.URL.Query().Get("ecosystem")
	name := r.URL.Query().Get("name")
	if eco == "" || name == "" {
		writeAPIError(w, http.StatusBadRequest, "input", "ecosystem and name are required")
		return
	}
	configured, allowed, err := d.sessions.RegistryAllowed(eco, name)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, registryAllowResponse{
		Configured: configured,
		Allowed:    allowed,
		Ecosystem:  eco,
		Name:       name,
	})
}

func (d *Daemon) handleSessionCreate(w http.ResponseWriter, r *http.Request) {
	var body createRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	req := session.CreateRequest{
		Mode:          session.Mode(body.Mode),
		Name:          body.Name,
		Tier:          runtime.Tier(body.Tier),
		Location:      runtime.Location(body.Location),
		ProjectID:     body.Project,
		EnvironmentID: body.Environment,
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

// historyItem is one row of GET /v1/sessions/history: a cheap summary of a
// PERSISTED session read from the durable trace store (F3.2). It carries no
// event payloads — only lifecycle metadata — so the history list adds no
// redacted/unredacted data path.
type historyItem struct {
	SessionID  string     `json:"session_id"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	Tier       string     `json:"tier,omitempty"`
	EventCount int        `json:"event_count"`
	Sealed     bool       `json:"sealed"`
}

// handleSessionHistory lists PERSISTED sessions (newest first) from the durable
// trace store — independent of the live List(), so an ended session (even one
// that survived a restart) still lists, replays (via ?from_seq=0 on the trace
// stream), and verifies.
func (d *Daemon) handleSessionHistory(w http.ResponseWriter, r *http.Request) {
	metas, err := d.sessions.TraceHistory(r.Context())
	if err != nil {
		writeSessionError(w, err)
		return
	}
	items := make([]historyItem, 0, len(metas))
	for _, m := range metas {
		items = append(items, historyItem{
			SessionID:  m.SessionID,
			StartedAt:  m.StartedAt,
			EndedAt:    m.EndedAt,
			Tier:       m.Tier,
			EventCount: m.EventCount,
			Sealed:     m.Sealed,
		})
	}
	writeJSON(w, http.StatusOK, items)
}

// verifyResponse is the GET /v1/sessions/{id}/verify body: the SERVER-SIDE
// verdict of recomputing the session's persisted chain and checking its seal
// against the TRUSTED daemon identity (the daemon's own public key, held
// out-of-band from the trace). The browser only renders this verdict — it cannot
// fabricate a ✓, because the trust anchor never comes from the seal being checked.
type verifyResponse struct {
	Verified  bool   `json:"verified"`
	Events    int    `json:"events"`
	BrokenSeq *int64 `json:"broken_seq,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// handleSessionVerify runs the F3.1 chain+seal check server-side over the
// session's PERSISTED events, pinning the seal to the daemon's own identity. It
// returns the verdict as JSON (never the events); a tampered on-disk trace
// reports verified=false with the first broken seq, matching `opslify verify`.
func (d *Daemon) handleSessionVerify(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	events, seal, err := d.sessions.TraceExport(r.Context(), id)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	res := trace.Verify(events, seal, d.trustedPub)
	resp := verifyResponse{Verified: res.OK, Events: res.Events, Reason: res.Reason}
	if !res.OK {
		bs := res.BrokenSeq
		resp.BrokenSeq = &bs
		// Verify only fills Events on success; report what we attempted so the
		// badge can still show a count next to the ✗.
		resp.Events = len(events)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSessionTrace serves the session's trace two ways over one endpoint. With
// `Accept: text/event-stream` it opens the F3.2 LIVE SSE tail (backfill from
// ?from_seq=N, then events as they append); otherwise it returns the full chain +
// seal as JSON (what `opslify verify` consumes). The caller verifies client-side
// (trace.Verify), so this endpoint only transports evidence.
func (d *Daemon) handleSessionTrace(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		d.streamSessionTrace(w, r, id)
		return
	}
	events, seal, err := d.sessions.TraceExport(r.Context(), id)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	if events == nil {
		events = []trace.Event{}
	}
	writeJSON(w, http.StatusOK, traceResponse{Events: events, Seal: seal})
}

// streamSessionTrace serves the local SSE tail. It backfills from ?from_seq=N
// (default 0) out of the durable log, then streams every subsequently-appended
// event as an SSE `data:` frame — the same event JSON the JSON path returns, so a
// live consumer and `opslify verify` see identical bytes. It ends when the client
// disconnects (request context cancelled).
func (d *Daemon) streamSessionTrace(w http.ResponseWriter, r *http.Request, id string) {
	var fromSeq uint64
	if v := r.URL.Query().Get("from_seq"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "input", "invalid from_seq: "+err.Error())
			return
		}
		fromSeq = n
	}
	backfill, live, cancel, err := d.sessions.TraceStream(id, fromSeq)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	defer cancel()

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "sandbox", "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	writeEvent := func(ev trace.Event) bool {
		if _, err := w.Write([]byte("data: ")); err != nil {
			return false
		}
		if err := enc.Encode(ev); err != nil { // Encode writes the trailing \n
			return false
		}
		if _, err := w.Write([]byte("\n")); err != nil { // blank line terminates the SSE frame
			return false
		}
		flusher.Flush()
		return true
	}

	for _, ev := range backfill {
		if !writeEvent(ev) {
			return
		}
	}
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-live:
			if !ok {
				return // subscription dropped (consumer fell behind) or session gone
			}
			if !writeEvent(ev) {
				return
			}
		}
	}
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

// handleSessionManifest returns the F7.3 workspace manifest (path+size+mtime+
// hash per file). It is READ-ONLY and path-guarded in the Manager; a hostile
// workspace cannot escape /workspace, exceed the file cap, or surface an
// excluded secret path here.
func (d *Daemon) handleSessionManifest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	entries, err := d.sessions.Manifest(r.Context(), id)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	if entries == nil {
		entries = []session.ManifestEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
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
		// F4.3: a command matching an approval gate did NOT spawn — it paused. Surface
		// a structured `pending` frame carrying the exec_id (200, no error) so the
		// caller (CLI/MCP) never treats a pause as a failure and never hangs; the
		// human resolves it out-of-band and the caller polls the approvals endpoint.
		var ape *session.ApprovalPendingError
		if errors.As(err, &ape) {
			_ = sink.pendingFrame(ape.ExecID, ape.Rule, ape.Reason)
			return
		}
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
	// F4.3 approval-gate pause: Status="pending" carries the exec_id the caller
	// polls (GET /v1/sessions/{id}/approvals/{exec_id}) and the rule that gated it.
	Status string `json:"status,omitempty"`
	ExecID string `json:"exec_id,omitempty"`
	Rule   string `json:"rule,omitempty"`
	Reason string `json:"reason,omitempty"`
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
func (s *httpSink) pendingFrame(execID, rule, reason string) error {
	return s.emit(frame{Status: "pending", ExecID: execID, Rule: rule, Reason: reason})
}

// maxRequestBody bounds any decoded request body.
//
// The secret routes need this most: nothing previously bounded a value, and every
// Put/Update rewrites the ENTIRE vault file under the global mutex (and OpenVault
// reads it whole at startup), so one oversized value permanently slows every
// later credential injection. 1 MiB is far above any real credential — an SSH
// key, a kubeconfig or a service-account JSON is kilobytes — while base64's 4/3
// expansion still leaves the decoded value comfortably bounded.
const maxRequestBody = 1 << 20

// decodeJSON strictly decodes an optional JSON body (empty body => zero value),
// rejecting unknown fields so a malformed request is a legible 400, not a
// silently-ignored field, and bounding the read so a large body cannot be used to
// exhaust memory or bloat daemon state.
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	// This check is redundant with MaxBytesReader below, which catches the same
	// case — it is kept because it names the actual size in the error, where
	// MaxBytesReader can only say "too large". Mutation testing confirms the bound
	// still holds with either line alone.
	if r.ContentLength > maxRequestBody {
		return fmt.Errorf("request body is %d bytes, over the %d-byte limit", r.ContentLength, maxRequestBody)
	}
	// MaxBytesReader covers a chunked body, where ContentLength is -1 and the
	// check above cannot see the size at all.
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// writeSessionError maps a manager error to an HTTP status + layered envelope.
func writeSessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, project.ErrNotFound), errors.Is(err, project.ErrExists),
		errors.Is(err, project.ErrInUse), errors.Is(err, project.ErrInvalidInput):
		// F8.1: a create naming an unknown/foreign project or environment fails at
		// the SCOPE layer, before any sandbox exists. Route it through the project
		// mapper so the operator sees layer "project", not a generic sandbox 500.
		writeProjectError(w, err)
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
	case errors.Is(err, session.ErrApprovalNotFound):
		writeAPIError(w, http.StatusNotFound, "policy", err.Error())
	case errors.Is(err, session.ErrApprovalResolved):
		// A resolve/deny on an already-resolved gate (race, double-apply, or a late
		// approval after timeout — the no-resurrection guard). 409 Conflict.
		writeAPIError(w, http.StatusConflict, "policy", err.Error())
	case errors.Is(err, session.ErrApprovalInvalidDecision):
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
	case errors.Is(err, session.ErrPolicyDenied), errors.Is(err, session.ErrPolicyApproval):
		// F4.2: a policy-layer refusal (exec classified deny/needs_approval, or a
		// spin-up whose tier the policy forbids). 403 with layer "policy" so the CLI
		// and MCP agent get an actionable, non-secret reason — never a silent fail.
		writeAPIError(w, http.StatusForbidden, "policy", err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "sandbox", err.Error())
	}
}

func writeAPIError(w http.ResponseWriter, status int, layer, msg string) {
	writeJSON(w, status, apiError{Layer: layer, Message: msg})
}
