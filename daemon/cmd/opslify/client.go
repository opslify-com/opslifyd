package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/opslify-com/opslifyd/internal/trace"
)

// client is the CLI's REST-over-unix-socket transport seam. All daemon calls go
// through it, and it is constructed with a socket path so unit tests can point
// it at a temp .sock served by an httptest-style fake — no daemon/podman/root.
type client struct {
	socketPath string
	http       *http.Client
	baseURL    string
}

// newClient builds a client that dials the daemon's Unix socket. The host in the
// URL is ignored (the dialer always targets socketPath); we use a fixed
// placeholder so net/http can parse the request line.
func newClient(socketPath string) *client {
	return &client{
		socketPath: socketPath,
		baseURL:    "http://opslify",
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

// layerError is a daemon error envelope {layer,error} surfaced to the user so a
// failure names the layer that rejected it (sandbox/egress/runtime/input/…).
type layerError struct {
	Layer   string
	Message string
	Status  int
}

func (e *layerError) Error() string {
	if e.Layer == "" {
		return e.Message
	}
	return fmt.Sprintf("error [%s]: %s", e.Layer, e.Message)
}

// connError wraps a transport-level failure (socket missing / daemon down) into
// a legible "is opslifyd running?" message that names the socket path.
type connError struct {
	socketPath string
	cause      error
}

func (e *connError) Error() string {
	return fmt.Sprintf("cannot reach opslifyd on %s: %v\nis opslifyd running?", e.socketPath, e.cause)
}
func (e *connError) Unwrap() error { return e.cause }

// wireError classifies a transport error: a missing socket / refused connection
// becomes a connError; anything else is returned as-is.
func (c *client) wireError(err error) error {
	if err == nil {
		return nil
	}
	// url errors from http.Client wrap the dial error; unwrap to inspect.
	var opErr *net.OpError
	if errors.As(err, &opErr) || errors.Is(err, os.ErrNotExist) {
		return &connError{socketPath: c.socketPath, cause: err}
	}
	return err
}

// decodeError reads a non-2xx response body as a {layer,error} envelope. If the
// body isn't the envelope shape, it falls back to the raw text.
func (c *client) decodeError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	var env struct {
		Layer   string `json:"layer"`
		Message string `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err == nil && env.Message != "" {
		return &layerError{Layer: env.Layer, Message: env.Message, Status: resp.StatusCode}
	}
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = resp.Status
	}
	return &layerError{Message: msg, Status: resp.StatusCode}
}

// --- request/response shapes (mirror internal/daemon wire contract) ---

type createReq struct {
	Mode string `json:"mode,omitempty"`
	Name string `json:"name,omitempty"`
	Tier string `json:"tier,omitempty"`
	TTL  string `json:"ttl,omitempty"`
}

// workspaceView mirrors session.WorkspaceView for the `ws ls` table.
type workspaceView struct {
	Name       string `json:"name"`
	Snapshots  int    `json:"snapshots"`
	LatestTag  int    `json:"latest_tag"`
	LatestTime string `json:"latest_time,omitempty"`
}

// listWorkspaces GETs /v1/workspaces.
func (c *client) listWorkspaces(ctx context.Context) ([]workspaceView, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/workspaces", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, c.decodeError(resp)
	}
	var out []workspaceView
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// removeWorkspace DELETEs /v1/workspaces/{name}.
func (c *client) removeWorkspace(ctx context.Context, name string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v1/workspaces/"+name, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return c.decodeError(resp)
	}
	return nil
}

type createResp struct {
	SessionID string `json:"session_id"`
	State     string `json:"state"`
}

type execReq struct {
	Argv  []string `json:"argv"`
	Cwd   string   `json:"cwd,omitempty"`
	Env   []string `json:"env,omitempty"`
	Stdin string   `json:"stdin,omitempty"`
}

// sessionView mirrors session.View for the ls table.
type sessionView struct {
	SessionID    string `json:"session_id"`
	Mode         string `json:"mode"`
	Tier         string `json:"tier"`
	State        string `json:"state"`
	AgeSeconds   int64  `json:"age_seconds"`
	TTLRemaining int64  `json:"ttl_remaining_seconds"`
}

// createSession POSTs /v1/sessions and returns the new session id.
func (c *client) createSession(ctx context.Context, req createReq) (createResp, error) {
	var out createResp
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/sessions", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return out, c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return out, c.decodeError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

// listSessions GETs /v1/sessions.
func (c *client) listSessions(ctx context.Context) ([]sessionView, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/sessions", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, c.decodeError(resp)
	}
	var out []sessionView
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// destroySession DELETEs /v1/sessions/{id}.
func (c *client) destroySession(ctx context.Context, id string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v1/sessions/"+id, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return c.decodeError(resp)
	}
	return nil
}

// traceResp mirrors the daemon's GET /v1/sessions/{id}/trace body.
type traceResp struct {
	Events []trace.Event    `json:"events"`
	Seal   *trace.Signature `json:"seal"`
}

// fetchTrace GETs a session's trace chain + seal so the CLI can verify it
// client-side (never trusting the daemon's own claim of integrity).
func (c *client) fetchTrace(ctx context.Context, id string) (traceResp, error) {
	var out traceResp
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/sessions/"+id+"/trace", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return out, c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, c.decodeError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

// streamTrace opens the F3.2 live SSE trace tail for a session over the Unix
// socket (backfill from fromSeq, then live events) and invokes onEvent for each
// event until the context is cancelled or the stream ends. It reuses the same
// endpoint the browser UI proxies to, so `opslify top` and `opslify ui` render
// identical data. Only the already-redacted stream is transported.
func (c *client) streamTrace(ctx context.Context, id string, fromSeq uint64, onEvent func(trace.Event)) error {
	u := fmt.Sprintf("%s/v1/sessions/%s/trace?from_seq=%d", c.baseURL, id, fromSeq)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Accept", "text/event-stream")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.decodeError(resp)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue // blank frame terminators / comments
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		var ev trace.Event
		if err := json.Unmarshal(payload, &ev); err != nil {
			continue // skip a malformed frame rather than aborting the tail
		}
		onEvent(ev)
	}
	if err := sc.Err(); err != nil {
		return c.wireError(err)
	}
	return nil
}

// execFrame is one NDJSON frame from the exec stream.
type execFrame struct {
	Stream    string `json:"stream"`
	Data      string `json:"data"`
	Truncated bool   `json:"truncated"`
	Exit      *int   `json:"exit_code"`
	Error     string `json:"error"`
}

// execResult is the outcome of a streamed exec.
type execResult struct {
	// ExitCode is the command's exit status; nil if the stream ended without one
	// (e.g. a mid-stream error frame).
	ExitCode *int
}

// execStream POSTs an exec, then consumes the NDJSON frame stream: stdout frames
// go to stdout, stderr frames to stderr, a truncation marker is announced on
// stderr, a mid-stream error frame becomes a layerError, and the exit_code frame
// is captured. It returns the exit code (when present) plus any error.
func (c *client) execStream(ctx context.Context, id string, req execReq, stdout, stderr io.Writer) (execResult, error) {
	var res execResult
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/sessions/"+id+"/exec", bytes.NewReader(body))
	if err != nil {
		return res, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return res, c.wireError(err)
	}
	defer resp.Body.Close()

	// A pre-stream failure (bad id, not-ready) comes back as a normal JSON error
	// with a non-2xx status — surface the layered envelope.
	if resp.StatusCode != http.StatusOK {
		return res, c.decodeError(resp)
	}

	sc := bufio.NewScanner(resp.Body)
	// Frames can be large (bounded by the daemon's output cap); allow a big line.
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var f execFrame
		if err := json.Unmarshal(line, &f); err != nil {
			return res, fmt.Errorf("malformed exec frame from daemon: %w", err)
		}
		switch {
		case f.Error != "":
			// Mid-stream failure frame — status was already 200, so this is the
			// legible failure. The daemon tags runtime faults here.
			return res, &layerError{Layer: "runtime", Message: f.Error}
		case f.Exit != nil:
			code := *f.Exit
			res.ExitCode = &code
		case f.Truncated:
			fmt.Fprintf(stderr, "\n[opslify: %s output truncated at cap]\n", frameStreamLabel(f.Stream))
		case f.Data != "":
			if f.Stream == "stderr" {
				io.WriteString(stderr, f.Data)
			} else {
				io.WriteString(stdout, f.Data)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return res, c.wireError(err)
	}
	return res, nil
}

func frameStreamLabel(s string) string {
	if s == "" {
		return "stdout"
	}
	return s
}
