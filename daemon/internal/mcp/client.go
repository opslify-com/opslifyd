// Package mcp implements the F2.1 `opslifyd mcp` stdio MCP server: a THIN
// translation layer that exposes opslify sandbox sessions to any MCP client
// (Claude Code first) as five tools, over the same Unix-socket REST API the CLI
// uses. All business logic lives in the daemon; this package only does schema
// translation, output capping, and file-size/path confinement so MCP spec churn
// stays isolated from the session engine.
package mcp

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
	"net/url"
	"os"
	"strings"
)

// client is the MCP server's REST-over-unix-socket transport seam — the same
// pattern as the CLI's client (cmd/opslify/client.go). It is constructed with a
// socket path so unit tests point it at a temp .sock served by a fake daemon,
// with no real daemon/podman/root.
type client struct {
	socketPath string
	http       *http.Client
	baseURL    string
}

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

// layerError surfaces the daemon's {layer,error} envelope so an MCP tool error
// names the layer that rejected the request (sandbox/egress/runtime/input/…).
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
// a legible message naming the socket, so a misconfigured client is obvious.
type connError struct {
	socketPath string
	cause      error
}

func (e *connError) Error() string {
	return fmt.Sprintf("cannot reach opslifyd on %s: %v (is opslifyd running?)", e.socketPath, e.cause)
}
func (e *connError) Unwrap() error { return e.cause }

func (c *client) wireError(err error) error {
	if err == nil {
		return nil
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) || errors.Is(err, os.ErrNotExist) {
		return &connError{socketPath: c.socketPath, cause: err}
	}
	return err
}

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

// --- wire shapes (mirror internal/daemon exactly) ---

type createReq struct {
	Mode string `json:"mode,omitempty"`
	Name string `json:"name,omitempty"`
	TTL  string `json:"ttl,omitempty"`
}

type createResp struct {
	SessionID string `json:"session_id"`
	State     string `json:"state"`
}

type execReq struct {
	Argv []string `json:"argv"`
	Cwd  string   `json:"cwd,omitempty"`
}

type execFrame struct {
	Stream    string `json:"stream"`
	Data      string `json:"data"`
	Truncated bool   `json:"truncated"`
	Exit      *int   `json:"exit_code"`
	Error     string `json:"error"`
	// F4.3 approval-gate pause.
	Status string `json:"status"`
	ExecID string `json:"exec_id"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// approvalView mirrors session.ApprovalView — the poll/GET response shape.
type approvalView struct {
	SessionID   string `json:"session_id"`
	ExecID      string `json:"exec_id"`
	Status      string `json:"status"`
	Rule        string `json:"rule"`
	Reason      string `json:"reason"`
	ArgvSummary string `json:"argv_summary"`
	Comment     string `json:"comment"`
	DenyReason  string `json:"deny_reason"`
	Ran         bool   `json:"ran"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	ExitCode    *int   `json:"exit_code"`
}

type uploadReq struct {
	Path       string `json:"path"`
	ContentB64 string `json:"content_b64"`
}

type downloadResp struct {
	ContentB64 string `json:"content_b64"`
}

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

func (c *client) destroySession(ctx context.Context, id string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v1/sessions/"+url.PathEscape(id), nil)
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

// execResult is the aggregated (capped) outcome an MCP exec tool returns. MCP
// tool results are a single response, not a stream, so the streamed NDJSON exec
// frames are aggregated here under a per-stream output cap with an explicit
// truncation marker — never unbounded.
type execResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	// F4.3: when a command matches an approval gate it does NOT run — Status is
	// "pending" and ExecID is the handle the agent polls. Empty Status => the
	// command ran and Stdout/Stderr/ExitCode are its result.
	Status string
	ExecID string
	Rule   string
	Reason string
}

func (c *client) exec(ctx context.Context, id string, req execReq, cap int) (execResult, error) {
	var res execResult
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/sessions/"+url.PathEscape(id)+"/exec", bytes.NewReader(body))
	if err != nil {
		return res, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return res, c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return res, c.decodeError(resp)
	}

	stdout := &cappedBuffer{cap: cap}
	stderr := &cappedBuffer{cap: cap}

	sc := bufio.NewScanner(resp.Body)
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
		case f.Status == "pending":
			// F4.3: the command matched an approval gate and was NOT spawned. Return
			// promptly with a structured pending status — never hang on a human.
			res.Status = "pending"
			res.ExecID = f.ExecID
			res.Rule = f.Rule
			res.Reason = f.Reason
			return res, nil
		case f.Error != "":
			// Mid-stream failure frame — the daemon tags runtime faults here.
			return res, &layerError{Layer: "runtime", Message: f.Error}
		case f.Exit != nil:
			res.ExitCode = *f.Exit
		case f.Truncated:
			// The daemon hit its own output cap; note it on the affected stream.
			c.markDaemonTruncated(stdout, stderr, f.Stream)
		case f.Data != "":
			if f.Stream == "stderr" {
				stderr.WriteString(f.Data)
			} else {
				stdout.WriteString(f.Data)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return res, c.wireError(err)
	}
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
	return res, nil
}

func (c *client) markDaemonTruncated(stdout, stderr *cappedBuffer, stream string) {
	if stream == "stderr" {
		stderr.WriteString("\n[daemon output cap reached]")
	} else {
		stdout.WriteString("\n[daemon output cap reached]")
	}
}

// getApproval polls a pending gate's current state. It is READ-ONLY: there is no
// client method to APPROVE a gate, so the agent cannot self-approve — resolution
// is exclusively the human control plane (CLI/UI/cloud).
func (c *client) getApproval(ctx context.Context, id, execID string) (approvalView, error) {
	var out approvalView
	u := c.baseURL + "/v1/sessions/" + url.PathEscape(id) + "/approvals/" + url.PathEscape(execID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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

func (c *client) uploadFile(ctx context.Context, id, path, contentB64 string) error {
	body, _ := json.Marshal(uploadReq{Path: path, ContentB64: contentB64})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/sessions/"+url.PathEscape(id)+"/files", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
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

func (c *client) downloadFile(ctx context.Context, id, path string) (string, error) {
	u := c.baseURL + "/v1/sessions/" + url.PathEscape(id) + "/files?path=" + url.QueryEscape(path)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return "", c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", c.decodeError(resp)
	}
	var out downloadResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.ContentB64, nil
}

// cappedBuffer accumulates output up to cap bytes, counting (not storing) the
// overflow, so a hostile command that floods a stream cannot OOM the MCP client.
// String() appends an explicit truncation marker when anything was dropped.
type cappedBuffer struct {
	cap     int
	buf     []byte
	omitted int
}

func (b *cappedBuffer) WriteString(s string) {
	room := b.cap - len(b.buf)
	if room <= 0 {
		b.omitted += len(s)
		return
	}
	if len(s) <= room {
		b.buf = append(b.buf, s...)
		return
	}
	b.buf = append(b.buf, s[:room]...)
	b.omitted += len(s) - room
}

func (b *cappedBuffer) String() string {
	if b.omitted == 0 {
		return string(b.buf)
	}
	return fmt.Sprintf("%s\n[truncated: %d bytes omitted]", b.buf, b.omitted)
}
