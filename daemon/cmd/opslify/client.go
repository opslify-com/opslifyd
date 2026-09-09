package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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
	// F8.1 scope. Both omitted => the daemon's default project/environment.
	Project     string `json:"project,omitempty"`
	Environment string `json:"environment,omitempty"`
}

// --- F8.1 project / environment surface ---

// projectView mirrors the daemon's project response (records only — no secret,
// and a policy layer is a PATH, never content).
type projectView struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Created      string            `json:"created"`
	RepoURL      string            `json:"repo_url,omitempty"`
	Capabilities map[string]string `json:"capabilities,omitempty"`
	PolicyFile   string            `json:"policy_file,omitempty"`
	Environments []environmentView `json:"environments"`
}

// environmentView mirrors the daemon's environment response.
type environmentView struct {
	ID            string `json:"id"`
	ProjectID     string `json:"project_id"`
	Name          string `json:"name"`
	Created       string `json:"created"`
	PolicyOverlay string `json:"policy_overlay,omitempty"`
	DefaultTier   string `json:"default_tier,omitempty"`
	DefaultTTL    string `json:"default_ttl,omitempty"`
	Production    bool   `json:"production"`
}

// createProjectReq is the POST /v1/projects body.
type createProjectReq struct {
	Name         string            `json:"name"`
	RepoURL      string            `json:"repo_url,omitempty"`
	Capabilities map[string]string `json:"capabilities,omitempty"`
	PolicyFile   string            `json:"policy_file,omitempty"`
	Environments []addEnvReq       `json:"environments,omitempty"`
}

// addEnvReq is the POST /v1/projects/{id}/environments body.
type addEnvReq struct {
	Name          string `json:"name"`
	PolicyOverlay string `json:"policy_overlay,omitempty"`
	DefaultTier   string `json:"default_tier,omitempty"`
	DefaultTTL    string `json:"default_ttl,omitempty"`
	Production    bool   `json:"production,omitempty"`
}

// createProject POSTs /v1/projects.
func (c *client) createProject(ctx context.Context, req createProjectReq) (projectView, error) {
	var out projectView
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/projects", bytes.NewReader(body))
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

// listProjects GETs /v1/projects.
func (c *client) listProjects(ctx context.Context) ([]projectView, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/projects", nil)
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
	var out []projectView
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// getProject GETs /v1/projects/{id}.
func (c *client) getProject(ctx context.Context, id string) (projectView, error) {
	var out projectView
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/projects/"+url.PathEscape(id), nil)
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

// addEnvironment POSTs /v1/projects/{id}/environments.
func (c *client) addEnvironment(ctx context.Context, projectID string, req addEnvReq) (environmentView, error) {
	var out environmentView
	body, _ := json.Marshal(req)
	u := c.baseURL + "/v1/projects/" + url.PathEscape(projectID) + "/environments"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
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

// listEnvironments GETs /v1/projects/{id}/environments.
func (c *client) listEnvironments(ctx context.Context, projectID string) ([]environmentView, error) {
	u := c.baseURL + "/v1/projects/" + url.PathEscape(projectID) + "/environments"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	var out []environmentView
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
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

// registryAllowResp mirrors the daemon's GET /v1/registry/allow body (F7.5).
type registryAllowResp struct {
	Configured bool   `json:"configured"`
	Allowed    bool   `json:"allowed"`
	Ecosystem  string `json:"ecosystem"`
	Name       string `json:"name"`
}

// registryAllowed GETs /v1/registry/allow — the F7.5 pre-install allowlist gate the
// operator CLI checks BEFORE running an install, so a non-allowlisted package is
// refused before any exec and an unconfigured proxy fails closed.
func (c *client) registryAllowed(ctx context.Context, ecosystem, name string) (registryAllowResp, error) {
	u := c.baseURL + "/v1/registry/allow?ecosystem=" + url.QueryEscape(ecosystem) + "&name=" + url.QueryEscape(name)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return registryAllowResp{}, err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return registryAllowResp{}, c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return registryAllowResp{}, c.decodeError(resp)
	}
	var out registryAllowResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return registryAllowResp{}, err
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

// manifestEntry mirrors session.ManifestEntry — one /workspace file's path,
// size, mtime and content hash, for host↔sandbox diffing (F7.3).
type manifestEntry struct {
	RelPath string `json:"rel_path"`
	Size    int64  `json:"size"`
	ModUnix int64  `json:"mod_unix"`
	SHA256  string `json:"sha256"`
}

type uploadFileReq struct {
	Path       string `json:"path"`
	ContentB64 string `json:"content_b64"`
}

type downloadFileResp struct {
	ContentB64 string `json:"content_b64"`
}

// fetchManifest GETs /v1/sessions/{id}/manifest — the F7.3 workspace manifest.
func (c *client) fetchManifest(ctx context.Context, id string) ([]manifestEntry, error) {
	u := c.baseURL + "/v1/sessions/" + id + "/manifest"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	var out []manifestEntry
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// uploadFile PUTs a /workspace-confined file into a session (F2.1 transfer,
// reused by the F7.3 sync engine for host→sandbox writes).
func (c *client) uploadFile(ctx context.Context, id, relPath string, content []byte) error {
	body, _ := json.Marshal(uploadFileReq{Path: relPath, ContentB64: base64.StdEncoding.EncodeToString(content)})
	u := c.baseURL + "/v1/sessions/" + id + "/files"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(body))
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

// downloadFile GETs a /workspace-confined file from a session (F2.1 transfer,
// reused by the F7.3 sync engine for sandbox→host writes).
func (c *client) downloadFile(ctx context.Context, id, relPath string) ([]byte, error) {
	u := c.baseURL + "/v1/sessions/" + id + "/files?path=" + url.QueryEscape(relPath)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	var out downloadFileResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.ContentB64)
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

// approvalView mirrors session.ApprovalView — the F4.3 approve/deny/list shape.
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

type resolveApprovalReq struct {
	Decision string `json:"decision"`
	Comment  string `json:"comment,omitempty"`
}

// listApprovals GETs /v1/approvals (the pending queue).
func (c *client) listApprovals(ctx context.Context) ([]approvalView, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/approvals", nil)
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
	var out []approvalView
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// resolveApproval POSTs an approve|deny decision for a pending gate.
func (c *client) resolveApproval(ctx context.Context, id, execID, decision, comment string) (approvalView, error) {
	var out approvalView
	body, _ := json.Marshal(resolveApprovalReq{Decision: decision, Comment: comment})
	u := c.baseURL + "/v1/sessions/" + id + "/approvals/" + execID
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
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

// --- F5.6 secrets management (metadata out, value in only) ---

// secretMeta mirrors the daemon's metadata-only secret projection. It carries NO
// value (the daemon never returns one).
type secretMeta struct {
	Ref       string `json:"ref"`
	Provider  string `json:"provider,omitempty"`
	Scope     string `json:"scope,omitempty"`
	TTL       string `json:"ttl,omitempty"`
	CreatedAt string `json:"created_at"`
}

// addSecretReq is the POST /v1/secrets body. The value is base64 so it may be
// binary; it travels IN only and is never returned.
type addSecretReq struct {
	Ref       string `json:"ref"`
	Provider  string `json:"provider,omitempty"`
	Scope     string `json:"scope,omitempty"`
	TTL       string `json:"ttl,omitempty"`
	ValueB64  string `json:"value_b64"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

// addSecret POSTs a secret value. The returned metadata carries no value.
func (c *client) addSecret(ctx context.Context, req addSecretReq) (secretMeta, error) {
	var out secretMeta
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/secrets", bytes.NewReader(body))
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

// listSecrets GETs /v1/secrets — metadata only, never a value.
func (c *client) listSecrets(ctx context.Context) ([]secretMeta, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/secrets", nil)
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
	var out []secretMeta
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// removeSecret DELETEs /v1/secrets/{ref}.
// secretConsumer mirrors broker.Consumer. It carries no value and no path to one.
type secretConsumer struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Scope string `json:"scope,omitempty"`
}

// secretView is metadata plus who addresses the ref — still never a value.
type secretView struct {
	secretMeta
	LastUsed  *time.Time       `json:"last_used,omitempty"`
	RotatedAt *time.Time       `json:"rotated_at,omitempty"`
	Consumers []secretConsumer `json:"consumers,omitempty"`
	InUse     bool             `json:"in_use"`
}

// rotateSecretReq carries the NEW value inward. Like add, a value only ever
// travels in this direction; no response returns one.
type rotateSecretReq struct {
	ValueB64 string `json:"value_b64"`
	Provider string `json:"provider,omitempty"`
	Scope    string `json:"scope,omitempty"`
	TTL      string `json:"ttl,omitempty"`
}

// escapeRef makes a ref safe to concatenate into a request path. A ref may
// legitimately contain '/' (e.g. "aws/deploy"), which must survive as path
// segments, but '?' and '#' must NOT — without this, `secrets rm 'x?force=true'`
// rewrote the query string and bypassed the in-use guard.
func escapeRef(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// listSecretsWithConsumers GETs /v1/secrets/consumers — metadata + who uses each
// ref. There is no response shape here that can carry a value.
func (c *client) listSecretsWithConsumers(ctx context.Context) ([]secretView, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/secrets/consumers", nil)
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
	var out []secretView
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// rotateSecret PUTs a new value under an existing ref.
func (c *client) rotateSecret(ctx context.Context, ref string, req rotateSecretReq) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.baseURL+"/v1/secrets/"+escapeRef(ref), bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.decodeError(resp)
	}
	return nil
}

// removeSecretForce DELETEs a ref, optionally past the in-use guard.
func (c *client) removeSecretForce(ctx context.Context, ref string, force bool) error {
	u := c.baseURL + "/v1/secrets/" + escapeRef(ref)
	if force {
		u += "?force=true"
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
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

func (c *client) removeSecret(ctx context.Context, ref string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v1/secrets/"+escapeRef(ref), nil)
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
	// F4.3 approval-gate pause.
	Status string `json:"status"`
	ExecID string `json:"exec_id"`
	Rule   string `json:"rule"`
}

// execResult is the outcome of a streamed exec.
type execResult struct {
	// ExitCode is the command's exit status; nil if the stream ended without one
	// (e.g. a mid-stream error frame).
	ExitCode *int
	// Pending is set (with ExecID) when the command matched an approval gate and did
	// NOT run — the caller reports the gate rather than treating it as success.
	Pending bool
	ExecID  string
	Rule    string
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
		case f.Status == "pending":
			// F4.3: the command matched an approval gate and did NOT run. Record the
			// pending handle so the caller can report it and poll — no hang.
			res.Pending = true
			res.ExecID = f.ExecID
			res.Rule = f.Rule
			return res, nil
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
