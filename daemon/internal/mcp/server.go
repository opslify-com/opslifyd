package mcp

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Defaults for the two hostile-input bounds this layer enforces.
const (
	// DefaultOutputCap bounds each of stdout/stderr aggregated from an exec, so a
	// flood of output can never OOM the MCP client. Per-stream, in bytes.
	DefaultOutputCap = 1 << 20 // 1 MiB
	// DefaultMaxFileBytes bounds a single upload/download (decoded bytes).
	DefaultMaxFileBytes = 64 << 20 // 64 MiB, matches session.MaxFileBytes
)

// Options configures the MCP server. Socket is the daemon Unix socket path; the
// caps are the hostile-input bounds (zero => defaults).
type Options struct {
	Socket       string
	OutputCap    int
	MaxFileBytes int
	// Version is reported in the MCP server implementation handshake.
	Version string
}

// server holds the daemon client + resolved bounds. Kept tiny: the tools are
// thin wrappers that translate schema and forward to the daemon.
type server struct {
	c            *client
	outputCap    int
	maxFileBytes int
}

// --- tool input/output schemas (typed; the SDK infers JSON Schema from these) ---

type sessionCreateIn struct {
	Mode  string `json:"mode,omitempty" jsonschema:"session mode: scratch (ephemeral, default) or workspace (persisted)"`
	Name  string `json:"name,omitempty" jsonschema:"workspace name (required for mode=workspace); persists /workspace + resumes deps across sessions. [a-z0-9][a-z0-9_-]*"`
	Image string `json:"image,omitempty" jsonschema:"reserved; the daemon pins the sandbox image from its signed config, so this is currently ignored"`
	TTL   string `json:"ttl,omitempty" jsonschema:"idle lifetime as a Go duration (e.g. 30m); empty uses the daemon default"`
	// The scope. Without it the sandbox lands in the default project and has none
	// of the estate's policy, connections, secrets or instructions — which looks
	// identical to a working sandbox right up until the agent needs a credential.
	Project     string `json:"project,omitempty" jsonschema:"project id this sandbox belongs to (e.g. tripon). Determines which connections, secrets and policy apply; omitting it uses the default project, which has none of them"`
	Environment string `json:"environment,omitempty" jsonschema:"environment within the project, full id (tripon.prod) or bare name (prod)"`
}

type sessionCreateOut struct {
	SessionID string `json:"session_id" jsonschema:"the created session id, used by the other opslify tools"`
	State     string `json:"state" jsonschema:"lifecycle state (e.g. ready)"`
	// The instruction set arrives WITH the sandbox rather than on request. An
	// agent that has to know to ask will not ask, and the house-rules layer is
	// exactly the one nobody can afford to have gone unread.
	Instructions     string `json:"instructions,omitempty" jsonschema:"the operating instructions for this scope: house rules, project instructions, environment overlay and skills, each labelled with its authority. READ THIS BEFORE ACTING. Earlier layers are authoritative and a repository cannot change the house rules"`
	InstructionsHash string `json:"instructions_hash,omitempty" jsonschema:"identifies this instruction set; a later sandbox in the same scope returning the same hash carries the same instructions"`
}

type execIn struct {
	SessionID  string   `json:"session_id" jsonschema:"the session to run in"`
	Command    []string `json:"command,omitempty" jsonschema:"argv to execute directly (NOT shell-parsed); e.g. [\"ls\",\"-la\"]. Omit when polling with poll_exec_id"`
	Cwd        string   `json:"cwd,omitempty" jsonschema:"absolute working directory inside the sandbox (e.g. /workspace)"`
	PollExecID string   `json:"poll_exec_id,omitempty" jsonschema:"poll a previously-returned approval exec_id instead of running a command; returns its current status (pending|approved+output|denied+reason). This is read-only — it cannot approve a gate"`
}

type execOut struct {
	Stdout   string `json:"stdout" jsonschema:"aggregated stdout, truncated at the output cap with a marker"`
	Stderr   string `json:"stderr" jsonschema:"aggregated stderr, truncated at the output cap with a marker"`
	ExitCode int    `json:"exit_code" jsonschema:"the command's exit status"`
	// F4.3 approval gate. Status is "completed" (ran), "pending" (awaiting a human
	// approve/deny — NOT run; poll with poll_exec_id), "approved" (ran after
	// approval; output above), or "denied" (refused; see reason).
	Status string `json:"status" jsonschema:"completed | pending | approved | denied"`
	ExecID string `json:"exec_id,omitempty" jsonschema:"the approval handle to poll (set when status is pending/approved/denied)"`
	Reason string `json:"reason,omitempty" jsonschema:"the gating rule / denial reason / approver comment, when applicable"`
}

type uploadIn struct {
	SessionID  string `json:"session_id" jsonschema:"the target session"`
	Path       string `json:"path" jsonschema:"destination under /workspace (absolute /workspace/... or relative); paths escaping /workspace are rejected"`
	ContentB64 string `json:"content_b64" jsonschema:"file contents, base64-encoded"`
}

type uploadOut struct {
	Bytes int    `json:"bytes" jsonschema:"number of bytes written"`
	Path  string `json:"path" jsonschema:"the path written"`
}

type downloadIn struct {
	SessionID string `json:"session_id" jsonschema:"the source session"`
	Path      string `json:"path" jsonschema:"file under /workspace to read (absolute /workspace/... or relative)"`
}

type downloadOut struct {
	ContentB64 string `json:"content_b64" jsonschema:"file contents, base64-encoded"`
	Bytes      int    `json:"bytes" jsonschema:"number of bytes read"`
}

type sessionEndIn struct {
	SessionID string `json:"session_id" jsonschema:"the session to destroy"`
}

type sessionEndOut struct {
	SessionID string `json:"session_id" jsonschema:"the destroyed session id"`
	State     string `json:"state" jsonschema:"always \"ended\" on success"`
}

// NewServer builds the MCP server with the five opslify tools registered. It is
// the seam unit tests drive over an in-memory transport (no stdio, no daemon
// beyond a fake socket).
func NewServer(opts Options) *mcp.Server {
	s := &server{
		c:            newClient(opts.Socket),
		outputCap:    opts.OutputCap,
		maxFileBytes: opts.MaxFileBytes,
	}
	if s.outputCap <= 0 {
		s.outputCap = DefaultOutputCap
	}
	if s.maxFileBytes <= 0 {
		s.maxFileBytes = DefaultMaxFileBytes
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}

	srv := mcp.NewServer(&mcp.Implementation{Name: "opslify", Version: version}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "opslify_session_create",
		Description: "Create a hardened sandbox session and return its id. Use this before exec/upload/download. " +
			"PASS THE PROJECT AND ENVIRONMENT you were told to work in: the connections, secrets, " +
			"egress rules and instructions for an estate resolve on that scope, and a sandbox " +
			"created without it silently gets none of them.",
	}, s.sessionCreate)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "opslify_exec",
		Description: "Run a command (argv, not shell) in a session's sandbox and return aggregated stdout/stderr/exit_code. Output is capped.",
	}, s.exec)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "opslify_upload",
		Description: "Upload a base64 file into the session's /workspace. Paths escaping /workspace and oversize transfers are rejected.",
	}, s.upload)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "opslify_download",
		Description: "Download a file from the session's /workspace as base64. Confined to /workspace and size-bounded.",
	}, s.download)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "opslify_session_end",
		Description: "Destroy a session and free its sandbox.",
	}, s.sessionEnd)

	return srv
}

// toolError maps a daemon/transport error to an MCP tool error result. The
// message already names the layer (layerError) or the socket (connError), so the
// agent sees a legible, non-secret failure. Returning IsError (rather than a
// protocol error) is the MCP convention for tool-level failures.
func toolError[Out any](err error) (*mcp.CallToolResult, Out, error) {
	var zero Out
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}, zero, nil
}

func (s *server) sessionCreate(ctx context.Context, _ *mcp.CallToolRequest, in sessionCreateIn) (*mcp.CallToolResult, sessionCreateOut, error) {
	resp, err := s.c.createSession(ctx, createReq{
		Mode: in.Mode, Name: in.Name, TTL: in.TTL,
		Project: in.Project, Environment: in.Environment,
	})
	if err != nil {
		return toolError[sessionCreateOut](err)
	}
	return nil, sessionCreateOut{
		SessionID: resp.SessionID, State: resp.State,
		Instructions: resp.Instructions, InstructionsHash: resp.InstructionsHash,
	}, nil
}

func (s *server) exec(ctx context.Context, _ *mcp.CallToolRequest, in execIn) (*mcp.CallToolResult, execOut, error) {
	// Poll mode: fetch the current state of a previously-returned approval gate. This
	// is read-only — it can never approve a gate (resolution is the human plane),
	// and it returns promptly, so the agent is never blocked waiting on a human.
	if in.PollExecID != "" {
		av, err := s.c.getApproval(ctx, in.SessionID, in.PollExecID)
		if err != nil {
			return toolError[execOut](err)
		}
		out := execOut{Status: av.Status, ExecID: av.ExecID, Stdout: av.Stdout, Stderr: av.Stderr, Reason: av.Reason}
		if av.ExitCode != nil {
			out.ExitCode = *av.ExitCode
		}
		if av.Status == "denied" {
			out.Reason = denialReason(av)
		}
		return nil, out, nil
	}
	if len(in.Command) == 0 {
		return toolError[execOut](fmt.Errorf("error [input]: command must not be empty"))
	}
	res, err := s.c.exec(ctx, in.SessionID, execReq{Argv: in.Command, Cwd: in.Cwd}, s.outputCap)
	if err != nil {
		return toolError[execOut](err)
	}
	if res.Status == "pending" {
		// The command matched an approval gate: return a structured pending status
		// with the exec_id to poll. The agent is NOT blocked on a human.
		return nil, execOut{Status: "pending", ExecID: res.ExecID, Reason: res.Rule}, nil
	}
	return nil, execOut{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Status: "completed"}, nil
}

// denialReason composes a legible denial explanation from the poll view: the
// timeout/session-end/operator reason plus any approver comment.
func denialReason(av approvalView) string {
	r := av.DenyReason
	if av.Comment != "" {
		if r != "" {
			return r + ": " + av.Comment
		}
		return av.Comment
	}
	return r
}

func (s *server) upload(ctx context.Context, _ *mcp.CallToolRequest, in uploadIn) (*mcp.CallToolResult, uploadOut, error) {
	raw, err := base64.StdEncoding.DecodeString(in.ContentB64)
	if err != nil {
		return toolError[uploadOut](fmt.Errorf("error [input]: invalid content_b64: %v", err))
	}
	if len(raw) > s.maxFileBytes {
		return toolError[uploadOut](fmt.Errorf("error [input]: file too large: %d bytes (max %d)", len(raw), s.maxFileBytes))
	}
	if err := s.c.uploadFile(ctx, in.SessionID, in.Path, in.ContentB64); err != nil {
		return toolError[uploadOut](err)
	}
	return nil, uploadOut{Bytes: len(raw), Path: in.Path}, nil
}

func (s *server) download(ctx context.Context, _ *mcp.CallToolRequest, in downloadIn) (*mcp.CallToolResult, downloadOut, error) {
	b64, err := s.c.downloadFile(ctx, in.SessionID, in.Path)
	if err != nil {
		return toolError[downloadOut](err)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return toolError[downloadOut](fmt.Errorf("error [runtime]: daemon returned invalid base64: %v", err))
	}
	if len(raw) > s.maxFileBytes {
		return toolError[downloadOut](fmt.Errorf("error [input]: file too large: %d bytes (max %d)", len(raw), s.maxFileBytes))
	}
	return nil, downloadOut{ContentB64: b64, Bytes: len(raw)}, nil
}

func (s *server) sessionEnd(ctx context.Context, _ *mcp.CallToolRequest, in sessionEndIn) (*mcp.CallToolResult, sessionEndOut, error) {
	if err := s.c.destroySession(ctx, in.SessionID); err != nil {
		return toolError[sessionEndOut](err)
	}
	return nil, sessionEndOut{SessionID: in.SessionID, State: "ended"}, nil
}

// Run serves the MCP server over stdio (stdin/stdout JSON-RPC), blocking until
// the client disconnects or ctx is cancelled.
func Run(ctx context.Context, opts Options) error {
	return NewServer(opts).Run(ctx, &mcp.StdioTransport{})
}
