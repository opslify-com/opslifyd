package agents

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Running an agent is the other half of the registry: Add proves a command
// speaks MCP, Run hands it a prompt and lets it work.
//
// The whole design rests on one rule: THE AGENT GETS NO TOOLS BUT OPSLIFY'S.
//
// Every one of these CLIs ships a shell, a file reader and a file writer that
// operate on the host it runs on. Started with its defaults, an agent driven
// from the cockpit would edit the operator's disk and run host commands directly,
// and every guarantee in this product — the sandbox, default-deny egress, the
// approval gates, the trace — would be decoration around a process that was
// never subject to any of it.
//
// So each run gets a throwaway configuration directory that (a) registers the
// daemon's own MCP server and (b) removes the built-in host tools, and the agent
// is started against that and nothing else. It can create sandboxes, exec inside
// them, and move files through /workspace. That is all it can do, and all of it
// is gated and traced like any other exec.

// RunRequest is one prompt handed to an agent.
type RunRequest struct {
	// Prompt is the operator's instruction, verbatim.
	Prompt string
	// Socket is the daemon API socket the agent's MCP server connects back to.
	Socket string
	// MCPCommand is the absolute path to the binary that serves `mcp`. The daemon
	// passes its OWN path: the agent must talk to this daemon, not to whatever
	// `opslifyd` happens to be on a PATH somewhere.
	MCPCommand string
	// ProjectID / EnvironmentID scope the work and are stated in the preamble, so
	// the agent knows which estate it is touching.
	ProjectID, EnvironmentID string
}

// RunSink receives an agent's output as it is produced. Same shape as the exec
// sink: an operator watching a model think should see it think.
type RunSink interface {
	Chunk(stream string, data []byte) error
	Exit(code int) error
}

// Runner drives registered agents.
type Runner struct {
	// WorkRoot is where per-run configuration directories are made. Each run gets
	// its own and it is removed afterwards.
	WorkRoot string
}

// opslifyTools is the complete set an agent may call. It is written out rather
// than wildcarded: a wildcard would silently admit whatever the MCP server grows
// next, and "the agent may do anything we later add" is not a decision anyone
// made.
var opslifyTools = []string{
	"mcp__opslifyd__opslify_session_create",
	"mcp__opslifyd__opslify_exec",
	"mcp__opslifyd__opslify_upload",
	"mcp__opslifyd__opslify_download",
	"mcp__opslifyd__opslify_session_end",
}

// hostTools are the built-ins denied by name.
//
// The allowlist alone is NOT enough, which was established by trying it: with
// --permission-mode default and only the opslify tools allowed, Claude Code still
// reached for Bash — the write was stopped by its own working-directory check,
// for an unrelated reason, and the agent observed that it could retry with that
// check disabled. --allowedTools governs approval, not availability. This list is
// what actually removes the tool.
//
// A blocklist rots as a CLI grows tools, so it does not stand alone either:
// UnconfinedTools compares it against what the handshake actually reported, and
// `agent add` says so when something is neither an opslify tool nor denied.
var hostTools = []string{
	// Shell and filesystem.
	"Bash", "BashOutput", "KillShell", "Read", "Write", "Edit", "MultiEdit",
	"NotebookEdit", "Glob", "Grep",
	// Network.
	"WebFetch", "WebSearch",
	// Delegation. The sharpest of these: a subagent is a fresh session, and a
	// fresh session has its own tools — so an agent that can spawn one can spawn
	// its way out of every restriction placed on it.
	"Agent", "Task", "TaskCreate", "TaskGet", "TaskList", "TaskOutput",
	"TaskStop", "TaskUpdate", "Skill", "ToolSearch",
	// Scheduling and outbound messaging: ways to act later, or elsewhere, outside
	// anything this run is watching.
	"CronCreate", "CronDelete", "CronList", "ScheduleWakeup",
	"SendMessage", "RemoteTrigger", "PushNotification", "Monitor",
	// Workspace and host integrations.
	"EnterWorktree", "ExitWorktree", "DesignSync", "Artifact",
	// Session-shape controls that have no meaning in a driven run.
	"TodoWrite", "ExitPlanMode", "EnterPlanMode", "ReportFindings",
	"AskUserQuestion", "ShareOnboardingGuide",
}

// UnconfinedTools reports which of an agent's PROBED tools are neither opslify's
// nor on the denylist — that is, which it would still be holding when driven.
//
// This exists because the denylist above is a blocklist, and a blocklist is only
// as current as the last time someone read the CLI's release notes. The registry
// already learns the real tool list during the handshake at `agent add`, so the
// gap is detectable at exactly the moment an operator is deciding to trust the
// thing. Reported rather than refused: a new harmless tool should not stop a
// registration, but nobody should find out about it by accident.
func UnconfinedTools(probed []string) []string {
	known := make(map[string]bool, len(hostTools)+len(opslifyTools)+len(qwenHostTools))
	for _, t := range hostTools {
		known[t] = true
	}
	for _, t := range qwenHostTools {
		known[t] = true
	}
	for _, t := range opslifyTools {
		known[t] = true
	}
	var out []string
	for _, t := range probed {
		if known[t] || strings.HasPrefix(t, "mcp__opslifyd__") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// qwenHostTools are Qwen Code's built-ins, which have different names.
var qwenHostTools = []string{
	"run_shell_command", "write_file", "replace", "read_file",
	"read_many_files", "glob", "search_file_content",
	"web_fetch", "google_web_search",
}

// Run executes one prompt and streams the agent's output to sink.
func (r *Runner) Run(ctx context.Context, a Agent, req RunRequest, sink RunSink) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if !a.Drivable() {
		return fmt.Errorf("%w: agent %q has no flavour, so the daemon does not know how to confine it; re-add it with --flavour claude|qwen|codex",
			ErrInvalidInput, a.Name)
	}
	if strings.TrimSpace(req.Prompt) == "" {
		return fmt.Errorf("%w: an empty prompt", ErrInvalidInput)
	}
	if req.MCPCommand == "" || req.Socket == "" {
		return fmt.Errorf("%w: the runner needs the daemon's own binary path and socket", ErrInvalidInput)
	}

	dir, err := os.MkdirTemp(r.WorkRoot, "agentrun-")
	if err != nil {
		return fmt.Errorf("agents: run workdir: %w", err)
	}
	// 0700: the configuration names the daemon's socket, and the run directory is
	// the agent's cwd. Nothing else on the host needs to read it.
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return err
	}
	defer os.RemoveAll(dir)

	argv, err := recipe(a, req, dir)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, a.Command, argv...)
	cmd.Dir = dir
	// The same allowlist the prober uses: a registered command is third-party code
	// and the daemon's environment may hold anything.
	cmd.Env = a.Env(os.Environ())
	// No stdin. These CLIs read a piped prompt when one is present, and an agent
	// that inherited the daemon's stdin would block forever waiting on it.
	cmd.Stdin = nil

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("agents: start %s: %w", a.Command, err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pump(stdout, "stdout", sink) }()
	go func() { defer wg.Done(); pump(stderr, "stderr", sink) }()
	wg.Wait()

	code := 0
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// A non-zero exit is the agent's answer, not a daemon fault: report the
			// code and let the operator read what it printed.
			code = ee.ExitCode()
		} else {
			return err
		}
	}
	return sink.Exit(code)
}

func pump(r io.Reader, stream string, sink RunSink) {
	br := bufio.NewReader(r)
	buf := make([]byte, 4096)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if err := sink.Chunk(stream, buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// preamble is prepended to every prompt. It states the constraints rather than
// relying on the model to infer them from tool availability, because a model
// that does not know it is sandboxed writes worse plans — it hedges around
// permissions it does not need to worry about, or promises host changes it
// cannot make.
func preamble(req RunRequest) string {
	// The scope instruction is the load-bearing line. Everything that makes a
	// sandbox useful for a particular estate — its connections, its secrets, its
	// egress allowlist, its instruction set — resolves on (project, environment).
	// An agent that creates a sandbox without them gets the default project, which
	// has none of it, and that failure is invisible: the sandbox starts fine and
	// the first credentialed request simply fails as though the token were wrong.
	scope := ""
	if req.ProjectID != "" {
		scope = "\nYou are working in project \"" + req.ProjectID + "\""
		if req.EnvironmentID != "" {
			scope += ", environment \"" + req.EnvironmentID + "\""
		}
		scope += ".\n\nEVERY call to opslify_session_create MUST pass project=\"" + req.ProjectID + "\""
		if req.EnvironmentID != "" {
			scope += " and environment=\"" + req.EnvironmentID + "\""
		}
		scope += ". A sandbox created without them lands in the default project and " +
			"silently has none of this estate's connections, secrets or egress rules — " +
			"it will start normally and then fail to reach anything.\n"
	} else {
		scope = "\nNo project was specified, so sandboxes will use the default project. " +
			"It has no connections or secrets configured.\n"
	}

	return "You are operating through opslify.\n\n" +
		"You have NO host shell and NO host filesystem access. Your only tools are " +
		"opslify's: create a sandbox, exec inside it, and move files through its " +
		"/workspace. Everything you run happens in a hardened container with " +
		"default-deny egress.\n" +
		scope +
		"\nCredentials are never given to you. A connection is referenced by name and " +
		"the daemon injects the value at the egress proxy, so an allowlisted host " +
		"will authenticate without you ever holding a token. Do not ask for one, and " +
		"do not try to read one — there is no route that returns one.\n\n" +
		"Commands matching an approval gate will PAUSE rather than run. That is " +
		"normal; report the pause and stop rather than trying to work around it.\n\n" +
		"Task:\n" + req.Prompt
}

// mcpServersJSON is the MCP configuration handed to a run: exactly one server,
// this daemon, reached over the socket it is actually listening on.
func mcpServersJSON(req RunRequest) ([]byte, error) {
	type server struct {
		Type    string   `json:"type"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	return json.MarshalIndent(struct {
		MCPServers map[string]server `json:"mcpServers"`
	}{MCPServers: map[string]server{
		"opslifyd": {
			Type:    "stdio",
			Command: req.MCPCommand,
			Args:    []string{"mcp", "--socket", req.Socket},
		},
	}}, "", "  ")
}

// recipe builds the argv for one flavour and writes whatever configuration that
// CLI reads from disk into dir.
func recipe(a Agent, req RunRequest, dir string) ([]string, error) {
	mcp, err := mcpServersJSON(req)
	if err != nil {
		return nil, err
	}
	prompt := preamble(req)

	// a.Args are deliberately NOT reused here. They are the arguments that make the
	// command speak MCP for the registry's handshake — `claude mcp serve`,
	// `codex mcp` — and prepending them to a run produces a completely different
	// invocation: the first attempt at this ran `claude mcp serve --print ... <prompt>`
	// and the agent answered a question about MCP instead of doing the work.
	// Probing and driving are two modes of the same binary, and the daemon owns
	// the argv for both.
	switch a.Flavour {
	case FlavourClaude:
		path := filepath.Join(dir, "mcp.json")
		if err := os.WriteFile(path, mcp, 0o600); err != nil {
			return nil, err
		}
		argv := []string{
			"--print",
			// STRICT: without this the agent also loads the operator's own MCP
			// servers from ~/.claude.json, which may include anything at all.
			"--strict-mcp-config",
			"--mcp-config", path,
			"--permission-mode", "acceptEdits",
			"--output-format", "text",
		}
		argv = append(argv, "--allowedTools")
		argv = append(argv, opslifyTools...)
		argv = append(argv, "--disallowedTools")
		argv = append(argv, hostTools...)
		if a.ModelHint != "" {
			argv = append(argv, "--model", a.ModelHint)
		}
		argv = append(argv, prompt)
		return argv, nil

	case FlavourQwen:
		// Qwen Code has no per-run MCP flag: it reads .qwen/settings.json from its
		// working directory. The run directory IS that project, so the operator's
		// own ~/.qwen configuration is not what the agent gets.
		qdir := filepath.Join(dir, ".qwen")
		if err := os.MkdirAll(qdir, 0o700); err != nil {
			return nil, err
		}
		var servers map[string]any
		if err := json.Unmarshal(mcp, &servers); err != nil {
			return nil, err
		}
		settings := map[string]any{
			"mcpServers": servers["mcpServers"],
			"tools":      map[string]any{"exclude": qwenHostTools},
		}
		b, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(qdir, "settings.json"), b, 0o600); err != nil {
			return nil, err
		}
		argv := []string{"--approval-mode", "yolo"}
		if a.ModelHint != "" {
			argv = append(argv, "-m", a.ModelHint)
		}
		argv = append(argv, prompt)
		return argv, nil

	case FlavourCodex:
		path := filepath.Join(dir, "mcp.json")
		if err := os.WriteFile(path, mcp, 0o600); err != nil {
			return nil, err
		}
		argv := []string{"exec", "--skip-git-repo-check"}
		if a.ModelHint != "" {
			argv = append(argv, "--model", a.ModelHint)
		}
		argv = append(argv, prompt)
		return argv, nil
	}
	return nil, fmt.Errorf("%w: no recipe for flavour %q", ErrInvalidInput, a.Flavour)
}
