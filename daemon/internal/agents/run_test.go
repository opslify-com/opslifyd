package agents

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The recipes are the security boundary for a driven agent. Every one of these
// CLIs ships a host shell; if a recipe stops removing it, the agent edits the
// operator's disk directly and every guarantee in the product becomes decoration.
// So the recipes are asserted field by field rather than smoke-tested.

func testReq() RunRequest {
	return RunRequest{
		Prompt:        "check the cluster",
		Socket:        "/run/opslify/opslifyd.sock",
		MCPCommand:    "/usr/local/bin/opslifyd",
		ProjectID:     "tripon",
		EnvironmentID: "tripon.prod",
	}
}

func mustRecipe(t *testing.T, a Agent) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	argv, err := recipe(a, testReq(), dir)
	if err != nil {
		t.Fatalf("recipe: %v", err)
	}
	return argv, dir
}

func hasPair(argv []string, flag, val string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag && argv[i+1] == val {
			return true
		}
	}
	return false
}

// has reports exact membership. Named to avoid probe_test.go's substring
// `contains`: for an argv an exact match is what matters — a flag that merely
// appears inside another string is not a flag that was passed.
func has(argv []string, v string) bool {
	for _, a := range argv {
		if a == v {
			return true
		}
	}
	return false
}

// --- claude --------------------------------------------------------------------

func TestClaudeRecipeConfinesToOpslifyTools(t *testing.T) {
	a := Agent{Name: "claude", Command: "/usr/bin/claude", Locality: LocalityHosted, Flavour: FlavourClaude}
	argv, dir := mustRecipe(t, a)

	if !has(argv, "--strict-mcp-config") {
		t.Error("--strict-mcp-config is missing: without it the agent also loads the " +
			"operator's own MCP servers, which may be anything")
	}
	if !has(argv, "--print") {
		t.Error("--print is missing; the run would try to be interactive and hang")
	}
	// Every opslify tool allowed...
	for _, tool := range opslifyTools {
		if !has(argv, tool) {
			t.Errorf("tool %s is not in --allowedTools; the agent cannot do its job", tool)
		}
	}
	// ...and every host tool denied.
	for _, tool := range hostTools {
		if !has(argv, tool) {
			t.Errorf("host tool %s is not in --disallowedTools; the agent could use it "+
				"on this machine", tool)
		}
	}
	if !hasPair(argv, "--mcp-config", filepath.Join(dir, "mcp.json")) {
		t.Error("the MCP config path is not passed")
	}

	// The config must name THIS daemon and THIS socket.
	b, err := os.ReadFile(filepath.Join(dir, "mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.MCPServers) != 1 {
		t.Fatalf("the agent was given %d MCP servers, want exactly 1", len(cfg.MCPServers))
	}
	srv, ok := cfg.MCPServers["opslifyd"]
	if !ok {
		t.Fatal("the opslifyd server is missing from the config")
	}
	if srv.Command != "/usr/local/bin/opslifyd" {
		t.Errorf("command = %q, want the daemon's own path — resolving through PATH "+
			"could reach a different build", srv.Command)
	}
	if !has(srv.Args, "/run/opslify/opslifyd.sock") {
		t.Errorf("args = %v, want the socket this daemon is listening on", srv.Args)
	}
}

func TestClaudeRecipeCarriesTheModelAndPrompt(t *testing.T) {
	a := Agent{Name: "c", Command: "/usr/bin/claude", Locality: LocalityHosted,
		Flavour: FlavourClaude, ModelHint: "claude-opus-5"}
	argv, _ := mustRecipe(t, a)
	if !hasPair(argv, "--model", "claude-opus-5") {
		t.Error("the model hint is not passed")
	}
	// The prompt is the LAST argument, so nothing the operator types can be read
	// as a flag.
	last := argv[len(argv)-1]
	if !strings.Contains(last, "check the cluster") {
		t.Fatalf("the prompt is not the final argument: %q", last)
	}
}

// --- qwen ----------------------------------------------------------------------

func TestQwenRecipeWritesAProjectSettingsFile(t *testing.T) {
	a := Agent{Name: "qwen", Command: "/usr/bin/qwen", Locality: LocalityLocal, Flavour: FlavourQwen}
	argv, dir := mustRecipe(t, a)

	// Qwen Code has no per-run MCP flag; it reads the project's .qwen/settings.json.
	// Writing it into the RUN directory is what keeps the operator's own ~/.qwen
	// configuration out of the agent's hands.
	b, err := os.ReadFile(filepath.Join(dir, ".qwen", "settings.json"))
	if err != nil {
		t.Fatalf("no project settings written: %v", err)
	}
	var cfg struct {
		MCPServers map[string]any `json:"mcpServers"`
		Tools      struct {
			Exclude []string `json:"exclude"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.MCPServers["opslifyd"]; !ok {
		t.Error("the opslifyd MCP server is not configured")
	}
	if len(cfg.MCPServers) != 1 {
		t.Errorf("%d MCP servers configured, want exactly 1", len(cfg.MCPServers))
	}
	for _, tool := range qwenHostTools {
		if !has(cfg.Tools.Exclude, tool) {
			t.Errorf("qwen host tool %s is not excluded; the agent could use it on this machine", tool)
		}
	}
	if !has(argv, "--approval-mode") {
		t.Error("--approval-mode is missing; the run would block waiting for a human")
	}
}

func TestQwenSettingsAreNotWorldReadable(t *testing.T) {
	a := Agent{Name: "qwen", Command: "/usr/bin/qwen", Locality: LocalityLocal, Flavour: FlavourQwen}
	_, dir := mustRecipe(t, a)
	info, err := os.Stat(filepath.Join(dir, ".qwen", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	// It names the daemon's socket.
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("settings.json is %v; it names the daemon socket and must not be group/world readable",
			info.Mode().Perm())
	}
}

// --- the preamble ---------------------------------------------------------------

func TestThePreambleStatesTheConstraints(t *testing.T) {
	p := preamble(testReq())
	for _, want := range []string{
		"NO host shell",
		"default-deny egress",
		"Credentials are never given to you",
		"PAUSE",
		"tripon.prod",
		"check the cluster",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("the preamble does not mention %q; a model that does not know it is "+
				"sandboxed writes worse plans and promises host changes it cannot make", want)
		}
	}
}

// TestThePreambleDemandsTheScopeOnEverySandbox.
//
// This is the load-bearing instruction. Connections, secrets, egress rules and
// the instruction set all resolve on (project, environment); a sandbox created
// without them lands in the default project and has none of it. The failure is
// invisible — the sandbox starts normally and the first credentialed request just
// fails as though the token were wrong — so the agent has to be told, in the
// imperative, on every run.
func TestThePreambleDemandsTheScopeOnEverySandbox(t *testing.T) {
	p := preamble(testReq())
	for _, want := range []string{
		"opslify_session_create",
		`project="tripon"`,
		`environment="tripon.prod"`,
		"MUST",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("the preamble does not contain %q — an agent that omits the scope "+
				"gets a sandbox with none of the estate's connections or secrets", want)
		}
	}
}

// TestThePreambleIsHonestWithNoProject: silence would read as "scoped correctly".
func TestThePreambleIsHonestWithNoProject(t *testing.T) {
	req := testReq()
	req.ProjectID, req.EnvironmentID = "", ""
	p := preamble(req)
	if !strings.Contains(p, "default project") {
		t.Error("with no project the preamble should say so, and say what that costs")
	}
	if strings.Contains(p, "MUST pass project") {
		t.Error("it demands a scope that was never supplied")
	}
}

// --- refusals --------------------------------------------------------------------

func TestAnAgentWithNoFlavourCannotBeDriven(t *testing.T) {
	r := &Runner{WorkRoot: t.TempDir()}
	a := Agent{Name: "mystery", Command: "/usr/bin/true", Locality: LocalityUnknown}
	err := r.Run(context.Background(), a, testReq(), &recordingSink{})
	if err == nil {
		t.Fatal("an agent with no flavour was driven; the daemon has no way to take its host tools away")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
	// Named explicitly: recipe() also refuses an unknown flavour, so a test that
	// only asserted "some error" would still pass with the Drivable check deleted.
	// Two guards is the intent; this asserts the FIRST one is still there, and
	// that the operator is told how to fix it.
	if !strings.Contains(err.Error(), "--flavour") {
		t.Errorf("err = %q; the refusal should name the flag that fixes it, and should "+
			"come from the Drivable check rather than falling through to recipe()", err)
	}
}

func TestAnUnknownFlavourIsRefusedAtValidation(t *testing.T) {
	a := Agent{Name: "x", Command: "/usr/bin/true", Locality: LocalityLocal, Flavour: "vim"}
	if err := a.Validate(); err == nil {
		t.Fatal("an unknown flavour was accepted; there is no recipe to confine it with")
	}
}

func TestAnEmptyPromptIsRefused(t *testing.T) {
	r := &Runner{WorkRoot: t.TempDir()}
	a := Agent{Name: "c", Command: "/usr/bin/true", Locality: LocalityHosted, Flavour: FlavourClaude}
	req := testReq()
	req.Prompt = "   \n\t "
	if err := r.Run(context.Background(), a, req, &recordingSink{}); err == nil {
		t.Fatal("an empty prompt was accepted")
	}
}

func TestTheRunnerNeedsItsOwnBinaryAndSocket(t *testing.T) {
	r := &Runner{WorkRoot: t.TempDir()}
	a := Agent{Name: "c", Command: "/usr/bin/true", Locality: LocalityHosted, Flavour: FlavourClaude}
	for _, req := range []RunRequest{
		{Prompt: "x", Socket: "/s"},                    // no MCPCommand
		{Prompt: "x", MCPCommand: "/usr/bin/opslifyd"}, // no Socket
	} {
		if err := r.Run(context.Background(), a, req, &recordingSink{}); err == nil {
			t.Fatalf("a run was accepted with an incomplete request: %+v", req)
		}
	}
}

// --- streaming --------------------------------------------------------------------

type recordingSink struct {
	out  strings.Builder
	errs strings.Builder
	exit *int
}

func (s *recordingSink) Chunk(stream string, b []byte) error {
	if stream == "stderr" {
		s.errs.Write(b)
	} else {
		s.out.Write(b)
	}
	return nil
}

func (s *recordingSink) Exit(code int) error { s.exit = &code; return nil }

// TestRunStreamsBothStreamsAndTheExitCode uses /bin/sh as a stand-in agent: the
// recipe would not produce this argv, but the streaming, environment and exit
// handling around it are what this exercises.
func TestRunStreamsBothStreamsAndTheExitCode(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fake-agent")
	if err := os.WriteFile(script,
		[]byte("#!/bin/sh\necho to-stdout\necho to-stderr >&2\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &Runner{WorkRoot: t.TempDir()}
	a := Agent{Name: "fake", Command: script, Locality: LocalityLocal, Flavour: FlavourCodex}
	sink := &recordingSink{}
	if err := r.Run(context.Background(), a, testReq(), sink); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(sink.out.String(), "to-stdout") {
		t.Errorf("stdout = %q", sink.out.String())
	}
	if !strings.Contains(sink.errs.String(), "to-stderr") {
		t.Errorf("stderr = %q", sink.errs.String())
	}
	if sink.exit == nil || *sink.exit != 7 {
		t.Errorf("exit = %v, want 7 — a non-zero agent is a task that did not finish", sink.exit)
	}
}

// TestTheRunDirectoryIsRemoved: it holds the daemon's socket path.
func TestTheRunDirectoryIsRemoved(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(t.TempDir(), "noop")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &Runner{WorkRoot: root}
	a := Agent{Name: "n", Command: script, Locality: LocalityLocal, Flavour: FlavourCodex}
	if err := r.Run(context.Background(), a, testReq(), &recordingSink{}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%d run director(ies) left behind: %v", len(entries), entries)
	}
}

// TestTheAgentInheritsOnlyAllowlistedEnvironment: a driven agent is third-party
// code, and the daemon's environment may hold anything the operator put there.
func TestTheAgentInheritsOnlyAllowlistedEnvironment(t *testing.T) {
	t.Setenv("OPSLIFY_TEST_SECRET_SAUCE", "leaked")
	t.Setenv("OPSLIFY_TEST_ALLOWED", "fine")

	out := filepath.Join(t.TempDir(), "env.txt")
	script := filepath.Join(t.TempDir(), "dump-env")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nenv > "+out+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &Runner{WorkRoot: t.TempDir()}
	a := Agent{
		Name: "e", Command: script, Locality: LocalityLocal, Flavour: FlavourCodex,
		EnvAllow: []string{"OPSLIFY_TEST_ALLOWED"},
	}
	if err := r.Run(context.Background(), a, testReq(), &recordingSink{}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "OPSLIFY_TEST_SECRET_SAUCE") {
		t.Error("a non-allowlisted variable reached the agent")
	}
	if !strings.Contains(string(b), "OPSLIFY_TEST_ALLOWED") {
		t.Error("the allowlisted variable did not reach the agent")
	}
}

// TestTheRecipeIgnoresTheProbeArgs.
//
// a.Args make the command speak MCP for the registry's handshake — `mcp serve`
// for Claude Code, `mcp` for Codex. Prepending them to a run produces a
// different invocation entirely: the first version of this did, and
// `claude mcp serve --print ... <prompt>` answered a question about MCP instead
// of doing the work. Probing and driving are two modes of one binary.
func TestTheRecipeIgnoresTheProbeArgs(t *testing.T) {
	for _, f := range []Flavour{FlavourClaude, FlavourQwen, FlavourCodex} {
		t.Run(string(f), func(t *testing.T) {
			a := Agent{
				Name: "a", Command: "/usr/bin/x", Locality: LocalityLocal, Flavour: f,
				Args: []string{"mcp", "serve", "--probe-only"},
			}
			argv, _ := mustRecipe(t, a)
			for _, probeArg := range []string{"serve", "--probe-only"} {
				if has(argv, probeArg) {
					t.Errorf("%s: the probe argument %q leaked into the run argv: %v",
						f, probeArg, argv)
				}
			}
			// "mcp" is the one that actually bit, and for codex "exec" is legitimate
			// while "mcp" is not.
			if has(argv, "mcp") {
				t.Errorf("%s: the probe argument \"mcp\" leaked into the run argv: %v", f, argv)
			}
		})
	}
}

// --- the denylist checks itself --------------------------------------------------

// TestUnconfinedToolsNamesWhatWouldSurvive.
//
// The denylist is a blocklist and blocklists rot. This is the mechanism that
// makes the rot visible: the handshake at `agent add` reports what a command
// actually exposes, and anything there that is neither opslify's nor denied is
// something a driven run would still be holding.
func TestUnconfinedToolsNamesWhatWouldSurvive(t *testing.T) {
	probed := []string{
		"Bash", "Read", "Write", // denied
		"mcp__opslifyd__opslify_exec",    // ours
		"SomeBrandNewTool", "AnotherOne", // neither
	}
	got := UnconfinedTools(probed)
	if len(got) != 2 || !has(got, "SomeBrandNewTool") || !has(got, "AnotherOne") {
		t.Fatalf("UnconfinedTools = %v, want exactly the two unknown tools", got)
	}
}

func TestUnconfinedToolsIsSilentWhenEverythingIsCovered(t *testing.T) {
	probed := append([]string{}, hostTools...)
	probed = append(probed, opslifyTools...)
	if got := UnconfinedTools(probed); len(got) != 0 {
		t.Fatalf("UnconfinedTools = %v, want none", got)
	}
}

// TestTheDenylistCoversTheDelegationTools is the specific gap that shipped: the
// first version denied Bash and the file tools and left Agent, Task and Skill
// available. A subagent is a fresh session with its own tools, so an agent that
// can spawn one can spawn its way out of every restriction placed on it.
func TestTheDenylistCoversTheDelegationTools(t *testing.T) {
	for _, tool := range []string{
		"Agent", "Task", "Skill", "ToolSearch",
		"CronCreate", "ScheduleWakeup", "SendMessage", "RemoteTrigger",
		"EnterWorktree", "BashOutput", "KillShell",
	} {
		if !has(hostTools, tool) {
			t.Errorf("%s is not denied; a driven agent would keep it", tool)
		}
	}
}

// TestEveryDeniedToolReachesTheClaudeArgv: the list is only a boundary if it is
// actually passed.
func TestEveryDeniedToolReachesTheClaudeArgv(t *testing.T) {
	a := Agent{Name: "c", Command: "/usr/bin/claude", Locality: LocalityHosted, Flavour: FlavourClaude}
	argv, _ := mustRecipe(t, a)
	for _, tool := range hostTools {
		if !has(argv, tool) {
			t.Errorf("%s is on the denylist but never reaches --disallowedTools", tool)
		}
	}
}
