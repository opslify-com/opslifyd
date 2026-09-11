package agents

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The catalogue is how an agent gets registered from the cockpit without the
// browser ever naming a command.
//
// `agent add` takes a path and PROBES it, which runs that command on the host.
// That is why POST /v1/agents is not on the tower's allowlist: admitting it would
// make the launch token the only thing between a web page and host code
// execution. But "you must use the CLI" is a bad answer to "how do I connect
// Claude", and an operator who cannot see their agents in the UI does not have an
// agent surface at all.
//
// So the browser picks an ENTRY, not a path. The candidate locations live here,
// in the daemon, and the daemon resolves and probes one of them. The set of
// commands that can ever run is fixed at compile time; a request can only choose
// among them.

// CatalogueEntry is one agent the daemon knows how to set up.
type CatalogueEntry struct {
	// ID is what a request names. Stable, lowercase.
	ID string `json:"id"`
	// Name is the default registry name, which an operator may override.
	Name        string  `json:"name"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Flavour     Flavour `json:"flavour"`
	// Locality is what this agent does with prompts, declared honestly up front
	// rather than left to the operator to guess.
	Locality Locality `json:"locality"`
	// DefaultModel is a hint, editable at install time.
	DefaultModel string `json:"default_model,omitempty"`
	// ModelHelp tells an operator where the model names come from.
	ModelHelp string `json:"model_help,omitempty"`
	// NeedsBaseURL marks an OpenAI-compatible agent: the UI asks for the endpoint,
	// because "which Ollama" is a question only the operator can answer.
	NeedsBaseURL bool `json:"needs_base_url,omitempty"`
	// DefaultBaseURL is the obvious answer, offered rather than assumed.
	DefaultBaseURL string `json:"default_base_url,omitempty"`
	// BaseURLHelp explains what the endpoint is.
	BaseURLHelp string `json:"base_url_help,omitempty"`
	// EnvAllow is the minimum this agent needs to inherit to function.
	EnvAllow []string `json:"env_allow,omitempty"`
	// ProbeArgs make the command speak MCP for the registration handshake. They
	// are NOT the arguments used to drive it — see recipe().
	ProbeArgs []string `json:"-"`
	// ServesMCP says whether this command can act as an MCP SERVER, which is what
	// the F8.5 handshake proves.
	//
	// The two directions are opposite and conflating them was a real bug: F8.5
	// registers an agent that OPSLIFY CALLS, and proves it by completing a
	// handshake. F8.9 registers a CLI that opslify DRIVES, which calls opslify —
	// it need not serve MCP at all. Claude Code satisfies both only because
	// `claude mcp serve` happens to exist. Qwen Code does not: `qwen mcp` is its
	// server-management subcommand and printing usage text to a handshake fails
	// with "invalid character 'U'", which is a confusing way to learn that the
	// question was wrong.
	ServesMCP bool `json:"serves_mcp"`
	// VerifyArgs run the command cheaply to prove it works, for entries that do
	// not serve MCP. Exit status only; output is not parsed.
	VerifyArgs []string `json:"-"`

	// candidates are the absolute paths tried, in order. Never supplied by a
	// caller: this is the whole point of the catalogue.
	candidates []string

	// Detected paths are filled in per-host by Catalogue().
	Found bool   `json:"found"`
	Path  string `json:"path,omitempty"`
}

// catalogue is the compile-time set. Adding one is a code change, deliberately.
var catalogue = []CatalogueEntry{
	{
		ID: "claude", Name: "claude", Title: "Claude Code",
		Description: "Anthropic's CLI. Uses your existing Claude subscription or API key — " +
			"opslify never sees either; authentication stays inside Claude Code.",
		Flavour: FlavourClaude, Locality: LocalityHosted,
		DefaultModel: "claude-opus-5",
		ModelHelp:    "any model your Claude Code login can reach, e.g. claude-opus-5 or claude-sonnet-5",
		ServesMCP:    true,
		ProbeArgs:    []string{"mcp", "serve"},
		VerifyArgs:   []string{"--version"},
		candidates: []string{
			"/usr/local/bin/claude", "/usr/bin/claude",
			"/opt/homebrew/bin/claude",
		},
	},
	{
		ID: "qwen", Name: "qwen", Title: "Qwen Code (local, via Ollama)",
		Description: "Runs against a model served by Ollama on this host. Prompts and command " +
			"output stay on this machine — nothing is sent to a provider.",
		Flavour: FlavourQwen, Locality: LocalityLocal,
		DefaultModel: "qwen3-coder:30b",
		ModelHelp:    "an Ollama model name — `ollama list` shows what is pulled",
		// Qwen Code reaches Ollama through an OpenAI-compatible endpoint, which it
		// finds through these. Allowlisted rather than inherited wholesale: a
		// registered command is third-party code.
		EnvAllow: []string{"OPENAI_BASE_URL", "OPENAI_API_KEY", "OLLAMA_HOST", "HOME", "PATH"},
		// Qwen Code consumes MCP; it does not serve it. Verified by running it.
		ServesMCP:  false,
		VerifyArgs: []string{"--version"},
		// Ollama speaks the OpenAI protocol at /v1, which is how a local model is
		// reached without a provider-specific client. Any compatible server works:
		// LM Studio, vLLM, a gateway.
		NeedsBaseURL:   true,
		DefaultBaseURL: "http://localhost:11434/v1",
		BaseURLHelp: "any OpenAI-compatible endpoint. Ollama serves one at " +
			"http://localhost:11434/v1 — change the host if it runs elsewhere",
		candidates: []string{
			"/usr/local/bin/qwen", "/usr/bin/qwen",
			"~/.local/bin/qwen", "~/.qwen/bin/qwen",
		},
	},
	{
		ID: "codex", Name: "codex", Title: "OpenAI Codex",
		Description: "OpenAI's CLI. Uses your existing Codex login; opslify never sees the credential.",
		Flavour:     FlavourCodex, Locality: LocalityHosted,
		DefaultModel: "",
		ModelHelp:    "leave blank to use whatever your Codex login defaults to",
		ServesMCP:    false,
		VerifyArgs:   []string{"--version"},
		candidates: []string{
			"/usr/local/bin/codex", "/usr/bin/codex", "/opt/homebrew/bin/codex",
		},
	},
}

// Catalogue returns the known agents with per-host detection filled in.
//
// Detection is reported rather than filtered: an operator whose Claude Code is
// installed somewhere unusual needs to be told "not found here" and given the
// CLI command, not shown an empty list that reads as "not supported".
func Catalogue() []CatalogueEntry {
	out := make([]CatalogueEntry, 0, len(catalogue))
	for _, e := range catalogue {
		e.Path, e.Found = resolveCandidate(e.candidates)
		e.candidates = nil // never leave the host's filesystem layout on the wire
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		// Found ones first, then alphabetical: the list is a chooser, and what is
		// actually installed is what an operator wants at the top.
		if out[i].Found != out[j].Found {
			return out[i].Found
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// CatalogueEntryByID returns the compile-time entry, with its candidates intact.
func CatalogueEntryByID(id string) (CatalogueEntry, bool) {
	for _, e := range catalogue {
		if e.ID == id {
			return e, true
		}
	}
	return CatalogueEntry{}, false
}

// Resolve turns a catalogue entry into the Agent that will be probed and stored.
//
// The command comes from the ENTRY, never from the caller. A request may choose
// the name and the model hint — neither of which is executed — and nothing else.
func (e CatalogueEntry) Resolve(name, model string) (Agent, bool) {
	return e.ResolveWith(name, model, "", "")
}

// ResolveWith adds the provider endpoint and an optional vault ref for its key.
// Neither is executed, so both may come from a caller.
func (e CatalogueEntry) ResolveWith(name, model, baseURL, apiKeyRef string) (Agent, bool) {
	path, ok := resolveCandidate(e.candidates)
	if !ok {
		return Agent{}, false
	}
	if name == "" {
		name = e.Name
	}
	if model == "" {
		model = e.DefaultModel
	}
	if baseURL == "" {
		baseURL = e.DefaultBaseURL
	}
	return Agent{
		Name: name, Command: path, Args: e.ProbeArgs,
		ModelHint: model, Locality: e.Locality,
		EnvAllow: e.EnvAllow, Description: e.Title,
		Flavour: e.Flavour, BaseURL: baseURL, APIKeyRef: apiKeyRef,
	}, true
}

// resolveCandidate returns the first candidate that exists and is executable.
//
// It does NOT fall back to a PATH lookup: PATH resolution would let a different
// binary answer tomorrow than the one the operator registered, which is the same
// reason Agent.Command must be absolute.
func resolveCandidate(candidates []string) (string, bool) {
	home, _ := os.UserHomeDir()
	for _, c := range candidates {
		p := c
		if len(p) > 1 && p[0] == '~' && home != "" {
			p = filepath.Join(home, p[1:])
		}
		if !filepath.IsAbs(p) {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
			continue
		}
		return p, true
	}
	return "", false
}

// VerifyRuns starts the command with its verification arguments and waits for a
// clean exit. Output is discarded: this proves the binary is present and runs,
// not that it does anything in particular.
func VerifyRuns(ctx context.Context, a Agent, args []string) error {
	if len(args) == 0 {
		args = []string{"--version"}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.Command, args...)
	cmd.Env = a.Env(os.Environ())
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		if snippet != "" {
			return fmt.Errorf("%s %s: %v: %s", a.Command, strings.Join(args, " "), err, snippet)
		}
		return fmt.Errorf("%s %s: %v", a.Command, strings.Join(args, " "), err)
	}
	return nil
}
