// Package agents is the F8.5 registry: a record of which MCP-speaking command
// acts as the agent for a project and environment.
//
// opslify ships no model. The operator binds Claude Code, a local Qwen via
// Ollama, Codex, or a command of their own, and the choice is visible everywhere
// it matters.
//
// THE REGISTRY IS NOT A PRIVILEGE DIAL. This is the single most important thing
// about this package. Which agent is bound changes three things — cost, latency,
// and WHERE PROMPTS GO — and never what the agent may do. The sandbox boundary,
// the connections, the policy gates and the audit trail are identical whichever
// agent is bound. If some future feature makes a binding grant capability, it
// belongs in policy (F8.7) behind an approval, not here.
package agents

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ErrNotFound is returned for an unknown agent or binding.
var ErrNotFound = errors.New("agents: not found")

// ErrExists is returned when an agent name is already taken.
var ErrExists = errors.New("agents: already exists")

// ErrInvalidInput marks a bad record: an unusable name, a command that is not
// absolute, an env key outside the allowlist rules.
var ErrInvalidInput = errors.New("agents: invalid input")

// ErrUnusable marks an agent that cannot serve — it failed the MCP handshake, or
// its command is missing. Reported at BIND time so an operator learns now rather
// than at the first task.
var ErrUnusable = errors.New("agents: unusable")

// Locality says whether prompts leave this host.
//
// It is a first-class field rather than a comment because it is the disclosure
// an operator actually needs: a hosted agent sends command output off-host, and
// a local one does not. Recording it means a Change can be read later and the
// question "did this estate's output leave the building?" has an answer.
type Locality string

const (
	// LocalityLocal means the command runs on this host and prompts do not leave
	// it (Ollama, llama.cpp, a local script).
	LocalityLocal Locality = "local"
	// LocalityHosted means the command talks to a provider, so command output
	// leaves this host.
	LocalityHosted Locality = "hosted"
	// LocalityUnknown is the honest default when the operator did not say. It is
	// NOT treated as local: assuming the safer-sounding answer about someone
	// else's data flow would be a lie by default.
	LocalityUnknown Locality = "unknown"
)

// Valid reports whether l is a known locality.
func (l Locality) Valid() bool {
	switch l {
	case LocalityLocal, LocalityHosted, LocalityUnknown:
		return true
	}
	return false
}

// Discloses renders the disclosure shown in the CLI and the cockpit.
func (l Locality) Discloses() string {
	switch l {
	case LocalityLocal:
		return "prompts and command output stay on this host"
	case LocalityHosted:
		return "command output is sent off-host to the provider"
	default:
		return "where prompts go is UNDECLARED — treat as off-host until confirmed"
	}
}

// Agent is a registered MCP-speaking command.
//
// It holds NO credential. A provider API key is a secret ref used by that
// command's own configuration, never injected by opslify into its environment —
// so an agent record is not a place a key can end up.
type Agent struct {
	// Name is the operator-facing identity, unique in the registry.
	Name string `json:"name"`
	// Command is the executable. It must be an ABSOLUTE path: resolving through
	// PATH would let a different binary answer tomorrow than the one the operator
	// tested at bind time, silently.
	Command string `json:"command"`
	// Args are fixed arguments passed on every invocation.
	Args []string `json:"args,omitempty"`
	// ModelHint records which model this command is expected to drive. It is a
	// HINT: the command decides, and we record what the operator declared so a
	// Change can name it. It never affects behaviour.
	ModelHint string `json:"model_hint,omitempty"`
	// Locality is the prompt-disclosure declaration.
	Locality Locality `json:"locality"`
	// EnvAllow is the ALLOWLIST of environment variable names this command
	// inherits from the daemon. Empty means it inherits nothing but the minimum.
	//
	// An allowlist because the daemon's own environment may hold anything an
	// operator put there, and a registered command is third-party code by
	// definition — an agent that inherited the daemon's environment wholesale
	// would be handed whatever happened to be in it.
	EnvAllow []string `json:"env_allow,omitempty"`
	// Description is free text for the operator's own benefit.
	Description string `json:"description,omitempty"`
}

// nameRe bounds an agent name to one safe identifier/filename segment, for the
// same reason project and connection names are bounded: it becomes a record id
// and appears in audit output.
var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// envKeyRe bounds an allowlisted environment variable name.
var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// deniedEnvKeys are never allowlistable, whatever the operator asks for.
//
// These are the variables that would let a registered command reach the daemon's
// own trust: its socket, its state, its vault key path. An operator can plausibly
// want to pass HOME or a proxy setting to an agent; nobody has a legitimate
// reason to hand it the daemon's control socket, and a typo should not be able to.
var deniedEnvKeys = map[string]string{
	"OPSLIFY_SOCKET":                     "the daemon control socket",
	"OPSLIFYD_SOCKET":                    "the daemon control socket",
	"OPSLIFY_VAULT_KEY":                  "the vault master key path",
	"OPSLIFY_LAUNCH_TOKEN":               "the UI launch token",
	"SSH_AUTH_SOCK":                      "a session's ssh agent socket (a signing oracle)",
	"KUBECONFIG":                         "a session's generated kubeconfig",
	"AWS_CONTAINER_CREDENTIALS_FULL_URI": "a session's credential endpoint",
	"AWS_CONTAINER_AUTHORIZATION_TOKEN":  "a session's credential endpoint token",
}

// Validate checks a record at the trust boundary.
func (a Agent) Validate() error {
	if !nameRe.MatchString(a.Name) {
		return fmt.Errorf("%w: agent name %q must be lowercase alphanumeric with dashes (1-40 chars)", ErrInvalidInput, a.Name)
	}
	if a.Command == "" {
		return fmt.Errorf("%w: agent %q needs a command", ErrInvalidInput, a.Name)
	}
	if !strings.HasPrefix(a.Command, "/") {
		// PATH resolution would let a different binary answer tomorrow than the one
		// the operator tested at bind time — a silent substitution of the component
		// that reads their whole estate.
		return fmt.Errorf("%w: agent %q command %q must be an absolute path, so the binary that answers cannot change under you",
			ErrInvalidInput, a.Name, a.Command)
	}
	if strings.ContainsAny(a.Command, "\x00\n\r") {
		return fmt.Errorf("%w: agent %q command contains a control character", ErrInvalidInput, a.Name)
	}
	for _, arg := range a.Args {
		if strings.ContainsRune(arg, 0) {
			return fmt.Errorf("%w: agent %q has an argument containing NUL", ErrInvalidInput, a.Name)
		}
	}
	if !a.Locality.Valid() {
		return fmt.Errorf("%w: agent %q locality %q must be local, hosted or unknown", ErrInvalidInput, a.Name, a.Locality)
	}
	if len(a.ModelHint) > 128 {
		return fmt.Errorf("%w: agent %q model hint is too long", ErrInvalidInput, a.Name)
	}
	if strings.ContainsAny(a.ModelHint, "\x00\n\r") {
		// It is written into the trace and shown in the cockpit.
		return fmt.Errorf("%w: agent %q model hint contains a control character", ErrInvalidInput, a.Name)
	}
	for _, key := range a.EnvAllow {
		if !envKeyRe.MatchString(key) {
			return fmt.Errorf("%w: agent %q env_allow entry %q is not a valid variable name", ErrInvalidInput, a.Name, key)
		}
		if why, denied := deniedEnvKeys[key]; denied {
			return fmt.Errorf("%w: agent %q may not inherit %s (%s)", ErrInvalidInput, a.Name, key, why)
		}
	}
	return nil
}

// Env builds the environment for the command from a base environment, keeping
// ONLY allowlisted keys.
//
// The base is the daemon's own environment. Nothing outside the allowlist
// crosses, which is the point: a registered command is third-party code, and the
// daemon's environment may hold anything an operator put there.
func (a Agent) Env(base []string) []string {
	allow := make(map[string]bool, len(a.EnvAllow))
	for _, k := range a.EnvAllow {
		if _, denied := deniedEnvKeys[k]; denied {
			// Defence in code: Validate already refuses these, but this function must
			// not be the place that passes one through if a record was written by an
			// older release or edited by hand.
			continue
		}
		allow[k] = true
	}
	out := make([]string, 0, len(allow))
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || !allow[k] {
			continue
		}
		out = append(out, kv)
	}
	sort.Strings(out)
	return out
}

// TraceFields is what session.start and a Change record about the bound agent.
//
// Identity and the model hint, so a decision is attributable to a model — plus
// locality, so the disclosure is in the record rather than only in a UI an
// auditor may never have seen. No command line: an operator's argument list can
// carry local paths and account identifiers, and the agent's IDENTITY is what
// makes a decision attributable.
func (a Agent) TraceFields() map[string]any {
	return map[string]any{
		"agent":          a.Name,
		"agent_model":    a.ModelHint,
		"agent_locality": string(a.Locality),
	}
}
