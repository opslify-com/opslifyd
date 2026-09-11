package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Store persists agent records and the per-scope bindings.
type Store interface {
	SaveAgent(a Agent) error
	LoadAgent(name string) (Agent, bool, error)
	ListAgents() ([]Agent, error)
	DeleteAgent(name string) error

	// SaveBinding records which agent serves a scope. An empty scopeKey is the
	// FALLBACK binding used when no more specific one exists.
	SaveBinding(scopeKey, agentName string) error
	LoadBindings() (map[string]string, error)
	DeleteBinding(scopeKey string) error
}

// FallbackScope is the scope key of the default binding. Spelled explicitly
// rather than left as an empty string, so a record's filename is never
// separator-adjacent.
const FallbackScope = "_fallback"

// ScopeKey renders a project/environment as one binding key.
func ScopeKey(projectID, environmentID string) string {
	switch {
	case environmentID != "":
		return environmentID
	case projectID != "":
		return projectID
	default:
		return FallbackScope
	}
}

// Prober checks that a registered command actually speaks MCP.
//
// A seam so the registry is testable without spawning processes, and so the
// handshake can be exercised against a deliberately broken command.
type Prober interface {
	// Probe runs the command and completes an MCP handshake, returning the tool
	// names it exposes.
	Probe(ctx context.Context, a Agent) ([]string, error)
}

// Registry is the operator-facing surface: register agents, bind them per scope,
// and resolve the one that serves a session.
type Registry struct {
	store  Store
	prober Prober
	log    *slog.Logger
}

// NewRegistry wires the registry. prober may be nil, in which case Add skips the
// handshake — acceptable only in tests, since the whole point of probing at bind
// time is that an operator learns now rather than at the first task.
func NewRegistry(store Store, prober Prober, log *slog.Logger) (*Registry, error) {
	if store == nil {
		return nil, fmt.Errorf("agents: a store is required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Registry{store: store, prober: prober, log: log}, nil
}

// Add registers an agent after PROVING it can serve.
//
// The handshake runs here, at bind time, because the alternative is discovering
// a typo'd command or a non-MCP binary at the first task — by which point an
// operator is debugging their work instead of their configuration.
func (r *Registry) Add(ctx context.Context, a Agent) ([]string, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if _, found, err := r.store.LoadAgent(a.Name); err != nil {
		return nil, err
	} else if found {
		return nil, fmt.Errorf("%w: agent %q (use `agent rm` then re-add, or pick another name)", ErrExists, a.Name)
	}
	var tools []string
	if r.prober != nil {
		var err error
		tools, err = r.prober.Probe(ctx, a)
		if err != nil {
			return nil, fmt.Errorf("%w: agent %q did not complete an MCP handshake: %v", ErrUnusable, a.Name, err)
		}
	}
	if err := r.store.SaveAgent(a); err != nil {
		return nil, err
	}
	return tools, nil
}

// Test probes a definition WITHOUT registering it.
func (r *Registry) Test(ctx context.Context, a Agent) ([]string, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if r.prober == nil {
		return nil, fmt.Errorf("%w: no prober configured", ErrUnusable)
	}
	tools, err := r.prober.Probe(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnusable, err)
	}
	return tools, nil
}

// List returns every registered agent, name-sorted.
func (r *Registry) List() ([]Agent, error) { return r.store.ListAgents() }

// Bindings returns the scope→agent map.
func (r *Registry) Bindings() (map[string]string, error) { return r.store.LoadBindings() }

// Use binds an agent to a scope.
//
// It does NOT touch sessions already running. A session recorded which agent it
// ran under at seq 0; re-pointing it mid-flight would make that record a lie, and
// the audit trail is worth more than the convenience.
func (r *Registry) Use(projectID, environmentID, agentName string) error {
	if _, found, err := r.store.LoadAgent(agentName); err != nil {
		return err
	} else if !found {
		return fmt.Errorf("%w: agent %q is not registered", ErrNotFound, agentName)
	}
	return r.store.SaveBinding(ScopeKey(projectID, environmentID), agentName)
}

// Unbind removes a scope's binding, so it falls back again.
func (r *Registry) Unbind(projectID, environmentID string) error {
	return r.store.DeleteBinding(ScopeKey(projectID, environmentID))
}

// Remove deletes an agent, refusing while a scope still binds it.
//
// Refusing rather than cascading: silently unbinding scopes would leave sessions
// starting under a different agent than the operator last chose, with nothing
// recording why.
func (r *Registry) Remove(name string) error {
	if _, found, err := r.store.LoadAgent(name); err != nil {
		return err
	} else if !found {
		return fmt.Errorf("%w: agent %q", ErrNotFound, name)
	}
	bindings, err := r.store.LoadBindings()
	if err != nil {
		return err
	}
	var bound []string
	for scope, agent := range bindings {
		if agent == name {
			bound = append(bound, scope)
		}
	}
	if len(bound) > 0 {
		sort.Strings(bound)
		return fmt.Errorf("%w: agent %q is bound to %s — unbind those first", ErrExists, name, strings.Join(bound, ", "))
	}
	return r.store.DeleteAgent(name)
}

// ForScope resolves the agent that serves a scope: the environment binding, then
// the project binding, then the fallback.
//
// Most specific wins, the same shape as the policy layers and the connection
// scoping — one scoping model across the product rather than three.
//
// A scope with no binding and no fallback returns ErrNotFound. That is NOT fatal
// to a session: opslify ships no model, so a daemon with no agent registered is
// a perfectly valid state for someone using the CLI directly. The caller decides.
func (r *Registry) ForScope(projectID, environmentID string) (Agent, error) {
	bindings, err := r.store.LoadBindings()
	if err != nil {
		return Agent{}, err
	}
	for _, key := range []string{
		ScopeKey(projectID, environmentID),
		ScopeKey(projectID, ""),
		FallbackScope,
	} {
		name, ok := bindings[key]
		if !ok {
			continue
		}
		a, found, err := r.store.LoadAgent(name)
		if err != nil {
			return Agent{}, err
		}
		if !found {
			// A binding pointing at a removed agent. Surface it and keep looking:
			// falling through to a broader binding is better than refusing, and a
			// silent skip would leave an operator wondering why their choice is
			// ignored.
			r.log.Warn("agents: binding points at an agent that no longer exists; falling through",
				"scope", key, "agent", name)
			continue
		}
		return a, nil
	}
	return Agent{}, fmt.Errorf("%w: no agent bound for %s/%s and no fallback", ErrNotFound, projectID, environmentID)
}

// --- file store ---------------------------------------------------------------

type fileStore struct {
	agentDir string
	bindPath string
	log      *slog.Logger
}

// NewFileStore returns a Store rooted at dir, created 0700: an agent record
// names local binaries and arguments, which describe a host's shape.
func NewFileStore(dir string) (Store, error) {
	agentDir := filepath.Join(dir, "agents")
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		return nil, fmt.Errorf("agents: create state dir %s: %w", agentDir, err)
	}
	// MkdirAll does not tighten an existing directory. See the same note in
	// internal/change: a state dir left loose by an earlier release stays loose.
	if err := os.Chmod(agentDir, 0o700); err != nil {
		return nil, fmt.Errorf("agents: secure state dir %s: %w", agentDir, err)
	}
	return &fileStore{agentDir: agentDir, bindPath: filepath.Join(dir, "agent-bindings.json"), log: slog.Default()}, nil
}

// safeRecordID is the last line of defence before filepath.Join. Callers
// validate at the trust boundary; this refuses anything that could still address
// a file outside the record directory.
func safeRecordID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty agent id", ErrInvalidInput)
	}
	if id != filepath.Base(id) || id == "." || id == ".." ||
		strings.ContainsAny(id, `/\`+"\x00") {
		return fmt.Errorf("%w: unsafe agent id %q", ErrInvalidInput, id)
	}
	return nil
}

func (s *fileStore) agentPath(name string) (string, error) {
	if err := safeRecordID(name); err != nil {
		return "", err
	}
	return filepath.Join(s.agentDir, name+".json"), nil
}

func writeAtomic(path string, v any, what string) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("agents: marshal %s: %w", what, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("agents: write %s: %w", what, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("agents: commit %s: %w", what, err)
	}
	return nil
}

func (s *fileStore) SaveAgent(a Agent) error {
	if err := a.Validate(); err != nil {
		return err
	}
	p, err := s.agentPath(a.Name)
	if err != nil {
		return err
	}
	return writeAtomic(p, a, "agent "+a.Name)
}

func (s *fileStore) LoadAgent(name string) (Agent, bool, error) {
	p, err := s.agentPath(name)
	if err != nil {
		return Agent{}, false, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Agent{}, false, nil
		}
		return Agent{}, false, fmt.Errorf("agents: read %s: %w", name, err)
	}
	var a Agent
	if err := json.Unmarshal(b, &a); err != nil {
		return Agent{}, false, fmt.Errorf("agents: parse %s: %w", name, err)
	}
	return a, true, nil
}

func (s *fileStore) ListAgents() ([]Agent, error) {
	entries, err := os.ReadDir(s.agentDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("agents: read state dir: %w", err)
	}
	var out []Agent
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(s.agentDir, e.Name()))
		if rerr != nil {
			s.log.Warn("agents: skipping unreadable record", "file", e.Name(), "err", rerr)
			continue
		}
		var a Agent
		if jerr := json.Unmarshal(b, &a); jerr != nil {
			// Surfaced, not silent: an operator would otherwise simply stop seeing
			// an agent they still have on disk.
			s.log.Warn("agents: skipping unparseable record — it will not appear in listings",
				"file", e.Name(), "err", jerr)
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *fileStore) DeleteAgent(name string) error {
	p, err := s.agentPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("agents: delete %s: %w", name, err)
	}
	return nil
}

func (s *fileStore) LoadBindings() (map[string]string, error) {
	b, err := os.ReadFile(s.bindPath)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("agents: read bindings: %w", err)
	}
	out := map[string]string{}
	if err := json.Unmarshal(b, &out); err != nil {
		// Bindings are ONE file, so a parse failure is not survivable the way a
		// single corrupt agent record is: guessing an empty map would silently
		// switch every scope to the fallback, or to nothing.
		return nil, fmt.Errorf("agents: parse bindings: %w", err)
	}
	return out, nil
}

func (s *fileStore) SaveBinding(scopeKey, agentName string) error {
	if err := safeRecordID(scopeKey); err != nil {
		return err
	}
	bindings, err := s.LoadBindings()
	if err != nil {
		return err
	}
	bindings[scopeKey] = agentName
	return writeAtomic(s.bindPath, bindings, "agent bindings")
}

func (s *fileStore) DeleteBinding(scopeKey string) error {
	bindings, err := s.LoadBindings()
	if err != nil {
		return err
	}
	if _, ok := bindings[scopeKey]; !ok {
		return fmt.Errorf("%w: no binding for scope %q", ErrNotFound, scopeKey)
	}
	delete(bindings, scopeKey)
	return writeAtomic(s.bindPath, bindings, "agent bindings")
}
