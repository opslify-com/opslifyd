package project

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// Sandboxes is the live-sandbox seam the Service consults before it removes a
// record. It is satisfied by *session.Manager; declaring it HERE (rather than
// importing session) keeps the dependency one-directional and lets removals be
// unit-tested with a fake.
type Sandboxes interface {
	// SessionsIn returns the ids of LIVE sessions scoped to projectID and, when
	// environmentID is non-empty, to that environment.
	SessionsIn(projectID, environmentID string) []string
	// Destroy tears one session down (container, egress rules, record).
	Destroy(ctx context.Context, id string) error
	// InFlightIn reports creates that have resolved this scope but not yet
	// registered — a sandbox is being built and is NOT yet visible to SessionsIn.
	// A removal must refuse while this is non-zero, or it deletes the governing
	// record out from under a sandbox that lands a moment later.
	InFlightIn(projectID, environmentID string) int
}

// Scope is a resolved (project, environment) pair plus the layered policy a
// session created in it runs under.
type Scope struct {
	Project     Project
	Environment Environment
	// Resolved is the daemon ⊕ project ⊕ environment policy: the TRUSTED baseline
	// a session in this scope starts from. A workspace policy narrows FURTHER over
	// it (F4.1) and can never widen it.
	Resolved policy.Resolved
}

// Base is the trusted policy model the session's workspace narrowing starts from
// and the enforcement floors (tier/ttl) are derived from.
func (s Scope) Base() policy.Policy { return s.Resolved.Policy }

// Clamps is the layer-tagged record of every widening attempt the project or
// environment layer made and had clamped.
func (s Scope) Clamps() []string { return s.Resolved.Notes }

// Options wires a Service. Store is required; the rest default.
type Options struct {
	// Store persists the records. Required.
	Store Store
	// Clock stamps record creation; nil => time.Now.
	Clock func() time.Time
	// Logger receives clamp/removal logs; nil => slog default.
	Logger *slog.Logger
	// Sandboxes is the live-sandbox seam used to order removals. nil means "no
	// sandboxes are known", which is only correct in tests — the daemon wires the
	// session Manager (see SetSandboxes, which completes the mutual reference the
	// constructor cannot).
	Sandboxes Sandboxes
}

// Service owns the project/environment records: validation, the ≥1-environment
// invariant, name uniqueness within a project, scope resolution, and ordered,
// fail-closed removal.
type Service struct {
	mu    sync.Mutex
	store Store
	now   func() time.Time
	log   *slog.Logger

	// removing holds environment ids whose removal has been CLAIMED but not yet
	// completed. The claim is taken under mu together with the >=1 sibling check,
	// so two concurrent removals cannot both decide they may proceed — which is
	// what makes a refusal side-effect-free: the loser refuses BEFORE it tears
	// any sandbox down. Guarded by mu.
	removing map[string]bool

	// sbMu guards sandboxes, which the composition root sets AFTER construction
	// (the Manager needs the Service and the Service needs the Manager).
	sbMu      sync.RWMutex
	sandboxes Sandboxes
}

// NewService validates options, constructs a Service, and ensures the implicit
// default project + environment exist, so a create that names neither always
// resolves (the backwards-compatibility path). Bootstrapping is idempotent.
func NewService(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("project: a Store is required")
	}
	s := &Service{
		removing:  map[string]bool{},
		store:     opts.Store,
		now:       opts.Clock,
		log:       opts.Logger,
		sandboxes: opts.Sandboxes,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if err := s.bootstrap(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetSandboxes completes the mutual reference between the Service and the session
// Manager: the Manager is constructed with the Service (it resolves a scope on
// every create), so the Service can only learn about live sandboxes afterwards.
func (s *Service) SetSandboxes(sb Sandboxes) {
	s.sbMu.Lock()
	s.sandboxes = sb
	s.sbMu.Unlock()
}

func (s *Service) liveSandboxes() Sandboxes {
	s.sbMu.RLock()
	defer s.sbMu.RUnlock()
	return s.sandboxes
}

// bootstrap creates the default project and its default environment when they are
// absent. It is called once from NewService and never overwrites an existing
// record (an operator may have edited the default project's capabilities).
func (s *Service) bootstrap() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok, err := s.store.LoadProject(DefaultProjectID)
	if err != nil {
		return err
	}
	if !ok {
		p := Project{ID: DefaultProjectID, Name: DefaultProjectID, Created: s.now()}
		if err := s.store.SaveProject(p); err != nil {
			return err
		}
	}
	_, ok, err = s.store.LoadEnvironment(DefaultEnvironmentID)
	if err != nil {
		return err
	}
	if !ok {
		e := Environment{
			ID:        DefaultEnvironmentID,
			ProjectID: DefaultProjectID,
			Name:      DefaultEnvironmentName,
			Created:   s.now(),
		}
		if err := s.store.SaveEnvironment(e); err != nil {
			return err
		}
	}
	return nil
}

// CreateProject validates and persists a project together with its
// environments. A project owns AT LEAST ONE environment, so a spec that names
// none gets the default one — an environment-less project is not representable.
// The environments are written BEFORE the project, so a crash mid-create leaves
// orphan environment records (invisible: every listing is by project) rather than
// a project that violates the ≥1 invariant.
func (s *Service) CreateProject(spec ProjectSpec) (Project, []Environment, error) {
	p, err := spec.validate()
	if err != nil {
		return Project{}, nil, err
	}
	envSpecs := spec.Environments
	if len(envSpecs) == 0 {
		envSpecs = []EnvironmentSpec{{Name: DefaultEnvironmentName}}
	}
	seen := make(map[string]struct{}, len(envSpecs))
	envs := make([]Environment, 0, len(envSpecs))
	for _, es := range envSpecs {
		e, err := es.validate(p.ID)
		if err != nil {
			return Project{}, nil, err
		}
		if _, dup := seen[e.Name]; dup {
			return Project{}, nil, fmt.Errorf("%w: environment %q is listed twice for project %q", ErrInvalidInput, e.Name, p.ID)
		}
		seen[e.Name] = struct{}{}
		envs = append(envs, e)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok, err := s.store.LoadProject(p.ID); err != nil {
		return Project{}, nil, err
	} else if ok {
		return Project{}, nil, fmt.Errorf("%w: project %q", ErrExists, p.ID)
	}
	now := s.now()
	p.Created = now
	for i := range envs {
		envs[i].Created = now
		if err := s.store.SaveEnvironment(envs[i]); err != nil {
			return Project{}, nil, err
		}
	}
	if err := s.store.SaveProject(p); err != nil {
		return Project{}, nil, err
	}
	s.log.Info("project created", "project", p.ID, "environments", len(envs))
	return p, envs, nil
}

// SetCapabilities replaces a project's role → tool map.
//
// REPLACE, not merge. A merge endpoint needs a second one to remove, and the two
// together let a caller reach a state neither of them describes; sending the
// whole desired map makes the result a function of the request alone, which is
// what makes retrying one safe.
//
// Capabilities are not a guardrail — they say which tools a project uses, and
// F8.4 routes skill packs off them while F8.2 binds connections to them. Widening
// them does not widen the policy, so this is not a Change: the gates and egress
// that a tool implies are separate edits, and those ARE classified.
func (s *Service) SetCapabilities(projectID string, caps map[string]string) (Project, error) {
	if projectID == "" {
		projectID = DefaultProjectID
	}
	clean, err := validateCapabilities(caps)
	if err != nil {
		return Project{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok, err := s.store.LoadProject(projectID)
	if err != nil {
		return Project{}, err
	}
	if !ok {
		return Project{}, fmt.Errorf("%w: project %q", ErrNotFound, projectID)
	}
	p.Capabilities = clean
	if err := s.store.SaveProject(p); err != nil {
		return Project{}, err
	}
	s.log.Info("project capabilities set", "project", p.ID, "capabilities", len(clean))
	return p, nil
}

// AddEnvironment validates and persists one environment inside an existing
// project. The name must be UNIQUE within that project: two environments with the
// same name would be two risk boundaries with one identity, which is exactly the
// ambiguity the separate-layers design exists to remove.
func (s *Service) AddEnvironment(projectID string, spec EnvironmentSpec) (Environment, error) {
	if projectID == "" {
		projectID = DefaultProjectID
	}
	if err := ValidateName("project", projectID); err != nil {
		return Environment{}, err
	}
	e, err := spec.validate(projectID)
	if err != nil {
		return Environment{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok, err := s.store.LoadProject(projectID); err != nil {
		return Environment{}, err
	} else if !ok {
		return Environment{}, fmt.Errorf("%w: project %q", ErrNotFound, projectID)
	}
	if _, ok, err := s.store.LoadEnvironment(e.ID); err != nil {
		return Environment{}, err
	} else if ok {
		return Environment{}, fmt.Errorf("%w: environment %q in project %q", ErrExists, e.Name, projectID)
	}
	e.Created = s.now()
	if err := s.store.SaveEnvironment(e); err != nil {
		return Environment{}, err
	}
	s.log.Info("environment added", "project", projectID, "environment", e.ID, "production", e.Production)
	return e, nil
}

// Projects returns every project, id-sorted.
func (s *Service) Projects() ([]Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.LoadProjects()
}

// Project returns one project with its environments.
func (s *Service) Project(id string) (Project, []Environment, error) {
	if id == "" {
		id = DefaultProjectID
	}
	if err := ValidateName("project", id); err != nil {
		return Project{}, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok, err := s.store.LoadProject(id)
	if err != nil {
		return Project{}, nil, err
	}
	if !ok {
		return Project{}, nil, fmt.Errorf("%w: project %q", ErrNotFound, id)
	}
	envs, err := s.environmentsLocked(id)
	if err != nil {
		return Project{}, nil, err
	}
	return p, envs, nil
}

// Environments returns one project's environments, id-sorted. An unknown project
// is ErrNotFound (never an empty list, which would read as "no environments").
func (s *Service) Environments(projectID string) ([]Environment, error) {
	if projectID == "" {
		projectID = DefaultProjectID
	}
	if err := ValidateName("project", projectID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok, err := s.store.LoadProject(projectID); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("%w: project %q", ErrNotFound, projectID)
	}
	return s.environmentsLocked(projectID)
}

// environmentsLocked filters the environment records by project. Callers hold mu.
func (s *Service) environmentsLocked(projectID string) ([]Environment, error) {
	all, err := s.store.LoadEnvironments()
	if err != nil {
		return nil, err
	}
	out := make([]Environment, 0, len(all))
	for _, e := range all {
		if e.ProjectID == projectID {
			out = append(out, e)
		}
	}
	return out, nil
}

// ResolveScope resolves the (project, environment) a session is being created in
// and the layered policy it runs under. Empty ids resolve to the default scope,
// so every pre-F8.1 caller keeps working and NO session is ever unscoped.
//
// environmentID accepts either the full id ("flight.staging") or the bare name
// ("staging") within projectID. An environment that belongs to a DIFFERENT
// project is refused: naming prod's environment from another project would cross
// the risk boundary the environment exists to draw.
//
// base is the daemon's trusted baseline policy (ManagerConfig.DefaultPolicy). It
// is passed in rather than held here so there is exactly one copy of the daemon
// policy in the process and no way for the two to drift.
func (s *Service) ResolveScope(base policy.Policy, projectID, environmentID string) (Scope, error) {
	if projectID == "" {
		projectID = DefaultProjectID
	}
	if err := ValidateName("project", projectID); err != nil {
		return Scope{}, err
	}

	s.mu.Lock()
	p, ok, err := s.store.LoadProject(projectID)
	if err != nil {
		s.mu.Unlock()
		return Scope{}, err
	}
	if !ok {
		s.mu.Unlock()
		return Scope{}, fmt.Errorf("%w: project %q", ErrNotFound, projectID)
	}
	env, err := s.resolveEnvironmentLocked(p, environmentID)
	s.mu.Unlock()
	if err != nil {
		return Scope{}, err
	}

	var layers []Layer
	if p.PolicyFile != "" {
		pol, err := LoadLayer("project policy_file", p.PolicyFile)
		if err != nil {
			return Scope{}, err
		}
		layers = append(layers, Layer{Name: "project " + p.ID, Policy: pol})
	}
	if env.PolicyOverlay != "" {
		pol, err := LoadLayer("environment policy_overlay", env.PolicyOverlay)
		if err != nil {
			return Scope{}, err
		}
		layers = append(layers, Layer{Name: "environment " + env.ID, Policy: pol})
	}
	resolved := ResolvePolicy(base, layers...)
	for _, clamp := range resolved.Notes {
		s.log.Warn("policy overlay clamped", "project", p.ID, "environment", env.ID, "reason", clamp)
	}
	return Scope{Project: p, Environment: env, Resolved: resolved}, nil
}

// resolveEnvironmentLocked maps an environment id/name to a record inside p.
// Callers hold mu.
func (s *Service) resolveEnvironmentLocked(p Project, environmentID string) (Environment, error) {
	if environmentID == "" {
		return s.defaultEnvironmentLocked(p)
	}
	id := environmentID
	if !strings.Contains(id, envIDSeparator) {
		if err := ValidateName("environment", id); err != nil {
			return Environment{}, err
		}
		id = EnvironmentID(p.ID, id)
	} else {
		// Fully-qualified "<project>.<env>": validate BOTH halves. Skipping this
		// let a caller-supplied id reach filepath.Join and address a record
		// outside the store — including a fabricated environment whose tier, ttl
		// and overlay path an attacker controls.
		proj, name, ok := strings.Cut(id, envIDSeparator)
		if !ok {
			return Environment{}, fmt.Errorf("%w: malformed environment id %q", ErrInvalidInput, environmentID)
		}
		if err := ValidateName("project", proj); err != nil {
			return Environment{}, err
		}
		if err := ValidateName("environment", name); err != nil {
			return Environment{}, err
		}
	}
	env, ok, err := s.store.LoadEnvironment(id)
	if err != nil {
		return Environment{}, err
	}
	if !ok {
		return Environment{}, fmt.Errorf("%w: environment %q", ErrNotFound, environmentID)
	}
	if env.ProjectID != p.ID {
		// Cross-project reference: refuse rather than silently serve another
		// project's risk boundary.
		return Environment{}, fmt.Errorf("%w: environment %q belongs to project %q, not %q", ErrInvalidInput, env.ID, env.ProjectID, p.ID)
	}
	return env, nil
}

// defaultEnvironmentLocked picks the environment a create with no environment
// lands in: the one named "default" if present, else the project's only
// environment. A project with several environments and no "default" must be told
// which one — guessing would put a session in prod by accident.
func (s *Service) defaultEnvironmentLocked(p Project) (Environment, error) {
	if env, ok, err := s.store.LoadEnvironment(EnvironmentID(p.ID, DefaultEnvironmentName)); err != nil {
		return Environment{}, err
	} else if ok {
		return env, nil
	}
	envs, err := s.environmentsLocked(p.ID)
	if err != nil {
		return Environment{}, err
	}
	switch len(envs) {
	case 0:
		return Environment{}, fmt.Errorf("%w: project %q has no environments", ErrNotFound, p.ID)
	case 1:
		return envs[0], nil
	default:
		names := make([]string, 0, len(envs))
		for _, e := range envs {
			names = append(names, e.Name)
		}
		return Environment{}, fmt.Errorf("%w: project %q has %d environments (%s); name one", ErrInvalidInput, p.ID, len(envs), strings.Join(names, ", "))
	}
}

// RemoveEnvironment tears down an environment: its live sandboxes first, then the
// record. Teardown is ORDERED and fails CLOSED — if a sandbox cannot be
// destroyed, the record is KEPT and the error returned, so a live sandbox is
// never orphaned from the environment that governs it.
//
// Removing a project's LAST environment is refused: a project owns ≥1
// environment, so the operator removes the project instead.
//
// environmentID accepts the full id or the bare name within projectID, and an
// environment belonging to another project is refused — the same guard
// ResolveScope applies, so a removal can never cross a risk boundary either.
func (s *Service) RemoveEnvironment(ctx context.Context, projectID, environmentID string) error {
	if projectID == "" {
		projectID = DefaultProjectID
	}
	if err := ValidateName("project", projectID); err != nil {
		return err
	}
	s.mu.Lock()
	p, ok, err := s.store.LoadProject(projectID)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: project %q", ErrNotFound, projectID)
	}
	env, err := s.resolveEnvironmentLocked(p, environmentID)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	siblings, err := s.environmentsLocked(env.ProjectID)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	// Decide AND claim atomically. Count only siblings not already claimed by a
	// concurrent removal, so the loser of a race refuses here — before it has
	// destroyed anything — rather than after teardown. A refusal must mean
	// nothing changed.
	if s.removing[env.ID] {
		s.mu.Unlock()
		return fmt.Errorf("%w: environment %q is already being removed", ErrInUse, env.ID)
	}
	remaining := 0
	for _, sib := range siblings {
		if !s.removing[sib.ID] {
			remaining++
		}
	}
	if remaining <= 1 {
		s.mu.Unlock()
		return fmt.Errorf("%w: environment %q is the last environment of project %q (a project owns at least one); remove the project instead",
			ErrInvalidInput, env.ID, env.ProjectID)
	}
	s.removing[env.ID] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.removing, env.ID)
		s.mu.Unlock()
	}()

	// Ordered teardown BEFORE the record is dropped: while the record exists the
	// sandbox is still attributable to a governing environment.
	if sb := s.liveSandboxes(); sb != nil {
		if n := sb.InFlightIn(env.ProjectID, env.ID); n > 0 {
			return fmt.Errorf("%w: %d session(s) are being created in environment %q; retry once they settle",
				ErrInUse, n, env.ID)
		}
		for _, id := range sb.SessionsIn(env.ProjectID, env.ID) {
			if err := sb.Destroy(ctx, id); err != nil {
				return fmt.Errorf("project: tear down sandbox %s of environment %s: %w", id, env.ID, err)
			}
			s.log.Info("sandbox torn down with environment", "environment", env.ID, "session", id)
		}
	}

	// RE-CHECK the >=1-environment invariant under the lock before deleting. The
	// first check ran before teardown, and teardown must happen OUTSIDE the lock
	// (it destroys containers); without this second check two concurrent removals
	// both observe two siblings, both tear down, and both delete — leaving an
	// environment-less project, which the model does not permit.
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok, err := s.store.LoadEnvironment(env.ID); err != nil {
		return err
	} else if !ok {
		// Another removal won the race and already deleted it. Idempotent success:
		// the caller's intent (this environment is gone) holds.
		return nil
	}
	siblings, err = s.environmentsLocked(env.ProjectID)
	if err != nil {
		return err
	}
	if len(siblings) <= 1 {
		return fmt.Errorf("%w: environment %q is the last environment of project %q (a project owns at least one); remove the project instead",
			ErrInvalidInput, env.ID, env.ProjectID)
	}
	if err := s.store.DeleteEnvironment(env.ID); err != nil {
		return err
	}
	s.log.Info("environment removed", "project", env.ProjectID, "environment", env.ID)
	return nil
}

// RemoveProject removes a project and all of its environments. It REFUSES while
// anything is live: deleting a project must not orphan a running sandbox holding
// connections, so the check fails closed rather than tearing down implicitly (an
// environment removal is a deliberate teardown; a project removal is not).
//
// The default project is never removable — it is the fallback scope for a create
// that names none, and removing it would break every unscoped caller.
func (s *Service) RemoveProject(ctx context.Context, projectID string) error {
	if err := ValidateName("project", projectID); err != nil {
		return err
	}
	if projectID == "" || projectID == DefaultProjectID {
		return fmt.Errorf("%w: the default project cannot be removed (it is the fallback scope for unscoped sessions)", ErrInvalidInput)
	}
	s.mu.Lock()
	_, ok, err := s.store.LoadProject(projectID)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: project %q", ErrNotFound, projectID)
	}
	envs, err := s.environmentsLocked(projectID)
	s.mu.Unlock()
	if err != nil {
		return err
	}

	if sb := s.liveSandboxes(); sb != nil {
		if live := sb.SessionsIn(projectID, ""); len(live) > 0 {
			return fmt.Errorf("%w: project %q has %d live session(s) (%s); end them first",
				ErrInUse, projectID, len(live), strings.Join(live, ", "))
		}
		// A create that has resolved this scope but not yet registered is building
		// a sandbox right now and is invisible to SessionsIn. Refuse, or the
		// record is deleted out from under a sandbox that lands a moment later.
		if n := sb.InFlightIn(projectID, ""); n > 0 {
			return fmt.Errorf("%w: %d session(s) are being created in project %q; retry once they settle",
				ErrInUse, n, projectID)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check under the lock: SessionsIn/InFlightIn ran unlocked (they take the
	// manager's mutex), so a create could have registered in between.
	if sb := s.liveSandboxes(); sb != nil {
		if live := sb.SessionsIn(projectID, ""); len(live) > 0 {
			return fmt.Errorf("%w: project %q has %d live session(s) (%s); end them first",
				ErrInUse, projectID, len(live), strings.Join(live, ", "))
		}
		if n := sb.InFlightIn(projectID, ""); n > 0 {
			return fmt.Errorf("%w: %d session(s) are being created in project %q; retry once they settle",
				ErrInUse, n, projectID)
		}
	}
	for _, e := range envs {
		if err := s.store.DeleteEnvironment(e.ID); err != nil {
			return err
		}
	}
	if err := s.store.DeleteProject(projectID); err != nil {
		return err
	}
	s.log.Info("project removed", "project", projectID, "environments", len(envs))
	return nil
}
