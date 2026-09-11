package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/agentcontext"
	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/project"
	"github.com/opslify-com/opslifyd/internal/regproxy"
	"github.com/opslify-com/opslifyd/internal/session/egress"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// namePrefix labels every sandbox the daemon creates. It makes containers
// attributable to opslify and gives a future `podman ps --filter` sweep a hook
// for out-of-band orphan detection (the persisted-record reconcile is the path
// unit-tested here; the podman sweep is gated on a real engine).
const namePrefix = "opslify-sess-"

// DefaultSnapshotRetention is how many workspace snapshots per name are kept
// when ManagerConfig.SnapshotRetention is left zero. Older snapshots are pruned
// (and their images removed) on each commit, so a workspace never accumulates
// unbounded images.
const DefaultSnapshotRetention = 3

// wsImagePrefix is the local image namespace every workspace snapshot lives in.
// A workspace name is validated (validateWorkspaceName) before it is ever
// interpolated here, so a snapshot ref can never escape this namespace or the
// on-disk workspace-record path.
const wsImagePrefix = "opslify/ws-"

// wsNameRe bounds a workspace name to a safe, traversal-free token: it must be a
// lowercase alnum start followed by alnum / '-' / '_', up to 64 chars. This
// keeps both the image ref (opslify/ws-<name>:<n>) and the on-disk record path
// (<state>/workspaces/<name>.json) inside their namespace — no '/', '..', ':',
// or whitespace can appear.
var wsNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// validateWorkspaceName rejects any name that could traverse out of the
// opslify/ws-* image namespace or the workspace-record directory.
func validateWorkspaceName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: workspace mode requires a name", ErrInvalidInput)
	}
	if !wsNameRe.MatchString(name) {
		return fmt.Errorf("%w: workspace name %q must match %s", ErrInvalidInput, name, wsNameRe.String())
	}
	return nil
}

// Sentinel errors. Each names its failure LAYER so callers (and the HTTP surface)
// can distinguish sandbox-lifecycle errors from runtime/engine errors from bad
// input — the failure-legibility requirement (README known-risk budget).
var (
	// ErrNotFound is returned for an unknown or already-ended session id.
	ErrNotFound = errors.New("session: not found")
	// ErrNotReady is returned when an exec targets a session that is not ready.
	ErrNotReady = errors.New("session: not ready for exec")
	// ErrInvalidInput is returned when a boundary check rejects caller input.
	// The sandbox occupant is hostile: every exec input is validated here.
	ErrInvalidInput = errors.New("session: invalid input")
	// ErrRuntimeUnavailable wraps an F0.3 Available() failure (engine/OCI runtime
	// missing) so a create failure is legibly a runtime problem, not a bug.
	ErrRuntimeUnavailable = errors.New("session: runtime unavailable")
	// ErrEgress wraps an F1.4 egress-programming failure so a create that fails
	// because default-deny egress could not be installed is legibly an EGRESS-layer
	// problem — never confused with a sandbox or runtime failure. It fails CLOSED:
	// a session whose egress could not be programmed is destroyed, never served
	// with unconstrained network.
	ErrEgress = errors.New("session: egress")
	// ErrPolicyDenied is returned by the F4.2 enforcement points when the resolved
	// policy denies an action: a spin-up whose requested tier is weaker than the
	// policy-required bound, or an exec whose argv the classifier denies. It is a
	// POLICY-layer failure (distinct from sandbox/runtime/egress) and it fails
	// CLOSED — a denied exec never touches the runtime.
	ErrPolicyDenied = errors.New("session: policy denied")
	// ErrPolicyApproval is returned when an exec matches approval_required. The
	// human approval loop is F4.3; for F4.2 this is a distinct-reason refusal (no
	// spawn, no hang) that carries the seam F4.3 will turn into a pause.
	ErrPolicyApproval = errors.New("session: policy requires approval")
)

// ManagerConfig carries the non-secret settings a Manager needs to realise
// sandboxes. It is derived from the daemon config (F0.1) at wiring time.
type ManagerConfig struct {
	// Image is the digest-pinned base rootfs the toolchain mounts over.
	Image string
	// ToolchainDigest is the signed, read-only F0.2 layer mounted at /opt/toolchain.
	ToolchainDigest string
	// WorkspaceRoot is the host directory under which per-session /workspace
	// dirs are created.
	WorkspaceRoot string
	// SandboxNetwork is the podman network sandboxes attach to (`--network`).
	// Empty uses the engine default. Set a named netavark bridge network to give
	// rootless containers a routable gateway so the F5.8 credential-blind
	// listeners can bind (rootless-default pasta has no bridge gateway).
	SandboxNetwork string
	// StateDir persists session records for restart reconciliation.
	StateDir string
	// DefaultTier is the isolation rung used when a create omits tier.
	DefaultTier runtime.Tier
	// DefaultTTL is the idle lifetime used when a create omits ttl.
	DefaultTTL time.Duration
	// ApprovalTTL is how long a pending human-approval gate (F4.3) waits before it
	// is FAIL-CLOSED auto-denied with reason "timeout". Zero => DefaultApprovalTTL
	// (10m). Measured on the injected clock, so tests advance it deterministically.
	ApprovalTTL time.Duration
	// Limits bounds every session's resources (a fork-bomb / OOM guard). The
	// hard-spec defaults (pids 256, mem 2G, cpu 2) are applied by the wiring if
	// left zero.
	Limits runtime.ResourceLimits
	// OutputCap / ChunkSize bound exec output; zero applies the defaults.
	OutputCap int
	ChunkSize int
	// WarmPoolSize is how many pre-created, paused sandboxes to keep ready for a
	// sub-second claim (F1.3). Zero disables the pool (pure create-on-demand).
	WarmPoolSize int
	// WarmPoolConcurrency caps how many warm containers are (re)built at once, so
	// replenishment never stampedes the engine or starves claims. Zero => default.
	WarmPoolConcurrency int
	// SnapshotRetention is how many rootfs snapshots per workspace name are kept
	// (older ones are pruned + their images removed on each commit). Zero =>
	// DefaultSnapshotRetention.
	SnapshotRetention int
	// DryRun enables F4.4 dry-run interception: before a gated destructive command
	// pauses for approval, a PREVIEW (terraform plan / kubectl --dry-run=server /
	// a policy dry_run rule) runs in-sandbox and its redacted diff is attached to
	// the approval prompt. Default false preserves the pre-F4.4 approval flow
	// exactly (no preview exec); the daemon wires it true.
	DryRun bool
	// DefaultPolicy is the daemon's trusted baseline policy (F4.1). A per-session
	// workspace policy at <workspace>/opslify.policy.yaml may only NARROW it. The
	// zero value is policy.Default() (no grants; deny-by-default creds), whose
	// resolved policy_hash is policy.DefaultHash.
	DefaultPolicy policy.Policy
}

// resolveFunc maps a (tier, location) to a concrete Runtime. Production uses
// runtime.ResolveRuntime; tests inject a fake so the whole manager is exercised
// with no podman/runsc present.
type resolveFunc func(runtime.Tier, runtime.Location) (runtime.Runtime, error)

// Manager owns session state + lifecycle, backed by the F0.3 Runtime. It is the
// daemon's single executor: all exec requests are mediated through it.
type Manager struct {
	cfg     ManagerConfig
	resolve resolveFunc
	clock   Clock
	store   Store
	egress  egress.Controller
	// sandboxIP maps a fresh container handle to its address on the egress bridge,
	// so per-session egress rules can be source-scoped. It is a seam: the F0.3
	// runtime does not yet expose a container IP, so production leaves it nil and
	// the egress rules are bridge-scoped (still default-deny + no direct DNS). Tests
	// inject it to exercise source-scoped rule generation.
	sandboxIP func(runtime.ContainerHandle) string
	// assembleContext resolves the F8.4 layered instruction set for a session's
	// scope and workspace. A seam rather than a concrete dependency so this package
	// keeps no knowledge of where house rules live; nil means no assembly is
	// configured and no context.assemble event is emitted.
	assembleContext ContextAssembler
	// agents resolves the F8.5 agent bound to a session's scope. A seam so this
	// package keeps no knowledge of the registry; nil means no agent is bound,
	// which is a valid state — opslify ships no model.
	agents AgentSource
	log    *slog.Logger

	// listenTCP binds a per-session credential-injecting listener (F5.8): the
	// bridge-gateway-bound F5.1 creds endpoint and F5.7 egress proxy. It mirrors
	// net.Listen's signature; production uses net.Listen. Tests override it so
	// they can assert the REQUESTED bind address (the gateway) without a real
	// gateway interface on the test host — the guard is that this is only ever
	// called with a gateway host that passed isBindableGateway (never 0.0.0.0).
	listenTCP func(network, addr string) (net.Listener, error)

	// trace is the F3.1 tamper-evident event sink (session.start/end, exec.*,
	// file.write). nil disables tracing (existing lifecycle behavior unchanged);
	// the daemon wires an in-memory sink signed by the daemon identity. redactor
	// (F3.3 seam) scrubs payloads before they are hashed; nil => no redaction.
	trace    trace.TraceSink
	redactor trace.Redactor

	// broker is the F5.6 credential broker. nil disables secret resolution (an
	// unwired daemon never resolves a secret). It gates a resolve on the session's
	// resolved-policy `creds` grants (deny-by-default) and audits every resolve.
	broker *broker.Broker

	// credInjector is the F5.1 executor-side credential injector. nil disables
	// injection (a session runs with no injected creds). At registerReady it
	// resolves every policy-granted cred through the broker, builds a scoped,
	// TTL-bounded injection (AWS container-credentials endpoint, or the GCP/Azure v1
	// env fallback), and stores the resulting env on the session — merged into every
	// exec. It is released on teardown.
	credInjector *broker.Injector

	// egressInject is the F5.7 per-session egress-proxy factory. nil disables the
	// credential-blind HTTP path (opt-in: no egress_inject config => no proxy, no env
	// change, no regression). At registerReady, if the resolved policy lights up an
	// egress-inject rule, it builds a per-session egressproxy.Proxy (F5.2) + a fresh
	// per-session CA + a sandbox-reachable listener, and the manager routes the
	// sandbox through it (HTTPS_PROXY + a daemon-written CA file — NEVER the token).
	// A cred designated for egress injection is EXCLUDED from the F5.1 env injector,
	// so its secret is resolved only at the proxy boundary and never enters the env.
	// The proxy + CA are torn down on session end.
	egressInject *EgressInjector

	// projects is the F8.1 project/environment registry. nil disables scoping: a
	// create then records the WELL-KNOWN default ids (so the trace shape is
	// uniform) and runs under cfg.DefaultPolicy alone, and a create that names a
	// project/environment is refused rather than silently unscoped. The daemon
	// always wires it.
	projects *project.Service

	// registryInject is the F7.5 per-session registry-proxy factory. nil disables
	// the operator package-install path (opt-in: no registry_proxy config => no
	// proxy, no routing env). At registerReady, when the proxy is configured, it
	// builds a per-session regproxy.Proxy bound to the session's resolved creds +
	// trace recorder + the F5.8 gateway listener, and the manager injects the
	// ecosystem routing env (PIP_INDEX_URL/NPM_CONFIG_REGISTRY/GOPROXY) so an
	// operator-initiated install resolves THROUGH the proxy (allowlist + attestation
	// + pkg.install audit). NEVER a credential in the env. Torn down on session end.
	registryInject *RegistryInjector

	mu       sync.Mutex
	sessions map[string]*Session
	// inflight counts creates that have RESOLVED a scope but not yet registered.
	// A sandbox is being built during that window; without counting it, a scope
	// removal racing an in-flight create sees "nothing live", deletes the
	// governing record, and orphans the sandbox that lands a moment later.
	// Keyed "<projectID>\x00<environmentID>".
	inflight map[string]int

	// apprMu guards the pending-approval registry (F4.3). It is a SEPARATE lock
	// from mu so the exec hot path and the approve/deny/timeout control plane never
	// contend on one mutex; the few places that touch both take mu inside apprMu,
	// never the reverse, so there is a single, deadlock-free lock order.
	apprMu    sync.Mutex
	approvals map[string]*approval

	// digestMu guards cfg.ToolchainDigest, which SetToolchainDigest mutates at
	// runtime (a signed-toolchain rotation). realize reads it through
	// toolchainDigest() so the on-demand and warm-pool create paths always agree
	// on the current digest — safe under -race.
	digestMu sync.RWMutex

	// pool is the F1.3 warm pool (nil when WarmPoolSize == 0). Create claims from
	// it before falling back to on-demand realize.
	pool *warmPool

	// wsMu serializes workspace-name-sensitive operations (a workspace create and
	// RemoveWorkspace) so a `ws rm` can never race a concurrent create of the same
	// name and delete the host dir out from under a starting session (F2.2 TOCTOU).
	// It is NOT on the exec/list hot path — only workspace create + rm take it.
	wsMu sync.Mutex

	reaperStop chan struct{}
	reaperDone chan struct{}
}

// Options wires a Manager. Resolve/Clock/Store default to production impls when
// nil, so main() passes only ManagerConfig + a logger while tests inject fakes.
// ContextAssembler resolves the layered instruction set a session will run
// under, given its scope and its workspace directory.
//
// It returns an error rather than a partial assembly, and Create treats that as
// FATAL: a session running with its house rules quietly missing is the failure
// this layer exists to prevent, and it would be invisible from the outside.
type ContextAssembler func(projectID, environmentID, workspaceDir string) (*agentcontext.Assembly, error)

type Options struct {
	Config  ManagerConfig
	Resolve resolveFunc
	Clock   Clock
	Store   Store
	// AssembleContext wires the F8.4 instruction assembly. nil => no assembly and
	// no context.assemble event (every pre-P8 test path).
	AssembleContext ContextAssembler
	// Agents wires the F8.5 registry. nil => sessions record no agent identity.
	Agents AgentSource
	// Egress programs per-session default-deny egress (F1.4). nil => egress.Noop
	// (no enforcement) so F1.1–F1.3 tests need no egress wiring; the daemon wires a
	// real NftController (or a loudly-warned Noop when nft/root is unavailable).
	Egress egress.Controller
	// SandboxIP resolves a container handle to its bridge address for source-scoped
	// egress rules; nil => bridge-scoped rules (see Manager.sandboxIP).
	SandboxIP func(runtime.ContainerHandle) string
	Logger    *slog.Logger
	// Trace is the F3.1 event sink. nil disables tracing. The daemon wires an
	// in-memory sink whose Seal is signed by the F1.1 daemon identity.
	Trace trace.TraceSink
	// Redactor is the F3.3 payload-scrub seam, applied before events are hashed.
	// nil => trace.NoopRedactor (no redaction in F3.1).
	Redactor trace.Redactor
	// Broker is the F5.6 credential broker backing ResolveSecret. nil disables
	// secret resolution — the daemon wires a broker over the local encrypted vault.
	Broker *broker.Broker
	// CredInjector is the F5.1 executor-side credential injector. nil disables
	// injection — the daemon wires it over the broker + the loopback creds endpoint.
	CredInjector *broker.Injector
	// EgressInject is the F5.7 per-session egress-proxy factory. nil disables the
	// credential-blind HTTP path (opt-in) — the daemon wires it only when the config
	// carries at least one egress_inject rule.
	EgressInject *EgressInjector
	// RegistryInject is the F7.5 per-session registry-proxy factory. nil disables
	// the operator install path (opt-in) — the daemon wires it only when the config
	// carries a registry_proxy section with at least one upstream.
	RegistryInject *RegistryInjector
	// Projects is the F8.1 project/environment registry every session is scoped
	// in. nil keeps the pre-F8.1 behaviour (every session lands in the well-known
	// default scope and an explicitly named project/environment is refused).
	Projects *project.Service
}

// NewManager validates options and constructs a Manager (it does not start the
// reaper or reconcile — call Reconcile then StartReaper, or Run, explicitly so
// tests control ordering).
func NewManager(opts Options) (*Manager, error) {
	cfg := opts.Config
	if cfg.OutputCap <= 0 {
		cfg.OutputCap = DefaultOutputCap
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = DefaultChunkSize
	}
	if cfg.DefaultTier == "" {
		cfg.DefaultTier = runtime.TierLocalHardened
	}
	if cfg.ApprovalTTL <= 0 {
		cfg.ApprovalTTL = DefaultApprovalTTL
	}

	m := &Manager{
		cfg:             cfg,
		approvals:       make(map[string]*approval),
		resolve:         opts.Resolve,
		clock:           opts.Clock,
		store:           opts.Store,
		egress:          opts.Egress,
		sandboxIP:       opts.SandboxIP,
		assembleContext: opts.AssembleContext,
		agents:          opts.Agents,
		log:             opts.Logger,
		trace:           opts.Trace,
		redactor:        opts.Redactor,
		broker:          opts.Broker,
		credInjector:    opts.CredInjector,
		egressInject:    opts.EgressInject,
		registryInject:  opts.RegistryInject,
		projects:        opts.Projects,
		sessions:        make(map[string]*Session),
		inflight:        make(map[string]int),
	}
	if m.redactor == nil {
		m.redactor = trace.NoopRedactor{}
	}
	if m.listenTCP == nil {
		m.listenTCP = net.Listen
	}
	if m.resolve == nil {
		m.resolve = runtime.ResolveRuntime
	}
	if m.egress == nil {
		m.egress = egress.Noop{}
	}
	if m.clock == nil {
		m.clock = SystemClock()
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	if m.store == nil {
		if cfg.StateDir == "" {
			return nil, errors.New("session: ManagerConfig.StateDir is required (restart reconciliation needs a durable record)")
		}
		fs, err := NewFileStore(cfg.StateDir)
		if err != nil {
			return nil, err
		}
		m.store = fs
	}
	return m, nil
}

// CreateRequest is the mediated session_create input.
type CreateRequest struct {
	Mode     Mode
	Name     string           // workspace name (workspace mode only; validated)
	Tier     runtime.Tier     // empty => the environment default, else cfg.DefaultTier
	Location runtime.Location // empty => local
	TTL      time.Duration    // <=0 => the environment default, else cfg.DefaultTTL
	// ProjectID / EnvironmentID place the session in an F8.1 scope. Both empty =>
	// the default project/environment, so every pre-F8.1 caller (CLI, MCP, the
	// existing REST body) keeps working unchanged. EnvironmentID accepts either
	// the full id ("flight.staging") or the bare name ("staging") within the
	// project.
	ProjectID     string
	EnvironmentID string
}

// sessionScope is the resolved F8.1 placement of one session: the ids it records,
// the TRUSTED policy baseline the scope imposes (daemon ⊕ project ⊕ environment),
// the environment's session defaults, and the layer-tagged record of every clamp
// the overlay resolution applied. It is computed BEFORE any container is built.
type sessionScope struct {
	projectID string
	envID     string
	// base is the trusted policy the workspace layer narrows over and the
	// enforcement floors are derived from. It is daemon-authoritative: the
	// project and environment layers are daemon-side records, and each of them
	// could only NARROW the daemon baseline to get here.
	base policy.Policy
	// tier/ttl are the environment's session defaults, already defaulted to the
	// daemon config values when the environment sets none. They are DEFAULTS, not
	// floors — a floor is expressed in the environment's policy overlay
	// (session.tier / session.ttl) and enforced from base.
	tier runtime.Tier
	ttl  time.Duration
	// clamps records every widening attempt the project/environment layers made
	// and had clamped, layer-tagged (extends the F4.1 workspace clamp record).
	clamps []string
}

// Create realises a new sandbox and registers it ready. When a warm pool is
// configured (F1.3) and holds a container matching the requested rung, Create
// CLAIMS one — returning in ~one unpause instead of a full engine create — and
// the pool replenishes in the background (a claim never blocks on a rebuild).
// Otherwise it falls back to an on-demand realize. Both paths go through the
// SAME realize (identical hardening + signed toolchain digest); the warm path is
// never a second, weaker create path.
func (m *Manager) Create(ctx context.Context, req CreateRequest) (*Session, error) {
	mode := req.Mode
	if mode == "" {
		mode = ModeScratch
	}
	if mode != ModeScratch && mode != ModeWorkspace {
		return nil, fmt.Errorf("%w: mode %q (want scratch|workspace)", ErrInvalidInput, mode)
	}
	name := ""
	if mode == ModeWorkspace {
		if err := validateWorkspaceName(req.Name); err != nil {
			return nil, err
		}
		name = req.Name
	}
	loc := req.Location
	if loc == "" {
		loc = runtime.LocationLocal
	}

	// F8.1 scope resolution. Decide WHICH project/environment this session is
	// created in before anything else: the environment supplies the trusted policy
	// baseline the rest of the create enforces against, plus its session defaults,
	// and both ids are recorded on the session, its durable record and the
	// session.start trace binding. A create naming neither lands in the default
	// scope, so no session is ever unscoped and nothing pre-F8.1 breaks.
	scope, err := m.resolveScope(req.ProjectID, req.EnvironmentID)
	if err != nil {
		return nil, err
	}
	// The scope is now committed for this create. Count it as in-flight until the
	// session registers, so a concurrent removal of that project/environment
	// refuses instead of orphaning the sandbox being built below.
	defer m.beginCreate(scope.projectID, scope.envID)()

	// F4.2 session-spin-up enforcement. Resolve the policy in force FIRST, then
	// clamp the session's tier/ttl to the daemon-authoritative bounds. This runs
	// before any container is built, so a policy-forbidden request is refused
	// without ever touching the runtime (fail-closed spin-up).
	resolved, err := m.resolveCreatePolicy(mode, name, scope.base)
	if err != nil {
		return nil, err
	}
	// Carry the scope's clamps into the session's resolved model so the record of
	// what the project/environment layers tried to widen travels with the policy
	// the session actually runs under (Notes are not part of the policy_hash).
	if len(scope.clamps) > 0 {
		resolved.Notes = append(append([]string(nil), scope.clamps...), resolved.Notes...)
	}
	tier, err := m.enforceTier(req.Tier, resolved, scope)
	if err != nil {
		// Legible, layer-tagged refusal — the requested tier is weaker than the
		// policy floor. No sandbox is created.
		m.log.Warn("policy denied session spin-up", "reason", err.Error(), "policy_hash", resolved.Hash)
		return nil, err
	}
	ttl := m.enforceTTL(req.TTL, resolved, scope)

	// Fast path: claim a pre-warmed sandbox. The pool holds only generic SCRATCH
	// containers (no per-name workspace dir or resume base), so a workspace create
	// always takes the on-demand realize path — never a warm claim. A warm
	// container is scope-AGNOSTIC (its hardening, image and tier are identical on
	// both paths), so the claim re-stamps it with THIS create's scope and resolved
	// policy — it never inherits the pool's pre-create policy.
	if m.pool != nil && mode == ModeScratch {
		if s, err := m.pool.claim(ctx, tier, loc, mode, ttl, scope, resolved); err != nil {
			return nil, err
		} else if s != nil {
			m.registerReady(s, "claimed")
			return s, nil
		}
		// Pool miss (empty or wrong rung): fall through to on-demand create.
	}

	// Serialize workspace create against RemoveWorkspace: while this create holds
	// wsMu, a concurrent `ws rm <name>` blocks until the session is registered,
	// then its in-use check sees the live session and refuses — so a rm can never
	// delete the host dir out from under a starting workspace session.
	if mode == ModeWorkspace {
		m.wsMu.Lock()
		defer m.wsMu.Unlock()
	}

	s, err := m.realize(ctx, tier, loc, mode, name, ttl, StateReady, resolved, scope)
	if err != nil {
		return nil, err
	}
	m.registerReady(s, "created")
	return s, nil
}

// resolveScope resolves the (project, environment) a create lands in and the
// trusted policy baseline that scope imposes.
//
// With no project service wired (the F1.x-era unit managers, or a daemon built
// without the control tower) the session still records the WELL-KNOWN default
// ids, so the trace shape is uniform and audit can always filter — but naming a
// project/environment explicitly is refused rather than silently ignored, which
// would place a "prod" session in an unscoped sandbox.
func (m *Manager) resolveScope(projectID, envID string) (sessionScope, error) {
	sc := sessionScope{
		projectID: project.DefaultProjectID,
		envID:     project.DefaultEnvironmentID,
		base:      m.cfg.DefaultPolicy,
		tier:      m.cfg.DefaultTier,
		ttl:       m.cfg.DefaultTTL,
	}
	if m.projects == nil {
		if projectID != "" || envID != "" {
			return sessionScope{}, fmt.Errorf("%w: project/environment scoping is not enabled on this daemon", ErrInvalidInput)
		}
		return sc, nil
	}
	resolved, err := m.projects.ResolveScope(m.cfg.DefaultPolicy, projectID, envID)
	if err != nil {
		// The project sentinels (invalid input / not found) are preserved so the
		// REST layer maps them to the right status with layer "project".
		return sessionScope{}, fmt.Errorf("session: scope: %w", err)
	}
	sc.projectID = resolved.Project.ID
	sc.envID = resolved.Environment.ID
	sc.base = resolved.Base()
	sc.clamps = resolved.Clamps()
	if t := resolved.Environment.DefaultTier; t != "" {
		sc.tier = runtime.Tier(t)
	}
	if d := resolved.Environment.DefaultTTL; d != "" {
		// Validated at environment-creation time; an unparseable value here would
		// mean a hand-edited record, so fall back to the daemon default rather
		// than failing the create.
		if parsed, perr := time.ParseDuration(d); perr == nil && parsed > 0 {
			sc.ttl = parsed
		} else {
			m.log.Warn("environment default_ttl is unparseable; using the daemon default",
				"environment", resolved.Environment.ID, "default_ttl", d)
		}
	}
	return sc, nil
}

// inflightKey scopes the in-flight counter to one (project, environment).
func inflightKey(projectID, environmentID string) string {
	return projectID + "\x00" + environmentID
}

// beginCreate marks a create as in-flight in its scope and returns the release
// func the caller MUST defer, so the count drops whether the create succeeds,
// fails, or panics.
func (m *Manager) beginCreate(projectID, environmentID string) func() {
	k := inflightKey(projectID, environmentID)
	m.mu.Lock()
	m.inflight[k]++
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		if m.inflight[k] <= 1 {
			delete(m.inflight, k)
		} else {
			m.inflight[k]--
		}
		m.mu.Unlock()
	}
}

// InFlightIn reports how many creates have resolved this scope but not yet
// registered. A scope removal MUST refuse while this is non-zero: the sandbox
// exists (or is about to) but is not yet visible to SessionsIn, so tearing the
// governing record down now would orphan it.
func (m *Manager) InFlightIn(projectID, environmentID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, c := range m.inflight {
		proj, env, _ := strings.Cut(k, "\x00")
		if proj != projectID {
			continue
		}
		if environmentID != "" && env != environmentID {
			continue
		}
		n += c
	}
	return n
}

// SessionsIn returns the ids of LIVE sessions scoped to projectID and, when
// environmentID is non-empty, to that environment. It is the F8.1 seam the
// project service uses to refuse a project removal while a sandbox is live and to
// tear an environment's sandboxes down in order — the daemon, not the UI, decides
// whether a scope is still in use.
func (m *Manager) SessionsIn(projectID, environmentID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, s := range m.sessions {
		if s.ProjectID != projectID {
			continue
		}
		if environmentID != "" && s.EnvironmentID != environmentID {
			continue
		}
		out = append(out, s.ID)
	}
	sort.Strings(out)
	return out
}

// realize builds one sandbox and persists its record, returning it in state st.
// It is the SINGLE create path shared by on-demand Create and warm-pool
// pre-create, so a warm container is guaranteed identical to an on-demand one:
// same hardening hard-spec (F0.3 base) and same signed toolchain digest. It does
// NOT register the session in the live map — the caller (Create for ready
// sessions; the pool for warm ones) decides that.
func (m *Manager) realize(ctx context.Context, tier runtime.Tier, loc runtime.Location, mode Mode, name string, ttl time.Duration, st State, resolved policy.Resolved, scope sessionScope) (*Session, error) {
	rt, err := m.resolve(tier, loc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	// Capability check: fail legibly BEFORE touching the engine so the operator
	// learns gVisor is missing rather than seeing an opaque create failure.
	if err := rt.Available(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRuntimeUnavailable, err)
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := m.clock.Now()

	// Writable workspace on the host, mounted rw at /workspace — the one writable
	// path (rootfs is read-only + RO toolchain, asserted in F0.3's base). This is
	// where ALL persistent workspace state lives: a `podman commit` snapshot would
	// NOT capture a bind mount, so the host dir IS the persistence mechanism.
	//   - scratch:   a per-SESSION dir (<root>/<id>), discarded on end.
	//   - workspace: a stable per-NAME dir (<root>/ws-<name>), kept across sessions
	//                and re-mounted on resume so installed deps/clones persist —
	//                including across a daemon restart (it is just a host directory).
	var wsDir string
	if m.cfg.WorkspaceRoot != "" {
		if mode == ModeWorkspace {
			wsDir = m.workspaceDir(name)
		} else {
			wsDir = filepath.Join(m.cfg.WorkspaceRoot, id)
		}
		if err := os.MkdirAll(wsDir, 0o700); err != nil {
			return nil, fmt.Errorf("session: create workspace %s: %w", wsDir, err)
		}
	}

	// Resume base image: ALWAYS the configured base image. Workspace state lives
	// entirely in the per-name /workspace host dir mounted above — that is what
	// carries installed deps / clones across sessions and daemon restarts. The
	// rootfs snapshot (opslify/ws-<name>:<n>) is still committed on end as retained
	// history and to future-proof a writable-rootfs tier, but it is NOT booted as
	// the resume base: under the always-read-only rootfs it captures nothing
	// useful, and booting a committed userns image is fragile — podman stores its
	// layers under the run's subuid range, so a later `--userns=auto` run that
	// draws a different range fails to map it ("user namespace with size N bigger
	// than the maximum allowed with userns=auto"). Booting the base image + host
	// dir sidesteps that entire failure class while preserving the feature's
	// contract (deps persist across sessions).
	// F4.2 image enforcement: the session ALWAYS boots a daemon-authoritative
	// image, never a workspace-supplied one. When the daemon POLICY pins an image
	// the resolved value is trustworthy (F4.1 drops a differing workspace image);
	// when the daemon policy leaves it unset the resolved image is the workspace's
	// pass-through value and MUST be ignored in favour of the daemon config image
	// (the F4.1 carry-over — an unset daemon bound never lets the workspace choose).
	baseImage := m.cfg.Image
	if m.cfg.DefaultPolicy.Session.Image != "" && resolved.Session.Image != "" {
		baseImage = resolved.Session.Image
	}

	spec := runtime.SessionSpec{
		Tier:            tier,
		Location:        loc,
		Image:           baseImage,
		ToolchainDigest: m.toolchainDigest(),
		Workspace:       wsDir,
		Limits:          m.cfg.Limits,
		Name:            namePrefix + id,
		Network:         m.cfg.SandboxNetwork,
		// A long-lived idle entrypoint so the container stays up for mediated
		// execs (the daemon spawns each command via Runtime.Exec).
		Entrypoint: []string{"sleep", "infinity"},
	}

	handle, err := rt.Create(ctx, spec)
	if err != nil {
		m.cleanupWorkspace(wsDir)
		return nil, fmt.Errorf("session: create sandbox: %w", err)
	}

	// Start the container so its idle entrypoint (sleep infinity) actually runs.
	// This is the shared start step for BOTH on-demand and warm sessions, so they
	// are identical up to the warm pool's extra pause: `podman exec` (on-demand)
	// and `podman pause` (warm freeze) each require a RUNNING container, which a
	// bare `podman create` does not provide. We start explicitly here (rather than
	// lazily on first exec) so the two paths stay consistent and the warm freeze
	// has something to pause. It fails CLOSED: an unstartable container is
	// unusable, so we destroy it rather than serve/warm a dead sandbox. Optional
	// Starter seam: a runtime (or fake) that does not implement it yields a
	// created-but-not-started container, preserving F0.3 unit behavior.
	if st, ok := rt.(runtime.Starter); ok {
		if err := st.Start(ctx, handle); err != nil {
			_ = rt.Destroy(ctx, handle)
			m.cleanupWorkspace(wsDir)
			return nil, fmt.Errorf("session: start sandbox: %w", err)
		}
	}

	s := &Session{
		ID:            id,
		Mode:          mode,
		Name:          name,
		Tier:          tier,
		Location:      loc,
		State:         st,
		Handle:        handle,
		WorkspaceDir:  wsDir,
		Created:       now,
		LastActivity:  now,
		TTL:           ttl,
		ProjectID:     scope.projectID,
		EnvironmentID: scope.envID,
		policyHash:    resolved.Hash,
		policy:        resolved,
	}

	// F8.4: resolve the layered instruction set BEFORE the sandbox is handed out.
	//
	// FAIL-CLOSED, and the ordering matters: a session that starts with its house
	// rules silently missing is the exact outcome layer 1 exists to prevent, and it
	// would be invisible — the agent would simply behave as though the rule had
	// never been written. An unreadable or unsafe source (a symlinked skill file
	// pointing at a host secret, say) therefore aborts the create and rolls the
	// container back, rather than degrading into a session with less context than
	// the operator believes it has.
	if m.assembleContext != nil {
		a, err := m.assembleContext(scope.projectID, scope.envID, wsDir)
		if err != nil {
			_ = rt.Destroy(ctx, handle)
			m.cleanupWorkspace(wsDir)
			return nil, fmt.Errorf("session: assemble agent context: %w", err)
		}
		s.assembly = a
	}

	if err := m.store.Save(recordOf(s)); err != nil {
		// Roll back the container so a persistence failure never leaks a sandbox.
		_ = rt.Destroy(ctx, handle)
		m.cleanupWorkspace(wsDir)
		return nil, err
	}

	// Install default-deny egress for this sandbox BEFORE it is ever handed out
	// (this path is shared by on-demand Create and warm pre-create, so both get it
	// identically). Fail CLOSED: if egress can't be programmed, destroy the sandbox
	// rather than serve one with unconstrained network. The failure is tagged
	// ErrEgress so the operator sees an egress-layer problem, not a sandbox bug.
	var sandboxIP string
	if m.sandboxIP != nil {
		sandboxIP = m.sandboxIP(handle)
	}
	if err := m.egress.SetupSession(ctx, egress.SessionNet{SessionID: id, SandboxIP: sandboxIP}); err != nil {
		_ = m.store.Delete(id)
		_ = rt.Destroy(ctx, handle)
		m.cleanupWorkspace(wsDir)
		return nil, fmt.Errorf("%w: %v", ErrEgress, err)
	}
	return s, nil
}

// registerReady adds a ready session to the live map. origin is "created" (fresh
// on-demand) or "claimed" (from the warm pool) for the audit log.
func (m *Manager) registerReady(s *Session, origin string) {
	// Open the trace chain and emit session.start BEFORE the session is visible in
	// the live map — so no concurrent exec can win seq 0. seq 0 is therefore always
	// session.start, and its payload carries the session-binding fields the chain
	// root commits to (image_digest + toolchain_lock_hash + policy_hash slot).
	// F8.5: resolve the bound agent BEFORE the chain opens, so its identity is in
	// session.start at seq 0 rather than arriving later as a separate event that
	// could be absent from a truncated trace.
	m.resolveAgent(s)
	if m.trace != nil {
		s.rec = trace.NewRecorder(m.trace, s.ID, m.redactor, m.clock.Now)
		if err := s.rec.Emit(context.Background(), trace.TypeSessionStart, map[string]any{
			"schema_version": trace.SchemaVersion,
			"tier":           string(s.Tier),
			"mode":           string(s.Mode),
			// F8.5: WHICH agent ran this session, and which model it was expected to
			// drive. Bound at seq 0 — the chain root — so a decision is attributable
			// to a model rather than to "an agent". agent_locality records whether
			// command output left this host: a disclosure an auditor needs and
			// cannot reconstruct later.
			"agent":               s.agentName,
			"agent_model":         s.agentModel,
			"agent_locality":      s.agentLocality,
			"image_digest":        m.cfg.Image,
			"toolchain_lock_hash": m.toolchainDigest(),
			"policy_hash":         s.policyHash, // F4.1: resolved policy_hash
			// F8.1: the scope this session ran in. Bound at seq 0 — the chain root —
			// so the whole session's evidence is attributable to one project and one
			// environment, and audit can filter by either without inference.
			"project_id":     s.ProjectID,
			"environment_id": s.EnvironmentID,
		}); err != nil {
			m.log.Warn("trace session.start emit failed", "session", s.ID, "err", err)
		}
		// F8.4: seq 1, immediately after session.start, so the instruction set is
		// bound to the chain root alongside the policy hash. The payload carries
		// layer names, hashes and SIZES only — never instruction CONTENT, which can
		// hold estate detail an operator never agreed to persist in an audit log.
		if s.assembly != nil {
			if err := s.rec.Emit(context.Background(), trace.TypeContextAssemble, s.assembly.TracePayload()); err != nil {
				m.log.Warn("trace context.assemble emit failed", "session", s.ID, "err", err)
			}
		}
	}
	// F5.1 executor-side credential injection. Resolve every policy-granted cred and
	// build the scoped, TTL-bounded injection BEFORE the session is visible in the
	// live map, so no exec can run before its creds are wired. It is fail-closed: a
	// per-cred resolve/adapter failure injects nothing for that cred (no raw-secret
	// fallback) and warns; the AWS blind path puts ONLY the endpoint URI + a
	// per-session token in credEnv (the value is served by the token-gated endpoint).
	// F5.8 reachability discovery. Before either credential-injecting listener is
	// built, discover the container's bridge IP + gateway (via the optional
	// NetworkInfo runtime capability) so the listeners can bind a CONTAINER-
	// REACHABLE address (the gateway, never loopback/0.0.0.0) and source-scope to
	// the owning container. When the runtime exposes no NetworkInfo the result is
	// "capability absent" and both paths keep their prior (loopback) behavior; when
	// it IS exposed but no gateway is discoverable, both paths FAIL CLOSED.
	sn := m.discoverSessionNet(context.Background(), s)
	m.injectCredentials(context.Background(), s, sn)
	// F5.7 credential-blind HTTP egress. If the resolved policy lights up an
	// egress-inject rule, build the per-session proxy + CA + listener and route the
	// sandbox through it (adds HTTPS_PROXY + a daemon-written CA file to credEnv —
	// never the token). Also single-owner here (no exec can observe s yet), so
	// s.credEnv/s.egress are set without a lock.
	m.injectEgressProxy(s, sn)
	// F7.5 operator package-install path. If the registry proxy is configured, build
	// the per-session regproxy.Proxy + gateway listener and inject the ecosystem
	// routing env (PIP_INDEX_URL/NPM_CONFIG_REGISTRY/GOPROXY) so a later operator
	// `workspace install` resolves through the proxy. No credential in the env.
	m.injectRegistryProxy(s, sn)
	// F5.8 host_input hole: the credential-blind listeners above bind the bridge
	// GATEWAY IP, which the sandbox reaches via the kernel input hook — governed by
	// the egress host_input chain, which is otherwise default-deny (F1.4). Now that
	// the listener ports are known, re-program egress so the sandbox may reach ONLY
	// those ports on ONLY the gateway. Without this the proxy is bound but the SYN
	// is dropped and the blind path times out. Fail-open is impossible here: no
	// ports (blind path inactive / fail-closed) => no hole, chain stays default-deny.
	m.allowBlindPathPorts(context.Background(), s, sn)
	m.mu.Lock()
	m.sessions[s.ID] = s
	m.mu.Unlock()
	m.log.Info("session "+origin, "session", s.ID, "tier", s.Tier, "mode", s.Mode, "container", s.Handle.ID)
}

// toolchainDigest returns the current signed toolchain digest under the digest
// lock (SetToolchainDigest may rotate it at runtime).
func (m *Manager) toolchainDigest() string {
	m.digestMu.RLock()
	defer m.digestMu.RUnlock()
	return m.cfg.ToolchainDigest
}

// SetToolchainDigest rotates the signed toolchain digest used for every NEW
// sandbox and, if a warm pool exists, drains the now-stale warm containers and
// rebuilds the pool on the new digest (F1.3: "toolchain change drains + rebuilds
// the pool"). A no-op when the digest is unchanged. In-flight and future
// on-demand creates immediately use the new digest via realize.
func (m *Manager) SetToolchainDigest(digest string) {
	m.digestMu.Lock()
	changed := m.cfg.ToolchainDigest != digest
	m.cfg.ToolchainDigest = digest
	m.digestMu.Unlock()
	if changed && m.pool != nil {
		m.pool.drainAndRebuild(digest)
	}
}

// StartWarmPool constructs and starts the warm pool from ManagerConfig
// (WarmPoolSize / WarmPoolConcurrency). It is a no-op when WarmPoolSize <= 0.
// Call after Reconcile (so a restart's orphans are reaped first) and before
// serving. Idempotent-safe: a second call with a pool already running is ignored.
func (m *Manager) StartWarmPool() {
	if m.cfg.WarmPoolSize <= 0 || m.pool != nil {
		return
	}
	conc := m.cfg.WarmPoolConcurrency
	if conc <= 0 {
		conc = defaultWarmConcurrency
	}
	m.pool = newWarmPool(m, m.cfg.WarmPoolSize, conc, m.cfg.DefaultTier, runtime.LocationLocal)
	m.pool.start()
}

// Exec runs one mediated command in a ready session, streaming bounded output to
// sink and finishing with the exit code. The session moves ready→execing→ready.
// Input is validated at the boundary (hostile occupant). writable carries the
// per-exec micro-scoping grant (v1-lite): paths under /workspace the command may
// write; empty means a read-only view. Enforcement of the transient mount view
// is a documented seam (full policy-driven version lands in P4/P5) — the grant is
// validated and recorded here.
func (m *Manager) Exec(ctx context.Context, id string, opts ExecOptions, sink ExecSink) error {
	if err := opts.validate(); err != nil {
		return err
	}

	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if s.State != StateReady {
		st := s.State
		m.mu.Unlock()
		return fmt.Errorf("%w: session %s is %s", ErrNotReady, id, st)
	}
	rt, err := m.resolve(s.Tier, s.Location)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("session: resolve runtime for exec: %w", err)
	}
	s.State = StateExecing
	handle := s.Handle
	rec := s.rec
	resolved := s.policy
	policyHash := s.policyHash
	m.mu.Unlock()

	// Always return the session to ready (or leave ended if reaped meanwhile).
	defer func() {
		m.mu.Lock()
		if cur, ok := m.sessions[id]; ok && cur.State == StateExecing {
			cur.State = StateReady
			cur.LastActivity = m.clock.Now()
		}
		m.mu.Unlock()
	}()

	// F4.2 EXEC INTERCEPTION. Classify the argv against the resolved policy BEFORE
	// the process is ever spawned. Classify is pure (no I/O, no shell-out — it can
	// never be an injection vector); the decision is recorded as a redacted,
	// chained policy.decision trace event carrying the policy_hash, so every
	// allow/deny/needs_approval is evidence under a known policy. A deny (or, for
	// F4.2, a needs_approval — the F4.3 pause is not built yet) returns a typed,
	// layer-tagged error and NEVER calls Runtime.Exec: the defer above returns the
	// session to ready.
	decision := policy.Classify(resolved, opts.Argv)
	if rec != nil {
		_ = rec.Emit(ctx, trace.TypePolicyDecision, map[string]any{
			"decision":     string(decision.Verdict),
			"rule":         decision.Rule,
			"argv_summary": strings.Join(opts.Argv, " "),
			"policy_hash":  policyHash,
		})
	}
	switch decision.Verdict {
	case policy.VerdictDeny:
		return fmt.Errorf("%w: %s [rule %s]", ErrPolicyDenied, decision.Reason, decision.Rule)
	case policy.VerdictNeedsApproval:
		// F4.3 PAUSE. The process is NOT spawned. Register a pending approval, move
		// the session to awaiting_approval, and emit approval.requested (which the
		// F3.2 SSE stream pushes to the F3.5 UI live). The call returns PROMPTLY with
		// a typed ApprovalPendingError carrying the exec_id — it NEVER blocks on a
		// human, so the MCP agent is never hung. Resolution (approve/deny) and the
		// fail-closed timeout arrive out-of-band through the human control plane.
		return m.registerApproval(ctx, id, opts, rec, policyHash, decision, rt, handle, resolved)
	case policy.VerdictAllow:
		// fall through to spawn.
	}

	return m.runExec(ctx, id, rt, handle, rec, opts, sink)
}

// ResolveSecret is the DAEMON-INTERNAL F5.6 credential resolution entrypoint — the
// seam F5.1 injection will consume. It looks up the session, gates the resolve on
// the session's RESOLVED policy `creds` grants (deny-by-default), fetches the value
// via the broker's internal backend, and emits a chained+redacted `cred.resolve`
// audit event under the session's trace. It returns the plaintext value ONLY to
// this internal caller; it is NEVER reachable from a REST/CLI/UI route (there is no
// handler that calls it). The caller SHOULD broker.Zeroize the value after use.
//
// It fails CLOSED: an unwired broker, an unknown session, an ungranted ref, or any
// backend error returns an error and NO value — and (except for an unknown session,
// which has no recorder) audits the denial.
func (m *Manager) ResolveSecret(ctx context.Context, id, ref string) ([]byte, broker.SecretMeta, error) {
	if m.broker == nil {
		return nil, broker.SecretMeta{}, fmt.Errorf("%w: credential broker is not enabled on this daemon", ErrNotFound)
	}
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return nil, broker.SecretMeta{}, fmt.Errorf("%w: session %s", ErrNotFound, id)
	}
	rec := s.rec
	grants := s.policy.Creds
	m.mu.Unlock()
	return m.broker.Resolve(ctx, rec, grants, ref)
}

// sessionNet is the F5.8 result of discovering a container's bridge network. It
// distinguishes three cases the two listener paths key off:
//   - known=false: the runtime exposes no NetworkInfo capability. Both listeners
//     keep their prior LOOPBACK behavior (opt-in: no capability => no change —
//     this is what every unit fake without NetworkInfo, and any runtime that
//     cannot report it, gets).
//   - known=true, ok=false: the capability IS present but no reachable gateway was
//     discoverable (inspect error, or an empty/unbindable gateway). Both listeners
//     FAIL CLOSED — no endpoint, no proxy env, no raw-secret fallback.
//   - known=true, ok=true: bind the listeners to gatewayIP, source-scoped to
//     containerIP, and advertise gatewayIP in the sandbox env.
type sessionNet struct {
	known       bool
	ok          bool
	containerIP string
	gatewayIP   string
}

// discoverSessionNet probes the container's bridge IP + gateway through the
// optional F5.8 NetworkInfo runtime capability. It never fails the session: a
// discovery error downgrades to a fail-closed blind path (ok=false), and an
// absent capability preserves prior behavior (known=false). The gateway is
// validated with isBindableGateway so a wildcard/empty address can never reach a
// bind call.
func (m *Manager) discoverSessionNet(ctx context.Context, s *Session) sessionNet {
	rt, err := m.resolve(s.Tier, s.Location)
	if err != nil {
		// Cannot even resolve the runtime — treat as capability absent (legacy).
		return sessionNet{}
	}
	ni, has := rt.(runtime.NetworkInfo)
	if !has {
		return sessionNet{}
	}
	cip, gip, err := ni.NetworkInfo(ctx, s.Handle)
	sn := sessionNet{known: true, containerIP: cip, gatewayIP: gip}
	if err != nil {
		m.log.Warn("network discovery failed; credential-blind listeners disabled (fail-closed)", "session", s.ID, "err", err)
		return sn
	}
	if cip == "" || !isBindableGateway(gip) {
		m.log.Warn("no reachable bridge gateway discovered; credential-blind listeners disabled (fail-closed)", "session", s.ID, "container_ip", cip, "gateway_ip", gip)
		return sn
	}
	sn.ok = true
	return sn
}

// allowBlindPathPorts re-programs the session's egress rules to punch a narrow hole
// in the host_input chain for the credential-blind listeners bound this round (the
// F5.7 egress proxy, F5.1 creds endpoint, F7.5 registry proxy). Those listeners bind
// the bridge gateway IP; the sandbox reaches them via the kernel input hook, which
// the default-deny host_input chain would otherwise drop. It collects the bound
// ports from the session handles and re-applies SetupSession with the gateway IP +
// ports, so the hole is scoped to daddr==gateway, saddr==sandbox, and ONLY those
// ports. It is a no-op unless the gateway path is live (sn.ok) and at least one
// listener bound — so an inactive/fail-closed blind path never widens host_input.
func (m *Manager) allowBlindPathPorts(ctx context.Context, s *Session, sn sessionNet) {
	if !sn.ok {
		return
	}
	var ports []int
	addPort := func(addr string) {
		if addr == "" {
			return
		}
		_, p, err := net.SplitHostPort(strings.TrimPrefix(addr, "http://"))
		if err != nil {
			return
		}
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			ports = append(ports, n)
		}
	}
	if s.egress != nil {
		addPort(s.egress.addr)
	}
	if s.credEndpoint != nil {
		addPort(s.credEndpoint.addr)
	}
	if s.registry != nil {
		addPort(s.registry.addr)
	}
	if len(ports) == 0 {
		return
	}
	err := m.egress.SetupSession(ctx, egress.SessionNet{
		SessionID:     s.ID,
		SandboxIP:     sn.containerIP,
		GatewayIP:     sn.gatewayIP,
		LocalTCPPorts: ports,
	})
	if err != nil {
		m.log.Warn("egress: could not open credential-blind listener ports; blind path may be unreachable", "session", s.ID, "err", err)
	}
}

// injectCredentials runs F5.1 executor-side injection for a freshly-registered
// session: it resolves the session's policy-granted creds through the broker
// (deny-by-default + `cred.resolve` audit), builds a scoped TTL-bounded injection
// per provider (AWS container-credentials endpoint, or the GCP/Azure v1 env
// fallback), and records the resulting env on the session for merge into every
// exec. Every resolved plaintext is Zeroized inside the injector. It is called
// before the session enters the live map, so s.credEnv is set without a lock
// (no concurrent exec can observe the session yet). A nil injector is a no-op.
func (m *Manager) injectCredentials(ctx context.Context, s *Session, sn sessionNet) {
	if m.credInjector == nil || len(s.policy.Creds) == 0 {
		return
	}
	// F5.7: a cred designated for egress-boundary injection is resolved ONLY at the
	// proxy (on the upstream leg) and must NEVER be placed in the sandbox env by the
	// F5.1 env injector. Drop those refs before injecting — a durable secret meant
	// for header injection can then never leak into the process env via the fallback.
	grants := s.policy.Creds
	if m.egressInject != nil {
		filtered := grants[:0:0]
		for _, c := range grants {
			if m.egressInject.isEgressInjectRef(c.Name) {
				continue
			}
			filtered = append(filtered, c)
		}
		grants = filtered
		if len(grants) == 0 {
			return
		}
	}

	// F5.8 endpoint binding. Decide WHERE the AWS blind-path creds endpoint the
	// injected AWS_CONTAINER_CREDENTIALS_FULL_URI points at is served:
	//   - capability absent (legacy): the injector's shared LOOPBACK endpoint
	//     (unchanged behavior for unit tests / runtimes without NetworkInfo);
	//   - capability present but no gateway: FAIL CLOSED — inject nothing;
	//   - gateway discovered: a PER-SESSION listener bound to the gateway,
	//     source-scoped to the container, advertised in the URI.
	var si broker.SessionInjection
	var err error
	switch {
	case !sn.known:
		si, err = m.credInjector.InjectSession(ctx, s.rec, s.ID, grants)
	case !sn.ok:
		m.log.Warn("credential injection disabled: no reachable creds endpoint bind (fail-closed, no env fallback)", "session", s.ID)
		return
	default:
		si, err = m.injectCredentialsGateway(ctx, s, sn, grants)
		if err != nil {
			m.log.Warn("credential endpoint bind failed; session runs without injected creds (fail-closed)", "session", s.ID, "err", err)
			return
		}
	}
	if err != nil {
		// An internal invariant break (e.g. token generation) — fail closed: the
		// session runs with NO injected creds rather than a partial/raw one.
		m.log.Warn("credential injection failed; session runs without injected creds", "session", s.ID, "err", err)
		return
	}
	s.credEnv = append(s.credEnv, si.Env...)
	for _, w := range si.Warnings {
		m.log.Warn("credential injection", "session", s.ID, "detail", w)
	}
}

// injectCredentialsGateway stands up a PER-SESSION F5.1 creds endpoint bound to the
// discovered bridge gateway (never loopback/0.0.0.0) and source-scoped to the
// owning container's IP, then injects with the gateway address advertised in the
// AWS endpoint URI (F5.8). It fails closed: with no CredServer to serve, or on a
// bind failure, it returns an error and the caller injects nothing (no raw-secret
// fallback). The started listener is recorded on the session for teardown.
func (m *Manager) injectCredentialsGateway(ctx context.Context, s *Session, sn sessionNet, grants []policy.Cred) (broker.SessionInjection, error) {
	if !m.credInjector.HasEndpoint() {
		return broker.SessionInjection{}, fmt.Errorf("cred: no endpoint wired for the gateway-bound blind path")
	}
	// Defense-in-code: never bind a wildcard for this credential-injecting listener.
	if !isBindableGateway(sn.gatewayIP) {
		return broker.SessionInjection{}, fmt.Errorf("cred: refusing to bind creds endpoint to non-reachable host %q", sn.gatewayIP)
	}
	ln, err := m.listenTCP("tcp", net.JoinHostPort(sn.gatewayIP, "0"))
	if err != nil {
		return broker.SessionInjection{}, fmt.Errorf("cred: bind gateway creds endpoint: %w", err)
	}
	// Advertise the GATEWAY host with the actual bound port (the daemon-side Addr()
	// may name a different host under a test listen seam).
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	base := "http://" + net.JoinHostPort(sn.gatewayIP, port)
	handler := sourceScoped(m.credInjector.EndpointHandler(), sn.containerIP, m.log)
	srv := &http.Server{Handler: handler}
	go func() {
		if serr := srv.Serve(ln); serr != nil && serr != http.ErrServerClosed {
			m.log.Warn("creds endpoint listener stopped", "session", s.ID, "err", serr)
		}
	}()
	s.credEndpoint = &sessionCredEndpoint{addr: base, close: func() { _ = srv.Close() }}
	si, err := m.credInjector.InjectSessionEndpoint(ctx, s.rec, s.ID, grants, base)
	if err != nil {
		srv.Close()
		s.credEndpoint = nil
		return broker.SessionInjection{}, err
	}
	m.log.Info("F5.8 gateway-bound creds endpoint active", "session", s.ID, "base_url", base, "source_ip", sn.containerIP)
	return si, nil
}

// injectEgressProxy runs F5.7 per-session egress-proxy wiring for a freshly
// registered session. When the resolved policy lights up an egress-inject rule it:
//   - builds a per-session egressproxy.Proxy (F5.2) + a fresh per-session CA and
//     starts a sandbox-reachable loopback listener (torn down on session end);
//   - writes the per-session CA cert (public cert ONLY — never the key) to a
//     daemon-controlled file in the session workspace, before first exec;
//   - appends HTTPS_PROXY/HTTP_PROXY (+ NO_PROXY) and CURL_CA_BUNDLE/SSL_CERT_FILE/
//     REQUESTS_CA_BUNDLE/GIT_SSL_CAINFO (pointing at the CA file) to s.credEnv.
//
// It injects the proxy ADDRESS + the CA PATH only — NEVER the token, which the
// proxy adds on the upstream leg. It is FAIL-CLOSED: a build/listener/CA-write
// failure injects no proxy env and no raw-secret fallback. A nil injector, or a
// session with no applicable rule, is a clean no-op (no env change). Called before
// the session enters the live map, so s.credEnv/s.egress are set without a lock.
func (m *Manager) injectEgressProxy(s *Session, sn sessionNet) {
	if m.egressInject == nil {
		return
	}
	// F5.8 reachable bind. When the runtime exposed a gateway, bind the proxy
	// listener to it (source-scoped to the container) and advertise the gateway in
	// HTTPS_PROXY; when the capability is present but no gateway is reachable, FAIL
	// CLOSED; when the capability is absent, keep the legacy loopback bind.
	var listen func() (net.Listener, error)
	var sourceIP, advertiseHost string
	if sn.known {
		if !sn.ok {
			m.log.Warn("egress proxy disabled: no reachable gateway bind (fail-closed)", "session", s.ID)
			return
		}
		gwAddr := net.JoinHostPort(sn.gatewayIP, "0")
		listen = func() (net.Listener, error) { return m.listenTCP("tcp", gwAddr) }
		sourceIP = sn.containerIP
		advertiseHost = sn.gatewayIP
	}
	se, err := m.egressInject.buildForSession(s.ID, s.policy, s.rec, listen, sourceIP, advertiseHost)
	if err != nil {
		// Fail-closed: the session runs with NO proxy env rather than a partial or
		// insecure route. Non-HTTP egress stays under F1.4 default-deny regardless.
		m.log.Warn("egress proxy build failed; session runs without credential-blind HTTP egress", "session", s.ID, "err", err)
		return
	}
	if se == nil {
		return // no applicable egress-inject rule for this session (opt-in no-op)
	}
	// The CA file must live in the session's /workspace mount so the sandbox can read
	// it. Without a workspace dir there is nowhere daemon-authoritative to write it —
	// fail closed rather than route TLS the sandbox cannot validate.
	if s.WorkspaceDir == "" {
		se.close()
		m.log.Warn("egress proxy disabled: no workspace dir to write the per-session CA", "session", s.ID)
		return
	}
	caHostPath := filepath.Join(s.WorkspaceDir, SandboxCAFileName)
	if err := os.WriteFile(caHostPath, se.caPEM, 0o644); err != nil {
		se.close()
		m.log.Warn("egress proxy disabled: cannot write per-session CA file", "session", s.ID, "err", err)
		return
	}
	caSandboxPath := path.Join(sandboxWorkspaceMount, SandboxCAFileName)
	proxyURL := "http://" + se.addr
	noProxy := append([]string{"localhost", "127.0.0.1"}, m.egressInject.noProxy...)
	// F5.8: the gateway-bound F5.1 creds endpoint lives on the SAME gateway host as
	// this proxy. Exclude that host from NO_PROXY so the AWS SDK's creds fetch goes
	// DIRECT to the endpoint rather than looping back through this proxy.
	if sn.ok && sn.gatewayIP != "" {
		noProxy = append(noProxy, sn.gatewayIP)
	}
	noProxyVal := strings.Join(noProxy, ",")
	s.credEnv = append(s.credEnv,
		"HTTPS_PROXY="+proxyURL,
		"https_proxy="+proxyURL,
		"HTTP_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"NO_PROXY="+noProxyVal,
		"no_proxy="+noProxyVal,
		"CURL_CA_BUNDLE="+caSandboxPath,
		"SSL_CERT_FILE="+caSandboxPath,
		"REQUESTS_CA_BUNDLE="+caSandboxPath,
		"GIT_SSL_CAINFO="+caSandboxPath,
	)
	s.egress = se
	m.log.Info("egress credential-blind HTTP path active", "session", s.ID, "proxy", proxyURL)
}

// injectRegistryProxy runs F7.5 per-session registry-proxy wiring for a freshly
// registered session. When the F5.5 proxy is configured it builds a per-session
// regproxy.Proxy (bound to the session's resolved creds + trace recorder), binds
// its listener to the F5.8 bridge gateway (source-scoped, never 0.0.0.0), and
// appends the ecosystem routing env (PIP_INDEX_URL/NPM_CONFIG_REGISTRY/GOPROXY ->
// the gateway proxy URL) to s.credEnv — NEVER a credential (the proxy injects the
// upstream credential server-side). It is FAIL-CLOSED: a build/listener failure, or
// a NetworkInfo-capable runtime with no reachable gateway, injects NO routing env
// and NO open-egress fallback. A nil injector / disabled proxy is a clean no-op.
// Called before the session enters the live map, so s.credEnv/s.registry are set
// without a lock.
func (m *Manager) injectRegistryProxy(s *Session, sn sessionNet) {
	if m.registryInject == nil || !m.registryInject.enabled {
		return
	}
	// F5.8 reachable bind, mirroring the egress path: bind the credential-injecting
	// proxy listener to the discovered gateway (source-scoped), fail closed when the
	// capability is present but no gateway is reachable, and keep the legacy loopback
	// bind when the capability is absent (unit tests / runtimes without NetworkInfo).
	var listen func() (net.Listener, error)
	var sourceIP, advertiseHost string
	if sn.known {
		if !sn.ok {
			m.log.Warn("registry proxy disabled: no reachable gateway bind (fail-closed, no open-egress fallback)", "session", s.ID)
			return
		}
		gwAddr := net.JoinHostPort(sn.gatewayIP, "0")
		listen = func() (net.Listener, error) { return m.listenTCP("tcp", gwAddr) }
		sourceIP = sn.containerIP
		advertiseHost = sn.gatewayIP
	}
	sr, err := m.registryInject.buildForSession(s.ID, s.policy, s.rec, listen, sourceIP, advertiseHost)
	if err != nil {
		m.log.Warn("registry proxy build failed; session runs without the operator install path (fail-closed)", "session", s.ID, "err", err)
		return
	}
	if sr == nil {
		return // proxy not configured (opt-in no-op)
	}
	s.credEnv = append(s.credEnv, sr.env...)
	s.registry = sr
	m.log.Info("registry proxy path active", "session", s.ID, "proxy", "http://"+sr.addr)
}

// RegistryAllowed is the F7.5 pre-install allowlist gate the operator CLI hits via
// the daemon before running an install. It reports whether the registry proxy is
// configured at all (configured) and whether ecosystem+name is allowlisted
// (allowed). A daemon with no registry proxy returns configured=false so the CLI
// fails closed ("install unavailable") rather than ever running an open-egress
// install. It resolves NOTHING and touches no session — it is a pure config query.
func (m *Manager) RegistryAllowed(ecosystem, name string) (configured, allowed bool, err error) {
	if m.registryInject == nil || !m.registryInject.enabled {
		return false, false, nil
	}
	ok, aerr := m.registryInject.Allowed(regproxy.Ecosystem(ecosystem), name)
	if aerr != nil {
		return true, false, aerr
	}
	return true, ok, nil
}

// runExec is the shared spawn+stream core used by the allow path (Exec) and the
// approved path (ResolveApproval): it emits exec.start, runs the command via the
// F0.3 Runtime, streams bounded output through the trace-wrapping sink, and emits
// exec.end. duration is measured on the injected clock (deterministic in tests).
// It performs NO policy classification — the caller has already decided to spawn.
func (m *Manager) runExec(ctx context.Context, id string, rt runtime.Runtime, handle runtime.ContainerHandle, rec *trace.Recorder, opts ExecOptions, sink ExecSink) error {
	start := m.clock.Now()
	if rec != nil {
		_ = rec.Emit(ctx, trace.TypeExecStart, map[string]any{
			"argv": opts.Argv,
			"cwd":  opts.Cwd,
		})
	}

	// F5.1: merge the session's injected credential env into this exec. credEnv holds
	// only scoped, TTL-bounded artifacts (AWS endpoint URI + per-session token, or a
	// short-lived GCP/Azure token) — never a raw durable secret. Caller env comes
	// first so a session's injected creds are authoritative and cannot be shadowed by
	// a caller-supplied duplicate key.
	m.mu.Lock()
	var credEnv []string
	if cur, ok := m.sessions[id]; ok {
		credEnv = cur.credEnv
	}
	m.mu.Unlock()
	env := opts.Env
	if len(credEnv) > 0 {
		env = append(append([]string(nil), opts.Env...), credEnv...)
	}

	req := runtime.ExecRequest{
		Argv:    opts.Argv,
		Env:     env,
		Workdir: opts.Cwd,
	}
	es, err := rt.Exec(ctx, handle, req)
	if err != nil {
		if rec != nil {
			_ = rec.Emit(ctx, trace.TypeExecEnd, map[string]any{
				"exit_code":   -1,
				"duration_ms": m.clock.Now().Sub(start).Milliseconds(),
				"error":       err.Error(),
			})
		}
		return fmt.Errorf("session: exec in %s: %w", id, err)
	}

	if rec == nil {
		return streamExec(ctx, sink, es, m.cfg.ChunkSize, m.cfg.OutputCap)
	}
	tsink := newTraceExecSink(ctx, rec, sink)
	serr := streamExec(ctx, tsink, es, m.cfg.ChunkSize, m.cfg.OutputCap)
	_ = rec.Emit(ctx, trace.TypeExecEnd, map[string]any{
		"exit_code":   tsink.exitCode(),
		"duration_ms": m.clock.Now().Sub(start).Milliseconds(),
	})
	return serr
}

// Destroy tears down a session: destroy the container, drop the record, and
// clean the scratch workspace. Deterministic cleanup — no leaked sandboxes.
// Destroying an unknown/ended session returns ErrNotFound.
func (m *Manager) Destroy(ctx context.Context, id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	delete(m.sessions, id)
	s.State = StateEnded
	m.mu.Unlock()
	return m.teardown(ctx, s, true, "destroyed")
}

// teardown destroys the container + workspace + record for an already-detached
// session. Errors are joined so a container-destroy failure still attempts (and
// reports) the record/workspace cleanup rather than leaking silently.
// teardown destroys the container + record for an already-detached session.
// snapshot=true commits a workspace rootfs snapshot first — set on a clean end
// (Destroy / TTL reap / graceful Shutdown), where the container is live and its
// state worth preserving. It is FALSE on restart Reconcile: an orphan from a
// prior daemon life is reaped, not re-snapshotted (its clean state is already in
// the last graceful snapshot, and the /workspace host dir carries the real
// state regardless — re-snapshotting a stale container on every restart would
// only churn the retention window with near-empty rootfs commits).
func (m *Manager) teardown(ctx context.Context, s *Session, snapshot bool, reason string) error {
	// FAIL-CLOSED: a session that ends (Destroy / TTL reap / graceful Shutdown /
	// restart reconcile) while an approval is still pending auto-DENIES it — never
	// auto-approves — and emits its policy.decision(denied, reason=session_end)
	// into the chain BEFORE the terminal session.end below, so no pending state is
	// leaked and the audit trail is complete.
	m.cancelSessionApprovals(ctx, s, "session_end")

	// F5.1: drop this session's endpoint credential so its per-session token can
	// never fetch again after teardown (idempotent; safe on the reconcile path).
	if m.credInjector != nil {
		m.credInjector.Release(s.ID)
	}
	// F5.8: close the per-session gateway-bound creds-endpoint listener (if any) so
	// it never outlives the session. Idempotent-safe on the reconcile path (an
	// orphan carries no live endpoint handle).
	if s.credEndpoint != nil {
		s.credEndpoint.close()
		s.credEndpoint = nil
	}

	// F5.7: tear down this session's egress proxy + listener. The per-session CA is
	// scrapped with the proxy (no cross-session reuse); a second session gets a fresh
	// CA/listener. Idempotent-safe on the reconcile path (an orphan carries no live
	// egress handle).
	if s.egress != nil {
		s.egress.close()
		s.egress = nil
	}

	// F7.5: tear down this session's registry proxy + listener so the per-session
	// proxy never outlives the session (no cross-session reuse). Idempotent-safe on
	// the reconcile path (an orphan carries no live registry handle).
	if s.registry != nil {
		s.registry.close()
		s.registry = nil
	}

	// Close the trace chain: emit the terminal session.end, then seal (sign the
	// final hash with the daemon identity). A nil recorder (tracing unwired, or an
	// orphan reconstructed on restart with no in-memory chain) makes this a no-op.
	if s.rec != nil {
		if err := s.rec.Emit(ctx, trace.TypeSessionEnd, map[string]any{"reason": reason}); err != nil {
			m.log.Warn("trace session.end emit failed", "session", s.ID, "err", err)
		}
		if _, err := s.rec.Seal(ctx); err != nil {
			m.log.Warn("trace seal failed", "session", s.ID, "err", err)
		}
	}

	var errs []error
	rt, rErr := m.resolve(s.Tier, s.Location)
	if rErr != nil {
		errs = append(errs, rErr)
	}
	// Workspace mode, clean end: commit a rootfs snapshot BEFORE destroying the
	// container (it must still exist to commit), record it (restart-surviving),
	// and prune to retention. The /workspace host dir is the real state carrier
	// and persists on its own — snapshotWorkspace never touches it.
	if snapshot && rErr == nil && s.Mode == ModeWorkspace && s.Name != "" {
		if err := m.snapshotWorkspace(ctx, rt, s); err != nil {
			errs = append(errs, err)
		}
	}
	if rErr == nil {
		if err := rt.Destroy(ctx, s.Handle); err != nil {
			errs = append(errs, err)
		}
	}
	// Remove the session's egress rules. Idempotent, so it is safe on the
	// reconcile/reap paths too (a session whose egress was never set up, or a
	// restart orphan, tears down cleanly with no rule leak).
	if err := m.egress.TeardownSession(ctx, s.ID); err != nil {
		errs = append(errs, err)
	}
	if err := m.store.Delete(s.ID); err != nil {
		errs = append(errs, err)
	}
	// Only scratch sessions discard their (per-session) workspace dir. A
	// workspace's per-NAME dir persists across sessions for the next resume — it
	// is removed only by `ws rm` (RemoveWorkspace).
	if s.Mode == ModeScratch {
		m.cleanupWorkspace(s.WorkspaceDir)
	}
	if len(errs) > 0 {
		return fmt.Errorf("session: teardown %s: %w", s.ID, errors.Join(errs...))
	}
	m.log.Info("session destroyed", "session", s.ID)
	return nil
}

// ActivePolicy returns the daemon's resolved baseline policy (F4.1) — the
// read-only view behind `GET /v1/policy`. It resolves the trusted DefaultPolicy
// on its own (no per-session workspace narrowing), so it reports the daemon's
// standing posture. The result carries only references/metadata, never a secret
// value.
func (m *Manager) ActivePolicy() policy.Resolved {
	return policy.ResolveDefault(m.cfg.DefaultPolicy)
}

// resolveCreatePolicy resolves the F4.1 policy used for F4.2 spin-up enforcement,
// BEFORE any container is built. A scratch session has an ephemeral, freshly
// empty /workspace and therefore never carries a workspace policy file — it runs
// under `base` alone. A workspace session's stable per-name dir may hold an
// (untrusted) opslify.policy.yaml, resolved (narrowed) over `base`; an invalid
// file is a hard, fail-closed error (refuse to serve).
//
// base is the TRUSTED baseline the session starts from: the daemon default under
// F4.1, and under F8.1 the daemon default already narrowed by the project and
// environment layers (each of which could itself only narrow). The workspace is
// therefore always the LAST and least-trusted rung of the same chain.
func (m *Manager) resolveCreatePolicy(mode Mode, name string, base policy.Policy) (policy.Resolved, error) {
	if mode != ModeWorkspace || m.cfg.WorkspaceRoot == "" {
		return policy.ResolveDefault(base), nil
	}
	return m.resolvePolicy(base, m.workspaceDir(name))
}

// enforceTier returns the tier the session must run at, or ErrPolicyDenied when
// the caller EXPLICITLY requested a tier weaker than the policy-required floor.
//
// The floor is derived ONLY from trusted sources — the daemon config default and
// the daemon POLICY pin — NEVER a workspace-supplied tier. This is the F4.1
// carry-over teeth: F4.1's narrowing lets a workspace session.tier pass through
// UNCLAMPED when the daemon policy leaves session.tier unset, so enforcement must
// not read resolved.Session.Tier in that case. When the daemon policy DOES pin a
// tier, resolved.Session.Tier is trustworthy (narrowing can only make it more
// isolated), so it is honoured as an additional floor.
// F8.1 extends "trusted" from the daemon policy alone to scope.base, the daemon
// policy already narrowed by the project and environment layers (both daemon-side
// records, each of which could itself only narrow). That is what lets a prod
// environment overlay impose a stricter rung than staging while a workspace file
// still cannot impose or relax one. With no project service wired, scope.base IS
// cfg.DefaultPolicy, so the pre-F8.1 behaviour is unchanged.
func (m *Manager) enforceTier(reqTier runtime.Tier, resolved policy.Resolved, scope sessionScope) (runtime.Tier, error) {
	// Running tier: the explicit request, else the scope default (the
	// environment's default_tier, or the daemon config default when it sets none).
	// The default is a DEFAULT, not a floor, so a caller may still pick the weaker
	// compat rung when no policy constrains it.
	tier := reqTier
	if tier == "" {
		tier = scope.tier
	}
	// A policy floor exists ONLY when the TRUSTED policy pins a tier. Then
	// resolved.Session.Tier is trustworthy (F4.1 narrowing can only make it MORE
	// isolated than the trusted pin). When the trusted side leaves session.tier
	// unset we deliberately do NOT read resolved.Session.Tier -- it is the
	// workspace's pass-through value -- so a workspace can neither impose nor
	// relax a tier (the F4.1 carry-over is satisfied by ignoring it outright).
	if scope.base.Session.Tier == "" {
		return tier, nil
	}
	floorRank, ok := policy.TierRank(resolved.Session.Tier)
	if !ok {
		return tier, nil
	}
	tRank, ok := policy.TierRank(string(tier))
	if !ok {
		return "", fmt.Errorf("%w: unknown tier %q", ErrInvalidInput, tier)
	}
	if tRank < floorRank {
		if reqTier != "" {
			// Explicitly requested a tier weaker than the policy floor → refuse.
			return "", fmt.Errorf("%w: requested tier %q is weaker than the policy-required minimum %q", ErrPolicyDenied, reqTier, resolved.Session.Tier)
		}
		// The config default is weaker than the policy floor → upgrade to the floor.
		return runtime.Tier(resolved.Session.Tier), nil
	}
	return tier, nil
}

// enforceTTL clamps the session ttl to the daemon-authoritative maximum. Like
// enforceTier, the maximum comes from trusted sources only: the daemon config
// default, tightened by the daemon POLICY ttl when it is set (resolved.Session.TTL
// is then trustworthy — narrowing takes the MIN, so it is never longer than the
// daemon pin). When the daemon policy leaves ttl unset, resolved.Session.TTL is
// the workspace's pass-through value and is IGNORED (the carry-over) — the bound
// is cfg.DefaultTTL, so a workspace proposing a longer ttl cannot lengthen the
// session. A requested ttl longer than the bound is clamped down, never honoured.
// F8.1: the bound comes from scope.base (daemon, narrowed by project and
// environment) and the fallback from the environment's default_ttl, so a prod
// overlay can shorten every session in it. A workspace still cannot lengthen one.
func (m *Manager) enforceTTL(reqTTL time.Duration, resolved policy.Resolved, scope sessionScope) time.Duration {
	ttl := reqTTL
	if ttl <= 0 {
		ttl = scope.ttl
	}
	// A ttl bound exists ONLY when the TRUSTED policy pins one. resolved.Session.TTL
	// is then trustworthy (narrowing takes the MIN, so it is never longer than the
	// trusted pin). When the trusted side leaves ttl unset we do NOT read the
	// resolved value (the workspace's pass-through), so a workspace proposing a
	// longer ttl can never lengthen the session (the F4.1 carry-over).
	if scope.base.Session.TTL == "" {
		return ttl
	}
	if d, err := time.ParseDuration(resolved.Session.TTL); err == nil && d > 0 {
		if ttl <= 0 || ttl > d {
			ttl = d
		}
	}
	return ttl
}

// resolvePolicy resolves the F4.1 policy for a session whose /workspace is
// backed by host dir wsDir. It reads an optional workspace policy file at
// <wsDir>/opslify.policy.yaml — untrusted, agent-controlled input — and NARROWS
// it over the daemon default (policy.Resolve), which structurally forbids the
// workspace from widening any grant. It fails CLOSED on three counts:
//   - an unparseable/invalid workspace policy is a hard error (refuse to serve),
//     never a silent fall-back to the permissive default;
//   - a workspace grant beyond the daemon's is dropped/clamped by Resolve (each
//     drop logged from resolved.Notes);
//   - when no file is present, the daemon default alone is resolved (its hash is
//     policy.DefaultHash for an empty default).
//
// An empty wsDir (WorkspaceRoot unset, e.g. many unit tests) yields the daemon
// default with no file read.
// base is the trusted baseline the workspace narrows over: the daemon default
// under F4.1, and under F8.1 that default already narrowed by the project and
// environment layers.
func (m *Manager) resolvePolicy(base policy.Policy, wsDir string) (policy.Resolved, error) {
	if wsDir == "" {
		return policy.ResolveDefault(base), nil
	}
	path := filepath.Join(wsDir, policy.DefaultFileName)
	ws, err := policy.Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			return policy.ResolveDefault(base), nil
		}
		// Invalid/unreadable workspace policy: refuse to serve (fail-closed). The
		// error carries layer context; the caller aborts the create.
		return policy.Resolved{}, fmt.Errorf("session: policy: %w", err)
	}
	resolved := policy.Resolve(base, ws)
	for _, note := range resolved.Notes {
		m.log.Warn("policy narrowed", "workspace_dir", wsDir, "reason", note)
	}
	return resolved, nil
}

// workspaceDir is the stable host directory backing a workspace name's
// /workspace across sessions and restarts. name is validated before this.
func (m *Manager) workspaceDir(name string) string {
	return filepath.Join(m.cfg.WorkspaceRoot, "ws-"+name)
}

// snapshotWorkspace commits the container's rootfs to opslify/ws-<name>:<tag>,
// appends it to the workspace's restart-surviving record, prunes older snapshots
// past the retention cap (removing their images best-effort), and persists the
// record. Called from teardown while the container is still alive.
func (m *Manager) snapshotWorkspace(ctx context.Context, rt runtime.Runtime, s *Session) error {
	rec, _, err := m.store.LoadWorkspace(s.Name)
	if err != nil {
		return fmt.Errorf("session: load workspace %q: %w", s.Name, err)
	}
	rec.Name = s.Name
	tag := rec.nextTag()
	image := fmt.Sprintf("%s%s:%d", wsImagePrefix, s.Name, tag)
	if _, err := rt.Snapshot(ctx, s.Handle, image); err != nil {
		return fmt.Errorf("session: snapshot workspace %q: %w", s.Name, err)
	}
	rec.Snapshots = append(rec.Snapshots, snapshotMeta{Image: image, Tag: tag, Created: m.clock.Now()})

	ret := m.cfg.SnapshotRetention
	if ret <= 0 {
		ret = DefaultSnapshotRetention
	}
	if len(rec.Snapshots) > ret {
		prune := rec.Snapshots[:len(rec.Snapshots)-ret]
		rec.Snapshots = rec.Snapshots[len(rec.Snapshots)-ret:]
		if remover, ok := rt.(runtime.ImageRemover); ok {
			for _, sm := range prune {
				if err := remover.RemoveImage(ctx, sm.Image); err != nil {
					m.log.Warn("prune workspace snapshot image", "workspace", s.Name, "image", sm.Image, "err", err)
				}
			}
		}
	}
	return m.store.SaveWorkspace(rec)
}

// WorkspaceView summarises a persisted workspace for `opslify ws ls`.
type WorkspaceView struct {
	Name       string    `json:"name"`
	Snapshots  int       `json:"snapshots"`
	LatestTag  int       `json:"latest_tag"`
	LatestTime time.Time `json:"latest_time,omitempty"`
}

// ListWorkspaces returns every persisted workspace (name + snapshot summary),
// name-sorted — the data behind `opslify ws ls`.
func (m *Manager) ListWorkspaces() ([]WorkspaceView, error) {
	recs, err := m.store.LoadWorkspaces()
	if err != nil {
		return nil, err
	}
	out := make([]WorkspaceView, 0, len(recs))
	for _, r := range recs {
		v := WorkspaceView{Name: r.Name, Snapshots: len(r.Snapshots)}
		if n := len(r.Snapshots); n > 0 {
			v.LatestTag = r.Snapshots[n-1].Tag
			v.LatestTime = r.Snapshots[n-1].Created
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// RemoveWorkspace deletes a workspace end-to-end: its snapshot images (best
// effort, via ImageRemover), its persisted record, and its /workspace host dir.
// It refuses while a live session is using the workspace so state is never
// pulled from under a running sandbox. A missing workspace is not an error.
func (m *Manager) RemoveWorkspace(ctx context.Context, name string) error {
	if err := validateWorkspaceName(name); err != nil {
		return err
	}
	// Serialize against workspace create (see Create): holding wsMu means an
	// in-flight create of this name has either finished (its session is now
	// visible to the in-use check below and we refuse) or has not started (and
	// will block until we finish), so the dir is never removed mid-start.
	m.wsMu.Lock()
	defer m.wsMu.Unlock()

	m.mu.Lock()
	for _, s := range m.sessions {
		if s.Mode == ModeWorkspace && s.Name == name {
			m.mu.Unlock()
			return fmt.Errorf("%w: workspace %q in use by session %s", ErrInvalidInput, name, s.ID)
		}
	}
	m.mu.Unlock()

	rec, ok, err := m.store.LoadWorkspace(name)
	if err != nil {
		return err
	}
	if ok {
		if rt, rErr := m.resolve(m.cfg.DefaultTier, runtime.LocationLocal); rErr == nil {
			if remover, isRemover := rt.(runtime.ImageRemover); isRemover {
				for _, sm := range rec.Snapshots {
					if err := remover.RemoveImage(ctx, sm.Image); err != nil {
						m.log.Warn("ws rm: remove snapshot image", "workspace", name, "image", sm.Image, "err", err)
					}
				}
			}
		}
		if err := m.store.DeleteWorkspace(name); err != nil {
			return err
		}
	}
	if m.cfg.WorkspaceRoot != "" {
		m.cleanupWorkspace(m.workspaceDir(name))
	}
	return nil
}

// List returns a stable (id-sorted) snapshot of live sessions as views.
func (m *Manager) List() []View {
	now := m.clock.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]View, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s.view(now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ReapExpired destroys every session idle past its TTL as of now. It is called
// by the reaper goroutine on each tick and directly by tests (deterministic,
// no sleeping). Returns the ids reaped.
func (m *Manager) ReapExpired(ctx context.Context, now time.Time) []string {
	m.mu.Lock()
	var due []*Session
	for _, s := range m.sessions {
		if s.State != StateExecing && s.State != StateAwaitingApproval && s.expired(now) {
			delete(m.sessions, s.ID)
			s.State = StateEnded
			due = append(due, s)
		}
	}
	m.mu.Unlock()

	var reaped []string
	for _, s := range due {
		if err := m.teardown(ctx, s, true, "ttl"); err != nil {
			m.log.Warn("reaper teardown error", "session", s.ID, "err", err)
		}
		m.log.Info("session reaped (ttl)", "session", s.ID)
		reaped = append(reaped, s.ID)
	}
	return reaped
}

// Reconcile is called once at startup: every persisted record is an orphan from
// a previous daemon lifetime (the daemon is the only executor, so nothing else
// is driving those containers). Destroy each and drop its record so a restart
// never leaks sandboxes. Returns the ids reaped.
func (m *Manager) Reconcile(ctx context.Context) ([]string, error) {
	records, err := m.store.LoadAll()
	if err != nil {
		return nil, err
	}
	var reaped []string
	for _, r := range records {
		s := sessionOf(r)
		if err := m.teardown(ctx, s, false, "reconcile"); err != nil {
			// Log and continue: one un-reapable orphan must not block startup or
			// stop us reaping the rest. The record is left so a later sweep retries.
			m.log.Warn("orphan reconcile teardown error", "session", r.ID, "err", err)
			continue
		}
		m.log.Info("orphan sandbox reaped on restart", "session", r.ID, "container", r.Handle.ID)
		reaped = append(reaped, r.ID)
	}
	return reaped, nil
}

// StartReaper launches the TTL reaper goroutine, ticking every interval. Stop
// with StopReaper. The goroutine uses the injected clock for the expiry decision
// so tests need not run it at all (they call ReapExpired directly).
func (m *Manager) StartReaper(interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	m.reaperStop = make(chan struct{})
	m.reaperDone = make(chan struct{})
	go func() {
		defer close(m.reaperDone)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-m.reaperStop:
				return
			case <-t.C:
				now := m.clock.Now()
				m.ExpireApprovals(context.Background(), now)
				m.ReapExpired(context.Background(), now)
			}
		}
	}()
}

// StopReaper stops the reaper goroutine and waits for it to exit.
func (m *Manager) StopReaper() {
	if m.reaperStop == nil {
		return
	}
	close(m.reaperStop)
	<-m.reaperDone
	m.reaperStop = nil
}

// Shutdown stops the reaper and destroys every live session (deterministic
// cleanup on daemon shutdown; the reaper-on-restart path is the safety net).
func (m *Manager) Shutdown(ctx context.Context) {
	m.StopReaper()
	// Drain the warm pool first so no paused warm container is leaked on exit
	// (F1.3 acceptance: no warm containers leak on shutdown). This blocks until
	// every in-flight builder has finished and every warm container is destroyed.
	if m.pool != nil {
		m.pool.close(ctx)
	}
	m.mu.Lock()
	var all []*Session
	for id, s := range m.sessions {
		delete(m.sessions, id)
		s.State = StateEnded
		all = append(all, s)
	}
	m.mu.Unlock()
	for _, s := range all {
		if err := m.teardown(ctx, s, true, "shutdown"); err != nil {
			m.log.Warn("shutdown teardown error", "session", s.ID, "err", err)
		}
	}
}

func (m *Manager) cleanupWorkspace(dir string) {
	if dir == "" {
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		m.log.Warn("workspace cleanup failed", "dir", dir, "err", err)
	}
}

// newID returns a random 128-bit hex session id (collision-resistant, opaque).
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session: generate id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func recordOf(s *Session) record {
	return record{
		ID:            s.ID,
		Mode:          s.Mode,
		Tier:          s.Tier,
		Location:      s.Location,
		Handle:        s.Handle,
		WorkspaceDir:  s.WorkspaceDir,
		Created:       s.Created,
		TTL:           s.TTL,
		ProjectID:     s.ProjectID,
		EnvironmentID: s.EnvironmentID,
	}
}

func sessionOf(r record) *Session {
	return &Session{
		ID:            r.ID,
		Mode:          r.Mode,
		Tier:          r.Tier,
		Location:      r.Location,
		State:         StateEnded,
		Handle:        r.Handle,
		WorkspaceDir:  r.WorkspaceDir,
		Created:       r.Created,
		TTL:           r.TTL,
		ProjectID:     r.ProjectID,
		EnvironmentID: r.EnvironmentID,
	}
}

// ExecOptions is the mediated exec input, validated at the trust boundary.
type ExecOptions struct {
	Argv     []string
	Cwd      string
	Env      []string // "KEY=VALUE"; NEVER secrets (P5 broker injects those)
	Stdin    []byte
	Writable []string // per-exec micro-scoping grant (paths under /workspace)
}

// validate enforces the boundary contract: the sandbox occupant is hostile and
// so is a buggy caller. It rejects empty/oversized argv, NUL injection, malformed
// env, non-absolute cwd, and writable grants escaping /workspace.
func (o ExecOptions) validate() error {
	if len(o.Argv) == 0 {
		return fmt.Errorf("%w: empty argv", ErrInvalidInput)
	}
	if len(o.Argv) > 4096 {
		return fmt.Errorf("%w: argv too long", ErrInvalidInput)
	}
	for _, a := range o.Argv {
		if strings.ContainsRune(a, '\x00') {
			return fmt.Errorf("%w: NUL byte in argv", ErrInvalidInput)
		}
	}
	for _, e := range o.Env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" || strings.ContainsRune(e, '\x00') {
			return fmt.Errorf("%w: env entry must be KEY=VALUE without NUL: %q", ErrInvalidInput, e)
		}
	}
	if o.Cwd != "" {
		if strings.ContainsRune(o.Cwd, '\x00') {
			return fmt.Errorf("%w: NUL byte in cwd", ErrInvalidInput)
		}
		if !strings.HasPrefix(o.Cwd, "/") {
			return fmt.Errorf("%w: cwd must be absolute: %q", ErrInvalidInput, o.Cwd)
		}
	}
	for _, p := range o.Writable {
		clean := filepath.Clean(p)
		if clean != "/workspace" && !strings.HasPrefix(clean, "/workspace/") {
			return fmt.Errorf("%w: writable grant %q must be under /workspace", ErrInvalidInput, p)
		}
	}
	return nil
}
