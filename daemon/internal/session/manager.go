package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
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
	log       *slog.Logger

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

	mu       sync.Mutex
	sessions map[string]*Session

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
type Options struct {
	Config  ManagerConfig
	Resolve resolveFunc
	Clock   Clock
	Store   Store
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
		cfg:       cfg,
		approvals: make(map[string]*approval),
		resolve:   opts.Resolve,
		clock:     opts.Clock,
		store:     opts.Store,
		egress:    opts.Egress,
		sandboxIP: opts.SandboxIP,
		log:       opts.Logger,
		trace:     opts.Trace,
		redactor:  opts.Redactor,
		broker:    opts.Broker,
		sessions:  make(map[string]*Session),
	}
	if m.redactor == nil {
		m.redactor = trace.NoopRedactor{}
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
	Tier     runtime.Tier     // empty => cfg.DefaultTier
	Location runtime.Location // empty => local
	TTL      time.Duration    // <=0 => cfg.DefaultTTL
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

	// F4.2 session-spin-up enforcement. Resolve the policy in force FIRST, then
	// clamp the session's tier/ttl to the daemon-authoritative bounds. This runs
	// before any container is built, so a policy-forbidden request is refused
	// without ever touching the runtime (fail-closed spin-up).
	resolved, err := m.resolveCreatePolicy(mode, name)
	if err != nil {
		return nil, err
	}
	tier, err := m.enforceTier(req.Tier, resolved)
	if err != nil {
		// Legible, layer-tagged refusal — the requested tier is weaker than the
		// policy floor. No sandbox is created.
		m.log.Warn("policy denied session spin-up", "reason", err.Error(), "policy_hash", resolved.Hash)
		return nil, err
	}
	ttl := m.enforceTTL(req.TTL, resolved)

	// Fast path: claim a pre-warmed sandbox. The pool holds only generic SCRATCH
	// containers (no per-name workspace dir or resume base), so a workspace create
	// always takes the on-demand realize path — never a warm claim.
	if m.pool != nil && mode == ModeScratch {
		if s, err := m.pool.claim(ctx, tier, loc, mode, ttl); err != nil {
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

	s, err := m.realize(ctx, tier, loc, mode, name, ttl, StateReady, resolved)
	if err != nil {
		return nil, err
	}
	m.registerReady(s, "created")
	return s, nil
}

// realize builds one sandbox and persists its record, returning it in state st.
// It is the SINGLE create path shared by on-demand Create and warm-pool
// pre-create, so a warm container is guaranteed identical to an on-demand one:
// same hardening hard-spec (F0.3 base) and same signed toolchain digest. It does
// NOT register the session in the live map — the caller (Create for ready
// sessions; the pool for warm ones) decides that.
func (m *Manager) realize(ctx context.Context, tier runtime.Tier, loc runtime.Location, mode Mode, name string, ttl time.Duration, st State, resolved policy.Resolved) (*Session, error) {
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
		ID:           id,
		Mode:         mode,
		Name:         name,
		Tier:         tier,
		Location:     loc,
		State:        st,
		Handle:       handle,
		WorkspaceDir: wsDir,
		Created:      now,
		LastActivity: now,
		TTL:          ttl,
		policyHash:   resolved.Hash,
		policy:       resolved,
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
	if m.trace != nil {
		s.rec = trace.NewRecorder(m.trace, s.ID, m.redactor, m.clock.Now)
		if err := s.rec.Emit(context.Background(), trace.TypeSessionStart, map[string]any{
			"schema_version":      trace.SchemaVersion,
			"tier":                string(s.Tier),
			"mode":                string(s.Mode),
			"agent":               "",
			"image_digest":        m.cfg.Image,
			"toolchain_lock_hash": m.toolchainDigest(),
			"policy_hash":         s.policyHash, // F4.1: resolved policy_hash
		}); err != nil {
			m.log.Warn("trace session.start emit failed", "session", s.ID, "err", err)
		}
	}
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

	req := runtime.ExecRequest{
		Argv:    opts.Argv,
		Env:     opts.Env,
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

// resolveCreatePolicy resolves the F4.1 policy used for F4.2 spin-up enforcement,
// BEFORE any container is built. A scratch session has an ephemeral, freshly
// empty /workspace and therefore never carries a workspace policy file — it runs
// under the daemon default. A workspace session's stable per-name dir may hold an
// (untrusted) opslify.policy.yaml, resolved (narrowed) over the daemon default;
// an invalid file is a hard, fail-closed error (refuse to serve).
func (m *Manager) resolveCreatePolicy(mode Mode, name string) (policy.Resolved, error) {
	if mode != ModeWorkspace || m.cfg.WorkspaceRoot == "" {
		return policy.ResolveDefault(m.cfg.DefaultPolicy), nil
	}
	return m.resolvePolicy(m.workspaceDir(name))
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
func (m *Manager) enforceTier(reqTier runtime.Tier, resolved policy.Resolved) (runtime.Tier, error) {
	// Running tier: the explicit request, else the daemon config default (prior
	// behavior — the config default is a DEFAULT, not a floor, so a caller may
	// still pick the weaker compat rung when no policy constrains it).
	tier := reqTier
	if tier == "" {
		tier = m.cfg.DefaultTier
	}
	// A policy floor exists ONLY when the daemon policy pins a tier. Then
	// resolved.Session.Tier is trustworthy (F4.1 narrowing can only make it MORE
	// isolated than the daemon pin). When the daemon policy leaves session.tier
	// unset we deliberately do NOT read resolved.Session.Tier — it is the
	// workspace's pass-through value — so a workspace can neither impose nor relax
	// a tier (the F4.1 carry-over is satisfied by ignoring it outright).
	if m.cfg.DefaultPolicy.Session.Tier == "" {
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
func (m *Manager) enforceTTL(reqTTL time.Duration, resolved policy.Resolved) time.Duration {
	ttl := reqTTL
	if ttl <= 0 {
		ttl = m.cfg.DefaultTTL
	}
	// A ttl bound exists ONLY when the daemon policy pins one. resolved.Session.TTL
	// is then trustworthy (narrowing takes the MIN, so it is never longer than the
	// daemon pin). When the daemon policy leaves ttl unset we do NOT read the
	// resolved value (the workspace's pass-through) — so a workspace proposing a
	// longer ttl can never lengthen the session (the F4.1 carry-over).
	if m.cfg.DefaultPolicy.Session.TTL == "" {
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
func (m *Manager) resolvePolicy(wsDir string) (policy.Resolved, error) {
	if wsDir == "" {
		return policy.ResolveDefault(m.cfg.DefaultPolicy), nil
	}
	path := filepath.Join(wsDir, policy.DefaultFileName)
	ws, err := policy.Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			return policy.ResolveDefault(m.cfg.DefaultPolicy), nil
		}
		// Invalid/unreadable workspace policy: refuse to serve (fail-closed). The
		// error carries layer context; the caller aborts the create.
		return policy.Resolved{}, fmt.Errorf("session: policy: %w", err)
	}
	resolved := policy.Resolve(m.cfg.DefaultPolicy, ws)
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
		ID:           s.ID,
		Mode:         s.Mode,
		Tier:         s.Tier,
		Location:     s.Location,
		Handle:       s.Handle,
		WorkspaceDir: s.WorkspaceDir,
		Created:      s.Created,
		TTL:          s.TTL,
	}
}

func sessionOf(r record) *Session {
	return &Session{
		ID:           r.ID,
		Mode:         r.Mode,
		Tier:         r.Tier,
		Location:     r.Location,
		State:        StateEnded,
		Handle:       r.Handle,
		WorkspaceDir: r.WorkspaceDir,
		Created:      r.Created,
		TTL:          r.TTL,
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
