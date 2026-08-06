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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// namePrefix labels every sandbox the daemon creates. It makes containers
// attributable to opslify and gives a future `podman ps --filter` sweep a hook
// for out-of-band orphan detection (the persisted-record reconcile is the path
// unit-tested here; the podman sweep is gated on a real engine).
const namePrefix = "opslify-sess-"

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
	log     *slog.Logger

	mu       sync.Mutex
	sessions map[string]*Session

	// digestMu guards cfg.ToolchainDigest, which SetToolchainDigest mutates at
	// runtime (a signed-toolchain rotation). realize reads it through
	// toolchainDigest() so the on-demand and warm-pool create paths always agree
	// on the current digest — safe under -race.
	digestMu sync.RWMutex

	// pool is the F1.3 warm pool (nil when WarmPoolSize == 0). Create claims from
	// it before falling back to on-demand realize.
	pool *warmPool

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
	Logger  *slog.Logger
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

	m := &Manager{
		cfg:      cfg,
		resolve:  opts.Resolve,
		clock:    opts.Clock,
		store:    opts.Store,
		log:      opts.Logger,
		sessions: make(map[string]*Session),
	}
	if m.resolve == nil {
		m.resolve = runtime.ResolveRuntime
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
	tier := req.Tier
	if tier == "" {
		tier = m.cfg.DefaultTier
	}
	loc := req.Location
	if loc == "" {
		loc = runtime.LocationLocal
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = m.cfg.DefaultTTL
	}

	// Fast path: claim a pre-warmed sandbox. The pool triggers its own background
	// replenishment; the claim itself never waits on it.
	if m.pool != nil {
		if s, err := m.pool.claim(ctx, tier, loc, mode, ttl); err != nil {
			return nil, err
		} else if s != nil {
			m.registerReady(s, "claimed")
			return s, nil
		}
		// Pool miss (empty or wrong rung): fall through to on-demand create.
	}

	s, err := m.realize(ctx, tier, loc, mode, ttl, StateReady)
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
func (m *Manager) realize(ctx context.Context, tier runtime.Tier, loc runtime.Location, mode Mode, ttl time.Duration, st State) (*Session, error) {
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

	// Per-session writable workspace on the host, mounted rw at /workspace. The
	// one persistent writable path; everything else is read-only rootfs + the RO
	// toolchain (asserted in F0.3's hardening base).
	wsDir := filepath.Join(m.cfg.WorkspaceRoot, id)
	if m.cfg.WorkspaceRoot != "" {
		if err := os.MkdirAll(wsDir, 0o700); err != nil {
			return nil, fmt.Errorf("session: create workspace %s: %w", wsDir, err)
		}
	} else {
		wsDir = ""
	}

	spec := runtime.SessionSpec{
		Tier:            tier,
		Location:        loc,
		Image:           m.cfg.Image,
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

	s := &Session{
		ID:           id,
		Mode:         mode,
		Tier:         tier,
		Location:     loc,
		State:        st,
		Handle:       handle,
		WorkspaceDir: wsDir,
		Created:      now,
		LastActivity: now,
		TTL:          ttl,
	}

	if err := m.store.Save(recordOf(s)); err != nil {
		// Roll back the container so a persistence failure never leaks a sandbox.
		_ = rt.Destroy(ctx, handle)
		m.cleanupWorkspace(wsDir)
		return nil, err
	}
	return s, nil
}

// registerReady adds a ready session to the live map. origin is "created" (fresh
// on-demand) or "claimed" (from the warm pool) for the audit log.
func (m *Manager) registerReady(s *Session, origin string) {
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

	req := runtime.ExecRequest{
		Argv:    opts.Argv,
		Env:     opts.Env,
		Workdir: opts.Cwd,
	}
	es, err := rt.Exec(ctx, handle, req)
	if err != nil {
		return fmt.Errorf("session: exec in %s: %w", id, err)
	}
	return streamExec(ctx, sink, es, m.cfg.ChunkSize, m.cfg.OutputCap)
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
	return m.teardown(ctx, s)
}

// teardown destroys the container + workspace + record for an already-detached
// session. Errors are joined so a container-destroy failure still attempts (and
// reports) the record/workspace cleanup rather than leaking silently.
func (m *Manager) teardown(ctx context.Context, s *Session) error {
	var errs []error
	if rt, err := m.resolve(s.Tier, s.Location); err != nil {
		errs = append(errs, err)
	} else if err := rt.Destroy(ctx, s.Handle); err != nil {
		errs = append(errs, err)
	}
	if err := m.store.Delete(s.ID); err != nil {
		errs = append(errs, err)
	}
	if s.Mode == ModeScratch {
		m.cleanupWorkspace(s.WorkspaceDir)
	}
	if len(errs) > 0 {
		return fmt.Errorf("session: teardown %s: %w", s.ID, errors.Join(errs...))
	}
	m.log.Info("session destroyed", "session", s.ID)
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
		if s.State != StateExecing && s.expired(now) {
			delete(m.sessions, s.ID)
			s.State = StateEnded
			due = append(due, s)
		}
	}
	m.mu.Unlock()

	var reaped []string
	for _, s := range due {
		if err := m.teardown(ctx, s); err != nil {
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
		if err := m.teardown(ctx, s); err != nil {
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
				m.ReapExpired(context.Background(), m.clock.Now())
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
		if err := m.teardown(ctx, s); err != nil {
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
