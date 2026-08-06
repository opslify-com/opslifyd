package session

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// poolRuntime is a Runtime double that also implements the optional Pauser, with
// enough instrumentation to prove F1.3's invariants without any real engine:
// per-container specs (digest/hardening parity), create/destroy/pause/unpause
// counts, a peak-concurrency observer (bounded-replenish), and an injectable
// per-create delay (so "claim never blocks on replenish" is observable).
type poolRuntime struct {
	createDelay time.Duration

	mu           sync.Mutex
	available    error
	pauseErr     error // when set, Pause fails (drives safe-degradation test)
	created      int
	started      int
	destroyed    int
	paused       int
	unpaused     int
	specs        map[string]runtime.SessionSpec // by container id
	pausedSet    map[string]bool                // currently-paused container ids
	runningSet   map[string]bool                // currently-started (running) ids
	ops          []string                       // ordered op log: "start:ID","pause:ID","unpause:ID"
	destroyedIDs []string

	inFlight int32
	peakConc int32
}

func newPoolRuntime() *poolRuntime {
	return &poolRuntime{
		specs:      map[string]runtime.SessionSpec{},
		pausedSet:  map[string]bool{},
		runningSet: map[string]bool{},
	}
}

func (r *poolRuntime) Create(_ context.Context, spec runtime.SessionSpec) (runtime.ContainerHandle, error) {
	n := atomic.AddInt32(&r.inFlight, 1)
	for {
		peak := atomic.LoadInt32(&r.peakConc)
		if n <= peak || atomic.CompareAndSwapInt32(&r.peakConc, peak, n) {
			break
		}
	}
	if r.createDelay > 0 {
		time.Sleep(r.createDelay)
	}
	atomic.AddInt32(&r.inFlight, -1)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.created++
	id := fmt.Sprintf("ctr-%d", r.created)
	r.specs[id] = spec
	return runtime.ContainerHandle{ID: id, Tier: spec.Tier, Runtime: "runsc"}, nil
}

func (r *poolRuntime) Exec(context.Context, runtime.ContainerHandle, runtime.ExecRequest) (runtime.ExecStream, error) {
	return runtime.ExecStream{Stdout: strings.NewReader(""), Stderr: strings.NewReader("")}, nil
}

func (r *poolRuntime) Destroy(_ context.Context, h runtime.ContainerHandle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.destroyed++
	r.destroyedIDs = append(r.destroyedIDs, h.ID)
	delete(r.pausedSet, h.ID)
	return nil
}

func (r *poolRuntime) Snapshot(context.Context, runtime.ContainerHandle, string) (runtime.ImageRef, error) {
	return runtime.ImageRef{}, nil
}

func (r *poolRuntime) Available() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.available
}

// Start implements the optional runtime.Starter seam: a warm/on-demand container
// must be RUNNING before pause (freeze) or exec.
func (r *poolRuntime) Start(_ context.Context, h runtime.ContainerHandle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started++
	r.runningSet[h.ID] = true
	r.ops = append(r.ops, "start:"+h.ID)
	return nil
}

func (r *poolRuntime) Pause(_ context.Context, h runtime.ContainerHandle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, "pause:"+h.ID)
	if r.pauseErr != nil {
		return r.pauseErr
	}
	if !r.runningSet[h.ID] {
		// Mirror a real engine: pausing a non-running container fails. A test that
		// pauses without starting first would trip this.
		return fmt.Errorf("cannot pause non-running container %s", h.ID)
	}
	r.paused++
	r.pausedSet[h.ID] = true
	return nil
}

func (r *poolRuntime) Unpause(_ context.Context, h runtime.ContainerHandle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unpaused++
	delete(r.pausedSet, h.ID)
	r.ops = append(r.ops, "unpause:"+h.ID)
	return nil
}

func (r *poolRuntime) opLog() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ops...)
}

func (r *poolRuntime) startedCount() int { r.mu.Lock(); defer r.mu.Unlock(); return r.started }

func (r *poolRuntime) counts() (created, destroyed, paused, unpaused int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.created, r.destroyed, r.paused, r.unpaused
}

func (r *poolRuntime) currentlyPaused() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pausedSet)
}

// newPoolManager wires a Manager over rt with a warm pool of the given size and
// concurrency, using an in-memory store and no workspace FS.
func newPoolManager(t *testing.T, rt *poolRuntime, size, conc int, digest string) *Manager {
	t.Helper()
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:               "img@sha256:base",
			ToolchainDigest:     digest,
			DefaultTier:         runtime.TierLocalHardened,
			DefaultTTL:          30 * time.Minute,
			Limits:              runtime.ResourceLimits{MemoryBytes: 2 << 30, CPUs: 2, PidsLimit: 256},
			WarmPoolSize:        size,
			WarmPoolConcurrency: conc,
		},
		Resolve: func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Store:   newMemStore(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func poolReadyLen(p *warmPool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ready)
}

// waitFor polls cond until true or the deadline; fails the test otherwise.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// AC: pool fills to warm_pool_size in the background, containers pre-created and
// paused (frozen) carrying the signed toolchain digest.
func TestWarmPool_FillsAndPauses(t *testing.T) {
	rt := newPoolRuntime()
	m := newPoolManager(t, rt, 3, 2, "sha256:tool-A")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())

	waitFor(t, time.Second, "pool to fill to 3", func() bool { return poolReadyLen(m.pool) == 3 })

	created, _, paused, _ := rt.counts()
	if created != 3 {
		t.Fatalf("created = %d, want 3", created)
	}
	if paused != 3 {
		t.Fatalf("paused = %d, want 3 (every warm container frozen)", paused)
	}
	if got := rt.currentlyPaused(); got != 3 {
		t.Fatalf("currentlyPaused = %d, want 3", got)
	}
}

// AC/QA: warm containers carry the correct signed toolchain digest AND are
// identical to an on-demand session's spec (hardening hard-spec parity). We
// compare a warm-built spec against an on-demand realize on a second manager.
func TestWarmPool_DigestAndHardeningParity(t *testing.T) {
	const digest = "sha256:tool-parity"

	// On-demand spec (no pool): realize one directly.
	rtOnDemand := newPoolRuntime()
	mOnDemand := newPoolManager(t, rtOnDemand, 0, 0, digest)
	sod, err := mOnDemand.realize(context.Background(), runtime.TierLocalHardened, runtime.LocationLocal, ModeScratch, time.Minute, StateReady)
	if err != nil {
		t.Fatalf("on-demand realize: %v", err)
	}
	onDemandSpec := rtOnDemand.specs[sod.Handle.ID]

	// Warm spec (via pool).
	rtWarm := newPoolRuntime()
	mWarm := newPoolManager(t, rtWarm, 1, 1, digest)
	mWarm.StartWarmPool()
	defer mWarm.Shutdown(context.Background())
	waitFor(t, time.Second, "warm fill", func() bool { return poolReadyLen(mWarm.pool) == 1 })
	warmSpec := rtWarm.specs["ctr-1"]

	if warmSpec.ToolchainDigest != digest {
		t.Fatalf("warm ToolchainDigest = %q, want %q", warmSpec.ToolchainDigest, digest)
	}
	// Everything except the per-session Name (embeds a random id) must be equal:
	// same image, digest, limits, tier, entrypoint. That is the parity invariant.
	onDemandSpec.Name = ""
	warmSpec.Name = ""
	if fmt.Sprintf("%+v", onDemandSpec) != fmt.Sprintf("%+v", warmSpec) {
		t.Fatalf("warm spec differs from on-demand spec:\n warm=%+v\n  ond=%+v", warmSpec, onDemandSpec)
	}
}

// AC: a claim yields a ready session sourced from the pool (no fresh create on
// the claim path) and thaws (unpauses) it.
func TestWarmPool_ClaimUsesWarmAndThaws(t *testing.T) {
	rt := newPoolRuntime()
	m := newPoolManager(t, rt, 2, 2, "sha256:tool-A")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())
	waitFor(t, time.Second, "fill to 2", func() bool { return poolReadyLen(m.pool) == 2 })

	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.State != StateReady {
		t.Fatalf("claimed session state = %s, want ready", s.State)
	}
	_, _, _, unpaused := rt.counts()
	if unpaused < 1 {
		t.Fatalf("claim did not unpause a warm container (unpaused=%d)", unpaused)
	}
	// The claimed session must be a live, listable session.
	if len(m.List()) != 1 {
		t.Fatalf("List len = %d, want 1", len(m.List()))
	}
}

// AC: pool replenishes to warm_pool_size after a claim.
func TestWarmPool_ReplenishesAfterClaim(t *testing.T) {
	rt := newPoolRuntime()
	m := newPoolManager(t, rt, 2, 2, "sha256:tool-A")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())
	waitFor(t, time.Second, "initial fill", func() bool { return poolReadyLen(m.pool) == 2 })

	if _, err := m.Create(context.Background(), CreateRequest{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// After claiming one, the pool refills to 2 in the background => 3 total made.
	waitFor(t, time.Second, "refill to 2", func() bool { return poolReadyLen(m.pool) == 2 })
	if created, _, _, _ := rt.counts(); created != 3 {
		t.Fatalf("created = %d, want 3 (2 initial + 1 replenish)", created)
	}
}

// QA: concurrent claims never hand the same container to two callers, and never
// panic. Run under -race with high concurrency. Any duplicate container id (or
// duplicate session id) is a lost-atomicity bug.
func TestWarmPool_ConcurrentClaimsAtomic(t *testing.T) {
	rt := newPoolRuntime()
	// Big pool so most claims hit warm; fall-through on-demand is also fine (still
	// must be unique). High concurrency to stress the pop-under-lock.
	m := newPoolManager(t, rt, 50, 8, "sha256:tool-A")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())
	waitFor(t, 2*time.Second, "fill to 50", func() bool { return poolReadyLen(m.pool) == 50 })

	const claimers = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	seenCtr := map[string]bool{}
	seenSess := map[string]bool{}

	wg.Add(claimers)
	for i := 0; i < claimers; i++ {
		go func() {
			defer wg.Done()
			s, err := m.Create(context.Background(), CreateRequest{})
			if err != nil {
				t.Errorf("Create: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seenCtr[s.Handle.ID] {
				t.Errorf("container %s handed out twice (atomicity broken)", s.Handle.ID)
			}
			if seenSess[s.ID] {
				t.Errorf("session id %s issued twice", s.ID)
			}
			seenCtr[s.Handle.ID] = true
			seenSess[s.ID] = true
		}()
	}
	wg.Wait()
	if len(seenSess) != claimers {
		t.Fatalf("distinct sessions = %d, want %d", len(seenSess), claimers)
	}
}

// AC/QA: a claim returns promptly and never blocks on replenishment, even when
// (re)builds are slow. With a 250ms per-create delay, the claim of an already-
// warm container must complete far faster than one build.
func TestWarmPool_ClaimDoesNotBlockOnReplenish(t *testing.T) {
	rt := newPoolRuntime()
	rt.createDelay = 250 * time.Millisecond
	m := newPoolManager(t, rt, 1, 1, "sha256:tool-A")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())
	waitFor(t, 2*time.Second, "warm 1 ready", func() bool { return poolReadyLen(m.pool) == 1 })

	start := time.Now()
	s, err := m.Create(context.Background(), CreateRequest{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s == nil || s.State != StateReady {
		t.Fatalf("claim did not return a ready session")
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("claim took %s; it blocked on the slow replenish build (want << 250ms)", elapsed)
	}
}

// QA: replenishment concurrency is bounded by WarmPoolConcurrency — the pool
// never stampedes the engine. With a build delay, the observed peak concurrent
// creates must not exceed the cap.
func TestWarmPool_BoundedReplenishConcurrency(t *testing.T) {
	rt := newPoolRuntime()
	rt.createDelay = 40 * time.Millisecond
	const cap = 3
	m := newPoolManager(t, rt, 20, cap, "sha256:tool-A")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())
	waitFor(t, 3*time.Second, "fill to 20", func() bool { return poolReadyLen(m.pool) == 20 })

	if peak := atomic.LoadInt32(&rt.peakConc); peak > int32(cap) {
		t.Fatalf("peak concurrent builds = %d, exceeds cap %d", peak, cap)
	}
}

// AC: a toolchain digest change drains the stale warm containers and rebuilds
// the pool on the new digest.
func TestWarmPool_DrainRebuildOnDigestChange(t *testing.T) {
	rt := newPoolRuntime()
	m := newPoolManager(t, rt, 3, 3, "sha256:old")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())
	waitFor(t, time.Second, "fill on old digest", func() bool { return poolReadyLen(m.pool) == 3 })

	m.SetToolchainDigest("sha256:new")

	// Old 3 destroyed, new 3 built => created 6, destroyed 3, pool back to 3.
	waitFor(t, 2*time.Second, "rebuild on new digest", func() bool {
		created, destroyed, _, _ := rt.counts()
		return poolReadyLen(m.pool) == 3 && created == 6 && destroyed == 3
	})

	// The 3 currently-warm containers must all carry the NEW digest.
	m.pool.mu.Lock()
	warm := append([]*Session(nil), m.pool.ready...)
	m.pool.mu.Unlock()
	for _, s := range warm {
		if got := rt.specs[s.Handle.ID].ToolchainDigest; got != "sha256:new" {
			t.Fatalf("warm container %s digest = %q, want sha256:new", s.Handle.ID, got)
		}
	}
}

// SetToolchainDigest with an unchanged digest is a no-op (no drain, no rebuild).
func TestWarmPool_DigestUnchangedIsNoop(t *testing.T) {
	rt := newPoolRuntime()
	m := newPoolManager(t, rt, 2, 2, "sha256:same")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())
	waitFor(t, time.Second, "fill", func() bool { return poolReadyLen(m.pool) == 2 })

	m.SetToolchainDigest("sha256:same")
	time.Sleep(20 * time.Millisecond)
	if created, destroyed, _, _ := rt.counts(); created != 2 || destroyed != 0 {
		t.Fatalf("unchanged digest triggered churn: created=%d destroyed=%d", created, destroyed)
	}
}

// AC: no warm containers leak on shutdown — every created warm container is
// destroyed, including ones still building when Shutdown races in.
func TestWarmPool_NoLeakOnShutdown(t *testing.T) {
	rt := newPoolRuntime()
	m := newPoolManager(t, rt, 5, 3, "sha256:tool-A")
	m.StartWarmPool()
	waitFor(t, time.Second, "fill to 5", func() bool { return poolReadyLen(m.pool) == 5 })

	m.Shutdown(context.Background())

	created, destroyed, _, _ := rt.counts()
	if created != destroyed {
		t.Fatalf("leak on shutdown: created=%d destroyed=%d", created, destroyed)
	}
	if poolReadyLen(m.pool) != 0 {
		t.Fatalf("pool still holds %d warm containers after shutdown", poolReadyLen(m.pool))
	}
}

// No-leak on shutdown while builds are in flight (Shutdown races replenish).
func TestWarmPool_NoLeakOnShutdownDuringBuild(t *testing.T) {
	rt := newPoolRuntime()
	rt.createDelay = 30 * time.Millisecond
	m := newPoolManager(t, rt, 6, 3, "sha256:tool-A")
	m.StartWarmPool()
	// Do not wait for full fill: shut down mid-build so builders are in flight.
	time.Sleep(20 * time.Millisecond)
	m.Shutdown(context.Background())

	created, destroyed, _, _ := rt.counts()
	if created != destroyed {
		t.Fatalf("leak on mid-build shutdown: created=%d destroyed=%d", created, destroyed)
	}
	if poolReadyLen(m.pool) != 0 {
		t.Fatalf("pool non-empty after shutdown: %d", poolReadyLen(m.pool))
	}
}

// A claim for a rung the pool does not hold is a clean miss: Create falls back to
// on-demand and still returns a ready session (the pool is not consulted).
func TestWarmPool_WrongRungFallsBackOnDemand(t *testing.T) {
	rt := newPoolRuntime()
	m := newPoolManager(t, rt, 2, 2, "sha256:tool-A")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())
	waitFor(t, time.Second, "fill", func() bool { return poolReadyLen(m.pool) == 2 })

	// local-docker != pool's local-hardened rung.
	s, err := m.Create(context.Background(), CreateRequest{Tier: runtime.TierLocalDocker})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.Tier != runtime.TierLocalDocker {
		t.Fatalf("session tier = %s, want local-docker", s.Tier)
	}
	// Pool for local-hardened is untouched (still 2).
	if poolReadyLen(m.pool) != 2 {
		t.Fatalf("pool disturbed by wrong-rung claim: %d", poolReadyLen(m.pool))
	}
}

// FIX #2 (real-engine prereq): a warm container is STARTED then PAUSED (in that
// order) when placed in the pool, and a claim UNPAUSES it. Proving start→pause
// wiring is what makes `podman pause` valid on a live engine (pause needs a
// running container).
func TestWarmPool_StartThenPauseThenUnpauseOnClaim(t *testing.T) {
	rt := newPoolRuntime()
	m := newPoolManager(t, rt, 1, 1, "sha256:tool-A")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())
	waitFor(t, time.Second, "warm 1 ready", func() bool { return poolReadyLen(m.pool) == 1 })

	// Exactly one start, and it precedes the pause for the same container.
	if got := rt.startedCount(); got != 1 {
		t.Fatalf("started = %d, want 1 (warm container must be started)", got)
	}
	ops := rt.opLog()
	if len(ops) < 2 || !strings.HasPrefix(ops[0], "start:") || !strings.HasPrefix(ops[1], "pause:") {
		t.Fatalf("warm lifecycle must be start then pause, got %v", ops)
	}
	if _, _, paused, _ := rt.counts(); paused != 1 {
		t.Fatalf("paused = %d, want 1", paused)
	}

	// Claim thaws it: an unpause appears after the start/pause.
	if _, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	waitFor(t, time.Second, "unpause on claim", func() bool {
		_, _, _, unpaused := rt.counts()
		return unpaused == 1
	})
}

// FIX #2 safe degradation (F1.3 invariant preserved): if pause FAILS, the warm
// container is held unpaused-but-hardened — still published and still claimable,
// with no leak. Correctness never depends on the freeze succeeding.
func TestWarmPool_PauseFailureDegradesSafely(t *testing.T) {
	rt := newPoolRuntime()
	rt.pauseErr = fmt.Errorf("pause unsupported on this host")
	m := newPoolManager(t, rt, 2, 2, "sha256:tool-A")
	m.StartWarmPool()
	defer m.Shutdown(context.Background())

	// Despite pause failing, the pool still fills (containers are started &
	// hardened, just not frozen) and nothing is leaked.
	waitFor(t, time.Second, "fill despite pause failure", func() bool { return poolReadyLen(m.pool) == 2 })
	if started := rt.startedCount(); started != 2 {
		t.Fatalf("started = %d, want 2 (start must still happen)", started)
	}
	if _, _, paused, _ := rt.counts(); paused != 0 {
		t.Fatalf("paused = %d, want 0 (pause failed)", paused)
	}

	// A claim still yields a ready, listable session (degraded but usable).
	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create after pause failure: %v", err)
	}
	if s.State != StateReady {
		t.Fatalf("claimed session state = %s, want ready", s.State)
	}
}
