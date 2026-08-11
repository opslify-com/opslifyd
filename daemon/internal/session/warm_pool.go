package session

import (
	"context"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// defaultWarmConcurrency bounds concurrent warm-container builds when the config
// leaves WarmPoolConcurrency unset. Small by design: replenishment is a
// background nicety and must never stampede the engine or starve real claims.
const defaultWarmConcurrency = 2

// warmPool keeps up to `size` pre-created, paused sandboxes ready for a
// sub-second claim (F1.3). It sits in front of Manager.Create's on-demand path.
//
// Concurrency model (the security-critical part):
//   - `ready` (the claimable containers) and the replenishment bookkeeping are
//     guarded by `mu`. A claim POPS under `mu`, so no two callers can ever be
//     handed the same container (atomicity — verified under -race).
//   - Building happens in background goroutines bounded by `sem` (never more
//     than maxConc engine creates at once). A claim NEVER waits on a build: it
//     either pops a ready container or misses cleanly and lets Create fall back
//     to on-demand.
//   - `digest` is the toolchain generation the current pool is built for. A
//     drain bumps it; any in-flight builder whose generation no longer matches
//     destroys its result instead of publishing it (no stale warm container is
//     ever claimable).
//   - `wg` tracks every background builder and drainer so close() can wait them
//     out and guarantee no warm container is leaked on shutdown.
type warmPool struct {
	m    *Manager
	tier runtime.Tier
	loc  runtime.Location
	size int
	sem  chan struct{} // bounds concurrent builds to maxConc

	mu       sync.Mutex
	ready    []*Session // paused, claimable containers
	inflight int        // builders currently running (counted toward target)
	digest   string     // toolchain generation this pool is built for
	closed   bool
	wg       sync.WaitGroup
}

// newWarmPool constructs a pool for the given rung. The initial generation is
// the manager's current toolchain digest.
func newWarmPool(m *Manager, size, maxConc int, tier runtime.Tier, loc runtime.Location) *warmPool {
	return &warmPool{
		m:      m,
		tier:   tier,
		loc:    loc,
		size:   size,
		sem:    make(chan struct{}, maxConc),
		digest: m.toolchainDigest(),
	}
}

// start kicks off the initial fill to `size`.
func (p *warmPool) start() { p.replenish() }

// claim atomically hands out one warm container for the requested rung, thaws it
// (unpause), and re-stamps it as a ready session with the caller's mode/ttl. It
// returns (nil, nil) on a clean miss — wrong rung, empty pool, or closed — so
// Create falls back to on-demand. Either way it triggers background
// replenishment; the claim never blocks on it.
func (p *warmPool) claim(ctx context.Context, tier runtime.Tier, loc runtime.Location, mode Mode, ttl time.Duration) (*Session, error) {
	// The pool only holds its own rung; a mismatched request is a clean miss.
	if tier != p.tier || loc != p.loc {
		return nil, nil
	}

	p.mu.Lock()
	if p.closed || len(p.ready) == 0 {
		p.mu.Unlock()
		// Even on a miss, nudge replenishment so the next caller hits.
		p.replenish()
		return nil, nil
	}
	// Pop the last entry under the lock: this is the atomic hand-off.
	last := len(p.ready) - 1
	s := p.ready[last]
	p.ready[last] = nil
	p.ready = p.ready[:last]
	p.mu.Unlock()

	// Thaw the container so it can accept execs. This unpause IS the warm-start
	// cost; it is bounded and does not touch the (background) replenish path.
	if err := p.unpause(ctx, s); err != nil {
		// A container we cannot thaw is unusable: destroy it (no leak) and treat
		// the claim as a miss so Create makes a fresh one.
		p.m.log.Warn("warm pool: unpause failed, discarding warm container", "session", s.ID, "err", err)
		p.destroy(ctx, s)
		p.replenish()
		return nil, nil
	}

	// Re-stamp warm → ready with the caller's disposition and re-persist so the
	// record reflects the real mode/ttl for reconciliation.
	now := p.m.clock.Now()
	s.Mode = mode
	s.TTL = ttl
	s.State = StateReady
	s.Created = now
	s.LastActivity = now
	if err := p.m.store.Save(recordOf(s)); err != nil {
		p.m.log.Warn("warm pool: re-persist on claim failed, discarding", "session", s.ID, "err", err)
		p.destroy(ctx, s)
		p.replenish()
		return nil, nil
	}

	p.replenish()
	return s, nil
}

// replenish launches background builders to bring the pool back to `size`,
// bounded by maxConc. It never blocks the caller: the actual engine creates run
// in goroutines. Extra builders beyond what is needed are never launched
// (inflight is counted against the target).
func (p *warmPool) replenish() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	gen := p.digest
	need := p.size - len(p.ready) - p.inflight
	if need <= 0 {
		p.mu.Unlock()
		return
	}
	p.inflight += need
	p.wg.Add(need)
	p.mu.Unlock()

	for i := 0; i < need; i++ {
		go p.build(gen)
	}
}

// build creates and pauses one warm container for generation gen, then publishes
// it to `ready` — unless the pool was closed or its generation moved on (a
// drain), in which case the freshly built container is destroyed rather than
// leaked or handed out stale. sem bounds how many builds run at once.
func (p *warmPool) build(gen string) {
	defer p.wg.Done()
	p.sem <- struct{}{}
	defer func() { <-p.sem }()

	ctx := context.Background()
	s, err := p.realizeWarm(ctx)

	p.mu.Lock()
	p.inflight--
	if err != nil {
		p.mu.Unlock()
		p.m.log.Warn("warm pool: build failed", "err", err)
		return
	}
	if p.closed || p.digest != gen {
		// Stale generation or shutting down: this container must not be published.
		p.mu.Unlock()
		p.destroy(ctx, s)
		return
	}
	p.ready = append(p.ready, s)
	p.mu.Unlock()
}

// realizeWarm builds a paused warm sandbox via the SHARED create path
// (Manager.realize), guaranteeing identical hardening + toolchain digest to
// on-demand sessions. Mode/ttl are placeholders re-stamped at claim. The
// generation check in build() discards any container a concurrent drain made
// stale, so nothing built here is ever published on the wrong digest.
func (p *warmPool) realizeWarm(ctx context.Context) (*Session, error) {
	s, err := p.m.realize(ctx, p.tier, p.loc, ModeScratch, "", 0, StateWarm)
	if err != nil {
		return nil, err
	}
	// Freeze it: a warm container costs no CPU until claimed. Best-effort — a
	// runtime without Pause keeps the container created-but-running (still
	// hardened, still claimable); correctness never depends on the freeze.
	if err := p.pause(ctx, s); err != nil {
		p.m.log.Warn("warm pool: pause unsupported/failed, holding unpaused", "session", s.ID, "err", err)
	}
	return s, nil
}

// drainAndRebuild advances the pool to a new toolchain generation: it evicts and
// destroys every currently-warm container (they carry the old, now-untrusted
// digest) and triggers a rebuild on the new digest. In-flight builders of the
// old generation self-destroy via build()'s generation check.
func (p *warmPool) drainAndRebuild(newDigest string) {
	p.mu.Lock()
	if p.closed || p.digest == newDigest {
		p.mu.Unlock()
		return
	}
	stale := p.ready
	p.ready = nil
	p.digest = newDigest
	p.mu.Unlock()

	p.m.log.Info("warm pool: draining on toolchain digest change", "drained", len(stale), "new_digest", newDigest)
	// Destroy the stale containers in the background so a rotation never blocks
	// the caller; tracked by wg so close() waits them out.
	if len(stale) > 0 {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for _, s := range stale {
				p.destroy(context.Background(), s)
			}
		}()
	}
	p.replenish()
}

// close drains the pool on shutdown: it stops publishing, waits for every
// in-flight builder and drainer to finish (they self-destroy their results), and
// destroys every remaining warm container. No warm container is leaked.
func (p *warmPool) close(ctx context.Context) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	remaining := p.ready
	p.ready = nil
	p.mu.Unlock()

	// Wait for builders/drainers first: any that publish after this point see
	// closed==true and destroy their own container instead of appending.
	p.wg.Wait()

	for _, s := range remaining {
		p.destroy(ctx, s)
	}
	p.m.log.Info("warm pool: drained on shutdown", "destroyed", len(remaining))
}

// pause freezes a warm container if its runtime supports the optional Pauser.
func (p *warmPool) pause(ctx context.Context, s *Session) error {
	if pr := p.pauser(s); pr != nil {
		return pr.Pause(ctx, s.Handle)
	}
	return nil
}

// unpause thaws a warm container if its runtime supports the optional Pauser.
func (p *warmPool) unpause(ctx context.Context, s *Session) error {
	if pr := p.pauser(s); pr != nil {
		return pr.Unpause(ctx, s.Handle)
	}
	return nil
}

// pauser resolves the session's runtime and returns its Pauser capability, or
// nil if the runtime cannot pause (or cannot be resolved).
func (p *warmPool) pauser(s *Session) runtime.Pauser {
	rt, err := p.m.resolve(s.Tier, s.Location)
	if err != nil {
		return nil
	}
	pr, _ := rt.(runtime.Pauser)
	return pr
}

// destroy tears a warm container down through the manager's shared teardown
// (container + record + workspace), so warm cleanup is as deterministic as
// session cleanup — no leaked containers, records, or scratch dirs.
func (p *warmPool) destroy(ctx context.Context, s *Session) {
	if err := p.m.teardown(ctx, s, false); err != nil {
		p.m.log.Warn("warm pool: teardown error", "session", s.ID, "err", err)
	}
}
