package egress

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// Config wires an NftController.
type Config struct {
	// Runner is the privileged nft seam; nil => a production NftRunner.
	Runner Runner
	// Resolver resolves allowlist entries; nil => NewDefaultResolver(RefreshTTL).
	Resolver Resolver
	// Allowlist is Config.EgressAllowlist (F0.1): domains and/or literal IPs the
	// sandbox may reach. Everything else is denied.
	Allowlist []string
	// Bridge every sandbox attaches to; empty => DefaultBridge.
	Bridge string
	// Clock drives the refresh loop; nil => SystemClock.
	Clock Clock
	// MinRefresh / MaxRefresh clamp the DNS refresh interval so a tiny record TTL
	// can't hammer DNS and a huge one can't strand a rotated address. Zero => 30s / 1h.
	MinRefresh time.Duration
	MaxRefresh time.Duration
	// Logger; nil => slog.Default().
	Logger *slog.Logger
}

// NftController is the production Controller. It keeps the current pinned IP set
// (resolved from the allowlist) and a per-session table for each active sandbox.
// On DNS refresh it re-pins and atomically reprograms every active session, so
// round-robin/rotated addresses keep working with no rule leak. All privileged
// work goes through the Runner seam.
type NftController struct {
	runner   Runner
	resolver Resolver
	allow    []string
	bridge   string
	clock    Clock
	minTTL   time.Duration
	maxTTL   time.Duration
	log      *slog.Logger

	mu       sync.Mutex
	pinned   []netip.Addr          // current allowlist IP set
	sessions map[string]SessionNet // active sessions, for reprogram-on-refresh

	stop chan struct{}
	done chan struct{}
}

// NewController builds an NftController, applying defaults. It does NOT resolve or
// start the refresh loop — call Start (so wiring controls ordering and tests drive
// RefreshOnce deterministically).
func NewController(cfg Config) *NftController {
	c := &NftController{
		runner:   cfg.Runner,
		resolver: cfg.Resolver,
		allow:    append([]string(nil), cfg.Allowlist...),
		bridge:   cfg.Bridge,
		clock:    cfg.Clock,
		minTTL:   cfg.MinRefresh,
		maxTTL:   cfg.MaxRefresh,
		log:      cfg.Logger,
		sessions: map[string]SessionNet{},
	}
	if c.runner == nil {
		c.runner = NftRunner{}
	}
	if c.bridge == "" {
		c.bridge = DefaultBridge
	}
	if c.clock == nil {
		c.clock = SystemClock()
	}
	if c.minTTL <= 0 {
		c.minTTL = 30 * time.Second
	}
	if c.maxTTL <= 0 {
		c.maxTTL = time.Hour
	}
	if c.resolver == nil {
		c.resolver = NewDefaultResolver(c.minTTL)
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	return c
}

// Available reports whether egress can actually be ENFORCED here (nft usable).
// The daemon uses it to decide between this controller and a loudly-warned Noop.
func (c *NftController) Available() error { return c.runner.Available() }

// Start performs the initial allowlist resolve (so the very first session is
// programmed with real IPs) and launches the refresh loop. Returns the initial
// refresh interval error only if the whole allowlist failed to resolve; a partial
// failure is logged and the loop retries.
func (c *NftController) Start(ctx context.Context) error {
	if _, err := c.refreshOnce(ctx); err != nil {
		c.log.Warn("egress: initial allowlist resolve failed; sessions will deny all until it succeeds", "err", err)
	}
	c.stop = make(chan struct{})
	c.done = make(chan struct{})
	go c.loop()
	return nil
}

// Close stops the refresh loop. It does NOT tear down active sessions (the Manager
// owns their lifecycle and tears each down on destroy).
func (c *NftController) Close() {
	if c.stop == nil {
		return
	}
	close(c.stop)
	<-c.done
	c.stop = nil
}

// SetupSession programs default-deny egress for one session with the current pin.
func (c *NftController) SetupSession(ctx context.Context, net SessionNet) error {
	if net.SessionID == "" {
		return fmt.Errorf("%w: SetupSession requires a session id", ErrEgress)
	}
	if net.Bridge == "" {
		net.Bridge = c.bridge
	}
	c.mu.Lock()
	c.sessions[net.SessionID] = net
	ips := append([]netip.Addr(nil), c.pinned...)
	c.mu.Unlock()

	if err := c.runner.Apply(ctx, buildApplyScript(net, ips)); err != nil {
		// Roll the record back so a failed apply doesn't leave a phantom active
		// session that a later refresh would try to reprogram.
		c.mu.Lock()
		delete(c.sessions, net.SessionID)
		c.mu.Unlock()
		return fmt.Errorf("%w: program session %s: %v", ErrEgress, net.SessionID, err)
	}
	c.log.Info("egress: session programmed", "session", net.SessionID, "allow_ips", len(ips), "bridge", net.Bridge)
	return nil
}

// TeardownSession deletes the session's table (idempotent, no leak) and drops it
// from the reprogram set.
func (c *NftController) TeardownSession(ctx context.Context, sessionID string) error {
	c.mu.Lock()
	delete(c.sessions, sessionID)
	c.mu.Unlock()
	if err := c.runner.Apply(ctx, buildTeardownScript(sessionID)); err != nil {
		return fmt.Errorf("%w: teardown session %s: %v", ErrEgress, sessionID, err)
	}
	c.log.Info("egress: session torn down", "session", sessionID)
	return nil
}

// refreshOnce re-resolves the allowlist and, if the pinned set changed, reprograms
// every active session atomically (delete+recreate table => no stale rule). It
// returns the next refresh interval. Exposed (unexported) for the loop and driven
// directly by tests with a fake resolver + fake runner.
func (c *NftController) refreshOnce(ctx context.Context) (time.Duration, error) {
	ips, next, err := resolveAll(ctx, c.resolver, c.allow, c.minTTL, c.maxTTL)
	if err != nil {
		return next, err
	}
	c.mu.Lock()
	if addrsEqual(ips, c.pinned) {
		c.mu.Unlock()
		return next, nil
	}
	c.pinned = ips
	active := make([]SessionNet, 0, len(c.sessions))
	for _, s := range c.sessions {
		active = append(active, s)
	}
	c.mu.Unlock()

	for _, s := range active {
		if err := c.runner.Apply(ctx, buildApplyScript(s, ips)); err != nil {
			// Best-effort: keep reprogramming the rest so one failure doesn't strand
			// every session on a stale pin.
			c.log.Warn("egress: reprogram on refresh failed", "session", s.SessionID, "err", err)
		}
	}
	c.log.Info("egress: allowlist refreshed", "allow_ips", len(ips), "sessions", len(active), "next_refresh", next)
	return next, nil
}

// loop refreshes on the interval returned by each resolve. It uses a real timer
// (thin ctx-gated glue); the refresh LOGIC — resolveAll, change detection, TTL
// selection, reprogram — is pure and unit-tested via refreshOnce.
func (c *NftController) loop() {
	defer close(c.done)
	// Seed with a conservative interval; refreshOnce returns the real next one.
	interval := c.minTTL
	for {
		timer := time.NewTimer(interval)
		select {
		case <-c.stop:
			timer.Stop()
			return
		case <-timer.C:
			next, err := c.refreshOnce(context.Background())
			if err != nil {
				c.log.Warn("egress: allowlist refresh failed; keeping prior pin", "err", err)
			}
			interval = next
			if interval < c.minTTL {
				interval = c.minTTL
			}
		}
	}
}

var _ Controller = (*NftController)(nil)
