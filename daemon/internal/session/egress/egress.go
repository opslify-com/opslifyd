// Package egress implements F1.4 — default-deny L3/L4 egress with DNS pinning.
//
// The sandbox occupant is hostile and the network is the primary exfil channel,
// so the posture is: a sandbox reaches NOTHING by default; only the IPs the
// daemon resolves from the configured allowlist, and it can never do its own DNS
// (port 53 outbound is dropped). The daemon is the sole resolver: it resolves the
// allowlisted domains, pins the resulting IPs into per-session nftables rules, and
// refreshes them so round-robin / multi-A domains keep working without ever
// handing the sandbox a resolver.
//
// Everything privileged (programming nftables) sits behind the Runner seam so the
// VALUABLE, TESTABLE CORE — the exact ruleset generated for a given allowlist, the
// resolver + refresh logic, and apply/teardown ordering + idempotency — is fully
// unit-testable with no root and no `nft` binary present. Real kernel packet
// enforcement is exercised by F1.5's escape suite on a host that actually has nft
// + root; this package proves the rules we GENERATE are correct and leak-free.
package egress

import (
	"context"
	"errors"
	"time"
)

// DefaultBridge is the host bridge every sandbox netns attaches to (F0.3). Egress
// rules are scoped to traffic arriving on it, so host traffic is never touched.
const DefaultBridge = "opslify0"

// ErrEgress is the layer sentinel wrapping every egress-programming failure, so a
// blocked/failed egress operation is legibly an `egress`-layer error, never
// confused with a sandbox/runtime failure (failure-legibility requirement).
var ErrEgress = errors.New("egress")

// SessionNet identifies one sandbox's network attachment for rule programming.
type SessionNet struct {
	// SessionID scopes the per-session nftables table (deterministic teardown:
	// the whole table is deleted on destroy, so no rule can leak).
	SessionID string
	// SandboxIP is the sandbox's address on the bridge. When set, the per-session
	// rules are scoped to this source address, so one sandbox's default-deny never
	// affects another's traffic. Empty means the runtime has not yet exposed the
	// container IP (F0.3 ContainerHandle carries none today); the rules then govern
	// all bridge traffic for that table — correct for a single sandbox, and the
	// generator is fully tested for both modes so wiring the IP later is a one-liner.
	SandboxIP string
	// Bridge is the host bridge name; empty => DefaultBridge.
	Bridge string
}

func (n SessionNet) bridge() string {
	if n.Bridge == "" {
		return DefaultBridge
	}
	return n.Bridge
}

// Controller programs and tears down per-session egress. The session Manager
// depends only on this interface, never on nftables, so it stays testable and the
// enforcement mechanism is swappable (nft today; an L7 proxy hook is P5/F4.7).
type Controller interface {
	// SetupSession programs default-deny egress for one session, allowing only the
	// currently-pinned allowlist IPs. It is idempotent: re-applying replaces the
	// session's table atomically, so an allowlist change leaks no prior rule.
	SetupSession(ctx context.Context, net SessionNet) error
	// TeardownSession removes every rule for the session. Idempotent and safe even
	// if SetupSession never ran or already ran — no rule leak on destroy.
	TeardownSession(ctx context.Context, sessionID string) error
}

// Clock is the injectable time source for the refresh loop (mirrors
// session.Clock; defined locally to avoid an import cycle with the session pkg).
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SystemClock is the production wall-clock.
func SystemClock() Clock { return systemClock{} }

// Noop is the disabled-egress controller. It is the Manager's default so session
// tests need no egress wiring, and the daemon wires it (with a loud warning) when
// the host lacks nft/root — egress cannot be ENFORCED there, and failing closed
// would make the daemon unusable in dev, so the choice is surfaced, not silent.
type Noop struct{}

func (Noop) SetupSession(context.Context, SessionNet) error { return nil }
func (Noop) TeardownSession(context.Context, string) error  { return nil }

// Available reports the Noop controller is always usable (it enforces nothing).
func (Noop) Available() error { return nil }

var _ Controller = Noop{}
