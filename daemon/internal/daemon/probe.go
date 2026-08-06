package daemon

import (
	"fmt"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// probeForTier returns a runtime-availability probe for the configured tier,
// backed by F0.3's ResolveRuntime + Runtime.Available(). It reuses the isolation
// ladder wholesale: /v1/health thus reports whether the engine + OCI runtime for
// the default rung (gVisor on local-hardened) are actually present. An
// unrecognised tier yields a legible probe error rather than a panic.
func probeForTier(tier string) func() error {
	t := runtime.Tier(tier)
	if t == "" {
		t = runtime.TierLocalHardened
	}
	rt, err := runtime.ResolveRuntime(t, runtime.LocationLocal)
	if err != nil {
		return func() error { return fmt.Errorf("daemon: resolve runtime for tier %q: %w", tier, err) }
	}
	return rt.Available
}
