package install

import (
	"errors"
	"testing"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// withLookPath swaps the injectable lookPath seam for the duration of a test.
func withLookPath(t *testing.T, present map[string]bool) {
	t.Helper()
	orig := lookPath
	lookPath = func(bin string) (string, error) {
		if present[bin] {
			return "/usr/bin/" + bin, nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { lookPath = orig })
}

func TestRecommendTierHardenedWhenRunsc(t *testing.T) {
	withLookPath(t, map[string]bool{"podman": true, "runsc": true, "runc": true})
	c := ProbeCapabilities()
	tier, _ := c.RecommendTier()
	if tier != runtime.TierLocalHardened {
		t.Fatalf("with runsc present expected local-hardened, got %q", tier)
	}
}

func TestRecommendTierFallsBackToRunc(t *testing.T) {
	withLookPath(t, map[string]bool{"podman": true, "runsc": false, "runc": true})
	c := ProbeCapabilities()
	if c.Runsc {
		t.Fatal("runsc should be absent")
	}
	tier, reason := c.RecommendTier()
	if tier != runtime.TierLocalDocker {
		t.Fatalf("missing runsc should recommend runc rung, got %q", tier)
	}
	if reason == "" {
		t.Error("fallback should carry a legible reason")
	}
}

func TestProbeNoToolsDoesNotCrash(t *testing.T) {
	withLookPath(t, map[string]bool{})
	c := ProbeCapabilities()
	if c.Podman || c.Runsc || c.Runc {
		t.Fatal("expected all capabilities absent")
	}
	// Still returns a tier, never panics.
	if tier, _ := c.RecommendTier(); tier == "" {
		t.Fatal("recommend tier must never be empty")
	}
}
