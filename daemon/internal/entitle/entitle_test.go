package entitle

import "testing"

// TestEverythingIsAllowedInThisPhase is the claim this package makes today, and
// the thing a reader should be able to verify in one place rather than by
// auditing call sites.
func TestEverythingIsAllowedInThisPhase(t *testing.T) {
	for _, f := range All() {
		if !Allows(f) {
			t.Errorf("feature %q must be allowed in this phase: nothing is gated yet", f)
		}
		if Reason(f) != "" {
			t.Errorf("feature %q reports a refusal reason while it is allowed: %q", f, Reason(f))
		}
	}
	// An unknown feature is allowed too. A gate that defaulted to DENY would make
	// adding a feature a silent outage until someone remembered to list it.
	if !Allows(Feature("something-added-tomorrow")) {
		t.Error("an unlisted feature must be allowed; defaulting to deny would make adding one an outage")
	}
}

// TestAllIsStableAndComplete: the set is enumerable so the claim above can be
// checked, and stable so a test asserting it does not flake.
func TestAllIsStableAndComplete(t *testing.T) {
	a, b := All(), All()
	if len(a) != len(b) {
		t.Fatal("All is not stable")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("All is not sorted deterministically: %v vs %v", a, b)
		}
	}
	seen := map[Feature]bool{}
	for _, f := range a {
		if f == "" {
			t.Error("All contains an empty feature name")
		}
		if seen[f] {
			t.Errorf("All contains %q twice", f)
		}
		seen[f] = true
	}
	// Every P8 surface that could plausibly be commercial is listed, so the
	// inventory is a real inventory rather than a sample.
	for _, must := range []Feature{FeatureCockpit, FeatureConnections, FeatureChanges,
		FeaturePolicyEdit, FeatureAgentRegistry} {
		if !seen[must] {
			t.Errorf("%q is missing from All", must)
		}
	}
}
