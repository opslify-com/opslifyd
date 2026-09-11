// Package entitle is the seam where a commercial edition could later gate
// features — and, today, the place that proves nothing is gated yet.
//
// It exists now rather than later for one reason: retrofitting an entitlement
// check across a finished product means touching every feature at once, and the
// touching is where mistakes go in. Adding the seam while the features are being
// written costs one call site each.
//
// WHAT IT DELIBERATELY IS NOT. There is no licence file, no tier, no expiry, no
// network call, and no machine fingerprint. Allows returns true for everything.
// A daemon must never fail to run a sandbox because a check could not reach a
// server, so the design that could do that is not built — and if entitlement ever
// does ship, the spec's commitment is an OFFLINE signature check, never a
// phone-home.
package entitle

import "sort"

// Feature names something that could plausibly be commercial later.
//
// Named constants rather than free strings so the set is enumerable: a test can
// assert every feature is currently allowed, which is the claim this package
// makes today.
type Feature string

const (
	// FeatureCockpit is the tower UI itself.
	FeatureCockpit Feature = "cockpit"
	// FeatureConnections is the F8.2 connection broker surface.
	FeatureConnections Feature = "connections"
	// FeatureChanges is the F8.6 review surface.
	FeatureChanges Feature = "changes"
	// FeaturePolicyEdit is the F8.7 governed guardrail editing.
	FeaturePolicyEdit Feature = "policy-edit"
	// FeatureAgentRegistry is the F8.5 bring-your-own-agent registry.
	FeatureAgentRegistry Feature = "agent-registry"
	// FeatureMemory is the F8.10 per-project memory.
	FeatureMemory Feature = "memory"
	// FeatureReviewer is the F8.9 adversarial reviewer.
	FeatureReviewer Feature = "reviewer"
)

// All is every gateable feature, sorted.
func All() []Feature {
	out := []Feature{
		FeatureCockpit, FeatureConnections, FeatureChanges, FeaturePolicyEdit,
		FeatureAgentRegistry, FeatureMemory, FeatureReviewer,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Allows reports whether a feature may be used.
//
// It returns true for everything in this phase. The signature takes a Feature so
// call sites read as a question rather than a constant, and so a future
// implementation changes one function instead of every caller.
//
// It cannot fail. There is no error return on purpose: an entitlement check that
// can fail is an entitlement check that can take a working daemon offline, and
// the only safe answer to "could not determine" would be true anyway.
func Allows(f Feature) bool {
	_ = f
	return true
}

// Reason explains a refusal for an operator. It is empty while everything is
// allowed, and exists so a future gate has somewhere to put a human sentence
// rather than surfacing a bare false.
func Reason(f Feature) string {
	if Allows(f) {
		return ""
	}
	return string(f) + " is not available in this edition"
}
