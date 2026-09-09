package project

import (
	"fmt"
	"os"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// knownTier reports whether t is a recognised isolation rung. It reuses the F4.1
// ladder (policy.TierRank) rather than restating it, so there is exactly one
// definition of the tier vocabulary in the daemon.
func knownTier(t string) bool {
	_, ok := policy.TierRank(t)
	return ok
}

// Layer is one named policy layer in the precedence chain
// daemon → project → environment → workspace. Name is what a recorded clamp is
// tagged with, so an operator reading the notes learns WHICH layer over-reached.
type Layer struct {
	Name   string
	Policy policy.Policy
}

// ResolvePolicy applies each layer in order over base under the F4.1
// narrows-not-widens invariant, and returns the resolved model + policy_hash +
// the layer-tagged record of every clamp.
//
// The narrowing itself is NOT implemented here: each step is the EXISTING
// policy.Resolve, whose merge functions only ever intersect grants, union
// restrictions, and clamp session limits. Widening is therefore structurally
// impossible at every rung — an environment overlay that tries to add an egress
// domain, a cred, a kubectl namespace, a weaker tier or a longer ttl than its
// project allows is dropped/clamped by Resolve and the drop lands in Notes, which
// this function tags with the layer name and carries into the result.
//
// With no layers the result is exactly policy.ResolveDefault(base) — the
// pre-F8.1 behaviour, byte for byte, including the well-known policy.DefaultHash
// for an empty base.
func ResolvePolicy(base policy.Policy, layers ...Layer) policy.Resolved {
	if len(layers) == 0 {
		return policy.ResolveDefault(base)
	}
	cur := policy.ResolveDefault(base)
	var clamps []string
	for _, l := range layers {
		next := policy.Resolve(cur.Policy, l.Policy)
		for _, note := range next.Notes {
			clamps = append(clamps, l.Name+": "+note)
		}
		cur = next
	}
	cur.Notes = clamps
	return cur
}

// LoadLayer reads and validates one policy layer file. It is fail-closed on every
// count that matters:
//   - a MISSING file is an error, not an empty layer: the operator configured a
//     path, so silently resolving without it would run the session under a
//     policy nobody chose;
//   - an unparseable/invalid file is a *policy.ValidationError with line-level
//     detail, which the caller treats as refuse-to-serve.
//
// The file's CONTENT needs no trust — ResolvePolicy can only narrow with it — so
// a layer file is safe to keep in a repo; it can tighten a session and never
// widen one.
func LoadLayer(kind, path string) (policy.Policy, error) {
	p, err := policy.Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			return policy.Policy{}, fmt.Errorf("%w: %s %q does not exist", ErrInvalidInput, kind, path)
		}
		return policy.Policy{}, fmt.Errorf("project: %s %s: %w", kind, path, err)
	}
	return p, nil
}
