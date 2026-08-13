package policy

import (
	"fmt"
	"time"
)

// Resolved is the merged, clamped, normalised policy a session runs under. It is
// the EXPORTED SEAM F4.2 consumes WITHOUT re-parsing: the enforcement engine
// reads Resolved.Policy for decisions and Resolved.Hash is bound into the trace.
//
// Invariant: Resolved.Policy is always a NARROWING of the daemon policy — every
// allow/egress/cred set is a subset of the daemon's, approval requirements are a
// superset, strict_exec is at least as strict, and session limits are no looser.
// Widening is structurally impossible: the merge functions only ever intersect
// (for grants) or union (for restrictions), so a workspace input can never
// enlarge a grant. Any workspace value that WOULD widen is dropped/clamped and
// recorded in Notes.
type Resolved struct {
	Policy
	// Hash is the deterministic policy_hash over the normalised Policy (see
	// Hash()). It is what session.start binds into the trace chain.
	Hash string `json:"hash"`
	// Notes records every clamp/drop the narrowing merge applied, so an operator
	// can see exactly where a workspace policy tried to widen and was denied.
	Notes []string `json:"notes,omitempty"`
}

// ResolveDefault resolves a lone daemon policy (no workspace file present). The
// result is simply the normalised daemon policy — there is nothing to narrow.
func ResolveDefault(daemon Policy) Resolved {
	n := daemon.normalize()
	return Resolved{Policy: n, Hash: hashOf(n)}
}

// Resolve merges a workspace policy OVER a daemon policy under the
// narrows-not-widens invariant and returns the resolved model + policy_hash.
//
// The daemon policy is trusted; the workspace policy is agent-controlled and
// untrusted. For each field the merge chooses the SAFER (more restrictive) of
// the two and records any workspace attempt to widen:
//   - allow sets (kubectl ns/verbs, terraform cmds, exec regexes), egress
//     domains, creds → INTERSECTION (workspace can only keep a subset);
//   - approval_required → UNION (workspace can only add gates);
//   - strict_exec → OR (workspace can only turn it on);
//   - session.ttl → MIN (workspace can only shorten);
//   - session.tier → the MORE isolated of the two (workspace cannot weaken);
//   - session.image → daemon's pin wins (a differing workspace image is dropped).
func Resolve(daemon, workspace Policy) Resolved {
	// NOTE: inputs are used RAW (not pre-normalized) so intersect can tell an
	// absent workspace set (nil → preserve daemon grant) from an explicitly empty
	// one ([] → narrow to nothing). The RESULT is normalized before hashing.
	d := daemon
	w := workspace
	var notes []string

	// strict_exec: OR — a workspace may only turn it ON (a tightening), never off.
	out := Policy{StrictExec: d.StrictExec || w.StrictExec}

	// ---- allow sets: intersection (workspace ⊆ daemon) ----
	out.Allow.Kubectl.Namespaces, notes = intersect("allow.kubectl.namespaces", d.Allow.Kubectl.Namespaces, w.Allow.Kubectl.Namespaces, notes)
	out.Allow.Kubectl.Verbs, notes = intersect("allow.kubectl.verbs", d.Allow.Kubectl.Verbs, w.Allow.Kubectl.Verbs, notes)
	out.Allow.Terraform.Commands, notes = intersect("allow.terraform.commands", d.Allow.Terraform.Commands, w.Allow.Terraform.Commands, notes)
	out.Allow.Exec, notes = intersect("allow.exec", d.Allow.Exec, w.Allow.Exec, notes)
	out.Egress.Domains, notes = intersect("egress.domains", d.Egress.Domains, w.Egress.Domains, notes)
	out.Creds, notes = intersectCreds(d.Creds, w.Creds, notes)

	// ---- approval_required: union (only add gates) ----
	out.ApprovalRequired = unionSet(d.ApprovalRequired, w.ApprovalRequired)

	// ---- session ----
	out.Session, notes = resolveSession(d.Session, w.Session, notes)

	n := out.normalize()
	return Resolved{Policy: n, Hash: hashOf(n), Notes: notes}
}

// resolveSession clamps each session limit to the daemon's, recording widening
// attempts. A daemon that leaves a field unset imposes no bound on it, so the
// workspace value passes through (it cannot widen a bound that does not exist).
func resolveSession(d, w Session, notes []string) (Session, []string) {
	out := Session{}

	// TTL: MIN of the two (workspace may only shorten). Unparseable/absent
	// values on either side fall back to the other's.
	dTTL, dOK := parseTTL(d.TTL)
	wTTL, wOK := parseTTL(w.TTL)
	switch {
	case dOK && wOK:
		if wTTL > dTTL {
			notes = append(notes, fmt.Sprintf("session.ttl: workspace %q exceeds daemon %q; clamped to daemon", w.TTL, d.TTL))
			out.TTL = d.TTL
		} else {
			out.TTL = w.TTL
		}
	case wOK:
		out.TTL = w.TTL
	case dOK:
		out.TTL = d.TTL
	}

	// Tier: choose the MORE isolated (higher rank). A workspace tier weaker than
	// the daemon's is a widening → clamp to daemon.
	switch {
	case w.Tier == "":
		out.Tier = d.Tier
	case d.Tier == "":
		out.Tier = w.Tier
	default:
		if tierRank[w.Tier] < tierRank[d.Tier] {
			notes = append(notes, fmt.Sprintf("session.tier: workspace %q is weaker than daemon %q; clamped to daemon", w.Tier, d.Tier))
			out.Tier = d.Tier
		} else {
			out.Tier = w.Tier
		}
	}

	// Image: a daemon pin is authoritative. A differing workspace image is a
	// widening (it could select an unvetted base) → drop it, keep the daemon's.
	switch {
	case d.Image != "" && w.Image != "" && d.Image != w.Image:
		notes = append(notes, fmt.Sprintf("session.image: workspace %q overrides daemon pin %q; clamped to daemon", w.Image, d.Image))
		out.Image = d.Image
	case d.Image != "":
		out.Image = d.Image
	default:
		out.Image = w.Image
	}
	return out, notes
}

// parseTTL parses a duration string; ok=false for empty/invalid (validation has
// already rejected a genuinely-invalid value, so this only guards empties here).
func parseTTL(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

// intersect returns daemon ∩ workspace for a grant set, recording each workspace
// element NOT in the daemon set as a dropped widening. When the workspace does
// not specify the set at all (nil), the daemon set passes through unchanged (the
// workspace is not narrowing it). An EMPTY (non-nil) workspace set means "grant
// nothing", which is a valid narrowing to the empty set.
//
// The result is ALWAYS a subset of the daemon set, so widening is impossible by
// construction.
func intersect(field string, daemon, workspace []string, notes []string) ([]string, []string) {
	if workspace == nil {
		return daemon, notes
	}
	dset := make(map[string]struct{}, len(daemon))
	for _, v := range daemon {
		dset[v] = struct{}{}
	}
	var out []string
	for _, v := range workspace {
		if _, ok := dset[v]; ok {
			out = append(out, v)
		} else {
			notes = append(notes, fmt.Sprintf("%s: workspace grant %q not permitted by daemon; dropped", field, v))
		}
	}
	return out, notes
}

// intersectCreds is intersect for creds keyed on the exact (name, provider)
// pair. Deny-by-default: a workspace cred the daemon did not list is dropped.
func intersectCreds(daemon, workspace []Cred, notes []string) ([]Cred, []string) {
	if workspace == nil {
		return daemon, notes
	}
	dset := make(map[Cred]struct{}, len(daemon))
	for _, c := range daemon {
		dset[c] = struct{}{}
	}
	var out []Cred
	for _, c := range workspace {
		if _, ok := dset[c]; ok {
			out = append(out, c)
		} else {
			notes = append(notes, fmt.Sprintf("creds: workspace grant %q (provider %q) not permitted by daemon; dropped", c.Name, c.Provider))
		}
	}
	return out, notes
}

// unionSet returns the de-duplicated union of two restriction sets (used for
// approval_required, where more entries = more restrictive = a valid narrowing).
func unionSet(a, b []string) []string {
	return sortedSet(append(append([]string{}, a...), b...))
}
