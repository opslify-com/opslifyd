package policy

import (
	"fmt"
	"reflect"
	"sort"
	"time"
)

// Direction is how an edit moves the guardrails.
type Direction string

const (
	// DirectionNarrowing tightens the guardrails. It applies immediately and
	// ungated: tightening during an incident must never wait for an approver.
	DirectionNarrowing Direction = "narrowing"
	// DirectionWidening loosens them. It requires an approved Change — guardrails
	// that can be widened without governance are not guardrails.
	DirectionWidening Direction = "widening"
	// DirectionEquivalent is no effective change.
	DirectionEquivalent Direction = "equivalent"
)

// Classification is the verdict plus the reasons behind it.
type Classification struct {
	Direction Direction
	// Widenings name every loosening found, so an approver reads WHAT is being
	// opened rather than only that something is.
	Widenings []string
	// Narrowings name every tightening, recorded even though they are ungated.
	Narrowings []string
}

// ClassifyEdit decides whether moving from one policy to another widens the
// guardrails.
//
// IT IS CONSERVATIVE BY CONSTRUCTION, and the construction matters more than the
// individual rules. Rather than looking for wideings and defaulting to
// "narrowing", it does the opposite: every field it understands is compared
// explicitly, those fields are then blanked on both sides, and ANY remaining
// difference is reported as widening.
//
// That inversion is what makes a widening slipping through as narrowing hard
// rather than merely unlikely. A field added to Policy tomorrow and forgotten
// here is automatically gated, because the residual comparison sees it change and
// cannot tell what it means. The failure mode of forgetting is an unnecessary
// approval, not an ungoverned loosening.
func ClassifyEdit(from, to Policy) Classification {
	from = from.normalize()
	to = to.normalize()
	c := Classification{Direction: DirectionEquivalent}

	// --- egress: an added host is a new place data can go ---------------------
	added, removed := setDiff(from.Egress.Domains, to.Egress.Domains)
	c.widen(added, "egress host allowed: %s")
	c.narrow(removed, "egress host removed: %s")

	// --- exec allowlist -------------------------------------------------------
	added, removed = setDiff(from.Allow.Exec, to.Allow.Exec)
	// A CHANGED pattern shows up as one added and one removed, so an edited regex
	// is gated. Comparing regex languages for containment is undecidable in
	// general, and guessing would be exactly the ambiguity this must not resolve
	// optimistically.
	c.widen(added, "exec pattern allowed: %s")
	c.narrow(removed, "exec pattern removed: %s")

	added, removed = setDiff(from.Allow.Kubectl.Namespaces, to.Allow.Kubectl.Namespaces)
	c.widen(added, "kubectl namespace allowed: %s")
	c.narrow(removed, "kubectl namespace removed: %s")

	added, removed = setDiff(from.Allow.Kubectl.Verbs, to.Allow.Kubectl.Verbs)
	c.widen(added, "kubectl verb allowed: %s")
	c.narrow(removed, "kubectl verb removed: %s")

	added, removed = setDiff(from.Allow.Terraform.Commands, to.Allow.Terraform.Commands)
	c.widen(added, "terraform command allowed: %s")
	c.narrow(removed, "terraform command removed: %s")

	// --- approval gates: the direction is INVERTED ----------------------------
	// More gates is tighter. Removing a gate is the loosening that matters most,
	// because it is the one that removes a human from the loop.
	added, removed = setDiff(from.ApprovalRequired, to.ApprovalRequired)
	c.widen(removed, "approval gate REMOVED: %s")
	c.narrow(added, "approval gate added: %s")

	// --- credential grants ----------------------------------------------------
	added, removed = setDiff(credKeys(from.Creds), credKeys(to.Creds))
	c.widen(added, "credential granted: %s")
	c.narrow(removed, "credential revoked: %s")

	// --- dry-run rules: more preview is tighter -------------------------------
	added, removed = setDiff(dryRunKeys(from.DryRun), dryRunKeys(to.DryRun))
	c.widen(removed, "preview rule removed: %s")
	c.narrow(added, "preview rule added: %s")

	// --- booleans -------------------------------------------------------------
	if from.StrictExec && !to.StrictExec {
		c.widenOne("strict exec turned OFF: commands outside the allowlist become possible")
	} else if !from.StrictExec && to.StrictExec {
		c.narrowOne("strict exec turned on")
	}
	if !from.DryRunWarnOnFailure && to.DryRunWarnOnFailure {
		// A failed preview stops blocking, so a gate can be offered on a command
		// nobody could preview.
		c.widenOne("failed previews now WARN instead of blocking")
	} else if from.DryRunWarnOnFailure && !to.DryRunWarnOnFailure {
		c.narrowOne("failed previews now block")
	}

	// --- session limits -------------------------------------------------------
	classifyTTL(&c, from.Session.TTL, to.Session.TTL)
	// Session.Tier and Session.Image are deliberately NOT handled here. Tier
	// ordering is a runtime concern this package does not own, and a different
	// base image is a different everything — neither can be called narrowing. They
	// are left to the residual below, which is what keeps that mechanism
	// load-bearing instead of decorative: a rule nothing exercises is a rule that
	// can rot unnoticed.

	// --- the residual: anything this function does not understand -------------
	//
	// Blank every field compared above on BOTH sides. If what remains still
	// differs, some field changed that no rule here accounts for — and an
	// unaccounted change cannot be called narrowing. This is the line that makes
	// forgetting safe.
	if diff := residualDiff(from, to); len(diff) > 0 {
		for _, field := range diff {
			// Named, not merely counted: an approver reading "cannot be classified"
			// with no field name cannot tell a tier change from something unknown.
			c.widenOne("policy field " + field + " changed and cannot be classified as narrowing; treating it as widening")
		}
	}

	switch {
	case len(c.Widenings) > 0:
		c.Direction = DirectionWidening
	case len(c.Narrowings) > 0:
		c.Direction = DirectionNarrowing
	default:
		c.Direction = DirectionEquivalent
	}
	return c
}

// residualDiff names every field that differs after the explicitly-classified
// ones are blanked.
//
// Reflection rather than a hand-written comparison on purpose: a field added to
// Policy tomorrow appears here automatically, with its own name, and is gated. A
// hand-written list would have to be remembered, and the whole point of this
// mechanism is that forgetting stays safe.
func residualDiff(from, to Policy) []string {
	a, b := residual(from), residual(to)
	if reflect.DeepEqual(a, b) {
		return nil
	}
	var out []string
	collectDiff(reflect.ValueOf(a), reflect.ValueOf(b), "", &out)
	if len(out) == 0 {
		// The structs differ but no leaf was attributed — report it rather than
		// silently returning nothing, which would turn a detected difference into
		// an ungated edit.
		out = append(out, "(unattributed)")
	}
	sort.Strings(out)
	return out
}

// collectDiff walks two values of the same type and names the differing leaves.
func collectDiff(a, b reflect.Value, path string, out *[]string) {
	if a.Kind() == reflect.Struct {
		t := a.Type()
		for i := 0; i < a.NumField(); i++ {
			name := t.Field(i).Name
			child := name
			if path != "" {
				child = path + "." + name
			}
			collectDiff(a.Field(i), b.Field(i), child, out)
		}
		return
	}
	if !reflect.DeepEqual(a.Interface(), b.Interface()) {
		*out = append(*out, path)
	}
}

// residual zeroes every field ClassifyEdit compares explicitly, leaving only what it
// does not understand.
func residual(p Policy) Policy {
	p.Egress.Domains = nil
	p.Allow.Exec = nil
	p.Allow.Kubectl.Namespaces = nil
	p.Allow.Kubectl.Verbs = nil
	p.Allow.Terraform.Commands = nil
	p.ApprovalRequired = nil
	p.Creds = nil
	p.DryRun = nil
	p.StrictExec = false
	p.DryRunWarnOnFailure = false
	p.Session.TTL = ""
	// Session.Tier and Session.Image are NOT blanked: they have no explicit rule,
	// so the residual is what gates them. See ClassifyEdit.
	return p
}

// classifyTTL compares session lifetimes. A LONGER ttl is a widening: a sandbox
// that lives longer holds its credentials longer.
//
// An unparseable duration on either side is gated rather than ignored — an edit
// whose effect cannot be computed is the definition of ambiguous.
func classifyTTL(c *Classification, fromTTL, toTTL string) {
	if fromTTL == toTTL {
		return
	}
	// An empty ttl means "inherit the daemon default", whose value is not known
	// here. Moving to or from inherit changes the effective lifetime by an unknown
	// amount, so it is gated.
	if fromTTL == "" || toTTL == "" {
		c.widenOne("session ttl changed to or from the inherited default (" +
			orNone(fromTTL) + " -> " + orNone(toTTL) + ")")
		return
	}
	fd, ferr := time.ParseDuration(fromTTL)
	td, terr := time.ParseDuration(toTTL)
	if ferr != nil || terr != nil {
		c.widenOne("session ttl changed to a value that cannot be parsed (" + fromTTL + " -> " + toTTL + ")")
		return
	}
	if td > fd {
		c.widenOne("session ttl lengthened from " + fromTTL + " to " + toTTL)
	} else if td < fd {
		c.narrowOne("session ttl shortened from " + fromTTL + " to " + toTTL)
	}
}

func (c *Classification) widen(items []string, format string) {
	for _, it := range items {
		c.widenOne(fmt.Sprintf(format, it))
	}
}

func (c *Classification) narrow(items []string, format string) {
	for _, it := range items {
		c.narrowOne(fmt.Sprintf(format, it))
	}
}

func (c *Classification) widenOne(reason string)  { c.Widenings = append(c.Widenings, reason) }
func (c *Classification) narrowOne(reason string) { c.Narrowings = append(c.Narrowings, reason) }

// setDiff returns what `to` added relative to `from`, and what it removed.
func setDiff(from, to []string) (added, removed []string) {
	inFrom := map[string]bool{}
	for _, s := range from {
		inFrom[s] = true
	}
	inTo := map[string]bool{}
	for _, s := range to {
		inTo[s] = true
	}
	for s := range inTo {
		if !inFrom[s] {
			added = append(added, s)
		}
	}
	for s := range inFrom {
		if !inTo[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// credKeys renders creds as comparable keys. Provider is included because the
// same name under a different provider is a different grant.
func credKeys(creds []Cred) []string {
	out := make([]string, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.Name+"@"+c.Provider)
	}
	return out
}

// dryRunKeys renders preview rules as comparable keys, including the preview
// command: changing what a preview RUNS changes what a reviewer sees.
func dryRunKeys(rules []DryRunRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		key := r.Pattern
		for _, p := range r.Preview {
			key += "\x00" + p
		}
		out = append(out, key)
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(inherit)"
	}
	return s
}
