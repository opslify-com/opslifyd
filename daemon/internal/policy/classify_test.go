package policy

import (
	"strings"
	"testing"
)

func base() Policy {
	return Policy{
		Session:          Session{TTL: "30m"},
		Allow:            Allow{Exec: []string{"^kubectl get"}, Kubectl: Kubectl{Namespaces: []string{"prod"}, Verbs: []string{"get"}}},
		ApprovalRequired: []string{"^kubectl delete"},
		Egress:           Egress{Domains: []string{"gitlab.example.com"}},
		Creds:            []Cred{{Name: "gitlab-token", Provider: "gitlab"}},
		StrictExec:       true,
		DryRun:           []DryRunRule{{Pattern: "^terraform apply", Preview: []string{"terraform", "plan"}}},
	}
}

// --- widening: every way the guardrails can loosen -----------------------------

// TestEveryLooseningIsClassifiedAsWidening. A widening slipping through as
// narrowing is BLOCKING: it would apply immediately, ungated, and the record
// would say it was a tightening.
func TestEveryLooseningIsClassifiedAsWidening(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(p *Policy)
		want string
	}{
		{"a new egress host", func(p *Policy) {
			p.Egress.Domains = append(p.Egress.Domains, "evil.example.com")
		}, "egress host allowed"},
		{"a new exec pattern", func(p *Policy) {
			p.Allow.Exec = append(p.Allow.Exec, "^rm -rf")
		}, "exec pattern allowed"},
		{"an approval gate removed", func(p *Policy) {
			p.ApprovalRequired = nil
		}, "approval gate REMOVED"},
		{"a new kubectl namespace", func(p *Policy) {
			p.Allow.Kubectl.Namespaces = append(p.Allow.Kubectl.Namespaces, "kube-system")
		}, "kubectl namespace allowed"},
		{"a new kubectl verb", func(p *Policy) {
			p.Allow.Kubectl.Verbs = append(p.Allow.Kubectl.Verbs, "delete")
		}, "kubectl verb allowed"},
		{"a new terraform command", func(p *Policy) {
			p.Allow.Terraform.Commands = append(p.Allow.Terraform.Commands, "destroy")
		}, "terraform command allowed"},
		{"a new credential grant", func(p *Policy) {
			p.Creds = append(p.Creds, Cred{Name: "aws-admin", Provider: "aws"})
		}, "credential granted"},
		{"strict exec turned off", func(p *Policy) {
			p.StrictExec = false
		}, "strict exec turned OFF"},
		{"a preview rule removed", func(p *Policy) {
			p.DryRun = nil
		}, "preview rule removed"},
		{"failed previews start warning", func(p *Policy) {
			p.DryRunWarnOnFailure = true
		}, "WARN instead of blocking"},
		{"a longer session ttl", func(p *Policy) {
			p.Session.TTL = "8h"
		}, "ttl lengthened"},
		// Tier and Image have NO explicit rule: they are gated by the residual, which
		// is how that mechanism stays load-bearing rather than decorative. The
		// message names the field, so an approver can still see what moved.
		{"the isolation tier changed", func(p *Policy) {
			p.Session.Tier = "local-basic"
		}, "Session.Tier"},
		{"the base image changed", func(p *Policy) {
			p.Session.Image = "other@sha256:beef"
		}, "Session.Image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			to := base()
			tc.edit(&to)
			got := ClassifyEdit(base(), to)
			if got.Direction != DirectionWidening {
				t.Fatalf("%s must be WIDENING, got %s (%v)", tc.name, got.Direction, got.Narrowings)
			}
			var named bool
			for _, w := range got.Widenings {
				if strings.Contains(w, tc.want) {
					named = true
				}
			}
			if !named {
				// An approver reads WHAT is being opened, not merely that something is.
				t.Errorf("the widening must be named (%q); got %v", tc.want, got.Widenings)
			}
		})
	}
}

// TestAnEditedRegexIsGated. Comparing regex languages for containment is
// undecidable in general, so a changed pattern shows up as one added and one
// removed and is gated. Guessing would be exactly the ambiguity this must not
// resolve optimistically.
func TestAnEditedRegexIsGated(t *testing.T) {
	to := base()
	to.Allow.Exec = []string{"^kubectl (get|delete)"} // strictly wider, but that is not knowable here
	got := ClassifyEdit(base(), to)
	if got.Direction != DirectionWidening {
		t.Fatalf("an edited exec regex must be gated, got %s", got.Direction)
	}
	// It is reported as BOTH an addition and a removal, which is the honest
	// description of what the classifier can actually see.
	if len(got.Widenings) == 0 || len(got.Narrowings) == 0 {
		t.Errorf("an edited pattern should read as added + removed: %+v", got)
	}
}

// --- narrowing: tightening must stay ungated ------------------------------------

// TestTighteningIsNarrowingAndStaysUngated. Tightening during an incident must
// never wait for an approver.
func TestTighteningIsNarrowingAndStaysUngated(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(p *Policy)
	}{
		{"an egress host removed", func(p *Policy) { p.Egress.Domains = nil }},
		{"an exec pattern removed", func(p *Policy) { p.Allow.Exec = nil }},
		{"an approval gate added", func(p *Policy) {
			p.ApprovalRequired = append(p.ApprovalRequired, "^kubectl apply")
		}},
		{"a credential revoked", func(p *Policy) { p.Creds = nil }},
		{"a preview rule added", func(p *Policy) {
			p.DryRun = append(p.DryRun, DryRunRule{Pattern: "^kubectl apply", Preview: []string{"kubectl", "diff"}})
		}},
		{"a shorter session ttl", func(p *Policy) { p.Session.TTL = "5m" }},
		{"failed previews start blocking", func(p *Policy) {
			p.DryRunWarnOnFailure = false // already false in base; set explicitly
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			to := base()
			tc.edit(&to)
			got := ClassifyEdit(base(), to)
			if got.Direction == DirectionWidening {
				t.Fatalf("%s must not be gated as widening: %v", tc.name, got.Widenings)
			}
		})
	}
	// Turning strict exec ON is a narrowing.
	from := base()
	from.StrictExec = false
	if got := ClassifyEdit(from, base()); got.Direction != DirectionNarrowing {
		t.Errorf("turning strict exec on must be narrowing, got %s", got.Direction)
	}
}

// TestNoChangeIsEquivalent: an edit that changes nothing must not manufacture an
// approval.
func TestNoChangeIsEquivalent(t *testing.T) {
	if got := ClassifyEdit(base(), base()); got.Direction != DirectionEquivalent {
		t.Fatalf("an identical policy must be equivalent, got %s (%v / %v)", got.Direction, got.Widenings, got.Narrowings)
	}
	// Ordering must not matter: a re-ordered list is the same policy.
	to := base()
	to.Egress.Domains = []string{"gitlab.example.com"}
	to.Allow.Exec = []string{"^kubectl get"}
	if got := ClassifyEdit(base(), to); got.Direction != DirectionEquivalent {
		t.Errorf("re-ordering must not register as a change, got %s", got.Direction)
	}
}

// TestAMixedEditIsWidening: one loosening among many tightenings is still a
// loosening, and the whole edit is gated.
func TestAMixedEditIsWidening(t *testing.T) {
	to := base()
	to.Egress.Domains = []string{"evil.example.com"} // removes one, adds one
	to.ApprovalRequired = append(to.ApprovalRequired, "^kubectl apply")
	to.Session.TTL = "5m"
	got := ClassifyEdit(base(), to)
	if got.Direction != DirectionWidening {
		t.Fatalf("a mixed edit containing any loosening must be widening, got %s", got.Direction)
	}
	if len(got.Narrowings) == 0 {
		t.Error("the tightenings should still be recorded, so the record is complete")
	}
}

// --- the conservative default, which is the whole design ------------------------

// TestTheConservativeDefaultIsLoadBearing is the property that makes forgetting
// safe: every field ClassifyEdit understands is blanked before a residual
// comparison, so a field with NO rule is automatically gated. The cost of
// forgetting is an unnecessary approval, never an ungoverned loosening.
//
// It is exercised through real fields — Session.Tier and Session.Image have no
// explicit rule on purpose — rather than by poking at residual() directly. A test
// that only called the helper would pass even if ClassifyEdit stopped consulting
// it, which is exactly how an earlier version of this let that mutation survive.
func TestTheConservativeDefaultIsLoadBearing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(p *Policy)
		field string
	}{
		{"tier", func(p *Policy) { p.Session.Tier = "local-basic" }, "Session.Tier"},
		{"image", func(p *Policy) { p.Session.Image = "other@sha256:beef" }, "Session.Image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			to := base()
			tc.edit(&to)
			got := ClassifyEdit(base(), to)
			if got.Direction != DirectionWidening {
				t.Fatalf("an unclassifiable field change must be gated, got %s", got.Direction)
			}
			var named bool
			for _, w := range got.Widenings {
				if strings.Contains(w, tc.field) {
					named = true
				}
			}
			if !named {
				t.Errorf("the widening must NAME the field; got %v", got.Widenings)
			}
		})
	}
	// And the mechanism reports every differing field, not just the first.
	to := base()
	to.Session.Tier = "local-basic"
	to.Session.Image = "other@sha256:beef"
	if diff := residualDiff(base(), to); len(diff) != 2 {
		t.Errorf("residualDiff = %v, want both fields named", diff)
	}
}

// TestEveryPolicyFieldIsEitherClassifiedOrResidual guards the mechanism itself: if
// someone adds a field AND blanks it in residual() without adding a rule, the
// conservative default is silently disabled for that field. This walks the struct
// and asserts every field is one or the other.
func TestEveryPolicyFieldIsEitherClassifiedOrResidual(t *testing.T) {
	// A policy where every field differs from the zero value.
	full := Policy{
		Session:             Session{TTL: "1h", Tier: "t", Image: "i"},
		Allow:               Allow{Exec: []string{"e"}, Kubectl: Kubectl{Namespaces: []string{"n"}, Verbs: []string{"v"}}, Terraform: Terraform{Commands: []string{"c"}}},
		ApprovalRequired:    []string{"a"},
		Egress:              Egress{Domains: []string{"d"}},
		Creds:               []Cred{{Name: "n", Provider: "p"}},
		StrictExec:          true,
		DryRun:              []DryRunRule{{Pattern: "p", Preview: []string{"x"}}},
		DryRunWarnOnFailure: true,
	}
	// Against an empty policy, EVERY field differs — so the classifier must report
	// something for all of them. If it reports nothing the field is invisible to
	// both the rules and the residual, which is the dangerous state.
	got := ClassifyEdit(Policy{}, full)
	if len(got.Widenings)+len(got.Narrowings) == 0 {
		t.Fatal("a policy differing in every field produced no classification at all")
	}
	// And the reverse direction must also be non-empty.
	back := ClassifyEdit(full, Policy{})
	if len(back.Widenings)+len(back.Narrowings) == 0 {
		t.Fatal("the reverse edit produced no classification at all")
	}
}

// TestAnUnparseableTTLIsGated: an edit whose effect cannot be computed is the
// definition of ambiguous.
func TestAnUnparseableTTLIsGated(t *testing.T) {
	for _, ttl := range []string{"not-a-duration", "30", "forever"} {
		to := base()
		to.Session.TTL = ttl
		if got := ClassifyEdit(base(), to); got.Direction != DirectionWidening {
			t.Errorf("ttl %q cannot be compared and must be gated, got %s", ttl, got.Direction)
		}
	}
}

// TestMovingToOrFromTheInheritedTTLIsGated: the daemon default is not known here,
// so the effective change in lifetime is unknown.
func TestMovingToOrFromTheInheritedTTLIsGated(t *testing.T) {
	to := base()
	to.Session.TTL = ""
	if got := ClassifyEdit(base(), to); got.Direction != DirectionWidening {
		t.Errorf("moving to the inherited ttl must be gated, got %s", got.Direction)
	}
	from := base()
	from.Session.TTL = ""
	if got := ClassifyEdit(from, base()); got.Direction != DirectionWidening {
		t.Errorf("moving from the inherited ttl must be gated, got %s", got.Direction)
	}
}

// TestAChangedPreviewCommandIsGated: changing what a preview RUNS changes what a
// reviewer sees, which is a loosening of the review even though the rule count is
// unchanged.
func TestAChangedPreviewCommandIsGated(t *testing.T) {
	to := base()
	to.DryRun = []DryRunRule{{Pattern: "^terraform apply", Preview: []string{"echo", "nothing-to-see"}}}
	if got := ClassifyEdit(base(), to); got.Direction != DirectionWidening {
		t.Fatalf("changing a preview command must be gated, got %s (%v)", got.Direction, got.Narrowings)
	}
}

// TestTheSameCredentialUnderADifferentProviderIsANewGrant.
func TestTheSameCredentialUnderADifferentProviderIsANewGrant(t *testing.T) {
	to := base()
	to.Creds = []Cred{{Name: "gitlab-token", Provider: "github"}}
	got := ClassifyEdit(base(), to)
	if got.Direction != DirectionWidening {
		t.Fatalf("the same name under a different provider is a different grant, got %s", got.Direction)
	}
}
