package policy

import (
	"strings"
	"testing"
)

// resolvedWith builds a Resolved directly from a Policy for classifier tests —
// no file parsing, so the classifier is exercised as the pure function it is.
func resolvedWith(p Policy) Resolved {
	n := p.normalize()
	return Resolved{Policy: n, Hash: hashOf(n)}
}

func TestClassify(t *testing.T) {
	// kubectl bounded to namespace "prod-a" and read verbs.
	kube := resolvedWith(Policy{
		Allow: Allow{Kubectl: Kubectl{
			Namespaces: []string{"prod-a"},
			Verbs:      []string{"get", "list"},
		}},
	})
	// terraform bounded to plan/validate.
	tf := resolvedWith(Policy{
		Allow: Allow{Terraform: Terraform{Commands: []string{"plan", "validate"}}},
	})
	// strict_exec with a single allow.exec pattern.
	strict := resolvedWith(Policy{
		StrictExec: true,
		Allow:      Allow{Exec: []string{`^echo( |$)`}},
	})
	// non-strict with an approval gate on kubectl delete.
	approval := resolvedWith(Policy{
		ApprovalRequired: []string{`kubectl delete`},
	})
	// wide-open non-strict default policy.
	open := resolvedWith(Policy{})

	cases := []struct {
		name    string
		r       Resolved
		argv    []string
		want    Verdict
		wantSub string // substring the fired Rule must contain
	}{
		// ---- kubectl namespace enforcement (headline) ----
		{"kubectl allowed ns+verb", kube, []string{"kubectl", "get", "pods", "-n", "prod-a"}, VerdictAllow, "allow.kubectl"},
		{"kubectl cross-namespace -n", kube, []string{"kubectl", "get", "pods", "-n", "prod-b"}, VerdictDeny, "namespaces"},
		{"kubectl cross-namespace --namespace=", kube, []string{"kubectl", "get", "pods", "--namespace=prod-b"}, VerdictDeny, "namespaces"},
		{"kubectl cross-namespace --namespace x", kube, []string{"kubectl", "get", "pods", "--namespace", "prod-b"}, VerdictDeny, "namespaces"},
		{"kubectl cross-namespace -nx stuck", kube, []string{"kubectl", "get", "pods", "-nprod-b"}, VerdictDeny, "namespaces"},
		{"kubectl unspecified ns => default denied", kube, []string{"kubectl", "get", "pods"}, VerdictDeny, "namespaces"},
		{"kubectl flag reorder allowed", kube, []string{"kubectl", "-n", "prod-a", "get", "pods"}, VerdictAllow, "allow.kubectl"},
		{"kubectl disallowed verb", kube, []string{"kubectl", "delete", "pod", "x", "-n", "prod-a"}, VerdictDeny, "verbs"},
		{"kubectl full path binary", kube, []string{"/usr/local/bin/kubectl", "get", "pods", "-n", "prod-a"}, VerdictAllow, "allow.kubectl"},

		// ---- terraform subcommand ----
		{"terraform allowed", tf, []string{"terraform", "plan"}, VerdictAllow, "allow.terraform"},
		{"terraform allowed with flags", tf, []string{"terraform", "-chdir=stack", "validate"}, VerdictAllow, "allow.terraform"},
		{"terraform disallowed", tf, []string{"terraform", "apply", "-auto-approve"}, VerdictDeny, "terraform.commands"},

		// ---- strict_exec ----
		{"strict allow match", strict, []string{"echo", "hi"}, VerdictAllow, "allow.exec"},
		{"strict not in allow denied", strict, []string{"curl", "http://x"}, VerdictDeny, "strict_exec"},
		{"strict kubectl no kube allowlist denied", strict, []string{"kubectl", "get", "pods"}, VerdictDeny, "strict_exec"},

		// ---- approval_required ----
		{"approval matches", approval, []string{"kubectl", "delete", "pod", "x"}, VerdictNeedsApproval, "approval_required"},
		{"approval non-match allowed", approval, []string{"kubectl", "get", "pods"}, VerdictAllow, "default-allow"},

		// ---- non-strict default ----
		{"open allows anything", open, []string{"curl", "http://x"}, VerdictAllow, "default-allow"},
		{"empty argv denied", open, []string{}, VerdictDeny, "empty-argv"},

		// ---- bypass characterization: a shell wrapper hides its sub-command ----
		// Non-strict: argv-matching sees only "sh -c ..."; approval on "kubectl
		// delete" DOES fire here because the residual string contains it, but a
		// crafted wrapper (indirection) would evade — documented in enforce.go.
		{"sh -c residual matches approval", approval, []string{"sh", "-c", "kubectl delete pod x"}, VerdictNeedsApproval, "approval_required"},
		// Strict is the strong mode: the wrapper's own argv ("sh") is not in the
		// allowlist, so it is denied regardless of what it would have run.
		{"sh -c denied under strict", strict, []string{"sh", "-c", "echo hi; curl http://x"}, VerdictDeny, "strict_exec"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.r, tc.argv)
			if got.Verdict != tc.want {
				t.Fatalf("verdict = %q, want %q (rule=%q reason=%q)", got.Verdict, tc.want, got.Rule, got.Reason)
			}
			if tc.wantSub != "" && !strings.Contains(got.Rule, tc.wantSub) {
				t.Fatalf("rule = %q, want to contain %q", got.Rule, tc.wantSub)
			}
			if got.Reason == "" {
				t.Fatalf("decision must carry a legible reason")
			}
		})
	}
}

func TestParseKubectl(t *testing.T) {
	cases := []struct {
		args    []string
		wantNS  string
		wantVrb string
	}{
		{[]string{"get", "pods", "-n", "prod-a"}, "prod-a", "get"},
		{[]string{"-n", "prod-a", "get", "pods"}, "prod-a", "get"},
		{[]string{"get", "--namespace=prod-b"}, "prod-b", "get"},
		{[]string{"get", "--namespace", "prod-b"}, "prod-b", "get"},
		{[]string{"get", "-n=prod-c"}, "prod-c", "get"},
		{[]string{"get", "-nprod-d"}, "prod-d", "get"},
		{[]string{"get", "pods"}, "", "get"},
		{[]string{"--kubeconfig=/x", "logs", "-n", "ns"}, "ns", "logs"},
	}
	for _, tc := range cases {
		ns, verb := parseKubectl(tc.args)
		if ns != tc.wantNS || verb != tc.wantVrb {
			t.Errorf("parseKubectl(%v) = (%q,%q), want (%q,%q)", tc.args, ns, verb, tc.wantNS, tc.wantVrb)
		}
	}
}
