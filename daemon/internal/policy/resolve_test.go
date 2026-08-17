package policy

import (
	"strings"
	"testing"
)

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// AC / QA (critical): a malicious workspace policy cannot WIDEN the daemon
// policy. Every over-reach — extra namespaces/verbs/terraform cmds/exec regexes,
// extra egress domains, extra creds, a weaker tier, a longer ttl, a different
// image, or turning strict_exec off — is clamped/dropped, and the resolved model
// is always a SUBSET of the daemon grants.
func TestResolveWorkspaceCannotWiden(t *testing.T) {
	daemon := Policy{
		Session: Session{TTL: "30m", Tier: "local-hardened", Image: "base@sha256:aaa"},
		Allow: Allow{
			Kubectl:   Kubectl{Namespaces: []string{"team-a"}, Verbs: []string{"get", "list"}},
			Terraform: Terraform{Commands: []string{"plan"}},
			Exec:      []string{"^git status"},
		},
		Egress:     Egress{Domains: []string{"api.github.com"}},
		Creds:      []Cred{{Name: "aws-ro", Provider: "aws"}},
		StrictExec: true,
	}
	// Adversarial workspace: grants itself everything extra.
	evil := Policy{
		Session: Session{TTL: "24h", Tier: "local-docker", Image: "evil@sha256:bbb"},
		Allow: Allow{
			Kubectl:   Kubectl{Namespaces: []string{"team-a", "kube-system"}, Verbs: []string{"get", "delete"}},
			Terraform: Terraform{Commands: []string{"plan", "apply", "destroy"}},
			Exec:      []string{"^git status", "^rm -rf /"},
		},
		Egress:     Egress{Domains: []string{"api.github.com", "evil.example.com"}},
		Creds:      []Cred{{Name: "aws-ro", Provider: "aws"}, {Name: "root", Provider: "aws"}},
		StrictExec: false, // tries to turn OFF strict exec
	}
	r := Resolve(daemon, evil)

	// Namespaces: kube-system dropped.
	if contains(r.Allow.Kubectl.Namespaces, "kube-system") {
		t.Fatalf("widened namespaces: %v", r.Allow.Kubectl.Namespaces)
	}
	if !contains(r.Allow.Kubectl.Namespaces, "team-a") {
		t.Fatalf("narrowing lost the legit namespace: %v", r.Allow.Kubectl.Namespaces)
	}
	// Verbs: delete dropped (not in daemon).
	if contains(r.Allow.Kubectl.Verbs, "delete") {
		t.Fatalf("widened verbs: %v", r.Allow.Kubectl.Verbs)
	}
	// Terraform: apply/destroy dropped.
	if contains(r.Allow.Terraform.Commands, "apply") || contains(r.Allow.Terraform.Commands, "destroy") {
		t.Fatalf("widened terraform: %v", r.Allow.Terraform.Commands)
	}
	// Exec: rm -rf dropped.
	if contains(r.Allow.Exec, "^rm -rf /") {
		t.Fatalf("widened exec: %v", r.Allow.Exec)
	}
	// Egress: evil domain dropped.
	if contains(r.Egress.Domains, "evil.example.com") {
		t.Fatalf("widened egress: %v", r.Egress.Domains)
	}
	// Creds: root dropped.
	for _, c := range r.Creds {
		if c.Name == "root" {
			t.Fatalf("widened creds: %v", r.Creds)
		}
	}
	// strict_exec cannot be turned off.
	if !r.StrictExec {
		t.Fatalf("workspace disabled strict_exec")
	}
	// ttl clamped to daemon (shorter), not the 24h ask.
	if r.Session.TTL != "30m" {
		t.Fatalf("ttl widened: %q", r.Session.TTL)
	}
	// tier clamped to daemon (more isolated), not local-docker.
	if r.Session.Tier != "local-hardened" {
		t.Fatalf("tier weakened: %q", r.Session.Tier)
	}
	// image pinned to daemon.
	if r.Session.Image != "base@sha256:aaa" {
		t.Fatalf("image widened: %q", r.Session.Image)
	}
	// Every widening attempt is recorded as a Note.
	if len(r.Notes) == 0 {
		t.Fatalf("no clamp notes recorded for a widening workspace")
	}
	joined := strings.Join(r.Notes, "\n")
	for _, want := range []string{"kube-system", "delete", "apply", "evil.example.com", "root", "session.ttl", "session.tier", "session.image"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected a clamp note mentioning %q; notes:\n%s", want, joined)
		}
	}

	// Structural invariant: resolved grant sets ⊆ daemon grant sets.
	assertSubset(t, "namespaces", r.Allow.Kubectl.Namespaces, daemon.Allow.Kubectl.Namespaces)
	assertSubset(t, "verbs", r.Allow.Kubectl.Verbs, daemon.Allow.Kubectl.Verbs)
	assertSubset(t, "terraform", r.Allow.Terraform.Commands, daemon.Allow.Terraform.Commands)
	assertSubset(t, "exec", r.Allow.Exec, daemon.Allow.Exec)
	assertSubset(t, "egress", r.Egress.Domains, daemon.Egress.Domains)
}

func assertSubset(t *testing.T, field string, got, super []string) {
	t.Helper()
	for _, g := range got {
		if !contains(super, g) {
			t.Fatalf("%s: resolved %q not a subset of daemon %v", field, g, super)
		}
	}
}

// A workspace that genuinely narrows (a strict subset + adds approval gates)
// resolves to exactly that narrowing, with no spurious notes.
func TestResolveLegitimateNarrowing(t *testing.T) {
	daemon := Policy{
		Allow:  Allow{Kubectl: Kubectl{Namespaces: []string{"team-a", "team-b"}, Verbs: []string{"get", "list", "apply"}}},
		Egress: Egress{Domains: []string{"a.com", "b.com"}},
	}
	ws := Policy{
		Allow:            Allow{Kubectl: Kubectl{Namespaces: []string{"team-a"}, Verbs: []string{"get"}}},
		Egress:           Egress{Domains: []string{"a.com"}},
		ApprovalRequired: []string{"^kubectl delete"},
		StrictExec:       true, // tightening
	}
	r := Resolve(daemon, ws)
	if len(r.Notes) != 0 {
		t.Fatalf("legit narrowing produced notes: %v", r.Notes)
	}
	if len(r.Allow.Kubectl.Namespaces) != 1 || r.Allow.Kubectl.Namespaces[0] != "team-a" {
		t.Fatalf("narrowing wrong: %v", r.Allow.Kubectl.Namespaces)
	}
	if !contains(r.ApprovalRequired, "^kubectl delete") {
		t.Fatalf("approval gate not added: %v", r.ApprovalRequired)
	}
	if !r.StrictExec {
		t.Fatalf("strict_exec tightening lost")
	}
}

// A nil (unspecified) workspace set leaves the daemon grant intact; an EMPTY
// (specified-but-empty) workspace set narrows to nothing — both are valid, and
// neither can widen.
func TestResolveNilVsEmptySet(t *testing.T) {
	daemon := Policy{Allow: Allow{Kubectl: Kubectl{Namespaces: []string{"team-a"}}}}

	// Workspace does not mention namespaces at all → daemon grant preserved.
	r1 := Resolve(daemon, Policy{})
	if len(r1.Allow.Kubectl.Namespaces) != 1 {
		t.Fatalf("nil workspace set should preserve daemon grant, got %v", r1.Allow.Kubectl.Namespaces)
	}

	// Workspace explicitly narrows to the empty set → nothing allowed.
	ws := Policy{Allow: Allow{Kubectl: Kubectl{Namespaces: []string{}}}}
	// A []string{} decodes as non-nil empty; simulate that here.
	ws.Allow.Kubectl.Namespaces = []string{}
	r2 := Resolve(daemon, ws)
	if len(r2.Allow.Kubectl.Namespaces) != 0 {
		t.Fatalf("empty workspace set should narrow to nothing, got %v", r2.Allow.Kubectl.Namespaces)
	}
}

// The resolved hash is deterministic and equals a hash over the normalized
// resolved model (the seam F4.2 consumes without re-parsing).
func TestResolveHashDeterministic(t *testing.T) {
	daemon := Policy{Allow: Allow{Kubectl: Kubectl{Namespaces: []string{"team-a", "team-b"}}}}
	ws := Policy{Allow: Allow{Kubectl: Kubectl{Namespaces: []string{"team-b"}}}}
	r1 := Resolve(daemon, ws)
	r2 := Resolve(daemon, ws)
	if r1.Hash != r2.Hash {
		t.Fatalf("resolved hash not deterministic: %s != %s", r1.Hash, r2.Hash)
	}
	if r1.Hash != Hash(r1.Policy) {
		t.Fatalf("resolved hash != hash of resolved model")
	}
	// The resolved model F4.2 reads is the narrowed one.
	if len(r1.Allow.Kubectl.Namespaces) != 1 || r1.Allow.Kubectl.Namespaces[0] != "team-b" {
		t.Fatalf("resolved model wrong: %v", r1.Allow.Kubectl.Namespaces)
	}
}
