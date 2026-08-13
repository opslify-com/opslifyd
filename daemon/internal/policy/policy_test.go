package policy

import (
	"errors"
	"strings"
	"testing"
)

// AC: a valid policy loads into the resolved model with all sections parsed.
func TestParseValidFullPolicy(t *testing.T) {
	src := `
session:
  ttl: 15m
  tier: local-hardened
  image: base@sha256:deadbeef
allow:
  kubectl:
    namespaces: [team-a, team-b]
    verbs: [get, list, apply]
  terraform:
    commands: [plan, apply]
  exec:
    - "^git (status|log)"
approval_required:
  - "^terraform apply"
egress:
  domains: [api.github.com, "*.hashicorp.com"]
creds:
  - name: aws-ro
    provider: aws
strict_exec: true
`
	p, err := Parse([]byte(src), "policy.yaml")
	if err != nil {
		t.Fatalf("valid policy failed to parse: %v", err)
	}
	if p.Session.TTL != "15m" || p.Session.Tier != "local-hardened" || p.Session.Image != "base@sha256:deadbeef" {
		t.Fatalf("session not parsed: %+v", p.Session)
	}
	if len(p.Allow.Kubectl.Namespaces) != 2 || len(p.Allow.Kubectl.Verbs) != 3 {
		t.Fatalf("kubectl allow not parsed: %+v", p.Allow.Kubectl)
	}
	if len(p.Allow.Terraform.Commands) != 2 || len(p.Allow.Exec) != 1 {
		t.Fatalf("allow not parsed: %+v", p.Allow)
	}
	if len(p.ApprovalRequired) != 1 || len(p.Egress.Domains) != 2 || len(p.Creds) != 1 {
		t.Fatalf("sections not parsed: %+v", p)
	}
	// AC: strict_exec parsed + surfaced.
	if !p.StrictExec {
		t.Fatalf("strict_exec not surfaced")
	}
}

// AC / QA: syntax, unknown-key, wrong-type, out-of-range, and semantic errors
// all produce legible line-level messages (table-driven).
func TestParseLineLevelErrors(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		wantLine int
		wantSub  string
	}{
		{
			name:     "unknown top-level key",
			src:      "session:\n  ttl: 5m\nbogus: true\n",
			wantLine: 3,
			wantSub:  "bogus",
		},
		{
			name:     "wrong type for strict_exec",
			src:      "strict_exec: \"not a bool\"\n",
			wantLine: 1,
			wantSub:  "bool",
		},
		{
			name:     "unknown kubectl verb",
			src:      "allow:\n  kubectl:\n    verbs: [get, destroy]\n",
			wantLine: 3,
			wantSub:  `unknown verb "destroy"`,
		},
		{
			name:     "unknown terraform command",
			src:      "allow:\n  terraform:\n    commands: [plan, nuke]\n",
			wantLine: 3,
			wantSub:  `unknown command "nuke"`,
		},
		{
			name:     "unknown tier",
			src:      "session:\n  tier: wide-open\n",
			wantLine: 2,
			wantSub:  "unknown tier",
		},
		{
			name:     "bad duration",
			src:      "session:\n  ttl: \"not-a-duration\"\n",
			wantLine: 2,
			wantSub:  "invalid duration",
		},
		{
			name:     "ttl out of range",
			src:      "session:\n  ttl: 72h\n",
			wantLine: 2,
			wantSub:  "exceeds maximum",
		},
		{
			name:     "uncompilable exec regex",
			src:      "allow:\n  exec:\n    - \"[unterminated\"\n",
			wantLine: 3,
			wantSub:  "invalid regex",
		},
		{
			name:     "uncompilable approval regex",
			src:      "approval_required:\n  - \"(bad\"\n",
			wantLine: 2,
			wantSub:  "invalid regex",
		},
		{
			name:     "malformed egress domain",
			src:      "egress:\n  domains: [\"http://x.com/path\"]\n",
			wantLine: 2,
			wantSub:  "invalid domain",
		},
		{
			name:     "cred missing provider",
			src:      "creds:\n  - name: aws-ro\n",
			wantLine: 2,
			wantSub:  "provider is required",
		},
		{
			name:     "pure yaml syntax error",
			src:      "session:\n  ttl: [unclosed\n",
			wantLine: 0, // yaml reports its own line; we only assert it's file-prefixed
			wantSub:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src), "policy.yaml")
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("expected *ValidationError, got %T: %v", err, err)
			}
			msg := verr.Error()
			if !strings.Contains(msg, "policy.yaml:") {
				t.Fatalf("error not file-prefixed: %q", msg)
			}
			if tc.wantSub != "" && !strings.Contains(msg, tc.wantSub) {
				t.Fatalf("want substring %q in %q", tc.wantSub, msg)
			}
			// The reported line must appear as policy.yaml:<line>:
			if tc.wantLine > 0 {
				found := false
				for _, le := range verr.Errors {
					if le.Line == tc.wantLine {
						found = true
					}
				}
				if !found {
					t.Fatalf("want a line-%d error, got %+v", tc.wantLine, verr.Errors)
				}
			}
		})
	}
}

// AC / QA: an absent-policy default has a stable, well-known policy_hash, and
// the hash is deterministic across repeated computation and insertion order.
func TestDefaultHashStable(t *testing.T) {
	// Pinned known value: a change to the canonical form (field order, version
	// tag, normalization) is caught loudly here.
	const want = "bf2fb9e607e3112caf9e8b13479cf59f8f094d3577031d510c67cdc74769dc2f"
	got := DefaultHash
	if got != want {
		t.Fatalf("DefaultHash changed: got %s want %s", got, want)
	}
	// Two independently-built empty policies hash identically.
	if Hash(Policy{}) != DefaultHash {
		t.Fatalf("empty Policy hash != DefaultHash")
	}
	// Recompute many times: no drift.
	for i := 0; i < 100; i++ {
		if hashOf(Default()) != got {
			t.Fatalf("hash drift at %d", i)
		}
	}
	t.Logf("DefaultHash = %s", got)
}

// QA: deterministic canonical serialization → the SAME logical policy hashes to
// the SAME value regardless of the order sets were written (mirrors the trace
// canonicalization stability test).
func TestPolicyHashOrderIndependent(t *testing.T) {
	a := Policy{
		Allow: Allow{Kubectl: Kubectl{
			Namespaces: []string{"team-b", "team-a", "team-a"}, // dup + unsorted
			Verbs:      []string{"list", "get"},
		}},
		Egress:           Egress{Domains: []string{"b.com", "a.com"}},
		ApprovalRequired: []string{"y", "x"},
	}
	b := Policy{
		Allow: Allow{Kubectl: Kubectl{
			Namespaces: []string{"team-a", "team-b"},
			Verbs:      []string{"get", "list"},
		}},
		Egress:           Egress{Domains: []string{"a.com", "b.com"}},
		ApprovalRequired: []string{"x", "y"},
	}
	if Hash(a) != Hash(b) {
		t.Fatalf("hash depends on set order/dups: %s != %s", Hash(a), Hash(b))
	}
	// A genuinely different policy must hash differently.
	c := b
	c.StrictExec = true
	if Hash(c) == Hash(b) {
		t.Fatalf("strict_exec change did not alter hash")
	}
}
