package egress

import (
	"net/netip"
	"strings"
	"testing"
)

func addrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

// The apply script is the heart of F1.4: it must encode default-deny, a scoped
// allowlist accept, the port-53 block ABOVE the accepts, and per-session isolation.
func TestBuildApplyScript_DefaultDenyAndAllowlist(t *testing.T) {
	net := SessionNet{SessionID: "abc123", SandboxIP: "10.88.0.5", Bridge: "opslify0"}
	got := buildApplyScript(net, addrs(t, "93.184.216.34", "1.1.1.1"))

	mustContain(t, got, "table inet opslify_sess_abc123 {")
	// Idempotent clean slate: add then delete then define.
	mustContainInOrder(t, got,
		"add table inet opslify_sess_abc123",
		"delete table inet opslify_sess_abc123",
		"table inet opslify_sess_abc123 {",
	)
	// Base chain, forward hook, policy accept (so non-sandbox traffic is untouched).
	mustContain(t, got, "type filter hook forward priority filter; policy accept;")
	// Scoped to this bridge + this sandbox source.
	mustContain(t, got, `iifname != "opslify0" accept`)
	mustContain(t, got, "ip saddr != 10.88.0.5 accept")
	// The default-deny terminal verdict.
	mustContain(t, got, "\t\tdrop\n")
	// Allowlist IPs are pinned into the v4 set, sorted deterministically.
	mustContain(t, got, "elements = { 1.1.1.1, 93.184.216.34 }")
	mustContain(t, got, "ip daddr @allow4 accept")
}

// No direct DNS: the port-53 drops MUST appear before the allowlist accepts so an
// allowlisted resolver IP can never be used for DNS (closes the exfil channel).
func TestBuildApplyScript_DNSBlockedAboveAllowlist(t *testing.T) {
	got := buildApplyScript(SessionNet{SessionID: "s1", SandboxIP: "10.88.0.9"}, addrs(t, "8.8.8.8"))
	mustContainInOrder(t, got,
		"udp dport 53 drop",
		"tcp dport 53 drop",
		"ip daddr @allow4 accept",
		"drop",
	)
	// The DNS drop is unconditional — even though 8.8.8.8 is allowlisted, it sits
	// above the accept, so port-53 to it is still dropped.
	if strings.Index(got, "udp dport 53 drop") > strings.Index(got, "@allow4 accept") {
		t.Fatal("port-53 block must precede allowlist accept")
	}
}

// An empty allowlist yields a pure default-deny: sets are declared empty and the
// accepts never match, so everything falls to drop.
func TestBuildApplyScript_EmptyAllowlistDeniesAll(t *testing.T) {
	got := buildApplyScript(SessionNet{SessionID: "s1", SandboxIP: "10.0.0.1"}, nil)
	mustContain(t, got, "set allow4 {")
	mustContain(t, got, "set allow6 {")
	if strings.Contains(got, "elements =") {
		t.Fatalf("empty allowlist must declare no elements, got:\n%s", got)
	}
	mustContain(t, got, "\t\tdrop\n")
}

// IPv6 allowlist entries go into the ip6 set with an ip6 accept.
func TestBuildApplyScript_IPv6(t *testing.T) {
	got := buildApplyScript(SessionNet{SessionID: "s1", SandboxIP: "fd00::5"}, addrs(t, "2606:2800:220:1:248:1893:25c8:1946"))
	mustContain(t, got, "type ipv6_addr")
	mustContain(t, got, "elements = { 2606:2800:220:1:248:1893:25c8:1946 }")
	mustContain(t, got, "ip6 daddr @allow6 accept")
	mustContain(t, got, "ip6 saddr != fd00::5 accept")
}

// Without a sandbox IP the rules are bridge-scoped (no saddr line) — still
// default-deny + no DNS. Documents the F0.3 "runtime exposes no container IP yet" seam.
func TestBuildApplyScript_NoSandboxIP_BridgeScoped(t *testing.T) {
	got := buildApplyScript(SessionNet{SessionID: "s1"}, addrs(t, "1.2.3.4"))
	if strings.Contains(got, "saddr") {
		t.Fatalf("no SandboxIP must omit the saddr scope, got:\n%s", got)
	}
	mustContain(t, got, `iifname != "opslify0" accept`)
	mustContain(t, got, "\t\tdrop\n")
}

// Two sessions produce distinct tables so their default-deny never collides — the
// basis of per-session isolation and leak-free teardown.
func TestBuildApplyScript_PerSessionTables(t *testing.T) {
	a := buildApplyScript(SessionNet{SessionID: "aaa", SandboxIP: "10.0.0.1"}, nil)
	b := buildApplyScript(SessionNet{SessionID: "bbb", SandboxIP: "10.0.0.2"}, nil)
	mustContain(t, a, "table inet opslify_sess_aaa {")
	mustContain(t, b, "table inet opslify_sess_bbb {")
}

// Round-robin returns the same addresses in varying order; the ruleset must be
// stable so a refresh doesn't churn rules needlessly.
func TestBuildApplyScript_DeterministicOrdering(t *testing.T) {
	net := SessionNet{SessionID: "s1", SandboxIP: "10.0.0.1"}
	one := buildApplyScript(net, addrs(t, "1.1.1.1", "2.2.2.2", "3.3.3.3"))
	two := buildApplyScript(net, addrs(t, "3.3.3.3", "1.1.1.1", "2.2.2.2"))
	if one != two {
		t.Fatalf("ruleset not order-stable:\n--- A ---\n%s\n--- B ---\n%s", one, two)
	}
}

func TestBuildTeardownScript_Idempotent(t *testing.T) {
	got := buildTeardownScript("abc123")
	// add-then-delete makes it safe whether or not the table exists.
	mustContainInOrder(t, got,
		"add table inet opslify_sess_abc123",
		"delete table inet opslify_sess_abc123",
	)
}

func TestSanitizeID(t *testing.T) {
	if got := sanitizeID("ab-cd.ef"); got != "ab_cd_ef" {
		t.Fatalf("sanitizeID = %q", got)
	}
	if got := sanitizeID(""); got != "anon" {
		t.Fatalf("empty sanitizeID = %q", got)
	}
}

func mustContain(t *testing.T, hay, needle string) {
	t.Helper()
	if !strings.Contains(hay, needle) {
		t.Fatalf("expected to contain %q, got:\n%s", needle, hay)
	}
}

func mustContainInOrder(t *testing.T, hay string, needles ...string) {
	t.Helper()
	idx := 0
	for _, n := range needles {
		i := strings.Index(hay[idx:], n)
		if i < 0 {
			t.Fatalf("expected %q after position %d, got:\n%s", n, idx, hay)
		}
		idx += i + len(n)
	}
}
