package egress

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// tablePrefix names the per-session nftables table. One table per session is the
// key to deterministic, leak-free teardown: `delete table` removes the chain, both
// sets, and every rule in a single atomic operation — nothing can be orphaned.
const tablePrefix = "opslify_sess_"

// tableName is the inet table for one session id. The id is daemon-generated hex
// (128-bit, see session.newID) so it is already nft-identifier-safe; we still
// sanitize defensively because the sandbox occupant is hostile and ids may one day
// come from elsewhere.
func tableName(sessionID string) string {
	return tablePrefix + sanitizeID(sessionID)
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "anon"
	}
	return b.String()
}

// splitFamilies partitions pinned IPs into sorted, de-duplicated v4 and v6 sets so
// the generated ruleset is deterministic (stable across refreshes that return the
// same addresses in a different order — round-robin DNS does exactly that).
func splitFamilies(ips []netip.Addr) (v4, v6 []netip.Addr) {
	seen4 := map[netip.Addr]bool{}
	seen6 := map[netip.Addr]bool{}
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() {
			if !seen4[ip] {
				seen4[ip] = true
				v4 = append(v4, ip)
			}
		} else {
			if !seen6[ip] {
				seen6[ip] = true
				v6 = append(v6, ip)
			}
		}
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i].Less(v4[j]) })
	sort.Slice(v6, func(i, j int) bool { return v6[i].Less(v6[j]) })
	return v4, v6
}

// buildApplyScript renders the full `nft -f` script that (re)programs one session's
// default-deny egress with exactly the pinned allowlist IPs. It is atomic and
// idempotent by construction:
//
//   - `add table` then `delete table` guarantees a clean slate whether or not the
//     table already existed (a bare `delete` would abort the script if absent, and
//     a bare `add` would leak the prior rules) — so re-apply on an allowlist change
//     never leaks a prior rule.
//   - The base chain hooks `forward` with policy ACCEPT and immediately returns any
//     packet that is not this sandbox's (wrong bridge / wrong source) — so this
//     table only ever governs its own sandbox and never breaks host or sibling
//     traffic. The DENY is the terminal `drop`, reached only by this sandbox.
//   - `udp/tcp dport 53 drop` sits ABOVE the allowlist accepts, so there is NO path
//     for the sandbox to do its own DNS even to an allowlisted IP — the DNS-exfil
//     channel is closed with no fallback resolver reachable.
//   - `ct state established,related accept` lets replies to daemon-initiated flows
//     back in without widening what the sandbox may INITIATE.
func buildApplyScript(net SessionNet, ips []netip.Addr) string {
	v4, v6 := splitFamilies(ips)
	tbl := tableName(net.SessionID)
	br := net.bridge()

	var b strings.Builder
	// Idempotent clean slate.
	fmt.Fprintf(&b, "add table inet %s\n", tbl)
	fmt.Fprintf(&b, "delete table inet %s\n", tbl)
	fmt.Fprintf(&b, "table inet %s {\n", tbl)

	// v4 allow set.
	b.WriteString("\tset allow4 {\n\t\ttype ipv4_addr\n")
	if len(v4) > 0 {
		b.WriteString("\t\telements = { " + joinAddrs(v4) + " }\n")
	}
	b.WriteString("\t}\n")
	// v6 allow set.
	b.WriteString("\tset allow6 {\n\t\ttype ipv6_addr\n")
	if len(v6) > 0 {
		b.WriteString("\t\telements = { " + joinAddrs(v6) + " }\n")
	}
	b.WriteString("\t}\n")

	// Egress chain — order is security-critical (see doc above).
	b.WriteString("\tchain egress {\n")
	b.WriteString("\t\ttype filter hook forward priority filter; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname != \"%s\" accept\n", br)
	if net.SandboxIP != "" {
		if ip, err := netip.ParseAddr(net.SandboxIP); err == nil {
			if ip.Unmap().Is4() {
				fmt.Fprintf(&b, "\t\tip saddr != %s accept\n", ip.Unmap())
			} else {
				fmt.Fprintf(&b, "\t\tip6 saddr != %s accept\n", ip.Unmap())
			}
		}
	}
	b.WriteString("\t\tct state established,related accept\n")
	// No direct DNS — above the allowlist accepts so it can never be bypassed.
	b.WriteString("\t\tudp dport 53 drop\n")
	b.WriteString("\t\ttcp dport 53 drop\n")
	// Allowlist accepts (empty sets simply never match → traffic falls to drop).
	b.WriteString("\t\tip daddr @allow4 accept\n")
	b.WriteString("\t\tip6 daddr @allow6 accept\n")
	// Default-deny: the terminal verdict for this sandbox.
	b.WriteString("\t\tdrop\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// buildTeardownScript renders the `nft -f` script that removes a session's table.
// `add` then `delete` makes it idempotent: it never errors whether the table
// exists, was already removed, or was never created — so destroy always leaves a
// clean slate (no rule leak) and is safe to call unconditionally.
func buildTeardownScript(sessionID string) string {
	tbl := tableName(sessionID)
	return fmt.Sprintf("add table inet %s\ndelete table inet %s\n", tbl, tbl)
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}
