package egress

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
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
//   - The `egress` chain hooks `forward` with policy ACCEPT and immediately returns
//     any packet that is not this sandbox's (wrong bridge / wrong source) — so this
//     table only ever governs its own sandbox and never breaks host or sibling
//     traffic. The DENY is the terminal `drop`, reached only by this sandbox.
//   - `udp/tcp dport 53 drop` sits ABOVE the allowlist accepts, so there is NO path
//     for the sandbox to do its own DNS even to an allowlisted IP — the DNS-exfil
//     channel is closed with no fallback resolver reachable.
//   - `ct state established,related accept` lets replies to daemon-initiated flows
//     back in without widening what the sandbox may INITIATE.
//
// The `host_input` chain closes the F1.4-QA gap (prereq #3): the `forward` hook only
// sees ROUTED egress. Traffic the sandbox sends to a service bound to the HOST itself
// — a runtime-injected resolver such as podman/aardvark-dns, `127.0.0.11`, or anything
// listening on the `opslify0` bridge IP — is delivered locally and traverses the
// kernel's `input` hook, NOT `forward`, so the forward-chain port-53 drop and
// default-deny never apply. Without this chain a sandbox could reach a host-local
// resolver and re-open the DNS/exfil channel the forward chain closes. `host_input`
// therefore mirrors the forward posture on the input path, but is scoped STRICTLY to
// sandbox-sourced packets so it cannot disturb the host's own inbound traffic or any
// other interface:
//
//   - It hooks `input` with policy ACCEPT and returns immediately for anything not
//     arriving on this sandbox's bridge (`iifname != opslify0`) or not from this
//     sandbox's source address — the host's own services and sibling sandboxes are
//     never affected.
//   - `ct state established,related accept` admits return/related packets (e.g. ICMP
//     errors) without widening what the sandbox may INITIATE toward the host: a fresh
//     DNS query is conntrack state `new`, so it can never match here and is dropped.
//   - `udp/tcp dport 53 drop` blocks any host-local resolver, matching the DNS-pinning
//     posture (the sandbox gets NO resolver; the daemon resolves and pins IPs).
//   - The terminal `drop` is default-deny for host-local services generally, following
//     the same no-fallback posture as the forward chain.
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

	// Egress chain — order is security-critical (see doc above). Governs ROUTED
	// egress via the forward hook.
	b.WriteString("\tchain egress {\n")
	b.WriteString("\t\ttype filter hook forward priority filter; policy accept;\n")
	writeSandboxScope(&b, br, net.SandboxIP)
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

	// host_input chain — governs traffic the sandbox sends to the HOST itself (a
	// host-local resolver, bridge-IP service, etc.), which the kernel delivers via
	// the input hook, not forward. Scoped STRICTLY to this sandbox's packets so the
	// host's own inbound traffic and sibling interfaces are never touched (see doc
	// above). Same delete-table teardown as `egress` — no separate cleanup, no leak.
	b.WriteString("\tchain host_input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy accept;\n")
	writeSandboxScope(&b, br, net.SandboxIP)
	// Return/related packets (e.g. ICMP errors) pass; a fresh sandbox→host query is
	// conntrack state `new`, so this never admits a new host-local flow.
	b.WriteString("\t\tct state established,related accept\n")
	// No host-local resolver: block DNS to the host, matching the forward-path drop.
	b.WriteString("\t\tudp dport 53 drop\n")
	b.WriteString("\t\ttcp dport 53 drop\n")
	// F5.8 credential-blind reachability: admit the sandbox to the daemon's
	// per-session credential-injecting listeners (F5.7 egress proxy, F5.1 creds
	// endpoint, F7.5 registry proxy), which bind the bridge GATEWAY IP and are
	// delivered via this input hook. Scoped to daddr==gateway AND the specific bound
	// ports (and, via writeSandboxScope above, saddr==this sandbox) — so it opens
	// ONLY the blind-path ports on ONLY the gateway, never a general host-local hole
	// and never port 53 (the DNS drop sits above this). No ports => no rule, so the
	// chain stays fully default-deny when the blind path is inactive.
	writeGatewayPortAllow(&b, net.GatewayIP, net.LocalTCPPorts)
	// Default-deny host-local services generally (no fallback), mirroring egress.
	b.WriteString("\t\tdrop\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// writeSandboxScope emits the early-accept lines shared by both hooks: any packet not
// arriving on this sandbox's bridge, or not from this sandbox's source address, is
// accepted immediately so the per-session table only ever governs its own sandbox and
// never disturbs host or sibling traffic. An empty SandboxIP omits the saddr line
// (bridge-scoped only — the F0.3 seam where the runtime exposes no container IP yet).
func writeSandboxScope(b *strings.Builder, bridge, sandboxIP string) {
	fmt.Fprintf(b, "\t\tiifname != \"%s\" accept\n", bridge)
	if sandboxIP == "" {
		return
	}
	ip, err := netip.ParseAddr(sandboxIP)
	if err != nil {
		return
	}
	if ip.Unmap().Is4() {
		fmt.Fprintf(b, "\t\tip saddr != %s accept\n", ip.Unmap())
	} else {
		fmt.Fprintf(b, "\t\tip6 saddr != %s accept\n", ip.Unmap())
	}
}

// writeGatewayPortAllow emits the F5.8 host_input accept for the credential-blind
// listener ports: `ip[6] daddr <gateway> tcp dport { ports } accept`, scoped to the
// gateway address so it can never admit traffic to any other host-local service. It
// emits nothing when the gateway is unset/unparyable or no ports are given, keeping
// the chain fully default-deny in the pre-F5.8 / blind-path-inactive case. Port 53
// is defensively excluded (the DNS drop already sits above this line, but excluding
// it here too means a mis-passed 53 can never reopen the resolver channel).
func writeGatewayPortAllow(b *strings.Builder, gatewayIP string, ports []int) {
	if gatewayIP == "" || len(ports) == 0 {
		return
	}
	gw, err := netip.ParseAddr(gatewayIP)
	if err != nil {
		return
	}
	seen := map[int]bool{}
	var list []string
	for _, p := range ports {
		if p <= 0 || p > 65535 || p == 53 || seen[p] {
			continue
		}
		seen[p] = true
		list = append(list, strconv.Itoa(p))
	}
	if len(list) == 0 {
		return
	}
	fam := "ip"
	if !gw.Unmap().Is4() {
		fam = "ip6"
	}
	fmt.Fprintf(b, "\t\t%s daddr %s tcp dport { %s } accept\n", fam, gw.Unmap(), strings.Join(list, ", "))
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
