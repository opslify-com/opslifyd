# Egress control

By default, a sandbox can reach **nothing** on the network. You open exactly what a session
needs — and even then, credential-bearing traffic is mediated so the agent never holds the
token.

## Default-deny

Each session gets its own **nftables** table implementing default-deny egress:

- traffic not from this sandbox's bridge/source is left alone (other sandboxes and the host
  are unaffected);
- **DNS is blocked** to the sandbox (no self-resolving; the daemon resolves and pins IPs) —
  this closes a common exfiltration channel;
- only **allowlisted** destination IPs are accepted;
- everything else is dropped.

The allowlist comes from your policy's `egress.domains` (and the daemon's
`egress_allowlist`), resolved to pinned IPs and refreshed periodically.

## The two legs

There are two distinct network paths, with different trust:

| Leg | Path | Enforcement |
|---|---|---|
| **Direct allowlisted egress** | sandbox → upstream (via host NAT) | nftables allowlist; needs host container NAT working |
| **Credential-blind egress** | sandbox → daemon proxy → upstream | the daemon injects the credential on the upstream leg |

For the credential-blind path, the daemon binds a per-session proxy on the **bridge
gateway** and opens a tightly-scoped hole in the input chain so the sandbox can reach *only*
that proxy port on *only* the gateway from *only* that sandbox — never a general host-local
opening, and never port 53.

## Fail-closed everywhere

- No allowlist match → dropped.
- No reachable gateway or no bound listener → the credential-blind path is **unavailable**
  (no hole opened, no header injected) — never an open-egress or raw-secret fallback.
- Per-session teardown deletes the whole nftables table, so no rule outlives its session.

## Requirements

- Egress enforcement requires the daemon to run as **root** with `nftables` usable — which
  is exactly how the systemd service runs it.
- Direct (non-proxied) sandbox egress also needs host **container NAT** (`ip_forward` + a
  masquerade rule). The installer enables `ip_forward`; a host firewall (ufw/firewalld)
  dropping `FORWARD` can still block it — see [Troubleshooting](../reference/troubleshooting.md).

## Related

- [Credential-blind broker](credential-broker.md) — how injection works.
- [Policy](policy.md) — where the egress allowlist comes from.
