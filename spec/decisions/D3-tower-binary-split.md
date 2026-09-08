# D3 — Control Tower is a separate binary, and where the commercial seam goes

**Status:** decided · **Phase:** P8 · **Amends:** D2, F8.8

## The problem
D2 decided the cockpit ships as a localhost SPA **served by the daemon**. That is right for delivery
and wrong for licensing: `opslifyd` is open source, so anything shipped inside it is open source too.
If the Control Tower is ever to be a commercial product, it cannot live in that binary.

Retrofitting the split later is expensive — it means unpicking handlers, auth and build wiring after
they have grown together. The seam costs almost nothing now and a great deal later, so it goes in
before the first Tower feature is written. **No licensing is implemented in this phase; only the seam.**

## Decision

**Two binaries, one API.**

| Binary | Licence | Contains |
|---|---|---|
| `opslifyd` (+ `opslify` CLI) | open source | daemon, sandboxes, MCP, connections, policy, audit, vault — complete and useful standalone |
| `opslify-tower` | to be decided (BSL candidate) | the cockpit: SPA assets + the server that serves them, a **client of the daemon API** |

Tower holds no privilege of its own. It talks to the daemon over the same Unix socket the CLI and MCP
already use, subject to the same group gating (F7.1 token auth still protects Tower's own HTTP
surface). It can therefore be replaced, forked, or run at a different version without touching the
daemon.

**The OSS daemon must remain genuinely complete.** Every operation Tower performs is available from
`opslify` on the command line. If the daemon becomes unusable without Tower it stops being open source
in any meaningful sense and the adoption engine dies. This is a hard rule, checkable in review: a
Tower feature that has no CLI equivalent is a design smell.

## The entitlement seam (build now, enforce never — yet)

One package in Tower, `internal/entitle`, with a single call shape:

```go
if !entitle.Allows(entitle.FeatureTeamApprovals) { … }
```

Rules for this phase:
- `Allows` **returns true for everything.** There is no licence file, no tier, no expiry, no network.
- All feature identifiers are declared in one place, so the set of gateable things is visible at a
  glance rather than scattered through handlers.
- Verification, when it arrives, is an **offline signature check** — a small signed blob (org, tier,
  seats, expiry) verified with a public key compiled into Tower. Reuses the Ed25519 machinery the
  daemon already uses for trace sealing. **No phone-home, ever**: the product claims air-gapped
  operation and default-deny egress, and a licence server would contradict both and be patched out in
  an afternoon regardless.
- A licence state may **only** disable Tower features. It may never stop the daemon, break a running
  sandbox, or interrupt an in-flight Change. Billing state must never break production.

## Consequences

- **F8.8** builds `opslify-tower`, not a handler set inside `opslifyd`. The existing F3.5/F7.4 SPA is
  the starting point and moves with it.
- The daemon's HTTP API becomes a **supported interface** with a version, since a separately-released
  binary depends on it. This is a benefit: it is already the contract the CLI and MCP rely on.
- `opslify ui` (F3.5) stays in the OSS daemon as the minimal free viewer — live sessions, trace,
  verify, approvals. Tower is the full operator surface, not the only one.
- Installer gains an optional Tower step; absence of Tower is a supported, complete configuration.

## Not decided here
The licence for Tower (BSL is the candidate), the free/paid line, and pricing. Those are commercial
decisions to make with buyer evidence, not architecture. This record exists so that making them later
costs a config change rather than a refactor.
