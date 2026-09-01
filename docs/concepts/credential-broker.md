# Credential-blind broker

The broker is what lets an agent perform **authenticated** actions — call GitLab, assume an
AWS role, pull from a private npm registry — **without ever seeing the credential**.

## The idea

Instead of putting a token in the sandbox's environment (where the agent can read and
exfiltrate it), the daemon injects the credential **at the network boundary**, on the leg
between the daemon and the upstream service. The sandbox sends an ordinary request; the
daemon adds the auth header on the way out.

```
sandbox ──(no token)──► daemon egress proxy ──(+ Authorization/PRIVATE-TOKEN)──► upstream
```

The agent, the sandbox environment, the workspace, and the audit trail contain **no token**.

## Where secrets live

Secrets are stored in a local **encrypted vault** (`/var/lib/opslify/vault.db`), sealed with
envelope encryption (AES-256-GCM) under the **vault master key**. The broker's interface is
deliberately **write-only** from the outside: you can add and list *names*, but there is no
API/UI/socket route that returns a secret value.

```bash
opslify secrets add gitlab-token --provider gitlab   # value from stdin, never an argument
opslify secrets ls                                    # names + metadata only
opslify secrets rm <ref>
```

## Injection mechanisms

The broker supports several injection styles, chosen per credential:

| Mechanism | For |
|---|---|
| **L7 egress proxy** | HTTP APIs — the daemon terminates TLS with a per-session CA and adds the auth header on the upstream leg (`egress_inject`). |
| **Cloud adapters** | AWS (STS AssumeRole via a container-credentials endpoint), GCP, Azure — scoped, TTL-bounded. |
| **Registry proxy** | pip/npm/Go — injects registry auth server-side, checksum-safe, allowlisted, attested. |
| **OAuth2 device flow** | Onboard OAuth2-backed services (`opslify creds add`) without pasting long-lived tokens. |

## Per-session, fail-closed

- Each session gets a **fresh per-session CA** (the private key never leaves the daemon).
- The credential-injecting listeners bind the **bridge gateway** and are **source-scoped**
  to the owning container.
- If the credential can't be resolved, or the network path isn't available, the broker
  **fails closed** — no header injected, no raw-secret fallback. The blind path is simply
  unavailable; a token is never leaked to make something work.

## The vault master key

The master key encrypts every secret. `opslify init` generates it and reveals it **once** —
save it in a password manager. Back it up any time with:

```bash
opslify vault key export
```

The key is **CLI-only** — no API, UI, or socket route ever returns it. Losing it makes
vaulted secrets unrecoverable (by design).

## Try it

Walk through a real, credential-blind GitLab call:
[Credential-blind API access](../guides/credential-blind-gitlab.md).
