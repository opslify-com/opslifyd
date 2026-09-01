# Overview

## The problem

AI coding agents are increasingly asked to do **operational** work: run a migration,
call a cloud API, build and push an image, apply a Terraform plan. To do that today, you
typically give the agent a shell — which means giving it your credentials, your
filesystem, and open network access. If the agent is wrong, compromised, or prompt-injected,
the blast radius is your machine and your accounts.

## The opslifyd model

opslifyd puts a daemon between the agent and your system:

```
   AI agent (Claude Code, any MCP client)
        │  MCP (stdio)
        ▼
   opslifyd  ──────────────►  hardened sandbox (per session)
   (policy, broker, audit)         • rootless, user-namespaced
        │                          • read-only rootfs, /workspace writable
        │                          • default-deny egress
        ▼
   your secrets (encrypted vault) ── injected ONLY at the network edge
```

- The agent never runs on your host directly. It asks the daemon to create a **session**
  (a sandbox) and run commands in it.
- Commands are classified by your **policy**; risky ones pause for **human approval**.
- Secrets are **credential-blind**: when a sandboxed tool calls an allowlisted API, the
  daemon injects the token on the *upstream* leg — the agent, the sandbox environment, and
  the audit log never contain it.
- Everything is recorded in a **hash-chained, signed audit trail** you can independently
  verify.

## Key properties

| Property | What it means |
|---|---|
| **Self-hosted** | Runs entirely on your host. No cloud dependency. |
| **Local-first, no-sudo daily use** | Installed once as a system service; you use it as a normal user via a group-gated socket. |
| **Isolation** | Each session is an independent kernel boundary (gVisor by default, or runc), rootless, read-only rootfs. |
| **Credential-blind** | The agent performs authenticated actions without ever holding the credential. |
| **Auditable** | Tamper-evident, replayable trail; `opslify verify` checks integrity against the daemon's signing identity. |
| **Governed** | Policy narrows (never widens) what a session may do; human approval for gated commands; destructive ops can dry-run first. |

## Components

| Component | What it is |
|---|---|
| `opslifyd` | The daemon (runs as a system service). Owns sandboxes, policy, the broker, and the audit sink. |
| `opslify` | The CLI you use day-to-day (`run`, `ui`, `secrets`, `workspace`, …). |
| MCP server | `opslifyd mcp` — the stdio server an AI agent connects to. |
| Dashboard | An embedded, localhost-only web UI (`opslify ui`) with per-launch token auth. |
| Broker + vault | Encrypted secret store; injects credentials at the network edge. |

## Where to go next

- **[Requirements](requirements.md)** — what your host needs.
- **[Quickstart](quickstart.md)** — install and run your first sandboxed command.
- **[Concepts](../concepts/architecture.md)** — how each part works.
- **[Guides](../guides/run-commands.md)** — task-focused walkthroughs.
