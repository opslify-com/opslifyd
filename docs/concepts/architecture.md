# Architecture

opslifyd is a single daemon that mediates every action an agent takes, plus a thin CLI and
an embedded dashboard. Nothing runs on your host directly on behalf of the agent — it all
goes through a sandbox.

## The pieces

```
        AI agent / you
           │        │
   MCP (stdio)   opslify CLI / dashboard
           │        │  (group-gated Unix socket)
           ▼        ▼
        ┌─────────────────────────────┐
        │           opslifyd           │
        │  • session manager           │
        │  • policy engine (F4)        │
        │  • credential broker (F5)    │
        │  • audit sink (F3)           │
        │  • egress controller (nft)   │
        └─────────────────────────────┘
             │            │
     podman/runc/gVisor   encrypted vault
             │
     ┌───────────────┐
     │  sandbox (per │   read-only rootfs · /workspace writable
     │   session)    │   rootless · user-namespaced · seccomp
     └───────────────┘   default-deny egress (nftables)
```

## Daemon (`opslifyd`)

The daemon is the only component that touches your host with privilege. It:

- **manages sessions** — creates/destroys sandboxes, tracks their lifecycle, reaps idle ones;
- **enforces policy** — classifies each command before it runs, gates risky ones for approval;
- **runs the broker** — resolves secrets from the encrypted vault and injects them at the
  network edge (credential-blind);
- **records the audit trail** — a hash-chained, signed, append-only log of every event;
- **programs egress** — per-session nftables rules implementing default-deny + an allowlist.

It runs as a **systemd service** and exposes a group-gated Unix socket
(`/run/opslify/opslifyd.sock`).

## Sandbox runtime

Each session is an OCI container via **podman**, using an OCI runtime tier:

- **gVisor (`runsc`)** — the default when available; intercepts syscalls in userspace for
  a strong isolation boundary.
- **runc** — a standard kernel-namespace container (`local-docker` tier).

Every sandbox is **rootless**, **user-namespaced**, has a **read-only rootfs** (only
`/workspace` is writable), a restrictive **seccomp** profile, dropped capabilities,
`no-new-privileges`, and **default-deny egress**. Commands are executed *into* the sandbox
by the daemon (`podman exec`), never by handing the agent a shell.

## CLI (`opslify`)

The command-line surface for humans: `run`, `session`, `ws`, `workspace`, `secrets`,
`policy`, `verify`, `ui`, `top`, `vault`, `creds`, `approvals`/`approve`/`deny`. It talks
to the daemon over the socket. See the [CLI reference](../reference/cli.md).

## MCP server

`opslifyd mcp` is a stdio [Model Context Protocol](https://modelcontextprotocol.io) server.
An MCP client (e.g. Claude Code) connects to it and gets tools to create sessions, run
commands, upload/download files, and end sessions — so the agent's whole operational
surface is the sandbox. See [Use with AI agents](../guides/ai-agents-mcp.md).

## Dashboard

`opslify ui` serves an embedded, localhost-only single-page app with **per-launch token
auth** (Jupyter-style). It's read + control over live sessions, the audit trail, secret
*names*, workspaces, and policy — and it can create sessions, run commands, and link
directories. See [The dashboard](../guides/dashboard.md).

## Trust boundaries

| Boundary | Enforced by |
|---|---|
| Agent ↔ host | The sandbox (kernel isolation, read-only rootfs, dropped caps) |
| Sandbox ↔ network | nftables default-deny + allowlist; the L7 egress proxy for credential injection |
| Agent ↔ secrets | The broker injects at the network edge; the agent/sandbox/trace never hold the token |
| Anyone ↔ audit trail | Hash chaining + Ed25519 signature; `opslify verify` checks it |
| Local page ↔ dashboard | Loopback bind + DNS-rebind Host-guard + per-launch token |

Read on: [Sessions & workspaces](sessions-workspaces.md) ·
[Credential-blind broker](credential-broker.md) · [Policy](policy.md) ·
[Audit](audit.md) · [Egress](egress.md).
