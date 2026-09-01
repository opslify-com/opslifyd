# opslifyd

**Run AI-agent DevOps commands on your own machine — safely.**

opslifyd is an open-source, self-hosted daemon that executes each command an AI agent
wants to run inside a **hardened, per-session sandbox**, with a **credential-blind secret
broker**, **policy + human approval** gates, and a **tamper-evident audit trail**. It
speaks [MCP](https://modelcontextprotocol.io), so Claude Code (or any MCP client) can
drive it directly — without you handing an agent your shell, your cloud keys, or your
filesystem.

<div class="grid cards" markdown>

- :material-shield-lock: **Credential-blind**

    Agents call GitLab, AWS, npm registries, etc. **without ever seeing the token** —
    the daemon injects it at the network boundary. [How it works →](concepts/credential-broker.md)

- :material-cube-outline: **Hardened sandboxes**

    Every command runs in a rootless, user-namespaced, read-only-rootfs container with
    default-deny egress. [Architecture →](concepts/architecture.md)

- :material-clipboard-check: **Policy + approval**

    Classify commands, require human approval for risky ones, dry-run destructive ops.
    [Policy →](concepts/policy.md)

- :material-file-certificate: **Tamper-evident audit**

    Every action is hash-chained and signed; `opslify verify` proves the trail wasn't
    edited. [Audit →](concepts/audit.md)

</div>

## The 60-second version

```bash
# 1. install once (sets up a background service; no sudo for daily use)
curl -fsSL https://opslify-com.github.io/opslifyd/install.sh | sudo sh

# 2. open a new terminal, then run a command in a fresh sandbox — as yourself
opslify run --mode scratch echo "hello from a sandbox"

# 3. open the dashboard
opslify ui
```

[Get started →](getting-started/quickstart.md){ .md-button .md-button--primary }
[Read the overview →](getting-started/overview.md){ .md-button }

## Why it exists

Giving an AI agent real DevOps power usually means giving it your shell — and therefore
your credentials, your filesystem, and unrestricted network access. opslifyd draws a hard
boundary: the agent asks the daemon to run a command; the daemon runs it in an isolated
sandbox, injects any needed credential **only at the network edge** (so the agent never
holds it), enforces your policy, and records a signed, replayable trail of exactly what
happened.

## What's built today

opslifyd is under active development. The phases below are **complete and on `main`**:

| Area | Status |
|---|---|
| Hardened sandbox runtime (gVisor/runc, rootless, read-only rootfs) | ✅ |
| MCP server (agents drive the daemon) | ✅ |
| Tamper-evident audit + redaction + local UI | ✅ |
| Policy engine + human approval + dry-run | ✅ |
| Credential-blind secret broker (egress injection, cloud adapters, OAuth2, registry proxy) | ✅ |
| Developer experience (key UX, host-linked workspaces + sync, full UI parity, package install) | ✅ |
| One-command installer (systemd service, no sudo for daily use) | ✅ |

On the roadmap: a cloud/team dashboard, compliance reporting, and additional sandbox
backends (Firecracker/Kata). See the [roadmap](about/roadmap.md).

!!! note "Self-hosted and local-first"
    Everything runs on your own host. There is no cloud dependency; the optional team
    plane is separate and opt-in.
