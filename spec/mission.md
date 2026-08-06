# Opslifyd — Mission & Positioning

## Positioning sentence

> **Opslifyd is the open-source, self-hosted control plane for auditable, policy-gated agent DevOps actions — with SOC-2-grade evidence out of the box.**

## The defensible square (why we exist)

Market research (Aug 2026) mapped every adjacent player. Each owns one side of the problem; **none owns ours**:

| Category | Players | What they do | The gap |
|---|---|---|---|
| Cloud agent sandboxes | E2B, Modal, Cloudflare, Fly, Vercel, Northflank | Generic code execution, hosted | Not self-hosted, not DevOps-native, no governance/evidence |
| Secretless / workload identity | Aembit, HashiCorp Vault, SPIFFE/SPIRE, Teleport | Credential brokering / identity | No sandbox, or (Teleport Beams) cloud + microVM only |
| AI-SRE | Resolve AI, Cleric, Traversal | Incident *investigation* | Read-only; don't safely *execute* infra changes |
| Coding-agent sandboxes | nono, container-use, Docker Sandboxes, Claude/Codex sandboxes | Dev-tool isolation | Dev-tools, not terraform/kubectl/aws governance + evidence |

**Our unclaimed square:** governed **DevOps action** layer + **self-hosted** + **compliance evidence**. Nobody sells it. We do.

## Why the market wants this now (demand signals)

- **Incidents:** Replit agent deleted a production DB during a code freeze (2025); Amazon Q extension prompt-injected to run destructive AWS CLI; s1ngularity/Nx weaponized AI CLIs' `--yolo` flags to exfiltrate 2,349 credentials.
- **Funded pull:** Resolve AI (~$1B val), Traversal ($48M A), Cleric (Gartner Cool Vendor) — but the safest incumbent (Cleric) is deliberately **read-only**.
- **Reading of the market:** buyers currently purchase **governed, human-in-the-loop** agent ops — audit, approval, policy — **not** autonomous credential-blind execution. That is why we front-load governance (P3/P4) and treat the broker (P5) as the upsell.

## Product pillars

1. **Containment in depth** — per-session sandbox behind an independent kernel boundary (gVisor default, Kata/Firecracker higher tiers), rootless, user-ns remapped, LSM-hardened inside.
2. **Auditability first** — live trace + tamper-evident hash-chained log binding actions + image digest + toolchain lock + policy hash. Verifiable offline.
3. **Human-in-the-loop control** — declarative policy, approval gates, dry-run interception of destructive ops.
4. **Reproducible environments** — Nix/devbox build-time composer; signed, content-addressed, read-only toolchains.
5. **Credential absence (later)** — executor-side injection so the agent never sees a secret; the autonomous-execution upsell.

## Non-goals (do NOT build these; they dilute the square)

- ❌ A hosted-first / cloud-only product. Cloud is a *late paid tier* for the non-regulated segment, never the flagship.
- ❌ A general-purpose code-execution sandbox competing with E2B/Modal on generic workloads.
- ❌ A standalone secret manager.
- ❌ Autonomous unattended execution as the default UX before governance has users.
- ❌ Multi-user auth / RBAC / remote access in the **local** UI (that belongs to the cloud/team plane).

## Vision (beyond v1)

- **Year 1:** the default governance layer developers reach for before letting an agent touch infra. OSS daemon + paid team control plane + compliance packs.
- **Year 2:** team control plane for agent operations — multi-node, K8s operator mode, compliance-grade audit (SOC 2 evidence), enterprise secret backends.
