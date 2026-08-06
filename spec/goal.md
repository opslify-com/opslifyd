# Opslifyd — Goal

## North star (one sentence)

Ship a self-hosted daemon that lets any AI agent execute real DevOps work inside hardened, per-session sandboxes — **auditable, policy-gated, human-approvable, and (later) credential-free by construction** — installable in one command on a developer's own machine.

## North star metric

An external user installs opslifyd, connects Claude Code, and completes a real, policy-gated deployment task — **watched live and cryptographically recorded** — within **15 minutes** of install, on their own machine, with no cloud dependency required.

## What "done" looks like at v1 (end of P4, the MVP)

A self-hosted operator can:
1. `opslify init` → pick their DevOps tools → get a signed, reproducible sandbox environment.
2. Point Claude Code (or any MCP client) at it.
3. Watch every command the agent runs, live, in a **local UI** (no cloud).
4. Have destructive commands (`terraform apply`, `kubectl delete`) **paused for their approval** with a diff preview.
5. Get a **tamper-evident, cryptographically signed record** of everything the agent did, verifiable offline.

All of that **without any credential broker** — that is the P5 upsell, not the MVP.

## What success is NOT (see [mission.md](mission.md) for non-goals)

- Not "yet another cloud sandbox." The win is self-hosted + governed + DevOps-native.
- Not autonomous unattended execution as the primary mode — the market buys human-in-the-loop first.
- Not a secret manager. It is a governed execution + evidence control plane.
