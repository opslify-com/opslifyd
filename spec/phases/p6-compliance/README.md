# Phase 6 — Compliance Packs, Cloud-MicroVM Tier, Hardening & Beta

**Weeks:** 19–24 · **Builder:** Go · **Depends on:** P5 (compliance can start after P4)

> Monetization + hardening + ship. Features at spec level; split into `features/F6.*.md` on activation.

## Goal
Turn the governance + evidence story into revenue (compliance packs + managed tier), harden all isolation tiers, and run a real beta.

## Tools
Go, Firecracker (cloud), Kata (high tier), goreleaser, cosign, Dagger CI matrix, Landlock/AppArmor.

---

### F6.1 — Compliance evidence packs (MONETIZATION HERO)
- Export SOC-2-style evidence from trace chains: per-session `actions + image_digest + toolchain_lock_hash + policy_hash`, signed, independently verifiable. **This is the paid line-item regulated buyers approve budget for** (promoted from original backlog).
- **Acceptance:** a completed session exports a pack that independently verifies.

### F6.2 — Cloud-microvm tier (paid managed)
- Firecracker on Opslify cloud behind the P0 `location=remote` seam. **Positioned as the easy on-ramp for the non-regulated segment — never the flagship.** Requires Opslify-side SOC 2, explicit "we broker your creds on our infra" disclosure, tenant isolation. **Do not start until self-hosted has real beta users.**

### F6.3 — Isolation tiers formalized
- `standard` (gVisor, default), `compat` (runc + full LSM stack), `high` (Kata microVM), `cloud` (Firecracker/remote). In-guest seccomp + Landlock/AppArmor on every tier. CI matrix runs full acceptance + escape suite on all.
- **Acceptance:** full acceptance + escape suite green on gVisor, runc-compat, and Kata.

### F6.4 — Distribution
- goreleaser static binaries (amd64/arm64), .deb/.rpm, AUR, signed curl installer with checksum verification.

### F6.5 — Docs & threat-model whitepaper
- Quickstart (install → Claude Code task < 15 min), policy reference, threat model vs E2B/Aembit/Beams/nono/Cloudflare, **public escape/exfil results matrix**.
- **Acceptance:** fresh Ubuntu 24.04 + Arch reach first successful agent task < 15 min, docs only.

### F6.6 — Beta
- 3–5 external users; structured feedback (install friction, first-task success, policy ergonomics). Opt-in telemetry (install success, session counts — **never command content**).

## Phase acceptance
- [ ] Compliance pack exports + verifies. Escape suite green on all tiers. All P1–P5 red-team scripts pass in CI on every release tag. Escape/exfil suite public with per-release matrix. Cloud tier (if built) tenant-isolated + disclosed.
