# Phase 3 — Audit Trace + Tamper-Evident Log + Local UI + Cloud Dashboard ⭐

**Weeks:** 6–10 · **Builder:** Go · **Depends on:** P2

> **MARKET HERO phase.** This is what you demo and sell on — governance/visibility with zero credential-broker complexity. Features at spec level; split into `features/F3.*.md` on activation.

## Goal
Every session action visible live (locally AND in cloud), cryptographically accountable, replayable. Local UI works with no cloud connection (for air-gapped/regulated buyers).

## Tools
Go, SHA-256 hash chain, Ed25519, SSE, `embed.FS` + xterm.js (local web UI), Bubble Tea (TUI), existing Opslify frontend/backend (cloud).

---

### F3.1 — Trace events (schema v1)
- Types: `session.start/end`, `exec.start` (argv,cwd), `exec.output` (chunks), `exec.end` (exit,duration), `file.write` (path,size); later `policy.decision` (P4), `cred.resolve` (P5).
- Every event `{ts, session_id, seq, type, payload, prev_hash, hash}` — **hash chain per session**, signed with daemon Ed25519 at close. Session binds `image_digest + toolchain_lock_hash + policy_hash`.
- **Acceptance:** editing a local trace file breaks `opslify verify <session>`.

### F3.2 — Transport
- Local ring buffer + append-only `/var/lib/opslify/traces/<session>.log`; SSE push to cloud with backoff, offline buffering, resume-from-acked-seq.
- **Acceptance:** network cut mid-session → no event loss after reconnect.

### F3.3 — Redaction v1
- Pattern scrub before events leave the daemon: AWS keys, GCP SA JSON, bearer/JWT, `password=`/`token=`, high-entropy strings (config threshold) → `[REDACTED:<type>]`; counts logged; never store raw upstream.
- **Acceptance:** seeded fake AWS key appears redacted in local UI, cloud, and storage.

### F3.4 — Cloud dashboard
- Sessions list (live state/host/agent/duration); live terminal stream + event timeline; replay/scrub; Kill button; `opslify verify`.
- **Acceptance:** exec output visible < 2s.

### F3.5 — Local UI (daemon-served, no cloud) ⭐
- `opslify ui` serves a static SPA on `127.0.0.1:<port>`; `opslify top` TUI variant. Consumes the **same** session API + SSE stream (no new backend).
- Views: live session list, streaming exec output (xterm.js), event timeline, replay, Kill button, approval prompts (once P4 lands).
- SPA embedded via `embed.FS`. **Localhost-only bind; NO auth in v1** (auth/RBAC/remote = cloud/team plane only).
- **Effort: ~4–7 days (web) / ~2–3 (TUI).** **Acceptance:** `opslify ui` shows running sessions live with no cloud configured; output visible < 2s.

## Phase acceptance
- [ ] All features pass. Local UI works fully offline. Trace chain verifies and breaks on tamper. Redaction catches seeded secrets everywhere.

## Sellable milestone
After P3: *"watch, replay, and cryptographically prove everything your agent did to your infra"* — to the human-in-the-loop market, no broker needed.
