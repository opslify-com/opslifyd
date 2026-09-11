# Opslifyd — Roadmap A (Re-sequenced Build Plan)

**Version:** 1.0
**Date:** August 2026
**Owner:** Qasim Aziz
**Supersedes:** the original dependency-ordered phase spec v0.1 (removed; content now lives in [phases/](phases/))
**Status:** Active build plan · detailed specs in [phases/](phases/) · deterministic graph in [graph.json](graph.json)

---

## 0. Why this re-sequence exists

The original phase spec ordered work by *technical dependency* (sandbox → MCP → trace → broker → policy). Market research says buyers today purchase **governed, human-in-the-loop agent operations** — audit, approval, policy — not autonomous credential-blind execution. The safest funded incumbent (Cleric) is deliberately **read-only**. Demand for agents *autonomously executing* destructive infra commands is asserted by analysts, not yet proven by buyers.

**Therefore this roadmap front-loads the market-aligned surface** (audit + approval + policy) and treats the autonomous secretless credential broker as the *upsell that lands after* the governance layer has real users. Same end-state vision; different order; faster to something sellable.

### Two locked architecture decisions (inputs to every phase)

**D1 — Environment: Nix/devbox as a build-time composer, never a runtime installer.**
User selects tools at install → devbox/Nix generates a locked, hashed toolchain (`flake.lock`) → baked into a **signed, content-addressed, read-only** layer the sandbox mounts. No installs inside the live sandbox. `flake.lock` hash becomes part of the audit attestation.

**D2 — Isolation: a runtime *ladder* behind one `Runtime` interface + a `location` abstraction (local vs remote).**
- `local-docker` — plain runc/Docker. Easy on-ramp, weak isolation. (compat tier)
- `local-hardened` ⭐ — **gVisor (runsc) + Podman (rootless) engine.** The hero / default. Independent user-space kernel, no KVM needed, runs on laptops and cloud VMs.
- `cloud-microvm` — Firecracker on Opslify-hosted cloud. **Paid managed tier for the non-regulated segment. Built last.** Never the flagship — self-hosted is the trust story.

---

## 1. Positioning this roadmap serves

> **Opslifyd is the open-source, self-hosted control plane for auditable, policy-gated agent DevOps actions — with SOC-2-grade evidence out of the box.**

The empty market square: AI-SRE vendors (Resolve/Cleric) do *investigation*; sandbox vendors (E2B/Modal/Cloudflare/Fly) do *generic execution*; nono/container-use do *dev-tool sandboxing*. **Nobody sells the governed-action layer, self-hosted, DevOps-native, with compliance evidence.** Every phase below must defend that square.

---

## 2. Phase ladder (re-sequenced)

| Phase | Original # | Theme | Why here |
|---|---|---|---|
| **P0** | (new) | Scaffold + Nix env composer + install UX | D1 is foundational; tool preloading is your first-run wow |
| **P1** | 1 | Hardened sandbox lifecycle (gVisor+Podman) + CLI | Core boundary; unchanged position |
| **P2** | 2 | MCP integration | Agents must reach it early |
| **P3** | 3 | **Audit trace + tamper-evident log + dashboard** | ⬆ **MARKET HERO** — moved up; this is what sells |
| **P4** | 5 | **Policy engine + approval gates + dry-run** | ⬆ **moved BEFORE broker** — human-in-the-loop is the buy |
| **P5** | 4 | Credential broker (secretless) | ⬇ **moved later** — the autonomous upsell |
| **P6** | 6 | Compliance evidence packs + cloud-microvm tier + beta | Monetization + hardening |

The two big moves: **audit (P3) and policy/approval (P4) come before the credential broker (P5).** You can demo, get users, and charge on P1–P4 alone.

---

## PHASE 0 — Scaffold, Nix Env Composer, Install UX (Weeks 1–2)

**Objective:** `opslify init` produces a signed, per-project toolchain the sandbox will mount read-only.

**In scope**
- Monorepo scaffold: **all Go under `daemon/`** (`daemon/go.mod`, `daemon/cmd/opslifyd`, `daemon/cmd/opslify`, `daemon/internal/{session,trace,policy,broker,mcp,env}`), plus `images/`, `nix/`. Repo root holds only `spec/`, `daemon/`, `.github/`. Module path stays `github.com/opslify-com/opslifyd`.
- Interfaces defined up front (even with single impls): `Runtime`, `SecretBackend`, `TraceSink`, `EnvBuilder`.
- Nix/devbox **env composer** (`internal/env`).

**Feature specs**

**F0.1 — Interactive install & tool selection**
- `opslify init` detects project(s) in a directory, prompts: "Which tools should agents have? [terraform, kubectl, helm, aws, gcloud, az, docker-cli, python, node, go, jq, ...]"
- Writes `opslify.env.yaml` (declared toolset + versions) + generates `devbox.json` / `flake.nix`.
- Config keys carried over from original F1.1: `session_ttl` (30m), `warm_pool_size` (1), `workspace_dir`, `egress_allowlist`.

**F0.2 — Nix build-time environment composer (D1)**
- Resolve declared tools via devbox/Nix → produce `flake.lock` (cryptographic manifest of every tool+version+hash).
- Bake resolved closure into a **content-addressed, read-only** rootfs/overlay layer.
- **cosign-sign** the layer; publish SBOM; record `toolchain_lock_hash`.
- Daemon refuses to start a session whose toolchain layer signature/digest doesn't verify.
- **No runtime installs**: the live sandbox mounts this layer read-only.

**F0.3 — Runtime/location abstraction (D2)**
- `Runtime` interface with `local-docker` (runc) and `local-hardened` (runsc/Podman) impls from day one.
- `location` field (`local` | `remote`) stubbed; `cloud-microvm` impl deferred to P6.

**Deliverables:** scaffolded monorepo, `opslify init`, Nix composer, signed toolchain layer, install script (dev).

**Acceptance**
- [ ] `opslify init` in a sample repo asks for tools and produces a signed, locked toolchain layer.
- [ ] Two different projects yield two different, minimal, independently-hashed toolchains.
- [ ] Daemon refuses an unsigned/digest-mismatched toolchain layer.
- [ ] `flake.lock` hash is recorded and retrievable for a built environment.

---

## PHASE 1 — Hardened Sandbox Lifecycle (Weeks 2–5)

**Objective:** A daemon that creates hardened per-session sandboxes (gVisor+Podman default) and executes mediated commands.

*(This is original Phase 1, with D1/D2 folded in. Retained largely intact — it was sound.)*

**Feature specs**

**F1.1 — Daemon bootstrap**
- REST API over Unix socket `/run/opslify/opslifyd.sock` (perms 0660, group `opslify`).
- Runs as `opslify` system user; generates daemon Ed25519 identity keypair.
- Engine = **Podman (rootless)**; default OCI runtime = **runsc (gVisor)**; `runc` compat fallback selectable.

**F1.2 — Session lifecycle API**
- `POST /sessions {mode, tier?, ttl?}` → `{session_id, state}`; claims a warm pool container, mounts the signed read-only toolchain (F0.2) + writable `/workspace`.
- `POST /sessions/{id}/exec {argv, cwd?, env?, stdin?}` → streams stdout/stderr; returns exit code. **Executor model: the daemon is the only executor** — every exec is a mediated request (policy/trace/cred hook points).
- `DELETE /sessions/{id}`; `GET /sessions`.
- **Container hard spec:** gVisor runtime, non-root UID 1000, user-ns remapped, read-only rootfs, writable `/workspace`, `no-new-privileges`, all caps dropped, seccomp default, `/proc` hygiene (`hidepid=2`, masked paths, ptrace denied), pids 256, mem 2G / CPU 2 (config), **no Docker socket**, attached only to `opslify0`.
- TTL reaper goroutine.

**F1.3 — Warm pool** — N paused pre-created sandboxes; claim + background replenish.

**F1.4 — Egress default-deny** — nftables default-deny + static allowlist + **DNS pinning** (daemon resolves allowlisted domains; sandbox gets IPs only). *(L7 proxy deferred to P5 with the broker.)*

**F1.5 — CLI** — `opslify run "<cmd>"`, `opslify session ls|kill|exec`.

**Acceptance** *(carried from original, tier-aware)*
- [ ] `opslify run "kubectl version --client"` works < 5s cold / < 1s warm on `local-hardened`.
- [ ] From inside: no internet except allowlisted IPs; direct DNS fails; `docker ps` fails; rootfs write outside `/workspace` fails; `/proc/<other-pid>` unreadable; ptrace denied.
- [ ] `uname -r` shows gVisor's kernel on `local-hardened`.
- [ ] **Escape suite v1** (public repo from day one): escape + exfil probes fail in CI on runc AND gVisor.
- [ ] Toolchain layer is mounted read-only; in-sandbox install attempt fails.
- [ ] Killing daemon reaps all sandboxes on restart.

**Known-risk engineering budget (from tech research):** allocate explicit time for (1) **docker-in-docker** overlay-on-overlay under gVisor (tmpfs upper layer workaround), (2) gVisor `iptables`/`io_uring` gaps for network-heavy tools, (3) legible failure messages distinguishing sandbox vs egress vs policy denials.

---

## PHASE 2 — MCP Integration (Weeks 5–6)

**Objective:** Claude Code / any MCP client uses opslify sessions as tools.

*(Original Phase 2, unchanged in intent.)*

**Feature specs**
- **F2.1 MCP tools:** `opslify_session_create`, `opslify_exec` (with output caps + truncation markers), `opslify_upload`/`opslify_download`, `opslify_session_end`. Server: `opslifyd mcp` (stdio), same Unix socket.
- **F2.2 Session modes:** `scratch` (destroyed on end), `workspace` (commit FS to `opslify/ws-<name>:<n>`, resume from snapshot; retention cap 3).
- **F2.3 Claude Code quickstart:** documented `.mcp.json`, example task in README.

**Acceptance**
- [ ] Claude Code completes "clone repo X, run its tests, report failures" using only opslify tools.
- [ ] Workspace session survives daemon restart with deps intact.
- [ ] Upload/download round-trips a 10MB file.

---

## PHASE 3 — Audit Trace + Tamper-Evident Log + Dashboard ⭐ (Weeks 6–10)

**Objective (MARKET HERO):** Every action visible live, cryptographically accountable, replayable. This is the phase you *demo and sell on.*

*(Original Phase 3, promoted. Emphasis shifted from "observability nice-to-have" to "compliance-grade evidence.")*

**Feature specs**

**F3.1 — Trace events (schema v1)** — `session.start/end`, `exec.start` (argv,cwd), `exec.output` (chunks), `exec.end` (exit,duration), `file.write` (path,size). Every event `{ts, session_id, seq, type, payload, prev_hash, hash}` — **hash chain per session**, signed with daemon identity key at close. Each session binds `image_digest + toolchain_lock_hash + policy_hash` (policy_hash populated in P4).

**F3.2 — Transport** — local ring buffer + append-only `/var/lib/opslify/traces/<session>.log`; SSE push to Opslify backend with backoff, offline buffering, resume-from-acked-seq.

**F3.3 — Redaction v1** — pattern scrub before events leave daemon: AWS keys, GCP SA JSON, bearer/JWT, `password=`/`token=`, high-entropy strings (config threshold). Replace with `[REDACTED:<type>]`; log counts; never store raw upstream.

**F3.4 — Cloud dashboard** — sessions list (live state/host/agent/duration); live terminal-style stream + event timeline; replay/scrub; **Kill button**; `opslify verify <session>` chain verification.

**F3.5 — Local UI (daemon-served, no cloud required)** *(strategic: this is the dashboard for air-gapped/regulated buyers who can't use the cloud one)*
- Daemon serves a static SPA on `127.0.0.1:<port>` (`opslify ui`), plus a `opslify top` TUI variant.
- Consumes the **same** session REST API (P1) + SSE trace stream (F3.2) — no new backend work.
- Views: live session list, streaming exec output (xterm.js), event timeline, replay, **Kill button**, approval prompts (once P4 lands).
- SPA bundle embedded in the Go binary (`embed.FS`) — nothing extra to install. **Localhost-only bind; no auth in v1** (auth/RBAC/remote access belong to the cloud/team plane, not here).
- **Effort: ~4–7 days** (web UI) or ~2–3 days (TUI only), because the event pipeline already exists.

**Acceptance**
- [ ] `opslify ui` shows running sessions live with no cloud connection configured.
- [ ] Exec output visible in local UI and cloud dashboard < 2s.
- [ ] Network cut mid-session → no event loss after reconnect.
- [ ] Seeded fake AWS key appears redacted in dashboard and upstream.
- [ ] Editing a local trace file breaks `opslify verify <session>`.
- [ ] Every session's trace binds image digest + toolchain lock + (later) policy hash.

**Sellable milestone:** after P3 you can pitch *"watch, replay, and cryptographically prove everything your agent did to your infra"* — to the human-in-the-loop market, with zero credential-broker complexity yet.

---

## PHASE 4 — Policy Engine + Approval Gates + Dry-Run ⭐ (Weeks 10–14)

**Objective (MARKET HERO cont.):** Sessions obey declarative policy; humans gate destructive actions; destructive infra ops are previewed before they run.

*(Original Phase 5, promoted ahead of the broker — this is the human-in-the-loop capability the market is actually buying.)*

**Feature specs**

**F4.1 — `opslify.policy.yaml`** — loaded from repo root or daemon default; schema-validated with line-level errors. Sections: `session` (ttl/runtime/tier/image), `allow` (kubectl namespaces/verbs, terraform commands, argv regex), `approval_required` (command patterns), `egress` (domains), `creds` (P5). `strict_exec: true` opt-in for exec-allowlist mode. **`policy_hash` written into every session trace.**

**F4.2 — Enforcement points** — Session Manager (egress/runtime/ttl at spin-up); Exec interceptor (argv pattern match before spawn). (Broker cred scoping wired in P5.)

**F4.3 — Approval gates** — matching command → exec paused (`awaiting_approval`), event pushed to dashboard; approve/deny + comment; timeout (default 10m) → auto-deny. **MCP tool returns structured pending/denied status — never hangs the agent.**

**F4.4 — Dry-run interception** — built-in rewrites: `terraform apply` → `terraform plan -out` first, diff surfaced beside the approval prompt; `kubectl delete/apply` → `--dry-run=server` diff first. Extensible rewrite rules in policy.

**Acceptance**
- [ ] `terraform apply` in a gated session → plan diff + approval prompt; approve applies; deny returns reason to agent.
- [ ] kubectl restricted to allowed namespace; cross-namespace call blocked + traced `policy.decision: deny`.
- [ ] Session with no grants cannot run gated commands.
- [ ] Policy syntax error fails fast with line-level message.

**Sellable milestone:** after P4 you have the *complete* human-in-the-loop governance product — sandbox + audit + policy + approvals + dry-run — **without any credential brokering.** This is the fundable, demo-able MVP. Get beta users here before building P5.

---

## PHASE 5 — Secretless Credential Broker (Weeks 14–19)

**Objective (the autonomous upsell):** Agents perform authenticated actions with zero secret visibility. Build this *after* governance has users, because it's the hardest surface and the least-proven demand.

*(Original Phase 4, demoted. Same technical content.)*

**Feature specs**

**F5.1 — Executor-side credential injection (primary model)** — daemon (the executor) mints scoped short-lived token → injects into spawned process env / request headers → zeroes broker memory → token expires. Worst-case in-sandbox probe sees only a scoped near-expiry token, itself captured in trace.
- AWS: container credentials endpoint (`AWS_CONTAINER_CREDENTIALS_FULL_URI`) so AWS CLIs/SDKs work unmodified.
- GCP/Azure: env injection at spawn (v1); metadata emulation (stretch).
- Generic HTTP: **L7 egress proxy** injects `Authorization` at the boundary — token never in sandbox.
- Per-session mTLS identity minted at create; broker validates identity + policy per resolution.

**F5.2 — L7 egress proxy** *(the piece research flagged as hardest)* — all sandbox HTTP(S) via daemon proxy (TLS-terminating for header-injection targets, SNI-validated pass-through elsewhere). Policy on method+host+path. Upload byte caps + entropy scoring → `egress.anomaly`. Non-HTTP stays default-deny + DNS pinning.
  - **Explicit engineering budget:** CA injection into each session trust store; graceful handling where TLS interception breaks **out-of-band signature/checksum verification** (Terraform provider installs, package managers) — route those through the P5.5 registry proxy instead of MITM.

**F5.3 — Tier 1 adapters** — AWS AssumeRole w/ session policy (15-min), GCP short-lived SA impersonation, Azure federated/managed identity. Source identity: host instance profile / user CLI session / vault bootstrap.

**F5.4 — Tier 2 OAuth2** — one adapter, per-service YAML; `opslify creds add github` → device flow → refresh token encrypted; access tokens minted per request, header-injection only.

**F5.5 — Tier 3 vault + package registry proxy** — SQLite `vault.db`, age/NaCl encryption, key in OS keyring; call-time injection only. `pip`/`npm`/`go` routed through daemon caching proxy with allowlist + Sigstore/attestation + `pkg.install` hash events. **This closes the poisoned-dependency exfil path and solves the checksum-vs-MITM conflict from F5.2.**

**F5.6 — SecretBackend interface + audit** — local vault default impl; Vault/OpenBao/ASM documented later. Every resolution emits `cred.resolve` {tier, provider, scope, ttl, policy_rule, success}.

**Acceptance**
- [ ] `aws s3 ls` succeeds with no AWS env/files in container (inspection script).
- [ ] Red-team script cannot recover plaintext secret from FS/env/proc/shim beyond scoped short-lived tokens.
- [ ] Private GitHub clone works via proxy injection; token never appears in sandbox.
- [ ] Every authenticated call has a matching `cred.resolve` event.

---

## PHASE 6 — Compliance Packs, Cloud-MicroVM Tier, Hardening & Beta (Weeks 19–24)

**Objective:** Monetize (compliance + managed tier), harden, ship beta.

**Feature specs**

**F6.1 — Compliance evidence packs (MONETIZATION HERO)** — export SOC-2-style evidence from trace chains: per-session `actions + image_digest + toolchain_lock_hash + policy_hash`, signed, verifiable. This is the paid line-item regulated buyers approve budget for. *(Promoted from original backlog #9 — it's your clearest willingness-to-pay.)*

**F6.2 — Cloud-microvm tier (paid managed)** — Firecracker on Opslify cloud behind the P0 `location=remote` abstraction. **Positioned as the easy on-ramp for the non-regulated segment — not the flagship.** Requires: Opslify-side SOC 2, clear "we broker your creds on our infra" disclosure, tenant isolation. Do not start until self-hosted has real beta users.

**F6.3 — Isolation tiers formalized** — `standard` (gVisor), `compat` (runc + LSMs), `high` (Kata), `cloud` (Firecracker/remote). In-guest seccomp + Landlock/AppArmor on every tier. CI matrix: full acceptance + escape suite on all.

**F6.4 — Distribution** — goreleaser static binaries (amd64/arm64), .deb/.rpm, AUR, signed curl installer w/ checksum.

**F6.5 — Docs & threat-model whitepaper** — quickstart (install → Claude Code task < 15 min), policy reference, threat model vs E2B/Aembit/Beams/nono/Cloudflare, **public escape/exfil results matrix** ("verify our claims yourself").

**F6.6 — Beta** — 3–5 external users; measure install friction, first-task success, policy ergonomics; opt-in telemetry (counts only, never command content).

**Acceptance**
- [ ] Fresh Ubuntu 24.04 + Arch: install → first agent task < 15 min, docs only.
- [ ] Compliance pack exports and independently verifies for a completed session.
- [ ] Full acceptance + escape suite green on gVisor, runc-compat, Kata (+ cloud when live).
- [ ] All P1–P5 red-team scripts pass in CI on every release tag.
- [ ] Escape/exfil suite public with per-release matrix.

---

## 3. Monetization mapped to phases

| Revenue line | Unlocked by | Buyer |
|---|---|---|
| **Team control plane** (multi-user policy, approval routing, SSO, audit retention) | P3 + P4 | security/platform team |
| **Compliance evidence packs** (SOC-2 export) | P6.1 | regulated orgs (highest willingness-to-pay) |
| **Cloud-microvm managed tier** | P6.2 | indie/SMB, zero-ops (non-regulated) |

Daemon stays open-source; charge for the team plane + compliance + managed cloud. Never monetize the daemon itself.

## 4. Sequencing discipline

- **MVP = P0–P4** (governed, human-in-the-loop, no broker). Ship, get beta users, validate demand for autonomous execution *before* investing in P5.
- P5 (broker) only after P4 users signal they want to remove the human from the loop.
- P6.2 (cloud) only after self-hosted has traction. It adds revenue, not defensibility — don't let it reshape the core.

## 5. Cross-phase practices (unchanged from v0.1)

- Interfaces first: `Runtime`, `SecretBackend`, `TraceSink`, `EnvBuilder` in P0.
- Red-team scripts as CI: every security acceptance criterion is an automated PR test.
- Public escape suite from day one.
- Daemon ↔ dashboard API versioned v1; trace schema carries `schema_version`.

---

*Next action: P0 — scaffold monorepo, build the Nix env composer (F0.2), stand up `opslify init`.*
