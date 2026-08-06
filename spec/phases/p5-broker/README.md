# Phase 5 — Secretless Credential Broker + L7 Egress Proxy

**Weeks:** 14–19 · **Builder:** Rust (secret-critical core) + Go (glue) · **Depends on:** P4

> The **autonomous-execution upsell** — the hardest surface, least-proven demand. Build only after P4 governance has real users signalling they want the human out of the loop. Features at spec level; split into `features/F5.*.md` on activation. **Secret-critical paths are Rust** (`Zeroize`/`secrecy`, `#![forbid(unsafe_code)]` outside audited FFI).

## Goal
Agents perform authenticated actions with **zero secret visibility** — the daemon (executor) injects scoped short-lived tokens on the trusted side; the agent never receives a value, env var, or even a phantom token.

## Tools
Rust (broker core, L7 proxy: hyper + rustls), Go (adapters/glue), per-session mTLS gRPC, SQLite + age/NaCl (vault), OS keyring, cloud provider SDKs, Sigstore (registry proxy).

---

### F5.1 — Executor-side credential injection (primary model)
- Daemon mints scoped short-lived token → injects into spawned process env / request headers → **zeroes broker memory after injection** → token expires with TTL. Worst-case in-sandbox probe sees only a scoped near-expiry token, itself captured in trace.
- AWS: container credentials endpoint (`AWS_CONTAINER_CREDENTIALS_FULL_URI`) so AWS CLIs/SDKs work unmodified. GCP/Azure: env injection at spawn (v1); metadata emulation (stretch). Generic HTTP: via F5.2 proxy header injection.
- Per-session mTLS identity minted at create; broker validates identity + policy per resolution.
- **Acceptance:** `aws s3 ls` succeeds with no AWS env/files in container; red-team cannot recover plaintext beyond scoped short-lived tokens.

### F5.2 — L7 egress proxy (Rust) — *research-flagged as hardest*
- All sandbox HTTP(S) via daemon proxy: TLS-terminating (per-session CA) for header-injection targets, or SNI-validated pass-through. Policy on method+host+path. Per-session upload byte caps; entropy scoring → `egress.anomaly`. Non-HTTP stays default-deny + DNS pinning (F1.4).
- **Known conflict (handle explicitly):** TLS interception breaks out-of-band signature/checksum verification (Terraform providers, package managers) → route those through the F5.5 registry proxy instead of MITM. Inject CA into each session trust store.
- **Acceptance:** private GitHub clone works via proxy injection; token never appears in sandbox.

### F5.3 — Tier 1 adapters
- AWS AssumeRole w/ session policy (scope-down from opslify policy, 15-min); GCP short-lived SA impersonation; Azure federated/managed identity. Source identity: host instance profile / user CLI session / vault bootstrap.

### F5.4 — Tier 2 OAuth2
- One adapter, per-service YAML (auth/token URL, scopes). `opslify creds add github` → device flow → refresh token encrypted; access tokens minted per request, **header injection only**, never persisted, never sent to sandbox as values.

### F5.5 — Tier 3 vault + package registry proxy
- SQLite `vault.db`, age/NaCl encryption, key in OS keyring / passphrase, perms 0600. Call-time injection only. `pip`/`npm`/`go` routed through daemon caching proxy (index-url/registry/GOPROXY) with allowlist + Sigstore/attestation + `pkg.install` hash events. **Closes the poisoned-dependency exfil path AND solves the checksum-vs-MITM conflict from F5.2.**

### F5.6 — SecretBackend interface + audit
- `SecretBackend` (Get/Put/List/Delete) — local vault default; Vault/OpenBao/ASM documented later. Every resolution emits `cred.resolve {tier, provider, scope, ttl, policy_rule, success}`.

## Phase acceptance
- [ ] All acceptance criteria pass; every authenticated call has a matching `cred.resolve` event; red-team recovers no plaintext secret from FS/env/proc/shim beyond scoped short-lived tokens.
