# Phase 7 — Developer Experience (DX)

**Depends on:** P3 (UI), P4 (policy), P5 (broker). **Builder:** Go.

> Make opslifyd *pleasant* to use without giving back the isolation that is the product. Every feature adds convenience; each ships with a guardrail baked into its acceptance criteria so the security story stays intact.

## Goal
Close the usability gaps that turn "a security researcher can run it" into "a developer enjoys it": full UI parity with the CLI, host-linked workspaces with automatic sync, painless key handling, and gated in-sandbox package installs.

## Features (dependency order)
- **F7.1 — UI launch-token auth** — a per-session bearer token (Jupyter-style launch URL) authenticates the localhost UI. The ENABLER: with auth, the UI can safely gain mutations (parity, linking, secrets) that a random web page / DNS-rebind can't reach. NOT the audit-signing key in the browser.
- **F7.2 — Key UX** — `opslify init` auto-generates the vault master key into the OS keyring (daemon reads it automatically; no startup fatal) with a ONE-TIME reveal + `opslify vault key export` for backup. No persistent "download master key" endpoint.
- **F7.3 — Host-linked workspaces + auto sync** — start a workspace from a host dir (e.g. `/home/alien/myapp`); auto copy-in + continuous bidirectional sync (file-watcher), COPY not bind, secrets excluded on the way in, git as the review/undo safety net (snapshot backup for non-git dirs). `opslify workspace export/sync`.
- **F7.4 — Full UI parity** — create session / run exec / manage secrets (names only) / workspaces / policy view from the browser, each behind F7.1 auth + the DNS-rebind Host-guard + path/sensitive-dir guardrails. Directory-linking + sync toggle live here (safe because of F7.1).
- **F7.5 — `opslify workspace install <pkg>`** — operator-initiated, gated through the F5.5 registry proxy into `/workspace` (project-local venv/node_modules), allowlist + attestation + `pkg.install` audit; session-scoped overlay for system-ish tools.

## Cross-cutting guardrails (every feature)
- No new mutation on the localhost UI without F7.1 auth + the Host-guard.
- Copy-not-bind for host workspaces; exclude/never-copy secret files (.env, .git creds, credentials.*); reviewable/undoable sync-back.
- Installs gated + audited + project-local; no free `apt` over open egress.
- Keys: auto-generate + keyring + one-time reveal; never the audit-signing key in a browser; no persistent secret-download endpoint.
- Cross-platform: CLI/UI/MCP are Go/browser (portable); the daemon+sandbox stay Linux (WSL2 on Windows; managed VM or cloud tier on macOS) — documented, not forced native.
