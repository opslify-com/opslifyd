# Roadmap

opslifyd is built in phases. This page tracks what's done and what's planned. It's a living
document — the [changelog](#changelog) at the bottom records notable changes.

## Done

| Phase | What shipped |
|---|---|
| **P0–P1** | Scaffold, hardened sandbox runtime (gVisor/runc, rootless, read-only rootfs, default-deny egress). |
| **P2** | MCP server — agents drive the daemon. |
| **P3** | Tamper-evident audit (hash chain + Ed25519 seal), redaction, durable trace, embedded local UI. |
| **P4** | Policy engine, human approval gates, dry-run for destructive ops. |
| **P5** | Credential-blind broker — encrypted vault, L7 egress injection, cloud adapters (AWS/GCP/Azure), OAuth2 device flow, registry proxy, live reachability. |
| **P7** | Developer experience — key UX, host-linked workspaces + auto sync, full UI parity, gated package install. |
| **Install** | One-command installer + systemd service (no sudo for daily use). |

## Planned

| Area | Description |
|---|---|
| **Team/cloud dashboard** | An optional, opt-in plane for shared audit retention and multi-user access with real auth/RBAC (the daemon already has a resumable trace uploader). |
| **Compliance reporting** | Exportable reports over the audit trail. |
| **More sandbox backends** | Firecracker / Kata microVMs as additional isolation tiers — a "batteries" model so operators pick the boundary that fits. |
| **Signed toolchain by default** | A packaged, cosign-signed toolchain so `--dev-skip-verify` is unnecessary out of the box. |
| **Cross-platform install** | First-class Windows (WSL2) and macOS (managed Linux VM) install paths. |
| **`opslify doctor`** | A one-shot health/diagnostics command (service, group, egress, image, keys). |
| **Public curl \| sh with auto-prereqs** | Installer that can also install podman/nftables for you. |

## How to scale this documentation

This site is plain Markdown built with MkDocs Material. To add a page:

1. create `docs/<section>/<page>.md`;
2. add one line under the right section in `mkdocs.yml`'s `nav:`;
3. commit — CI rebuilds and republishes.

New feature areas get a page under **Concepts** (how it works) and a task page under
**Guides** (how to use it), plus reference updates. See [Contributing](contributing.md).

## Changelog

- **2026-08** — One-command installer + systemd service (no sudo for daily use);
  credential-blind reachability verified on a live host; full documentation site.
- Earlier — P0–P5 and P7 completed and tagged (see the repository tags `p0-complete` …
  `p7-complete`).
