# Phase 1 — Hardened Sandbox Lifecycle (gVisor + Podman)

**Weeks:** 2–5 · **Builder:** Go · **Depends on:** P0 (F0.1, F0.2, F0.3 approved)

## Goal
A daemon that creates hardened per-session sandboxes (gVisor+Podman default) mounting the signed read-only toolchain, and executes **mediated** commands (the daemon is the only executor). Plus the public escape suite from day one.

## Features
| id | title | file | depends |
|---|---|---|---|
| F1.1 | Daemon bootstrap & REST API | [features/F1.1-daemon-bootstrap.md](features/F1.1-daemon-bootstrap.md) | P0 |
| F1.2 | Session lifecycle API | [features/F1.2-session-lifecycle.md](features/F1.2-session-lifecycle.md) | F1.1, F0.2, F0.3 |
| F1.3 | Warm pool | [features/F1.3-warm-pool.md](features/F1.3-warm-pool.md) | F1.2 |
| F1.4 | Default-deny egress + DNS pinning | [features/F1.4-egress-dns-pinning.md](features/F1.4-egress-dns-pinning.md) | F1.2 |
| F1.5 | CLI + public escape suite | [features/F1.5-cli-escape-suite.md](features/F1.5-cli-escape-suite.md) | F1.2 |

## Phase acceptance
- [ ] `opslify run "kubectl version --client"` < 5s cold / < 1s warm on `local-hardened`.
- [ ] From inside: no internet except allowlisted IPs; direct DNS fails; `docker ps` fails; rootfs write outside `/workspace` fails; `/proc/<other-pid>` unreadable; ptrace denied.
- [ ] `uname -r` shows gVisor kernel on `local-hardened`.
- [ ] Escape suite v1 (public repo) — escape + exfil probes fail in CI on runc AND gVisor.
- [ ] Toolchain mounted read-only; in-sandbox install fails.
- [ ] Killing daemon reaps all sandboxes on restart.

## Tools
Go, Podman, gVisor/runsc, nftables, cosign (verify), Cobra.

## Known-risk engineering budget (from tech research — handle explicitly)
- docker-in-docker overlay-on-overlay under gVisor → tmpfs upper layer / `containerd-snapshotter=false`.
- gVisor partial `iptables`, `io_uring` off, no nested KVM → detect + legible errors.
- Distinguish sandbox vs egress vs runtime failures in every error surfaced.
