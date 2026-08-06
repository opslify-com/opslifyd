# Phase 0 — Scaffold, Nix Env Composer, Install UX

**Weeks:** 1–2 · **Builder:** Go · **Depends on:** none

## Goal
`opslify init` produces a signed, per-project, reproducible toolchain the sandbox will later mount read-only — and the monorepo + four shared interfaces exist. This is the foundation the whole build stands on.

## In scope
- Monorepo scaffold + module layout.
- The four shared interfaces (`Runtime`, `EnvBuilder`, `TraceSink`, `SecretBackend`) with single/stub impls.
- Nix/devbox build-time env composer (D1).
- Interactive install + tool selection UX.

## Out of scope
- Running sandboxes (P1), MCP (P2), trace pipeline (P3), policy (P4), broker (P5).

## Features
| id | title | file | parallel-safe |
|---|---|---|---|
| F0.1 | Interactive install & tool selection | [features/F0.1-install-tool-selection.md](features/F0.1-install-tool-selection.md) | after F0.2 |
| F0.2 | Nix build-time environment composer | [features/F0.2-nix-env-composer.md](features/F0.2-nix-env-composer.md) | yes |
| F0.3 | Runtime & location abstraction | [features/F0.3-runtime-location-abstraction.md](features/F0.3-runtime-location-abstraction.md) | yes |

## Phase acceptance
- [ ] `opslify init` in a sample repo asks for tools and produces a signed, locked toolchain layer.
- [ ] Two different projects yield two different, minimal, independently-hashed toolchains.
- [ ] Daemon refuses an unsigned/digest-mismatched toolchain layer.
- [ ] `flake.lock` hash is recorded and retrievable for a built environment.
- [ ] The four interfaces compile with single impls and are referenced by later phases.

## Tools
Go, Nix, devbox, cosign/sigstore, syft (SBOM), Cobra (CLI), YAML.
