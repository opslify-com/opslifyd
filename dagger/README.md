# Opslifyd verification pipeline (Dagger)

One definition that runs **identically on your machine and in CI** — no flying blind on a
remote runner. Every stage is `dagger call <fn> --source=.` from the repo root.

## Stages

| `dagger call …` | What it verifies | Needs |
|---|---|---|
| `graph --source=.` | Deterministic requirements graph: no cycles / dangling `Depends on:`/`Blocks:` / missing features | python (containerized) |
| `unit --source=.` | `go build` + `vet` + `gofmt` + **race-enabled unit suite** for the whole daemon module | go (containerized) |
| `integration --source=.` | F0.2 tool-dependent ACs: **real** flake.lock resolution, real OCI layer + **cosign** signature, **syft** SBOM | nix+devbox+cosign+syft (containerized via `nixos/nix`) |
| `all --source=.` | Fast gate: `graph` then `unit` | — |

Run everything containerizable locally:
```bash
dagger call all --source=.
dagger call integration --source=.
```

## Verification matrix — what proves what

Three tiers of confidence. Dagger covers the first two on any machine with Docker; the third is
inherently host/kernel-level.

| Claim | How it's verified | Tier | Status |
|---|---|---|---|
| Requirements graph integrity | `dagger call graph` | containerized | ✅ runs here |
| Daemon logic, state machines, concurrency (race) | `dagger call unit` | containerized | ✅ runs here |
| Exec pipe-drain / D1+D2 deadlock fixes | `unit` (deterministic io.Pipe + gated `sh` tests) | containerized | ✅ runs here |
| Egress **ruleset generation** (default-deny, port-53, input-hook, teardown) | `unit` (string-output tests) | containerized | ✅ runs here |
| F0.2 real nix/cosign/syft (AC1/AC2/AC4/AC5) | `dagger call integration` | containerized | ⏳ needs a run |
| **gVisor isolation** (`uname`=gVisor, `docker ps` fails, rootfs RO, `/proc` hidden, ptrace denied) | F1.5 escape suite on a **privileged host** with podman+runsc | **host/kernel** | ⛔ tests not built yet |
| **nftables packet-drop** (real egress deny, direct-DNS fail, host-local resolver drop) | F1.5 escape suite on a host with nft + root + netns | **host/kernel** | ⛔ tests not built yet |
| **podman start→pause→unpause** on a live gVisor container; sub-second warm-start | Real-engine integration on a privileged host | **host/kernel** | ⛔ tests not built yet |
| No orphaned in-container process after exec-kill | Real-engine integration on a privileged host | **host/kernel** | ⛔ tests not built yet |

## The honest boundary

Dagger gives **reproducible, on-system** verification for everything that doesn't require a real
kernel boundary. But the load-bearing **security proofs** — gVisor actually containing an escape,
nftables actually dropping a packet — are kernel-level: they need a **privileged host** running
podman + gVisor(runsc) + nftables as root/CAP_NET_ADMIN, and, crucially, **the escape-suite tests
that assert them do not exist yet** (the current `*Gated` tests only probe `Available()`; they don't
create a container or check isolation).

So "real-engine verification" is two pieces:
1. **This pipeline** — proves build/logic/toolchain-integration, reproducibly, now.
2. **F1.5 (escape suite) + real-engine integration tests** — must be *built*, then run either on a
   privileged host directly or via a privileged Dagger stage (`--privileged`, host netns) that this
   pipeline can grow once those tests exist.

CI (GitHub Actions or any runner) just calls the same `dagger call` targets, so there is one source
of truth for verification regardless of where it runs.
