# Opslifyd — Architecture & Diagrams

All diagrams are Mermaid so agents can parse them. This is the shared mental model every agent must hold.

---

## 0. Repo layout (locked)

All Go code lives under **`daemon/`** so the repo root stays docs-first. Module path is `github.com/opslify-com/opslifyd`; the module root is `daemon/` (that's where `go.mod`/`go.sum` live). Run all `go` commands from `daemon/`; CI uses `working-directory: daemon`.

```
opslifyd/
├── spec/                # all docs & agent specs (goal/mission/architecture/phases/best-practices/tools)
├── .github/workflows/   # CI (validate + integration)
└── daemon/              # the Go module
    ├── go.mod  go.sum
    ├── cmd/{opslifyd,opslify}/     # daemon + CLI entrypoints
    └── internal/{env,session,trace,policy,broker,mcp}/
```
(P5 Rust components live under `daemon/` too, e.g. `daemon/broker-rs/`, `daemon/proxy-rs/`, when introduced.)

## 1. Stack (locked)

| Concern | Choice | Why |
|---|---|---|
| Primary language | **Go** | Ecosystem: gVisor, containerd, Podman bindings, cosign/sigstore, Dagger, official MCP SDK all Go |
| Secret-critical paths (P5) | **Rust** | Credential broker core + L7 egress proxy — memory-zeroing, safe plaintext-secret handling |
| Container engine | **Podman** (rootless) — containerd acceptable | Daemonless, rootless-by-default; strong security posture; no root Docker daemon |
| OCI runtime (default) | **gVisor / `runsc`** | Independent user-space kernel, no KVM needed, runs on laptops + cloud VMs |
| OCI runtime (compat) | **runc** | Fallback for tools gVisor breaks |
| OCI runtime (high, later) | **Kata**, then **Firecracker** (cloud tier) | microVM boundary; Firecracker needs KVM → cloud only |
| Env composer | **Nix + devbox** | Reproducible, content-addressed; `flake.lock` = SBOM/attestation |
| Image signing / SBOM | **cosign / sigstore**, **syft** | Signed, digest-pinned toolchains |
| Build & CI | **Dagger** | Reproducible pipelines in Go |
| MCP | **official Go SDK** (`modelcontextprotocol/go-sdk`) | Thin layer over stable internal API |
| Trace hashing / signing | **SHA-256 hash chain**, **Ed25519** signatures | Tamper-evident, offline-verifiable |
| Local UI | **Go `embed.FS` SPA + xterm.js**; TUI via **Bubble Tea** | Zero-install, localhost-only |
| Policy | **YAML + JSON-schema validation** (OPA/Rego optional later) | Simple, line-level errors first |
| Egress proxy (P5) | **Rust: hyper + rustls** | TLS terminate/pass-through, header injection |
| Local vault (P5) | **SQLite + age/NaCl**, key in OS keyring | Encrypted at rest, call-time injection only |
| Transport (daemon API) | **REST over Unix socket** `/run/opslify/opslifyd.sock` | Local, permissioned (0660, group `opslify`) |
| Cloud upstream (P3+) | **SSE** with offline buffering | Resume-from-acked-seq |

---

## 2. System overview

```mermaid
flowchart TB
    subgraph host["Developer machine / self-hosted node"]
        cli["opslify CLI"]
        mcp["opslifyd mcp (stdio)"]
        agent["AI agent (Claude Code)"]

        subgraph daemon["opslifyd daemon (Go)  — the ONLY executor"]
            api["REST API (Unix socket)"]
            sm["Session Manager"]
            reaper["TTL Reaper"]
            warm["Warm Pool"]
            env["EnvBuilder (Nix/devbox)"]
            trace["TraceSink (hash chain + Ed25519)"]
            policy["Policy Engine (P4)"]
            broker["Credential Broker (P5, Rust)"]
            proxy["L7 Egress Proxy (P5, Rust)"]
            ui["Local UI server (embed.FS)"]
        end

        subgraph rt["Runtime (D2 ladder)"]
            gv["gVisor/runsc (default)"]
            rc["runc (compat)"]
            kata["Kata (high)"]
        end

        subgraph sess["Per-session sandbox"]
            tool["signed read-only toolchain (Nix)"]
            ws["writable /workspace"]
        end

        keyring["OS keyring"]
        vault["vault.db (SQLite, encrypted)"]
        tracelog["/var/lib/opslify/traces/*.log"]
    end

    cloud["Opslify cloud (dashboard / compliance) — optional"]

    agent --> mcp --> api
    cli --> api
    api --> sm
    sm --> warm --> rt --> sess
    sm --> env --> tool
    sm --> policy
    sm --> trace --> tracelog
    trace -. SSE .-> cloud
    ui --> trace
    broker --> vault
    broker --> keyring
    sess --> proxy --> internet["allowlisted egress"]
    reaper --> sess
```

---

## 3. Session lifecycle

```mermaid
sequenceDiagram
    participant A as Agent (MCP)
    participant D as Daemon (executor)
    participant P as Policy (P4)
    participant R as Runtime (gVisor)
    participant S as Sandbox
    participant T as TraceSink
    participant B as Broker (P5)

    A->>D: session_create {mode, tier}
    D->>R: claim warm container + mount signed toolchain (RO) + /workspace (RW)
    D->>T: session.start (binds image_digest + toolchain_lock + policy_hash)
    A->>D: exec {argv}
    D->>P: check argv (allow / approval_required / deny)
    alt approval_required
        P-->>D: pause (awaiting_approval)
        D->>T: policy.decision pending
        Note over D: human approves in UI → resume, or timeout → auto-deny
    end
    alt cred needed (P5)
        D->>B: mint scoped short-lived token
        B-->>D: inject at spawn (env/header); zero memory after
        D->>T: cred.resolve {scope, ttl}
    end
    D->>S: spawn process (daemon is executor)
    S-->>D: stdout/stderr chunks + exit code
    D->>T: exec.output (redacted) + exec.end
    A->>D: session_end
    D->>R: destroy (scratch) / snapshot (workspace)
    D->>T: session.end + sign chain (Ed25519)
```

---

## 4. Tamper-evident trace chain

```mermaid
flowchart LR
    e0["session.start<br/>hash0 = H(payload0)"] --> e1["exec.start<br/>hash1 = H(prev=hash0 + payload1)"]
    e1 --> e2["exec.output<br/>hash2 = H(prev=hash1 + payload2)"]
    e2 --> e3["exec.end<br/>hash3 = H(prev=hash2 + payload3)"]
    e3 --> e4["session.end<br/>hash4 = H(prev=hash3 + payload4)"]
    e4 --> sig["Ed25519 signature over hash4<br/>(daemon identity key)"]
    sig --> verify["opslify verify &lt;session&gt;<br/>recompute chain + check sig"]
```

Any edit to any event breaks every downstream hash → `opslify verify` fails. Each session binds `image_digest + toolchain_lock_hash + policy_hash` → the compliance evidence pack (P6).

---

## 5. Agent build workflow

```mermaid
flowchart LR
    orch["Orchestrator<br/>reads global.md<br/>picks ready feature"] -->|assign| build["Builder (senior)<br/>Go (P0–P4) / Rust (P5)<br/>implement + test + self-review"]
    build -->|diff + evidence| qa["QA (senior)<br/>acceptance + QA checklist<br/>escape/red-team suite"]
    qa -->|pass| human["Manual approval (you)"]
    qa -.->|fail: reasons| build
    human -.->|reject: reasons| build
    human -->|approve| done["Status: approved<br/>unblocks dependents"]
```

---

## 6. Shared interfaces (defined in P0, single impls first)

```go
// Runtime — isolation ladder (D2). Impls: RuncRuntime, GvisorRuntime, (KataRuntime, RemoteFirecracker later)
type Runtime interface {
    Create(ctx, SessionSpec) (ContainerHandle, error)
    Exec(ctx, ContainerHandle, ExecRequest) (ExecStream, error)
    Destroy(ctx, ContainerHandle) error
    Snapshot(ctx, ContainerHandle, name string) (ImageRef, error) // workspace mode
    Available() error // F0.3: capability probe (engine + OCI runtime present) so callers fall back down the ladder legibly
}

// EnvBuilder — Nix/devbox build-time composer (D1). Produces signed read-only toolchain.
type EnvBuilder interface {
    Compose(ctx, ToolSelection) (LockedEnv, error) // -> flake.lock + closure
    Bake(ctx, LockedEnv) (SignedLayer, error)      // -> cosign-signed, digest-pinned
    Verify(ctx, SignedLayer) error
}

// TraceSink — hash-chained, signed events. Impls: FileSink, then CloudSSESink.
type TraceSink interface {
    Emit(ctx, Event) error       // appends, computes prev_hash/hash
    Sign(ctx, sessionID) (Signature, error)
    Verify(ctx, sessionID) error
}

// SecretBackend — P5. Impls: LocalVault (default), later Vault/OpenBao/ASM.
type SecretBackend interface {
    Get(ref) (Secret, error); Put(ref, Secret) error; List() ([]Ref, error); Delete(ref) error
}
```

Rust P5 components (broker, proxy) speak to the Go daemon over **per-session mTLS gRPC**; the `SecretBackend` interface is the Go-side contract they satisfy via FFI or a local gRPC service.
