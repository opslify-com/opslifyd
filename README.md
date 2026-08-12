# opslifyd

**Opslifyd is the open-source, self-hosted control plane for auditable, policy-gated
agent DevOps actions.** It runs each AI-agent command inside a hardened, per-session
sandbox — an independent kernel boundary (gVisor by default), rootless, user-namespaced,
read-only rootfs, with default-deny egress — so an agent can do real DevOps work on your
own machine without you handing it your shell. It speaks MCP, so Claude Code (or any MCP
client) can drive it directly.

This repo is the **P2** slice: the daemon, the sandbox runtime, and the MCP server are
real today. Live audit/trace (P3), policy + approval gates (P4), and the credential-blind
broker (P5) are on the roadmap and **not** in this build — see
[What's real vs. later](#whats-real-vs-later). We don't overstate: this is a hardened
sandbox with an MCP surface, not yet the full governance plane.

- Mission & positioning: [`spec/mission.md`](spec/mission.md)
- Goal / north star: [`spec/goal.md`](spec/goal.md)
- Verification pipeline (prove our claims): [`dagger/README.md`](dagger/README.md)
- Manual test walkthroughs: [`spec/manual-tests/`](spec/manual-tests/)

---

## Quickstart (Claude Code in ~15 min)

### 1. Build

Two binaries live in the `daemon/` Go module: `opslifyd` (the daemon + MCP server) and
`opslify` (the operator CLI).

```bash
cd daemon
go build -o /usr/local/bin/opslifyd ./cmd/opslifyd
go build -o /usr/local/bin/opslify  ./cmd/opslify
```

You also need a container engine (**podman**) on the host. The default `local-hardened`
tier additionally needs **gVisor/runsc** registered as a podman runtime; the
`local-docker` tier (runc) skips that if you just want to try things out. See the tier
caveats in [`spec/manual-tests/F2.2-session-modes.md`](spec/manual-tests/F2.2-session-modes.md).

#### Host prerequisites (until the installer script lands)

The daemon expects a few pieces of host setup a package installer would normally provide.
On Debian/Ubuntu:

```bash
sudo apt update && sudo apt install -y podman            # container engine (required)
# A seccomp profile at the path the hardened spec points to (podman ships one):
sudo install -D /usr/share/containers/seccomp.json /etc/opslify/seccomp.json
#   (or point elsewhere without root: export OPSLIFY_SECCOMP_PROFILE=/usr/share/containers/seccomp.json)
# A subuid/subgid range for rootful podman's --userns=auto (if root has none):
echo "containers:200000:65536" | sudo tee -a /etc/subuid /etc/subgid
```

`local-hardened` (gVisor) also needs `runsc` installed and registered as a podman runtime;
`local-docker` (runc) avoids that. A one-line install script that automates all of this
(prereq detection + podman/runsc + the two binaries) is planned.

### 2. `opslify init` — pick tools & bake the signed toolchain

```bash
opslify init            # interactive: detect the project, curate the agent toolset
# opslify init --yes    # non-interactive: accept the detected tools
```

`init` writes the daemon config + identity and drives the build of a **signed,
content-addressed toolchain layer**, recording its `toolchain_digest` in the config. The
daemon **verifies this digest before it will serve** (fail-closed) — so producing it
requires **nix** and **cosign** on your PATH. Without a signed digest the daemon refuses
to start (see the caveat below).

Useful flags: `--config <path>`, `--identity-key <path>`, `--systemd-unit <path>`,
`--base-image repo@sha256:...`, `--force`.

### 3. Run the daemon

Minimal `config.yaml` (default path `/etc/opslify/config.yaml`):

```yaml
image: docker.io/library/alpine:3.20     # base rootfs
tier: local-hardened                      # gVisor; use local-docker for runc
session_ttl: 30m
workspace_dir: /var/lib/opslify/workspaces
warm_pool_size: 0
egress_allowlist:                         # default-deny; only these destinations are reachable
  - github.com
  - "*.githubusercontent.com"
# toolchain_digest: sha256:...           # written by `opslify init` (required to serve)
```

Start it:

```bash
sudo opslifyd                            # uses /etc/opslify/config.yaml
# sudo opslifyd --config ./config.yaml --socket /run/opslify/opslifyd.sock
```

The daemon **verifies the signed toolchain before serving** and **fails closed on
egress**: if it can't program nftables default-deny it refuses to start rather than run
sandboxes with unconstrained network.

> **Dev-only escape hatches** (both log loudly; **never use in production**):
> - `--insecure-no-egress` (or `OPSLIFY_INSECURE_NO_EGRESS=1`) — run with **UNENFORCED**
>   egress when nftables is unavailable; removes network containment.
> - `--dev-skip-verify` (or `OPSLIFY_DEV_SKIP_VERIFY=1`) — skip verify-before-serve so a
>   box **without nix/cosign** can serve an unsigned toolchain for local testing.
>
> For a real setup, run `opslify init` (with nix + cosign) to bake a signed digest instead.
> If the CLI can't reach the socket as your user, add `--socket-group <your-group>` to the
> daemon (the socket is `0660`), or run the CLI with `sudo`.

### 4. Register the MCP server with Claude Code

Drop a `.mcp.json` at your project root (Claude Code auto-discovers it). A ready copy is
committed at [`examples/.mcp.json`](examples/.mcp.json):

```json
{
  "mcpServers": {
    "opslify": {
      "command": "opslifyd",
      "args": ["mcp", "--socket", "/run/opslify/opslifyd.sock"]
    }
  }
}
```

`opslifyd mcp` is a **thin stdio MCP client of the running daemon** — it talks to the same
Unix socket the CLI uses (`--socket`, default `/run/opslify/opslifyd.sock`). It exposes
five tools:

| Tool | Inputs | Does |
|---|---|---|
| `opslify_session_create` | `mode` (`scratch`\|`workspace`), `name?`, `ttl?` | Create a sandbox session, returns `session_id` |
| `opslify_exec` | `session_id`, `command` (argv array), `cwd?` | Run a command (argv, **not** shell) → `stdout`/`stderr`/`exit_code` |
| `opslify_upload` | `session_id`, `path`, `content_b64` | Write a base64 file under `/workspace` |
| `opslify_download` | `session_id`, `path` | Read a file from `/workspace` as base64 |
| `opslify_session_end` | `session_id` | Destroy the session |

Optional tuning flags on `opslifyd mcp`: `--output-cap <bytes>` (per-stream exec output
cap, default 1 MiB) and `--max-file-bytes <bytes>` (max upload/download, default 64 MiB).

Start Claude Code from that directory; it will list the `opslify_*` tools.

---

## Example task walkthrough

Point Claude Code at opslify and give it a task it must do **only through the opslify
tools** — e.g.:

> "Create a workspace session named `demo`, clone `https://github.com/<org>/<repo>` into
> `/workspace`, build it, run its tests, and report any failures. Keep the workspace so I
> can resume it."

A typical tool sequence the agent runs:

1. `opslify_session_create({ mode: "workspace", name: "demo" })` → `{ session_id: "…", state: "ready" }`
   A **workspace** session gives a stable, per-name `/workspace` that **persists across
   sessions** (installed deps and clones survive), even across a daemon restart. (Use
   `mode: "scratch"` — the default — for throwaway work that's discarded on end.)
2. `opslify_exec({ session_id, command: ["git", "clone", "https://…", "."], cwd: "/workspace" })`
   The clone only succeeds if the host is in `egress_allowlist` (default-deny) — the sample
   config above allows `github.com`. For a quick throwaway demo you can instead start the
   daemon with the dev-only `--insecure-no-egress`.
3. `opslify_exec({ session_id, command: ["make", "build"], cwd: "/workspace" })`
4. `opslify_exec({ session_id, command: ["make", "test"], cwd: "/workspace" })` → the agent
   reads `exit_code` + `stderr` and reports failures.
5. `opslify_session_end({ session_id })` when done. Because it's a `workspace`, the
   `/workspace` state is retained for the next `name: "demo"` session.

Watch it live from your shell while the agent works:

```bash
opslify session ls        # active sessions: SESSION ID / MODE / TIER / STATE / AGE / TTL REMAINING
opslify ws ls             # persistent workspaces: NAME / SNAPSHOTS / LATEST TAG / LATEST TIME
```

And drive or clean up the same sandboxes yourself:

```bash
opslify run --mode workspace --name demo -- cat /workspace/state.txt   # one-shot create+exec+destroy
opslify session exec <id> -- ls -la /workspace                          # exec in an existing session
opslify session kill <id>                                               # destroy a session
opslify ws rm demo                                                      # remove a workspace (refused if in use)
```

(`opslify run` also takes `--tier`, `--cwd`, `--keep`, and `--socket`.)

---

## The trust story — verify our claims yourself

Every command the agent ran executed inside a hardened gVisor sandbox: `--cap-drop=ALL`,
`--userns=auto`, read-only rootfs, private PID namespace, seccomp, and **default-deny
egress** — the agent's only writable path is the `/workspace` bind mount, and it can't
reach the network beyond the configured allowlist.

Don't take our word for it. The escape matrix is a public, reproducible Dagger suite that
runs container-escape, kernel-identity, and toolchain probes **inside** a real hardened
sandbox and asserts they're blocked (plus a "teeth test" that proves the checks would
catch a real escape). From the **repo root**:

```bash
dagger call escape-suite --source=.     # F1.5 escape matrix on real gVisor+runc
dagger call escape-egress --source=.    # F1.5 exfil matrix: nftables drops non-allowlisted egress
```

See [`dagger/README.md`](dagger/README.md) for the full pipeline (`graph`, `unit`,
`integration`, `all`).

---

## What's real vs. later

**Real today (P0–P2):**
- `opslify init` → curated, **signed & content-addressed** toolchain; **verify-before-serve**.
- Per-session **hardened sandbox** (gVisor default tier), read-only rootfs, user-ns, seccomp.
- **Default-deny egress** (nftables), fail-closed daemon startup.
- **Scratch & workspace session modes** (persistent, resumable `/workspace`).
- **MCP server** (`opslifyd mcp`) with the five session tools + the `opslify` operator CLI.

**On the roadmap (not in this build):**
- **P3** — live audit/trace + tamper-evident, hash-chained, offline-verifiable record.
- **P4** — declarative **policy** + **approval gates** with dry-run diff preview for
  destructive ops; the local watch UI. (This is the v1/MVP bar.)
- **P5** — the **credential-blind broker**: executor-side secret injection so the agent
  never sees a credential. This is the later upsell, **not** available now.

---

## License

See [`LICENSE`](LICENSE).
