# Run commands

The everyday operation: run a command inside a sandbox with `opslify run`.

## Basics

```bash
opslify run --mode scratch echo "hello"
opslify run --mode scratch python3 --version
```

`run` creates a session, runs the command, streams its output, and (unless you pass
`--keep`) destroys the session afterwards.

## Flags

| Flag | Meaning |
|---|---|
| `--mode scratch\|workspace` | Ephemeral vs persistent `/workspace`. |
| `--name <name>` | Workspace name (required with `--mode workspace`). |
| `--tier <tier>` | Isolation tier (default: the daemon's, e.g. `local-hardened`). |
| `--cwd <dir>` | Working directory inside the sandbox. |
| `--keep` | Don't destroy the session after the command exits. |
| `--socket <path>` | Daemon socket (default `/run/opslify/opslifyd.sock`). |

## Keeping a session and running more in it

```bash
SID=$(opslify run --keep --mode workspace --name myapp true | grep -oE '[0-9a-f]{32}' | head -1)
opslify session exec "$SID" bash -lc 'echo more work; ls /workspace'
opslify session ls
opslify session kill "$SID"
```

!!! tip "Flag order for `session exec`"
    `session exec` stops parsing flags once the command begins, so put `--socket` (and any
    other flag) **before** the session id:
    `opslify session exec --socket … <id> <cmd>`.

## Commands that need approval

If your [policy](../concepts/policy.md) marks a command as `approval_required`, `run`
shows it as **pending** instead of executing it. Approve it from another terminal or the
dashboard:

```bash
opslify approvals
opslify approve <session-id> <exec-id>
```

## Network access

A sandbox is default-deny on the network. To let a command reach a host, add it to your
policy's `egress.domains` (and, for authenticated calls, wire a credential — see
[Credential-blind API access](credential-blind-gitlab.md)). Without that, outbound calls
are refused by design.

## Shells

Run an interactive-ish shell by keeping the session and exec-ing `bash`:

```bash
opslify run --keep --mode workspace --name myapp bash -lc 'your; commands; here'
```

(The sandbox base image ships a shell + `curl`. Add more tools with
[`opslify workspace install`](install-packages.md).)
