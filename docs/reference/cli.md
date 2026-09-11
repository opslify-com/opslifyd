# CLI reference

The `opslify` CLI talks to the daemon over its socket (default
`/run/opslify/opslifyd.sock`). Run any command with `--help` for full flags.

!!! tip "No sudo"
    After install, run these as your normal user (you're in the `opslify` group). Only
    service management needs sudo.

## Command overview

| Command | What it does |
|---|---|
| `opslify run "<cmd>" [args…]` | Create a session, run a command in the sandbox, stream output. |
| `opslify session ls\|exec\|kill` | Manage live sessions. |
| `opslify ws ls\|rm` | Manage persistent workspaces. |
| `opslify workspace sync\|export\|install` | Host-linked sync, export, and package install. |
| `opslify secrets add\|ls\|rm` | Manage broker secrets (values are write-only). |
| `opslify creds add` | Onboard OAuth2-backed services via device flow. |
| `opslify vault key export` | Print the vault master key once for backup (CLI-only). |
| `opslify policy` | Author and validate `opslify.policy.yaml`. |
| `opslify approvals` / `approve` / `deny` | List and resolve pending approval gates. |
| `opslify verify <session-id>` | Verify a session's tamper-evident trace chain. |
| `opslify ui` | Serve the localhost dashboard (per-launch token). |
| `opslify top` | Live session table + selected-session stream in the terminal. |
| `opslify init [dir]` | Detect a project, select tools, build the signed toolchain, generate keys. |

## `opslify run`

```
opslify run "<cmd>" [args...] [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `--mode scratch\|workspace` | daemon default | Ephemeral vs persistent `/workspace`. |
| `--name <name>` | — | Workspace name (required for `--mode workspace`). |
| `--tier <tier>` | daemon default | Isolation tier. |
| `--cwd <dir>` | — | Working directory in the sandbox. |
| `--keep` | false | Don't destroy the session after the command exits. |
| `--socket <path>` | `/run/opslify/opslifyd.sock` | Daemon socket. |

## `opslify session`

```
opslify session ls
opslify session exec --socket <sock> <id> <cmd> [args...]
opslify session kill <id>
```

!!! warning "Flag order for `exec`"
    Put `--socket` **before** the session id — `exec` stops parsing flags once the command
    begins.

## `opslify secrets`

```
opslify secrets add <ref> [--from-file <path>] [--provider <p>] [--scope <s>] [--ttl <d>] [--overwrite]
opslify secrets ls
opslify secrets rm <ref>
```

Values come from stdin or `--from-file`, never an argument. `ls` shows names/metadata only.

## `opslify workspace`

```
opslify workspace sync <host-dir> [--new | --session <id>] [--once]
opslify workspace export <session-id> <host-dir>
opslify workspace install <ecosystem> <package>[@version] --session <id>
```

## `opslify ui`

```
opslify ui [--no-open] [--port <n>] [--host <loopback-ip>] [--socket <path>]
```

## `opslify verify`

```
opslify verify <session-id>
```

## `opslify init`

```
opslify init [dir] [--config <path>] [--identity-key <path>] [--vault-key-file <path>] [--base-image <ref>] [--yes] [--force]
```

Used by the installer; you rarely run it directly after install.

---

For the daemon side, see [Service management](service.md) and [Configuration](config.md).
