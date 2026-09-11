# Sessions & workspaces

## Sessions

A **session** is one sandbox with a lifecycle. You create it, run commands in it, and it's
destroyed when you're done or when it goes idle past its TTL. Each session is isolated from
every other.

Two modes:

| Mode | `/workspace` | Use for |
|---|---|---|
| **scratch** | ephemeral, empty, discarded on end | one-off commands, throwaway work |
| **workspace** | persistent, named, restored next time | a project you return to |

Create and run in one step with `opslify run`:

```bash
opslify run --mode scratch echo hi                 # ephemeral
opslify run --mode workspace --name myapp bash     # persistent, named "myapp"
```

Manage live sessions with `opslify session`:

```bash
opslify session ls
opslify session exec <id> <cmd>     # run another command in an existing session
opslify session kill <id>
```

Sessions have an **idle TTL** (default 30m, configurable). The daemon reaps idle sessions
and tears down their sandbox, network rules, and any per-session listeners.

## Workspaces

A **workspace** is the persistent `/workspace` state behind a named session — it survives
across sessions so dependencies and files you build up are still there next time.

```bash
opslify ws ls          # list workspaces (name, snapshots, latest tag/time)
opslify ws rm <name>   # remove a workspace and its snapshots (refused if in use)
```

Under the hood, workspace state is captured as snapshots and restored by booting the base
image with the workspace directory attached (a resume model that avoids user-namespace
range issues from committing container images).

## Host-linked workspaces (sync)

You can start a workspace **from a directory on your host** and keep the two in sync — edit
code in your editor, and it flows into the sandbox; the agent's changes flow back:

```bash
opslify workspace sync /home/you/myapp --new
```

Key properties:

- **Copy, not bind.** The host directory is never bind-mounted into the sandbox (that would
  let sandboxed code write straight to your real filesystem). Files move by explicit,
  guarded transfer.
- **Secrets excluded.** `.env`, `*.pem`, `id_rsa`, `credentials`, `.ssh/`, etc. are never
  copied into the sandbox.
- **Undoable sync-back.** A git working tree is reviewed with git; a non-git directory gets
  a timestamped backup before the first write-back; conflicts land in a `.opslify-conflict`
  sibling rather than clobbering your edit.

See the guide: [Workspaces & host sync](../guides/workspaces-sync.md).

## Installing tools into a workspace

Missing a tool in the sandbox? An operator can install it — allowlisted, proxied, audited,
and **project-local** (into `/workspace`, never the read-only base image):

```bash
opslify workspace install pip <package>
```

See [Install packages](../guides/install-packages.md).
