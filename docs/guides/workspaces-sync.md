# Workspaces & host sync

Work on a real project: keep a directory on your host in sync with a sandbox `/workspace`,
so you edit in your own editor and the agent works on the same files — without giving the
sandbox direct access to your filesystem.

## Persistent workspaces

```bash
opslify run --mode workspace --name myapp bash -lc 'echo hi > /workspace/a.txt'
opslify ws ls          # name, snapshots, latest tag/time
opslify ws rm myapp    # remove (refused if in use)
```

The `/workspace` state persists across sessions under that name.

## Host-linked sync

Start (or attach to) a workspace from a host directory and keep them in sync:

```bash
# create a new session from a host dir and keep it in sync
opslify workspace sync /home/you/myapp --new

# or sync into an existing session
opslify workspace sync /home/you/myapp --session <id>

# one reconcile then exit (no watch)
opslify workspace sync /home/you/myapp --new --once
```

While it runs: edits on your host flow into the sandbox; the agent's edits flow back to your
host directory. Press Ctrl-C to stop (it does a final reconcile first).

## One-shot export

Pull a session's `/workspace` out to a host directory, no watching:

```bash
opslify workspace export <session-id> /home/you/out
```

## How it stays safe

- **Copy, not bind.** Your host directory is never mounted into the sandbox — files move by
  explicit, guarded transfer. Sandboxed code can't write straight to your filesystem.
- **Secrets never ride in.** A deny-list (`.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`,
  `credentials`, `.ssh/`, `.aws/`, `.git/` internals, high-entropy secret filenames) is
  applied **before** any upload. Add your own patterns with a `.opslifyignore`
  (gitignore-style; it can only *add* exclusions).
- **Sync-back is undoable.** A git working tree → review with `git status` / `git checkout`.
  A non-git directory → a timestamped `.opslify-backup-<ts>/` is taken before the first
  write-back. A file changed on **both** sides → the sandbox version is written to a
  `.opslify-conflict` sibling instead of overwriting your edit.

## Limitations (current)

- **Rootful-only for the daemon's write privileges** applies to the whole product; sync
  itself runs in your CLI process.
- **Host → sandbox deletions are not propagated** yet (a deleted host file is not removed
  from `/workspace`; you get a warning). Sandbox → host deletions are quarantined, never a
  silent delete of your file.
- Sandbox → host changes are observed on a short poll (~2s), so they appear with a small
  delay; host → sandbox is prompt.
