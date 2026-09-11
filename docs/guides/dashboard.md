# The dashboard

`opslify ui` serves a localhost-only web dashboard for watching and controlling opslifyd —
no cloud, no accounts.

## Launch

```bash
opslify ui
```

It prints a URL containing a **one-time launch token**:

```
opslify ui listening on http://127.0.0.1:4646/ (localhost-only, per-launch token auth)
open this URL (carries the launch token): http://127.0.0.1:4646/?token=…
```

Open that full URL in your browser. The token sets an HttpOnly cookie on first load, so you
only need the tokenized URL once per launch.

Flags:

| Flag | Meaning |
|---|---|
| `--no-open` | Don't try to open a browser (print the URL only — useful on headless/remote hosts). |
| `--port <n>` | Port to serve on (default `4646`). |
| `--host <ip>` | Bind host (must be loopback; non-loopback is refused). |
| `--socket <path>` | Daemon socket. |

## What you can do

- **Sessions** — live sessions, their trace stream, `verify` verdict, and Kill.
- **History** — past sessions.
- **Secrets** — secret *names* and metadata only (a value is never returned to the browser),
  plus add/remove.
- **Workspaces** — list and remove.
- **Policy** — the active resolved policy.
- **Create / Exec** — start a session and run a command from the browser (exec goes through
  the same policy + approval path as the CLI).
- **Link** — link a host directory and toggle sync (guarded against sensitive paths).

## Security

The dashboard is safe to run because every route is behind:

- **loopback bind** — it only listens on `127.0.0.1`;
- a **DNS-rebind Host-guard** — requests with a non-loopback Host are refused;
- a **per-launch token** — a page without the token gets `401`, so a random web page (or a
  DNS-rebind attacker) can't act.

It never exposes secret values, never returns raw `/workspace` file bytes, and never loads
the audit-signing key into the browser. Directory-linking runs in the `opslify ui` host
process (not the daemon), so the daemon never learns arbitrary host paths, and sensitive
directories are refused.

!!! tip "Headless / remote host"
    Use `opslify ui --no-open` and copy the token URL. If you need it from another machine,
    tunnel it over SSH (`ssh -L 4646:127.0.0.1:4646 host`) rather than binding a non-loopback
    address (which the UI refuses).
