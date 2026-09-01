# Quickstart

From zero to a sandboxed command in about two minutes.

!!! info "Prerequisites"
    A Linux host with **systemd**, **podman**, and **nftables**. See
    [Requirements](requirements.md). You'll need `sudo` for the one-time install only.

## 1. Install

=== "One-liner (recommended)"

    ```bash
    curl -fsSL https://opslify-com.github.io/opslifyd/install.sh | sudo sh
    ```

    See [One-line install](../install/one-line.md) for what this does and how to pin a version.

=== "From a clone"

    ```bash
    git clone https://github.com/opslify-com/opslifyd
    cd opslifyd
    sudo ./scripts/install.sh
    ```

The installer sets up a background service, creates the `opslify` group and adds you to
it, and prints your **vault master key once** — save it in a password manager.

## 2. Activate your group membership

Group membership takes effect in a **new login shell**. Either open a new terminal, or:

```bash
newgrp opslify
```

## 3. Run your first sandboxed command

```bash
opslify run --mode scratch echo "hello from a sandbox"
```

You should see:

```
hello from a sandbox
```

That ran inside a fresh, isolated, rootless sandbox — not on your host.

## 4. Try a persistent workspace

A **workspace** keeps `/workspace` state across sessions (great for a project):

```bash
opslify run --mode workspace --name myapp bash -lc 'echo "build artifacts live here" > /workspace/notes.txt; ls -l /workspace'
opslify ws ls        # see your workspaces
```

## 5. Open the dashboard

```bash
opslify ui
```

It prints a URL with a one-time token, e.g.:

```
open this URL (carries the launch token): http://127.0.0.1:4646/?token=…
```

Open it in your browser to watch live sessions, inspect the audit trail, manage secret
names, browse workspaces, and more. See [The dashboard](../guides/dashboard.md).

## 6. (Optional) Let an AI agent drive it

Point an MCP client (e.g. Claude Code) at the daemon so the agent runs everything through
opslifyd. See [Use with AI agents](../guides/ai-agents-mcp.md).

## What next?

- **[Credential-blind API access](../guides/credential-blind-gitlab.md)** — let an agent
  call GitLab/AWS/etc. without ever seeing the token.
- **[Workspaces & host sync](../guides/workspaces-sync.md)** — edit code on your host and
  keep it synced into the sandbox.
- **[Configure policy](../guides/policy-config.md)** — decide what sessions may do and
  what needs approval.
- **[Troubleshooting](../reference/troubleshooting.md)** — if a step didn't work.
