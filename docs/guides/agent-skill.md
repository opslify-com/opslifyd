# Agent setup (MCP + skill file)

To let an AI agent use opslifyd, do two things:

1. **Give it the MCP server** so it has the tools.
2. **Give it the skill** — a short instruction block so it knows *how* to use them
   (sandbox workflow, credential-blind model, default-deny networking, approvals).

## 1. Register the MCP server

=== "Claude Code"

    ```bash
    claude mcp add opslifyd -s user -- opslifyd mcp
    claude mcp list        # → opslifyd: ✔ Connected
    ```

=== "Claude Desktop"

    Add to `claude_desktop_config.json`:

    ```json
    {
      "mcpServers": {
        "opslifyd": {
          "command": "opslifyd",
          "args": ["mcp"]
        }
      }
    }
    ```

=== "Any MCP client"

    Launch the stdio server: `opslifyd mcp`. It connects to the running daemon over the
    group-gated socket, so the process must run as a user in the `opslify` group.

The agent now has five tools: `opslify_session_create`, `opslify_exec`, `opslify_upload`,
`opslify_download`, `opslify_session_end`.

!!! note "Group membership"
    Whatever launches the agent must be in the `opslify` group (the socket is group-gated).
    If the client shows *failed to connect*, start it from a fresh login (or a
    `newgrp opslify` shell).

## 2. Give the agent the skill

Paste the block below into your agent's instructions:

- **Claude Code** — into your `CLAUDE.md` (project or user memory), or a skill file.
- **Claude Desktop / other** — into the system prompt or a project instruction.

It teaches the agent the sandbox workflow and the rules that make opslifyd safe. Copy it
verbatim:

````markdown
## Using opslifyd (sandboxed DevOps)

You have opslifyd MCP tools. Run **all** shell / DevOps / CLI / API commands through them —
never assume you have a host shell. opslifyd executes each command in a hardened, isolated
sandbox with a credential-blind secret broker, default-deny networking, and a
tamper-evident audit trail.

### Tools
- `opslify_session_create(mode, name?, ttl?)` — create a sandbox. `mode` is `"scratch"`
  (ephemeral, default) or `"workspace"` (persistent; requires a `name`). Returns a
  `session_id`.
- `opslify_exec(session_id, command, cwd?)` — run a command. `command` is an **argv array,
  NOT shell-parsed**: `["ls","-la"]`. For pipes/globs/`&&`/env expansion use
  `["sh","-lc","<script>"]`. Returns `stdout`/`stderr`/`exit_code` (output is capped).
- `opslify_upload(session_id, path, content_b64)` / `opslify_download(session_id, path)` —
  move files in/out of `/workspace` (base64; confined to `/workspace`).
- `opslify_session_end(session_id)` — destroy the sandbox. Always call this when finished.

### Workflow
1. Create a session — `scratch` for one-offs; `workspace` with a stable `name` for ongoing
   project work (its `/workspace` and installed deps persist across sessions).
2. Run commands with `opslify_exec`. `/workspace` is the ONLY writable path — put files there.
3. End the session when done.

### Credentials — you never handle them
- To call an authenticated API (GitLab, GitHub, AWS, DigitalOcean, any cloud), just make
  the **normal** request, e.g. `curl https://gitlab.example.com/api/v4/projects`. The daemon
  injects the credential at the network boundary.
- Do **NOT** ask the user for tokens/passwords, do **NOT** put secrets in commands, and do
  **NOT** try to read secret values — they are unavailable to you by design.
- If a call returns 401/403, tell the user the credential or its host-binding may be
  missing. Do not try to work around it or fetch a token yourself.

### Networking
- Egress is **default-deny**. Only hosts the operator allowlisted are reachable; other
  hosts fail or time out — that is expected, not a bug. If you need another host, ask the
  user to allowlist it.
- There is no general DNS in the sandbox; use the hostnames the operator allowed.

### Approvals
- Some commands require human approval (operator policy). If `opslify_exec` returns a
  `pending` status with an `exec_id`, **stop and tell the user it's awaiting their
  approval**. You may poll it with `opslify_exec(session_id, poll_exec_id=<id>)`, which is
  **read-only** — you cannot approve it yourself. Wait for the human.

### Rules
- Keep commands as argv; use `sh -lc` only when you need shell features.
- Prefer `workspace` mode for multi-step work so state persists.
- Clean up sessions you create.
- Do not attempt to escape the sandbox, read host paths outside `/workspace`, or disable
  egress — these are enforced and audited.
````

## 3. Verify the agent can use it

Ask the agent something operational:

> "Using opslifyd, create a sandbox, run `uname -a`, and end the session."

It should call `opslify_session_create` → `opslify_exec` → `opslify_session_end`. Watch it
live in the [dashboard](dashboard.md) (`opslify ui`) or with `opslify top`.

## Where to put the skill (Claude Code specifics)

- **Project memory:** add the block to `CLAUDE.md` in your project root — applies to that
  project.
- **User memory:** add it to your global `CLAUDE.md` — applies everywhere.
- **A skill:** if you use Claude Code skills, drop it in a `SKILL.md` so it's loaded on
  demand.

The block is intentionally short and provider-agnostic, so it works in any agent that can
follow a system/instruction prompt plus MCP tools.

## Related

- [Use with AI agents (MCP)](ai-agents-mcp.md) — more on the MCP server.
- [Authenticate any service](authentication.md) — wire the credentials the agent will use
  blind.
- [Providers & secret managers](providers.md) — per-provider examples.
