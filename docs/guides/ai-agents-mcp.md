# Use with AI agents (MCP)

opslifyd speaks the [Model Context Protocol](https://modelcontextprotocol.io), so an AI
agent can drive it directly — every command the agent runs goes through a sandbox, under
your policy, with the audit trail and credential-blind broker in force.

## The MCP server

```bash
opslifyd mcp
```

This is a **stdio** MCP server. An MCP client launches it and communicates over
stdin/stdout. It exposes tools to:

- create a session (scratch or workspace),
- run a command (`exec`) and stream output,
- upload/download files to/from `/workspace`,
- end a session.

The agent's entire operational surface is the sandbox — it cannot run on your host
directly, and it never receives credentials.

## Connect Claude Code

Add opslifyd as an MCP server in Claude Code's configuration. For example:

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

Then ask the agent to do operational work ("list my GitLab projects", "run the test
suite", "build the image") — it will create a session and run commands through opslifyd.

!!! note "The daemon must be running and reachable"
    `opslifyd mcp` connects to the running daemon over its socket. Make sure the service is
    active (`systemctl is-active opslifyd`) and that the user launching the MCP server is in
    the `opslify` group.

## What the agent sees (and doesn't)

- **Sees:** command output (redacted), exit codes, files it creates in `/workspace`.
- **Doesn't see:** your credentials (injected at the network edge), the vault master key,
  the audit-signing key, or anything outside the sandbox.

## Gated commands

If a command matches your policy's `approval_required`, the agent receives a **pending**
result and waits — a human approves or denies it (`opslify approve` / `opslify deny`, or the
dashboard). See [Policy & approvals](../concepts/policy.md).

## Credential-blind actions

To let the agent call an authenticated API without holding the token, wire the credential
once (see [Credential-blind API access](credential-blind-gitlab.md)). The agent then just
makes the request; the daemon injects the credential on the way out.
