# Phase 2 — MCP Integration

**Weeks:** 5–6 · **Builder:** Go · **Depends on:** P1 (F1.2 approved)

> Features below are at **spec level**. On activating this phase, the orchestrator's first task is to split them into `features/F2.*.md` at full depth (P0/P1 files are the template).

## Goal
Claude Code / any MCP client uses opslify sessions as tools, over a thin layer on the stable internal API.

## Tools
Go, **official MCP Go SDK** (`modelcontextprotocol/go-sdk`), stdio transport.

---

### F2.1 — MCP tools
- Server as subcommand `opslifyd mcp` (stdio), connecting to the same Unix socket.
- Tools: `opslify_session_create({mode, image?, ttl?})`; `opslify_exec({session_id, command, cwd?})` → `{stdout, stderr, exit_code}` **with output size caps + truncation markers**; `opslify_upload({session_id, path, content_b64})` / `opslify_download({session_id, path})`; `opslify_session_end({session_id})`.
- **Acceptance:** Claude Code completes "clone repo X, run its tests, report failures" using only opslify tools. Upload/download round-trips a 10MB file.

### F2.2 — Session modes
- `scratch` (destroyed on end, default); `workspace` (on end, commit FS to `opslify/ws-<name>:<n>`; `create({mode:"workspace", name})` resumes latest snapshot). `opslify ws ls|rm`; retention cap (default keep 3).
- **Acceptance:** workspace session survives daemon restart and resumes with installed deps intact.

### F2.3 — Claude Code quickstart
- Documented `.mcp.json` snippet + example task walkthrough in README.
- **Acceptance:** a new user follows the quickstart to a working session.

## Phase acceptance
- [ ] All three features' acceptance criteria pass.
- [ ] MCP layer is thin over the internal API (spec churn isolated).
- [ ] Output caps prevent unbounded tool responses.
