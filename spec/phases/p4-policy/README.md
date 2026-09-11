# Phase 4 — Policy Engine + Approval Gates + Dry-Run ⭐

**Weeks:** 10–14 · **Builder:** Go · **Depends on:** P3

> **MARKET HERO (cont.) — completes the MVP.** Human-in-the-loop governance is what buyers purchase today. This is the last phase before the credential broker. Features at spec level; split into `features/F4.*.md` on activation.

## Goal
Sessions obey declarative policy; humans gate destructive actions; destructive infra ops are previewed before they run. **No credential broker yet** — this is the complete, fundable governance product.

## Tools
Go, YAML + JSON-schema validation (OPA/Rego optional later), the P3 trace/UI for approval prompts.

---

### F4.1 — `opslify.policy.yaml`
- Loaded from repo root (workspace) or daemon default; schema-validated with **line-level errors**.
- Sections: `session` (ttl, runtime/tier, image), `allow` (kubectl namespaces/verbs, terraform commands, argv regex), `approval_required` (command patterns), `egress` (domains), `creds` (which refs/providers — enforced in P5). Deny-by-default for creds; exec default-allow with `strict_exec: true` opt-in. **`policy_hash` written into every session trace.**
- **Acceptance:** syntax error fails fast with line-level message.

### F4.2 — Enforcement points
- Session Manager: egress rules, runtime, ttl at spin-up. Exec interceptor: argv pattern match before spawn. (Broker cred scoping wired in P5.)
- **Acceptance:** kubectl restricted to allowed namespace; cross-namespace call blocked + traced `policy.decision: deny`.

### F4.3 — Approval gates
- Matching command → exec paused (state `awaiting_approval`), event pushed to local UI + cloud; approve/deny + optional comment; timeout (config, default 10m) → auto-deny. **MCP tool returns structured pending/denied status — never hangs the agent.**
- **Acceptance:** approve → applies; deny → agent gets denial with reason; timeout → auto-deny.

### F4.4 — Dry-run interception
- Built-in rewrites: `terraform apply` → `terraform plan -out` first, surface diff beside the approval prompt; `kubectl delete/apply` → `--dry-run=server` diff first. Extensible rewrite rules in policy.
- **Acceptance:** `terraform apply` in a gated session produces a plan diff + approval prompt.

## Phase acceptance
- [ ] All features pass. A gated `terraform apply` shows diff + approval; kubectl namespace restriction enforced + traced; session with no `creds` grants (spec present, enforced P5) documented; policy syntax errors are line-level.

## Sellable milestone
After P4: the **complete human-in-the-loop governance MVP** — sandbox + audit + policy + approvals + dry-run, no credential brokering. Get beta users here before building P5.
