# Configure policy

Policy decides what a session may do and what needs a human. See
[Policy & approvals](../concepts/policy.md) for the concepts; this is the how-to.

## Where policy lives

- **Daemon default** — referenced by `policy_file:` in `/etc/opslify/config.yaml`. This is
  authoritative.
- **Workspace policy** — an optional `opslify.policy.yaml` in a workspace. It can only
  **narrow** the daemon default (intersect allowed sets, add approvals, shorten TTL) — never
  widen it.

## A minimal policy

```yaml
# opslify.policy.yaml
session:
  ttl: 30m
egress:
  domains: [gitlab.com, api.github.com]
creds:
  - name: gitlab-token
    provider: gitlab
approval_required:
  - "terraform apply"
  - "kubectl delete"
```

## Fields

| Field | Meaning |
|---|---|
| `session.ttl` / `session.tier` / `session.image` | Per-session limits (workspace may only make these stricter). |
| `egress.domains` | Destinations the sandbox may reach (reconciled with default-deny). |
| `creds` | Credentials the session may use (deny-by-default; only ones the daemon allows). |
| `approval_required` | Command patterns that pause for human approval. |
| `strict_exec` | `true` = allowlist-only exec; `false` (default) = allow-with-approval. |
| `allow.exec` / `allow.kubectl` / `allow.terraform` | Positive allow sets (narrowing shrinks them). |
| `dry_run` | Preview-rewrite rules for destructive commands (daemon-authoritative). |

## Validate before applying

```bash
opslify policy --help      # author + validate opslify.policy.yaml
```

Apply a daemon default by pointing `policy_file:` at it and restarting:

```bash
sudo systemctl restart opslifyd
```

## Approvals in practice

```bash
opslify approvals                 # list pending gates
opslify approve <id> <exec-id>    # run the paused command
opslify deny <id> <exec-id>       # refuse it
```

Un-approved gates are auto-denied after the approval TTL (fail-closed).

## The policy_hash

The resolved policy is hashed and bound into the audit trail, so every action is provably
tied to the exact policy that was in force. Changing policy changes the hash — visible in
`opslify verify` output and the trace.
