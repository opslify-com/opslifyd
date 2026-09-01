# Policy & approvals

Policy decides **what a session may do** and **what needs a human**. It's evaluated before a
command runs — nothing risky slips through by executing first and asking later.

## The policy file

Policy is expressed in `opslify.policy.yaml`. The daemon has an authoritative default; a
workspace may supply its own policy, but it can only **narrow** the daemon's — never widen
it (a workspace can't grant itself more than the operator allows).

```yaml
# What the sandbox may reach (reconciles with default-deny egress)
egress:
  domains: [gitlab.com]

# Credentials this session may use (deny-by-default; only ones the daemon allows)
creds:
  - name: gitlab-token
    provider: gitlab

# Commands that require human approval before running
approval_required:
  - "terraform apply"
  - "kubectl delete"

# Optional: allowlist-only exec (default is allow-with-approval)
strict_exec: false
```

The **resolved** policy (daemon default narrowed by any workspace policy) is hashed, and the
`policy_hash` is bound into the audit trail — so every action is provably tied to the exact
policy in force.

## Command classification

Before a command runs, the daemon classifies it against the policy:

- **allowed** → runs;
- **approval required** → pauses as a pending gate until a human approves or denies;
- **denied** → refused.

## Human approval

Gated commands wait for a decision:

```bash
opslify approvals                 # list pending gates
opslify approve <id> <exec-id>    # let the paused command run
opslify deny <id> <exec-id>       # refuse it
```

Approvals are **fail-closed**: a gate that isn't approved within the approval TTL is
auto-denied. Agents driving via MCP see the pending state and wait.

## Dry-run for destructive ops

For destructive commands, the daemon can run a **preview** first (e.g. `terraform plan`
before `apply`), pin the plan's hash, and re-verify it at apply time. A preview that fails
blocks the command by default (fail-closed), so you never approve an apply whose plan you
couldn't see.

## Authoring & validating

```bash
opslify policy --help        # author/validate opslify.policy.yaml
```

See the guide: [Configure policy](../guides/policy-config.md), and the full field list in
[Configuration](../reference/config.md).
