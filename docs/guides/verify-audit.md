# Verify the audit trail

Every session produces a tamper-evident, signed trail. Verifying it proves it wasn't edited
and is attributable to your daemon's identity. See [Audit trail](../concepts/audit.md) for
the concepts.

## Verify a session

```bash
opslify verify <session-id>
```

- **Pass** — the hash chain recomputes correctly and the seal matches the trusted daemon
  identity (`/etc/opslify/identity.key.pub`). The trail is intact and attributable.
- **Fail** — the chain was altered, an event was inserted/removed, or the seal doesn't match
  the trusted key.

Verification pins to the *trusted* public key, not a key embedded in the seal — so a forged
seal cannot validate itself.

## Watch a session live

```bash
opslify top          # live session table + selected-session stream in the terminal
```

Or use the [dashboard](dashboard.md) to stream a live session's trace and replay past ones.

## Where trails are stored

Append-only logs live under `/var/lib/opslify/trace/` (one per session). They survive daemon
restarts; a corrupted middle line is detected as tampering.

## What's in the trail

Session start (with the resolved `policy_hash`), each command (`exec.start`/`exec.end` and
redacted output), policy decisions, approvals, credential *resolutions* (metadata only,
never the secret), package installs, and session end — each hash-chained to the previous.

## Redaction

Output is redacted before storage (pattern + entropy detection, path-aware), so high-entropy
secrets that appear in command output don't end up in the trail.

## Optional: ship trails to a team plane

Set `trace.cloud_url` in the config to enable the resumable uploader (opt-in). By default
everything stays local. See the [roadmap](../about/roadmap.md).
