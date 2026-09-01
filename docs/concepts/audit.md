# Audit trail

Every action opslifyd takes is recorded in a **tamper-evident** log: a hash-chained,
Ed25519-signed, append-only trail you can replay and independently verify.

## What's recorded

Per session, the daemon emits structured events — session start, each command
(`exec.start` / `exec.end` / output chunks), policy decisions, approvals, credential
resolutions (metadata only — never the secret), package installs, and session end. Each
event is bound into the session's chain along with the resolved `policy_hash`.

## Tamper-evidence

- **Hash chaining.** Each event includes the hash of the previous one, so any insertion,
  deletion, or edit anywhere breaks the chain.
- **Signed seal.** The chain is sealed with the daemon's **Ed25519 identity key**. Verify
  checks the seal against a *trusted* public key (the daemon's `identity.key.pub`), not a
  key embedded in the seal — so a forged seal can't validate itself.
- **Durable + append-only.** Trails are written to `/var/lib/opslify/trace/` and survive a
  daemon restart; a corrupted middle line is detected as tampering.

## Redaction

Before anything is written, output is passed through **redaction** (F3.3): pattern-based
plus entropy-based detection, path-aware to avoid over-scrubbing. High-entropy secrets that
appear in command output are scrubbed from the stored trail. (Low-entropy dummy strings may
not trip the entropy heuristic — real credentials, which are high-entropy, do.)

## Verifying

```bash
opslify verify <session-id>
```

This recomputes the chain and checks the signature against the trusted daemon identity. A
pass means the trail is intact and attributable; a failure means it was altered or the seal
doesn't match the trusted key.

## Viewing

- **Live + replay:** the [dashboard](../guides/dashboard.md) streams a session's trace and
  can replay a past one.
- **Terminal:** `opslify top` shows a live session table + selected-session stream.

## Cloud upload (optional)

The trace sink includes a resumable uploader that can push sealed trails to a cloud
endpoint (`trace.cloud_url`) for a team/retention plane. It's opt-in; by default everything
stays local. See the [roadmap](../about/roadmap.md) for the team dashboard.

See the guide: [Verify the audit trail](../guides/verify-audit.md).
