# Manual test — P3 (audit trace + UI) & P4 (policy + approval + dry-run)

What you're verifying: every agent action is a tamper-evident, redacted, signed trace
you can watch live and `opslify verify`; and the daemon enforces a declarative policy,
pauses destructive commands for human approval, and previews them first.

Assumes the root-daemon dev setup from the F2.2 guide (podman installed, seccomp profile,
subuid range). Run the daemon with the dev flags; the CLI needs `sudo` (root-owned socket).

## 0. Rebuild + start

```bash
cd ~/workhub/projects/opslifyd/daemon
sudo go build -o /usr/local/bin/opslifyd ./cmd/opslifyd
sudo go build -o /usr/local/bin/opslify  ./cmd/opslify
```

Terminal 1 — daemon (leave running):
```bash
sudo opslifyd --config /etc/opslify/config.yaml --socket-group "" --insecure-no-egress --dev-skip-verify
```

---

## P3 — audit trace, verify, redaction, UI

### 1. Run a session, then verify its signed trace
```bash
sudo opslify run -- sh -c 'echo hello; uname -a'
# the session is destroyed after, but its trace log persists (durable):
sudo ls -t /var/lib/opslify/traces/           # newest <session-id>.log is your session
SID=$(sudo ls -t /var/lib/opslify/traces/ | head -1 | sed 's/\.log$//')
sudo opslify verify "$SID"
```
Expect: `OK: session <id> verified — N events, chain intact, sealed + signature valid`.

### 2. Redaction — a secret never lands raw in the trace
```bash
sudo opslify run -- echo AKIAIOSFODNN7EXAMPLE
SID=$(sudo ls -t /var/lib/opslify/traces/ | head -1 | sed 's/\.log$//')
sudo grep -c AKIAIOSFODNN7EXAMPLE /var/lib/opslify/traces/$SID.log   # => 0 (never raw)
sudo grep -o 'REDACTED:[a-z-]*'  /var/lib/opslify/traces/$SID.log    # => REDACTED:aws-key
```

### 3. Tamper-evidence — editing the log breaks verify
```bash
sudo cp /var/lib/opslify/traces/$SID.log /tmp/orig.log
sudo sed -i 's/uname/unamX/' /var/lib/opslify/traces/$SID.log        # alter one recorded arg
sudo opslify verify "$SID"                                           # => TAMPER ... FAILED at seq N (exit 1)
sudo cp /tmp/orig.log /var/lib/opslify/traces/$SID.log               # restore
```

### 4. Live UI + TUI
Terminal 2:
```bash
sudo opslify ui --no-open      # prints http://127.0.0.1:4646/
```
Open http://127.0.0.1:4646 in a browser. In Terminal 3 start a long session and watch it stream:
```bash
sudo opslify run -- sh -c 'for i in 1 2 3 4 5; do echo line $i; sleep 1; done'
```
Also try the terminal UI: `sudo opslify top`.
Security pokes: `sudo opslify ui --host 0.0.0.0` is refused (loopback-only); the browser can
reach only read + Kill (create/exec are blocked through the UI bridge).

---

## P4 — policy, enforcement, approval, dry-run

### 5. Write a daemon policy + lint it
```bash
cat | sudo tee /etc/opslify/policy.yaml <<'YAML'
strict_exec: true
allow:
  exec:
    - "^echo"
    - "^uname"
    - "^cat"
    - "^ls"
approval_required:
  - "rm"
YAML

opslify policy check /etc/opslify/policy.yaml     # => ok + policy_hash (no sudo needed; pure lint)
```
Try a broken policy to see line-level errors:
```bash
printf 'allow:\n  kubectl:\n    verbs: [destroy]\n' > /tmp/bad.yaml
opslify policy check /tmp/bad.yaml                # => /tmp/bad.yaml:3: unknown verb "destroy" ... (exit 1)
```

Point the daemon at the policy, then **restart the daemon** (Ctrl-C Terminal 1, start again):
```bash
# add this line to /etc/opslify/config.yaml (once):
echo 'policy_file: /etc/opslify/policy.yaml' | sudo tee -a /etc/opslify/config.yaml
# restart:
sudo opslifyd --config /etc/opslify/config.yaml --socket-group "" --insecure-no-egress --dev-skip-verify
```

### 6. Enforcement — a disallowed command is denied before it runs
```bash
sudo opslify run -- echo hi          # allowed  -> prints hi
sudo opslify run -- whoami           # DENIED   -> error [policy]: ... (whoami not in allow, strict_exec)
```
Confirm the deny is in the audit trail:
```bash
SID=$(sudo ls -t /var/lib/opslify/traces/ | head -1 | sed 's/\.log$//')
sudo grep -o 'policy.decision[^}]*' /var/lib/opslify/traces/$SID.log | head
```
Every session's trace root also binds the `policy_hash` (prove which policy was in force).

### 7. Approval gate — a destructive command pauses for a human
```bash
sudo opslify run --keep -- rm -rf /tmp/whatever
# prints:
#   [opslify: command requires approval — rule rm]
#   [opslify: approve with `opslify approve <session> <exec_id>` or deny ...]
```
Watch it live in the UI (an approval prompt appears), and list/resolve it:
```bash
sudo opslify approvals                                  # shows the pending gate + exec_id
sudo opslify deny <session> <exec_id> --comment "nope"  # or: opslify approve <session> <exec_id>
```
Deny → the command never runs; approve → it runs. Both land in the trace as `policy.decision`
(with your comment). Timeout (default 10m) auto-denies. The agent is never left hanging.

### 8. (Optional) Dry-run preview
Requires `terraform` or `kubectl` in the sandbox toolchain (the default alpine image has
neither, so bake them via `opslify init` tool selection to see real diffs). With them present:
a gated `terraform apply` first runs `terraform plan` and shows the diff beside the approval
prompt; approve replays the **saved plan** (hash-pinned, so a tampered plan is refused).

---

## What "pass" looks like
- [ ] `opslify verify` passes on an untouched session; **fails** after any edit to the log.
- [ ] A seeded AWS key appears only as `[REDACTED:aws-key]` in the trace — never raw.
- [ ] `opslify ui` shows sessions live and streams output; `--host 0.0.0.0` is refused.
- [ ] `opslify policy check` gives ok+hash or a line-level error.
- [ ] A non-allowed command is denied with `error [policy]`; the deny is traced with `policy_hash`.
- [ ] A `rm` command pauses; `opslify approvals` lists it; approve runs it / deny blocks it; both traced.
```
