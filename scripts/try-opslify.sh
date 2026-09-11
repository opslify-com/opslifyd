#!/usr/bin/env bash
# try-opslify.sh — stand up a DISPOSABLE opslify for evaluation, in one command.
#
#   ./scripts/try-opslify.sh          # set it up and walk the surfaces
#   ./scripts/try-opslify.sh --clean  # remove everything it created
#
# THIS IS NOT THE INSTALLER. It exists so you can click around the control tower
# in five minutes without touching your machine, and it makes two deliberate
# trades to avoid needing root:
#
#   * EGRESS IS NOT ENFORCED. Default-deny egress needs nftables and root. Without
#     it a sandbox has unconstrained network — so do not put a real credential in
#     this, and do not run a real workload through it.
#   * THE TOOLCHAIN IS NOT VERIFIED. verify-before-serve is skipped.
#
# Everything lives under one directory and `--clean` removes it. Nothing is
# installed, no service is registered, no system file is touched.
#
# For a real install — root, nftables, systemd, group-gated socket, all controls
# ON — use scripts/install.sh.
set -euo pipefail

# NOT /tmp: this holds the workspace an operator is invited to open in an editor,
# and a tmpfs or a reboot-cleaned directory is a bad place to leave work. It is
# still disposable — `--clean` removes it — just not somewhere the system might
# remove it for you.
ROOT="${OPSLIFY_TRY_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/opslify-try}"
SOCK="$ROOT/api.sock"
TOWER_ADDR="${OPSLIFY_TRY_ADDR:-127.0.0.1:14646}"
# A digest-pinned base image is required by config validation. It is never pulled
# here (no sandbox is started), so the digest only has to be well-formed.
BASE_IMAGE="${OPSLIFY_TRY_IMAGE:-docker.io/library/alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000}"
# gVisor is the default and the right one. Without runsc installed no sandbox can
# start at all, which makes the Shell tab and every exec surface untestable — so
# OPSLIFY_TRY_TIER=local-docker falls back to runc for a look around. That is a
# WEAKER boundary: runc shares the host kernel.
TIER="${OPSLIFY_TRY_TIER:-local-hardened}"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
step() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

o() { "$ROOT/opslify" --socket "$SOCK" "$@"; }

stop_all() {
  pkill -f "opslifyd --config $ROOT/etc/config.yaml" 2>/dev/null || true
  pkill -f "opslify-tower --socket $SOCK" 2>/dev/null || true
}

if [[ "${1:-}" == "--clean" ]]; then
  say "stopping anything still running"
  stop_all
  sleep 0.3
  say "removing $ROOT"
  rm -rf "$ROOT"
  say "done — nothing else was installed, so there is nothing else to undo"
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. Build
# ---------------------------------------------------------------------------
# Re-running is the normal case — you rebuild, you look again. The seed steps
# below are creates, and a create against state from the last run fails ("project
# already exists"), which read as the script being broken rather than as leftovers.
# So a second run starts from a clean directory unless asked not to.
if [[ -d "$ROOT" && "${OPSLIFY_TRY_KEEP:-}" != "1" ]]; then
  say "found a previous instance at $ROOT — resetting it"
  say "(set OPSLIFY_TRY_KEEP=1 to keep its state and skip seeding)"
  stop_all
  sleep 0.3
  rm -rf "$ROOT"
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -d "$REPO/daemon" ]] || die "run this from a checkout: $REPO/daemon not found"
command -v go >/dev/null || die "go is required to build (this script builds from source)"

step "building three binaries"
mkdir -p "$ROOT"/{state,workspaces,etc,proj}
( cd "$REPO/daemon"
  go build -o "$ROOT/opslifyd"      ./cmd/opslifyd
  go build -o "$ROOT/opslify"       ./cmd/opslify
  go build -o "$ROOT/opslify-tower" ./cmd/opslify-tower )
say "opslifyd, opslify, opslify-tower -> $ROOT"

# ---------------------------------------------------------------------------
# 2. Configure
# ---------------------------------------------------------------------------
step "writing a self-contained config"
cat > "$ROOT/etc/config.yaml" <<EOF
image: $BASE_IMAGE
workspace_dir: $ROOT/workspaces
tier: $TIER
session_ttl: 30m
vault:
  path: $ROOT/state/vault.db
  key_file: $ROOT/state/vault.key
identity_key: $ROOT/state/identity.key
house_rules_path: $ROOT/etc/house-rules.md
trace:
  dir: $ROOT/state/traces
EOF

# House rules are the F8.4 layer an agent cannot edit: daemon-held, never read
# from a workspace. Seeded so `opslify context show` has something to show.
cat > "$ROOT/etc/house-rules.md" <<'EOF'
# House rules

Never restart db-01. Fail over first, then ask.
State blast radius in counted resources, never adjectives.
If you cannot describe the revert, do not propose the change.
EOF
say "config + house rules written"

step "generating the daemon identity and vault key"
# `init` mints the Ed25519 trace-signing identity and the vault master key. The
# private key is 0600 and never leaves this directory.
( cd "$ROOT/proj" && "$ROOT/opslify" init . --yes \
    --config "$ROOT/etc/config.yaml" \
    --identity-key "$ROOT/state/identity.key" \
    --vault-key-file "$ROOT/state/vault.key" \
    --base-image "$BASE_IMAGE" >/dev/null 2>&1 ) || die "opslify init failed"
say "identity: $(ls -1 "$ROOT"/state/identity.key* | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# 3. Run
# ---------------------------------------------------------------------------
step "starting the daemon"
warn "EGRESS IS NOT ENFORCED and the toolchain is NOT verified — evaluation only."
warn "Do not put a real credential in this instance."
stop_all
rm -f "$SOCK"
setsid nohup "$ROOT/opslifyd" \
  --config "$ROOT/etc/config.yaml" \
  --socket "$SOCK" --socket-group "" \
  --dev-skip-verify --insecure-no-egress \
  > "$ROOT/daemon.log" 2>&1 < /dev/null &

for _ in $(seq 1 50); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || { tail -20 "$ROOT/daemon.log"; die "the daemon did not start — log above"; }
grep -E '"msg":"F8|"msg":"listening' "$ROOT/daemon.log" \
  | sed 's/.*"msg":"//; s/".*//' | sed 's/^/    /'

# ---------------------------------------------------------------------------
# 4. Seed something worth looking at
# ---------------------------------------------------------------------------
if o project show tripon >/dev/null 2>&1; then
  step "reusing the existing seed data"
  say "project tripon is already here — skipping the seed steps"
else

step "creating a project with two environments"
o project create tripon --env prod --env staging

step "storing a secret (the value comes from stdin, never argv)"
printf 'glpat-FAKE-EVALUATION-TOKEN' | o secrets add gitlab-token --provider gitlab
o secrets ls

step "defining a connection that references the secret BY REF"
o connection add gitlab --kind http --secret gitlab-token \
  --host gitlab.example.com --config header_name=PRIVATE-TOKEN --project tripon
o connection ls

step "the delete guard: removing a secret something depends on"
if o secrets rm gitlab-token 2>&1 | sed 's/^/    /'; then
  warn "expected that removal to be REFUSED — the guard may be broken"
fi

step "a NARROWING policy edit — applies immediately, no approval"
o policy gate '^kubectl delete' --project tripon --env tripon.prod

step "a WIDENING policy edit — refused, becomes a change for approval"
o policy allow-egress evil.example.com --project tripon --env tripon.prod \
  --reason "evaluation walkthrough"

step "seeding project memory (runbooks the agent can search)"
# Memory lives in the project's workspace so it travels with the repo. Written
# here so the Memory screen and opslify_memory_search have something real.
MEM="$ROOT/workspaces/ws-tripon/.opslify/memory"
mkdir -p "$MEM/runbooks" "$MEM/architecture"
cat > "$MEM/runbooks/deploy.md" <<'MD'
# Deploying yarvel

## Prerequisites
The pipeline must be green and a maintainer must be on call.
Deploys are frozen on Fridays after 14:00 UTC.

## Rollback
To revert a bad release, re-apply the previous manifest with argocd, then drain
the old replicaset. Never delete the namespace — it holds the persistent volume
claims and recreating it loses staging data.

## Contacts
Page the on-call rota in #tripon-ops.
MD
cat > "$MEM/architecture/overview.md" <<'MD'
# tripon architecture

## Services
yarvel-main is the API. activity-ms and recent-search are behind the ocelot
gateway. rihla-social-server is independent and has its own database.

## Databases
db-01 is the primary Postgres. db-02 is a streaming replica with automatic
failover managed by Patroni. Failover takes roughly 30 seconds.

## Ingress
All external traffic enters through the ocelot gateway on gitlab.tripon.io.
MD
o memory ls --project tripon

step "the change it created"
o change ls

fi

# ---------------------------------------------------------------------------
# 5. Cockpit
# ---------------------------------------------------------------------------
step "starting the cockpit"
setsid nohup "$ROOT/opslify-tower" --socket "$SOCK" --addr "$TOWER_ADDR" \
  > "$ROOT/tower.log" 2>&1 < /dev/null &
for _ in $(seq 1 50); do grep -q 'cockpit:' "$ROOT/tower.log" 2>/dev/null && break; sleep 0.1; done
URL="$(grep -o 'http://[^ ]*' "$ROOT/tower.log" | head -1)"
[[ -n "$URL" ]] || { tail -10 "$ROOT/tower.log"; die "the cockpit did not start — log above"; }

# The base URL and token, so the probes below are copy-pasteable rather than
# something to reconstruct. ${URL%%/?*} does NOT work here: '?' is a glob
# wildcard in that expansion and silently truncates to "http:/".
BASE="http://$TOWER_ADDR"
TOKEN="${URL##*token=}"

cat <<EOF

────────────────────────────────────────────────────────────────────────
  Cockpit:  $URL

  The token is per-launch and is not written to disk. Sections: Sandboxes,
  Changes, Connections, Secrets, Policy, Instructions, Agents.

  Try to break it — each of these should be REFUSED:

    # 401 — no token
    curl -si $BASE/ | head -1

    # 403 — foreign Host, even with a valid token (DNS-rebinding guard)
    curl -si -H 'Host: evil.example.com' -H 'X-Opslify-UI-Token: $TOKEN' \
         $BASE/v1/sessions | head -1

    # 403 — deleting a secret is not on the cockpit's allowlist
    curl -si -X DELETE -H 'X-Opslify-UI-Token: $TOKEN' \
         $BASE/v1/secrets/gitlab-token | head -1

    # the stored credential appears in NONE of these
    for p in /v1/secrets /v1/secrets/consumers /v1/connections /v1/changes; do
      printf '%s leaks: ' "\$p"
      curl -s -H 'X-Opslify-UI-Token: $TOKEN' "$BASE\$p" | grep -c glpat- || true
    done

  CLI:      $ROOT/opslify --socket $SOCK <command>
  Logs:     $ROOT/daemon.log  $ROOT/tower.log
  Remove:   $0 --clean
────────────────────────────────────────────────────────────────────────
EOF
