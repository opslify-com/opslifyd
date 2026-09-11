#!/usr/bin/env bash
# opslify installer — sets up opslifyd as a system service so end users never
# need sudo: the daemon runs once (root, at boot) and users in the `opslify`
# group talk to it over a group-gated socket.
#
# Run ONCE with sudo:   sudo ./scripts/install.sh
# Uninstall:            sudo ./scripts/uninstall.sh
#
# Idempotent: safe to re-run (it upgrades binaries/config in place).
set -euo pipefail

# ---------------------------------------------------------------------------
# Config (override via env)
# ---------------------------------------------------------------------------
PREFIX="${OPSLIFY_PREFIX:-/usr/local/bin}"
ETC="${OPSLIFY_ETC:-/etc/opslify}"
VAR="${OPSLIFY_VAR:-/var/lib/opslify}"
GROUP="${OPSLIFY_GROUP:-opslify}"
NET="${OPSLIFY_NET:-opslify-net}"
IFACE="${OPSLIFY_IFACE:-opslify0}"
BASE_IMAGE="${OPSLIFY_BASE_IMAGE:-localhost/opslify-base:latest}"
# The upstream image we pull for the sandbox base. It already ships curl + a CA
# bundle + a shell, so install needs NO container egress (only a registry pull,
# which uses the host network). Override to use your own base.
BASE_SRC="${OPSLIFY_BASE_SRC:-docker.io/alpine/curl:latest}"
UNIT="/etc/systemd/system/opslifyd.service"
# Where to find (or build) the binaries: a dir containing opslify + opslifyd,
# else the repo is built with `go` if available.
BIN_SRC="${OPSLIFY_BIN_SRC:-}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run with sudo: sudo $0"

# The human who invoked sudo — they get added to the group.
TARGET_USER="${SUDO_USER:-${OPSLIFY_USER:-}}"
[ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ] || warn "could not detect a non-root user to add to the '$GROUP' group; set OPSLIFY_USER=<name> and re-run if needed"

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------
say "Checking prerequisites"
command -v podman >/dev/null 2>&1 || die "podman not found. Install it first (e.g. 'sudo pacman -S podman' / 'sudo apt install podman')."
command -v nft    >/dev/null 2>&1 || die "nftables (nft) not found. Install it first (e.g. 'sudo pacman -S nftables' / 'sudo apt install nftables')."
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) not found; this installer targets systemd hosts."
say "podman $(podman --version | awk '{print $3}'), nft present, systemd present"

# ---------------------------------------------------------------------------
# 1b. Container egress preflight + auto-remediation
# ---------------------------------------------------------------------------
# Sandboxes (and any non-proxied allowlisted egress) need the host to forward +
# NAT container traffic. The classic failure is net.ipv4.ip_forward=0, which
# leaves containers with a route but no outbound. We enable it (standard for any
# container host — Docker's installer does the same) and reload podman's network
# rules. Install itself no longer needs container egress (the base image is
# PULLED, not built), so a residual failure only warns.
egress_ok() { podman run --rm "$BASE_SRC" sh -c 'ping -c1 -W3 1.1.1.1 >/dev/null 2>&1' >/dev/null 2>&1; }
say "Checking container egress (sandbox networking)"
if podman image exists "$BASE_SRC" 2>/dev/null && egress_ok; then
  say "Container egress OK"
else
  fwd="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
  if [ "$fwd" != "1" ]; then
    say "Enabling IPv4 forwarding (was $fwd) — required for container networking"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-opslify-forward.conf
  fi
  podman network reload --all >/dev/null 2>&1 || true
  say "Applied forwarding + reloaded podman network rules (verified after image pull)"
fi

# ---------------------------------------------------------------------------
# 2. Binaries
# ---------------------------------------------------------------------------
if [ -z "$BIN_SRC" ]; then
  if [ -x "$REPO_ROOT/daemon/cmd/opslify" ] || command -v go >/dev/null 2>&1; then
    say "Building binaries from source ($REPO_ROOT/daemon)"
    ( cd "$REPO_ROOT/daemon" \
        && go build -o /tmp/opslify.build.opslify       ./cmd/opslify \
        && go build -o /tmp/opslify.build.opslifyd      ./cmd/opslifyd \
        && go build -o /tmp/opslify.build.opslify-tower ./cmd/opslify-tower )
    install -m 0755 /tmp/opslify.build.opslify       "$PREFIX/opslify"
    install -m 0755 /tmp/opslify.build.opslifyd      "$PREFIX/opslifyd"
    # The cockpit is a separate binary and a CLIENT of the daemon: it runs as the
    # OPERATOR, not as a service, and is never started by the unit below. Killing
    # it leaves the daemon and its sandboxes untouched.
    install -m 0755 /tmp/opslify.build.opslify-tower "$PREFIX/opslify-tower"
    rm -f /tmp/opslify.build.opslify /tmp/opslify.build.opslifyd /tmp/opslify.build.opslify-tower
  else
    die "no OPSLIFY_BIN_SRC given and 'go' not installed to build from source"
  fi
else
  say "Installing binaries from $BIN_SRC"
  [ -x "$BIN_SRC/opslify" ] && [ -x "$BIN_SRC/opslifyd" ] || die "$BIN_SRC must contain executable opslify and opslifyd"
  install -m 0755 "$BIN_SRC/opslify"  "$PREFIX/opslify"
  install -m 0755 "$BIN_SRC/opslifyd" "$PREFIX/opslifyd"
  # The cockpit is optional in a binary drop: a headless install is a complete
  # install, because every cockpit action has a CLI equivalent.
  if [ -x "$BIN_SRC/opslify-tower" ]; then
    install -m 0755 "$BIN_SRC/opslify-tower" "$PREFIX/opslify-tower"
  else
    warn "no opslify-tower in $BIN_SRC — installing headless (the CLI is complete on its own)"
  fi
fi
say "Installed $PREFIX/opslify and $PREFIX/opslifyd"
[ -x "$PREFIX/opslify-tower" ] && say "Installed $PREFIX/opslify-tower (run it as yourself: opslify-tower)"

# Warn if some other 'opslify' earlier in the invoking user's PATH would shadow
# the one we just installed (a common cause of "unknown command"/stale behavior).
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ]; then
  _resolved="$(runuser -l "$TARGET_USER" -c 'command -v opslify' 2>/dev/null || true)"
  if [ -n "$_resolved" ] && [ "$_resolved" != "$PREFIX/opslify" ]; then
    warn "another 'opslify' shadows the installed one for $TARGET_USER: $_resolved"
    warn "remove it (e.g. 'rm $_resolved') or ensure $PREFIX is earlier in PATH."
  fi
fi

# ---------------------------------------------------------------------------
# 3. Group + directories
# ---------------------------------------------------------------------------
say "Ensuring group '$GROUP' and directories"
getent group "$GROUP" >/dev/null 2>&1 || groupadd --system "$GROUP"
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ]; then
  id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx "$GROUP" || usermod -aG "$GROUP" "$TARGET_USER"
  say "Added '$TARGET_USER' to group '$GROUP' (takes effect on next login / 'newgrp $GROUP')"
fi
install -d -m 0755 "$ETC"
install -d -m 0750 "$VAR" "$VAR/workspaces" "$VAR/trace"

# ---------------------------------------------------------------------------
# 4. Bridge network (routable gateway for the credential-blind path, F5.9)
# ---------------------------------------------------------------------------
if podman network exists "$NET" 2>/dev/null; then
  say "Podman network '$NET' already exists"
else
  say "Creating podman network '$NET' (interface $IFACE)"
  podman network create --interface-name "$IFACE" "$NET" >/dev/null
fi

# ---------------------------------------------------------------------------
# 5. Base sandbox image (curl + CA certs so tools can make HTTPS calls)
# ---------------------------------------------------------------------------
if podman image exists "$BASE_IMAGE" 2>/dev/null; then
  say "Base image '$BASE_IMAGE' already present"
else
  # PULL a ready-made image (curl + CA bundle + shell already baked in) and retag
  # it as the local base. A registry pull uses the HOST network, so this works
  # even when container egress/NAT is not set up yet — no apk, no build container.
  say "Pulling base sandbox image ($BASE_SRC)"
  _pulled=0
  for i in 1 2 3; do
    if podman pull "$BASE_SRC" >/dev/null 2>&1; then _pulled=1; break; fi
    warn "pull attempt $i failed; retrying in 5s"; sleep 5
  done
  [ "$_pulled" -eq 1 ] || die "could not pull the base image '$BASE_SRC' after 3 attempts.
     The HOST needs registry access (this is separate from container egress).
     - test:  podman pull docker.io/library/alpine:3.20
     - if that fails, check the host's internet/DNS/proxy, then re-run this installer."
  podman tag "$BASE_SRC" "$BASE_IMAGE"
  say "Base image ready as '$BASE_IMAGE'"
fi

# Now that the base image exists, verify container egress for real (and re-remediate once).
if egress_ok; then
  say "Container egress verified"
else
  warn "Container egress test failed even after enabling forwarding."
  warn "Sandboxes will still work for the credential-blind proxy path (that uses the daemon's"
  warn "host network), but DIRECT allowlisted egress from a sandbox may not until the host's"
  warn "container NAT is fixed. Common causes: a host firewall (ufw/firewalld) dropping FORWARD,"
  warn "or a VPN. Check:  sudo nft list ruleset | grep -i masquerade   and your firewall rules."
fi

# ---------------------------------------------------------------------------
# 6. Keys (identity + vault master key) — generated once, vault key revealed once
# ---------------------------------------------------------------------------
if [ -f "$ETC/vault.key" ] && [ -f "$ETC/identity.key" ]; then
  say "Keys already present in $ETC (leaving them untouched)"
else
  say "Generating keys (the vault master key is shown ONCE below — SAVE IT)"
  echo "-------------------------------------------------------------------"
  "$PREFIX/opslify" init "$VAR/workspaces" \
    --config "$ETC/config.yaml" \
    --identity-key "$ETC/identity.key" \
    --vault-key-file "$ETC/vault.key" \
    --yes || warn "init returned non-zero (toolchain signing may be skipped; keys are what we need)"
  echo "-------------------------------------------------------------------"
fi
# Keys stay 0600 root:root — the daemon runs as root and reads them directly; it
# REFUSES looser perms (the identity key must be exactly 0600). Never group-readable.
chown root:root "$ETC/vault.key" "$ETC/identity.key" 2>/dev/null || true
chmod 0600 "$ETC/vault.key" "$ETC/identity.key" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 7. Daemon config (complete + correct — overwrites init's minimal one)
# ---------------------------------------------------------------------------
say "Writing $ETC/config.yaml"
cat > "$ETC/config.yaml" <<EOF
# opslifyd config — written by scripts/install.sh
image: $BASE_IMAGE
session_ttl: 30m
warm_pool_size: 1
workspace_dir: $VAR/workspaces
sandbox_network: $NET          # F5.9: routable gateway for the credential-blind path
tier: local-docker
identity_key: $ETC/identity.key
vault:
  path: $VAR/vault.db
  key_file: $ETC/vault.key
trace:
  dir: $VAR/trace
# To enable credential-blind egress for a service, add an egress_inject rule and
# a matching policy grant, then: opslify secrets add <ref>. See INSTALL.md.
EOF
chmod 0644 "$ETC/config.yaml"

# ---------------------------------------------------------------------------
# 8. systemd unit — daemon runs as root at boot, socket group-gated to $GROUP
# ---------------------------------------------------------------------------
# NOTE: --dev-skip-verify runs without a cosign-signed toolchain (fine for a
# single-host / self-serve install where you trust your own base image). A
# production multi-tenant deployment should bake a signed toolchain and drop it.
say "Installing systemd unit $UNIT"
cat > "$UNIT" <<EOF
[Unit]
Description=opslify daemon (opslifyd) — credential-blind DevOps sandbox
Documentation=https://github.com/opslify-com/opslifyd
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Runs as root (needs it for nftables + podman), but with primary group $GROUP so
# systemd makes /run/opslify owned root:$GROUP — letting $GROUP members traverse in
# to the group-gated socket. That is what lets users run 'opslify' WITHOUT sudo.
Group=$GROUP
ExecStart=$PREFIX/opslifyd --config $ETC/config.yaml --socket /run/opslify/opslifyd.sock --socket-group $GROUP --dev-skip-verify
RuntimeDirectory=opslify
RuntimeDirectoryMode=0750
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

say "Enabling + starting opslifyd"
systemctl daemon-reload
systemctl enable --now opslifyd

sleep 2
if systemctl is-active --quiet opslifyd; then
  say "opslifyd is running."
else
  warn "opslifyd did not start; check: journalctl -u opslifyd -n 50"
fi

cat <<EOF

============================================================
 opslify is installed.

 The daemon runs as a system service (no sudo for daily use).
 To use it WITHOUT sudo, start a new login shell OR run:

     newgrp $GROUP

 Then, as yourself (no sudo):

     opslify run --mode scratch echo hello     # run a command in a sandbox
     opslify ui                                # open the dashboard
     opslify ws ls                             # list workspaces

 Service control (needs sudo):
     systemctl status opslifyd
     journalctl -u opslifyd -f
============================================================
EOF
