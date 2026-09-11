#!/usr/bin/env bash
# opslify uninstaller — reverses scripts/install.sh.
# Run with sudo:  sudo ./scripts/uninstall.sh
# Keeps your keys + vault by default (so secrets stay recoverable).
# Pass --purge to also delete /etc/opslify, /var/lib/opslify, the network, and the base image.
set -euo pipefail

PREFIX="${OPSLIFY_PREFIX:-/usr/local/bin}"
ETC="${OPSLIFY_ETC:-/etc/opslify}"
VAR="${OPSLIFY_VAR:-/var/lib/opslify}"
GROUP="${OPSLIFY_GROUP:-opslify}"
NET="${OPSLIFY_NET:-opslify-net}"
BASE_IMAGE="${OPSLIFY_BASE_IMAGE:-localhost/opslify-base:latest}"
UNIT="/etc/systemd/system/opslifyd.service"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo $0" >&2; exit 1; }

say "Stopping + disabling opslifyd"
systemctl disable --now opslifyd 2>/dev/null || true
rm -f "$UNIT"
systemctl daemon-reload 2>/dev/null || true

say "Removing per-session sandboxes + leaked nft tables"
for c in $(podman ps -aq --filter "name=opslify-sess" 2>/dev/null); do podman rm -f "$c" >/dev/null 2>&1 || true; done
nft list tables 2>/dev/null | grep opslify_sess | while read -r _ fam tbl; do nft delete table "$fam" "$tbl" 2>/dev/null || true; done

say "Removing binaries"
rm -f "$PREFIX/opslify" "$PREFIX/opslifyd" "$PREFIX/opslify-tower"

if [ "$PURGE" -eq 1 ]; then
  say "PURGE: removing config, state, network, base image, and group"
  rm -rf "$ETC" "$VAR"
  podman network rm -f "$NET" 2>/dev/null || true
  podman image rm -f "$BASE_IMAGE" 2>/dev/null || true
  groupdel "$GROUP" 2>/dev/null || true
else
  say "Kept $ETC (keys/config) and $VAR (vault/state). Re-run with --purge to remove them."
fi

say "Done."
