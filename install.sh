#!/bin/sh
# opslify one-liner bootstrap.
#
#   curl -fsSL https://opslify-com.github.io/opslifyd/install.sh | sudo sh
#
# Downloads the opslify binaries for this host and runs the full installer
# (scripts/install.sh) so opslifyd ends up as a system service you use WITHOUT
# sudo afterwards. Reads no positional args; configure via env vars (see below).
#
# Env:
#   OPSLIFY_VERSION         release tag to install (default: latest)
#   OPSLIFY_DOWNLOAD_BASE   base URL for release assets
#                           (default: https://github.com/<repo>/releases/{latest/download|download/<tag>})
#   OPSLIFY_RAW_BASE        raw base for scripts/install.sh (default: raw.githubusercontent.com/<repo>/main)
#   OPSLIFY_PREFIX          binary install dir (default: /usr/local/bin)
#   OPSLIFY_BASE_SRC        upstream sandbox base image (default: docker.io/alpine/curl:latest)
set -eu

REPO="${OPSLIFY_REPO:-opslify-com/opslifyd}"
VERSION="${OPSLIFY_VERSION:-latest}"
RAW_BASE="${OPSLIFY_RAW_BASE:-https://raw.githubusercontent.com/$REPO/main}"

if [ "$VERSION" = "latest" ]; then
  DL_BASE="${OPSLIFY_DOWNLOAD_BASE:-https://github.com/$REPO/releases/latest/download}"
else
  DL_BASE="${OPSLIFY_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download/$VERSION}"
fi

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root, e.g.:  curl -fsSL <url> | sudo sh"

# --- detect os/arch -------------------------------------------------------
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
[ "$os" = "linux" ] || die "opslifyd requires Linux (got: $os). On Windows use WSL2; on macOS use a Linux VM."
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) die "unsupported architecture: $arch (supported: amd64, arm64)" ;;
esac

# --- fetch helper ---------------------------------------------------------
fetch() { # fetch <url> <dest>
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else die "need curl or wget to download"; fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

# --- get binaries ---------------------------------------------------------
got_bins=0
tarball="opslify-linux-$arch.tar.gz"
say "Downloading opslify ($VERSION, linux/$arch)"
if fetch "$DL_BASE/$tarball" "$TMP/$tarball" 2>/dev/null; then
  tar -xzf "$TMP/$tarball" -C "$TMP/bin" 2>/dev/null || true
  # accept either flat binaries or a bin/ subdir in the tarball
  [ -f "$TMP/bin/opslify" ]  || { f="$(find "$TMP/bin" -name opslify  -type f 2>/dev/null | head -1)"; [ -n "$f" ] && cp "$f" "$TMP/bin/opslify"; }
  [ -f "$TMP/bin/opslifyd" ] || { f="$(find "$TMP/bin" -name opslifyd -type f 2>/dev/null | head -1)"; [ -n "$f" ] && cp "$f" "$TMP/bin/opslifyd"; }
  if [ -f "$TMP/bin/opslify" ] && [ -f "$TMP/bin/opslifyd" ]; then chmod +x "$TMP/bin/opslify" "$TMP/bin/opslifyd"; got_bins=1; fi
fi

if [ "$got_bins" -ne 1 ]; then
  # Fallback: build from source if the toolchain is present.
  if command -v go >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then
    say "No release asset found; building from source"
    git clone --depth 1 "https://github.com/$REPO" "$TMP/src" >/dev/null 2>&1 || die "git clone failed"
    ( cd "$TMP/src/daemon" && go build -o "$TMP/bin/opslify" ./cmd/opslify && go build -o "$TMP/bin/opslifyd" ./cmd/opslifyd ) || die "source build failed"
    got_bins=1
  fi
fi
[ "$got_bins" -eq 1 ] || die "could not obtain binaries. Set OPSLIFY_DOWNLOAD_BASE to a reachable release, or install 'go'+'git' to build from source."

# --- run the full installer ----------------------------------------------
say "Fetching the installer"
fetch "$RAW_BASE/scripts/install.sh" "$TMP/install.sh" || die "could not download scripts/install.sh from $RAW_BASE"
chmod +x "$TMP/install.sh"

say "Running the installer"
OPSLIFY_BIN_SRC="$TMP/bin" \
OPSLIFY_PREFIX="${OPSLIFY_PREFIX:-/usr/local/bin}" \
OPSLIFY_BASE_SRC="${OPSLIFY_BASE_SRC:-docker.io/alpine/curl:latest}" \
OPSLIFY_USER="${SUDO_USER:-${OPSLIFY_USER:-}}" \
  bash "$TMP/install.sh"
