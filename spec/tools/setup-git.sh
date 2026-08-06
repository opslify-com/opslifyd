#!/usr/bin/env bash
# One-time git setup for the Opslifyd repo. Run from the repo root.
# Enables the pre-commit graph-validation hook for everyone who clones.
set -euo pipefail

git config core.hooksPath .githooks
chmod +x .githooks/* spec/tools/*.sh 2>/dev/null || true
echo "core.hooksPath -> .githooks (pre-commit graph validation enabled)"
