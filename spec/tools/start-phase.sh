#!/usr/bin/env bash
# start-phase.sh — begin a new phase on its own branch.
# Usage:  spec/tools/start-phase.sh <phase-folder>     e.g. p1-sandbox
#
# Model: main holds the approved history. Each phase lives on phase/<folder>.
# Feature work branches off the phase branch; approved features are pushed back
# to the phase branch (see approve-feature.sh). When the whole phase is approved,
# the phase branch merges into main.
set -euo pipefail

phase="${1:?usage: start-phase.sh <phase-folder e.g. p1-sandbox>}"

if [ ! -d "spec/phases/${phase}" ]; then
    echo "No such phase folder: spec/phases/${phase}" >&2
    exit 1
fi

git checkout main
git pull --ff-only origin main 2>/dev/null || echo "(no remote main to pull; continuing)"
git checkout -b "phase/${phase}"
git push -u origin "phase/${phase}" 2>/dev/null || echo "(remote push skipped; run 'git push -u origin phase/${phase}' when ready)"

echo
echo "On branch phase/${phase}."
echo "Create feature branches off this branch: git checkout -b feat/<Fx.y>-<slug>"
