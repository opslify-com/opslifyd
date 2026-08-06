#!/usr/bin/env bash
# approve-feature.sh — the "approval apply hook".
# Run ONLY after QA has passed a feature AND you (human) have signed off.
# It flips the feature's Status to `approved`, regenerates the graph, commits,
# and pushes to the current phase branch — unblocking dependents.
#
# Usage:  spec/tools/approve-feature.sh <feature-id>     e.g. F0.2
set -euo pipefail

fid="${1:?usage: approve-feature.sh <feature-id e.g. F0.2>}"

branch="$(git rev-parse --abbrev-ref HEAD)"
case "$branch" in
    phase/*) ;;
    *) echo "Refusing: not on a phase/* branch (currently on '$branch'). Run start-phase.sh first." >&2; exit 1 ;;
esac

# Locate the detailed feature file (inline spec-level features must be split first).
file="$(grep -rl "^# ${fid} " spec/phases/*/features/ 2>/dev/null | head -n1 || true)"
if [ -z "$file" ]; then
    echo "No detailed feature file found for ${fid}." >&2
    echo "If it is still an inline (spec-level) feature, split it into phases/<phase>/features/${fid}-*.md first." >&2
    exit 1
fi

# Flip **Status:** <anything> -> approved on the metadata line.
sed -i -E "s/(\*\*Status:\*\* )[A-Za-z-]+/\1approved/" "$file"

# Regenerate + validate the deterministic graph (also enforced by pre-commit).
python3 spec/tools/specgraph.py

git add "$file" spec/graph.json spec/graph.mmd
git commit -m "${fid}: approved (QA pass + manual sign-off)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin "$branch" 2>/dev/null || echo "(remote push skipped; run 'git push origin ${branch}' when authenticated)"

echo
echo "Approved ${fid} -> status=approved, committed to ${branch}. Dependents may now unblock."
