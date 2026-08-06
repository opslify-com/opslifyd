# Git Workflow — branches, hooks & approval (all agents)

Deterministic branching so the three-agent workflow maps cleanly onto git.

## Branch model

```
main                     approved history only. Never commit directly.
 └─ phase/p0-scaffold    one branch per phase (matches the folder name)
     └─ feat/F0.2-...     one branch per feature, off the phase branch
```

- **`main`** — only approved work lands here. When *every* feature in a phase is `approved`, the phase is **not** merged directly — the orchestrator pushes the phase branch and **opens a pull request into `main`**, which the **human merges after their own manual QA**. The orchestrator never merges to `main` itself.
- **`phase/<folder>`** — the integration branch for a phase (e.g. `phase/p1-sandbox`). Approved features are pushed here.
- **`feat/<Fx.y>-<slug>`** — a builder's working branch for one feature, branched off the phase branch. (Reconciles the "one feature = one branch" rule in [shared-engineering.md §7](shared-engineering.md).)

## Lifecycle → git mapping

| Workflow step | git action | Tool |
|---|---|---|
| Orchestrator activates a phase | create/checkout `phase/<folder>` off `main` | `spec/tools/start-phase.sh <folder>` |
| Builder starts a feature | `git checkout -b feat/<Fx.y>-<slug>` off the phase branch | manual |
| Builder → QA handoff | orchestrator pushes `feat/*` to origin | `git push origin feat/<Fx.y>-<slug>` |
| **QA pass + your manual approval** | flip Status→`approved`, regen graph, commit, **push to the phase branch** | `spec/tools/approve-feature.sh <Fx.y>` |
| All features in phase approved | push phase branch, **open a PR into `main`** — human merges after manual QA | `git push origin phase/<folder>` + `gh pr create` (or the compare URL) |
| Human merges the PR | phase lands on `main`; orchestrator tags | human merges on GitHub; orchestrator `git fetch` + `git tag` |
| Start next phase | checkout a new `phase/<folder>` off updated `main` | `spec/tools/start-phase.sh <folder>` |

**Pushing & PRs:** the orchestrator pushes feature/phase branches to `origin` as work progresses (auth is configured). Opening the phase PR uses `gh pr create` when the `gh` CLI/token is available; otherwise the orchestrator surfaces the GitHub compare URL (`https://github.com/opslify-com/opslifyd/compare/main...phase/<folder>`) for the human to click. **The orchestrator opens the PR but never merges it — the human does, after manual QA.**

## The two "hooks"

There are two distinct mechanisms — don't confuse them:

1. **`pre-commit` git hook** (`.githooks/pre-commit`) — fires on *every commit*. Regenerates
   [../graph.json](../graph.json) and **refuses the commit** on a dependency cycle, a dangling
   `Depends on:`/`Blocks:`, or a missing feature. This is the anti-hallucination gate. Enable once
   per clone: `bash spec/tools/setup-git.sh` (sets `core.hooksPath .githooks`).

2. **Approval "apply hook"** (`spec/tools/approve-feature.sh`) — *not* a git event hook; it's the
   script the orchestrator runs **after QA passes and you manually sign off**. It sets the feature's
   `Status: approved`, regenerates the graph, commits, and pushes to the current phase branch —
   which is what unblocks dependent features in [../graph.json](../graph.json).

## Rules

- ❌ Never commit to `main` directly. ❌ Never **merge** a phase PR into `main` — the human does that after manual QA. ❌ Never run `approve-feature.sh` without QA pass **and** human sign-off.
- ✅ Run `bash spec/tools/setup-git.sh` right after cloning so the validation hook is active.
- ✅ A feature is only `approved` via the approval script (keeps status, graph, and branch in lockstep).
- ✅ Regenerate the graph after any `Depends on:`/`Blocks:`/`Status:` change (the pre-commit hook does this automatically).
- ✅ **Do NOT add a `Co-Authored-By: Claude` trailer** to commits in this repo — the user wants sole authorship visible on GitHub.
