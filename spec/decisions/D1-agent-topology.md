# D1 — Agent topology: skill packs, not an agent per tool

**Status:** decided · **Phase:** P8 · **Supersedes:** nothing · **Informs:** F8.4, F8.9

## The proposal

When a project is onboarded it declares roles — git = GitLab, infra = DigitalOcean, CI = GitLab CI,
deployment = ArgoCD, orchestration = Kubernetes, IaC = Terraform. The idea under discussion was to
make **each of those a separate agent** with its own `agent.md`, and to combine them into a
multi-agent system: a Kubernetes agent, a CI/CD agent, an Azure agent, working together.

## What is right about it

Three parts of the proposal are correct and are adopted:

1. **Per-tool instruction files.** Integrating a tool should generate a dedicated `*.md` that
   describes how *this* estate uses it — not generic documentation. Adopted as F8.4.
2. **The agent should help write them.** On integration, the onboarding agent reads what is actually
   there (the `.gitlab-ci.yml` files, the chart values, the Terraform modules) and drafts the file for
   the operator to edit. This is a far better onboarding moment than an empty template, and it makes
   the instructions true on day one. Adopted as F8.4.
3. **Role declarations are useful.** "CI = GitLab CI, deployment = ArgoCD" is real information. It is
   adopted — as a **capability map used for routing**, not as a process topology.

## Why one-agent-per-tool is the wrong decomposition

**DevOps work does not decompose by tool. It decomposes by task, and tasks cross tools.**

Take a routine request: *"deploy the new version of flight-ms."* That single task touches git (tag),
CI (pipeline), the registry (image), ArgoCD (sync), Kubernetes (rollout status), and possibly
Terraform (if infra moved). Under a per-tool topology that is five or six handoffs for one intent.

Three concrete failures follow:

- **The diagnosis lives between the tools.** A Kubernetes agent looking at a crash-looping pod cannot
  tell you the cause is a bad image the CI pipeline pushed twenty minutes ago. The most valuable
  reasoning in operations is exactly the reasoning that spans tool boundaries — and a per-tool
  topology puts a context boundary precisely there.
- **Handoffs lose the "why".** Agent A knows why it chose an action; agent B receives only what. Every
  boundary is a place for intent to be dropped and for a subtly wrong action to be taken confidently.
- **Nobody is in charge.** With six peers, an ambiguous task needs a coordinator, and the coordinator
  needs enough context about all six domains to arbitrate — at which point it is the single agent you
  were trying to avoid, plus five extra failure modes.

There is also a plain cost argument: each agent is a separate context to fill, so the same task costs
several times more and takes longer, for a worse result.

## What the proposal is actually reaching for

The real need is **domain-deep context without drowning in irrelevance** — the agent working on CI
should have deep CI knowledge and not be carrying Terraform provider docs.

That is a **context-loading problem, not an agent-topology problem**, and it has a much cheaper
answer: **one operator agent, many skill packs, loaded by task.** The capability map from onboarding
does the routing — a task mentioning deployment loads `argocd.md` + `kubernetes.md`; a task about
pipelines loads `gitlab-ci.md`. Routing is cheap, debuggable, and adds no boundary where intent can be
lost.

This delivers everything the proposal wanted — per-tool `.md` files, deep tool-specific instruction,
composability — without handoff loss, coordination overhead, or ambiguous authority.

## Where multi-agent genuinely pays, and why

Multi-agent is adopted for one case, because there the second agent's **independence is the point**
rather than an accident of decomposition:

**Adversarial review (F8.9).** A reviewer agent examines a proposed Change *before* a human sees it,
tasked with finding the flaw rather than agreeing. This works here for a reason specific to opslifyd:
**the Change is already a complete handoff artifact** — intent, pinned diff, blast radius, policy
decision, prepared inverse. The reviewer needs nothing from the operator agent's context, so the usual
multi-agent failure (lossy handoff) does not apply. The artifact *is* the interface.

Two further uses are permitted where they follow the same rule — no shared state, or a complete
artifact as the interface:

- **Fan-out over independent work.** "Audit all twenty repos for outdated base images" parallelises
  cleanly because the items do not interact.
- **Different models for different jobs.** A cheap local model greps logs; a stronger one writes the
  plan. This is cost optimisation and rides the F8.5 agent registry.

## Decision

- **One operator agent per session**, given layered instructions (F8.4) with skill packs routed by the
  onboarding capability map.
- **Per-tool `*.md` generated on integration**, drafted by the agent from what it reads in the repo,
  edited by the operator, versioned in the repo, hash-recorded in every Change.
- **Multi-agent reserved for adversarial review** (F8.9), fan-out over independent items, and
  model-tier selection — never as a decomposition of one task across tools.

## Revisit if

- Skill packs for a large estate cannot be routed into a single context without material loss — then
  a **planner/executor** split (still not per-tool) becomes the next candidate.
- Reviewer agents prove valuable enough that a standing *watcher* role (triggered, read-only, opens
  Changes) earns its own topology entry.
