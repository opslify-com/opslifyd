# Phase 8 — Control Tower

**Depends on:** P3 (audit/UI), P4 (policy), P5 (broker), P7 (DX). **Builder:** Go + SPA.

> Turn the daemon into a product an operator lives in. A **project** gathers the platforms it runs on, the connections it may use, the instructions its agent follows, and the changes it has made — and every one of those is a first-class object with a home in the UI, a CLI verb, and a line in the tamper-evident trace.

## Goal
Today opslifyd is a superb engine with a session-shaped surface: you create sandboxes and run commands. P8 adds the layer above — **projects and environments**, a **connection broker** that generalises credential-blindness beyond HTTP tokens, **layered agent instructions** (per-tool skills), a **bring-your-own-agent** registry, and a **cockpit** that makes all of it operable. The unit of work stops being a session and becomes a **Change**.

## The two ideas the phase rests on

**1. A connection is a capability, not a secret.** P5 proved this for HTTP headers. P8 generalises it: the daemon keeps the credential and hands the sandbox *the smallest thing that still works* — a proxy address, a credential-free kubeconfig, an ssh-agent socket that only returns signatures, a 15-minute scoped token. The "what the agent receives" column is the security argument, and it must be answerable for every kind.

**2. Context is layered and provenanced, not a prompt.** What an agent is told is assembled from ordered layers — daemon house rules (locked), project instructions, environment overlay, per-tool skills, generated tool contracts. Later layers may add, never contradict an earlier one, and every Change records the exact instruction set it ran under **by hash**, so "why did it do that?" is answerable a year later against the rules it actually had, not the ones in the repo today.

**3. Injected vs retrieved.** A rule the agent must *always* follow is a **skill** (F8.4) — small, curated, injected, hashed. A document it *might need to consult* is **memory** (F8.10) — a corpus, searched on demand, with per-retrieval provenance. Conflating them breaks at the first real project: a memory folder cannot be injected without exhausting the context budget.

## Delivery model
The cockpit ships as the **localhost browser SPA served by the daemon** — no desktop app, no cloud dependency. Zero install, zero version skew, and it reuses the F7.1 auth already built and QA'd; remote access is an SSH tunnel, which is how this audience administers servers anyway. Approval notifications use the browser Notification API plus an `opslify notify` webhook hook rather than an Electron client. See `spec/decisions/D2-ui-delivery-model.md`.

## Features (dependency order)

- **F8.1 — Project & environment model** — the spine. `Project → Environment` owns workspace, policy, connections, instructions and agent binding; everything else in P8 hangs off it. Environments are separate layers (not headings in one file) so prod can narrow staging.
- **F8.2 — Connection broker** — one `Connection` interface with pluggable kinds. v1 ships `http` (F5.2/F5.7, existing), `kubernetes` (credential-free kubeconfig → session proxy), and `ssh` (daemon-held agent, destination-constrained keys, per-signature policy). `database` and `network` are declared and deferred.
- **F8.3 — Secrets surface** — the reference model made explicit: store a value once, get a **ref**; refs are what config, connections and agents see. Project-scoped listing, rotation, and "which connections consume this". Wraps the existing F5.6 vault; adds no read path.
- **F8.4 — Instructions & skills** — layered context assembly with provenance. Per-tool `*.md` generated on tool integration, editable, versioned in the repo; house rules daemon-held and read-only. `context.assemble` recorded per session with a hash bound into the trace.
- **F8.5 — Agent registry** — bring-your-own-agent. Any MCP-speaking command (Claude Code, a local Qwen via Ollama, Codex, custom CLI) bound per project *and* environment with a fallback. The sandbox boundary is identical whichever is chosen; the model choice changes cost, latency and where prompts go, never what the agent may do.
- **F8.6 — Change as the unit of work** — promote the P4 approval gate into a first-class, addressable object: intent, preview/diff, policy decision, steps, blast radius, prepared inverse, signed trace. Everything the UI shows and every agent handoff is a Change.
- **F8.7 — Policy editing as a Change** — create/update egress allowlists and gates from the UI/CLI. **Widening requires approval; narrowing does not.** Precedence daemon → project → environment → workspace, each only able to narrow; clamps recorded.
- **F8.8 — Cockpit UI** — the three-pane operator surface (collapsible sidebar, tabbed work area, agent panel, trace drawer) plus the surfaces above, all behind F7.1 token auth.
- **F8.10 — Project memory** — a per-project folder of the operator's own documents (architecture notes, runbooks, postmortems) that the agent **retrieves from on demand** rather than carrying in every context. Distinct from skills by mechanism: skills are injected, memory is searched. Lexical retrieval by default — no embedding service, no network.
- **F8.9 — Reviewer agent (the multi-agent piece)** — a second agent adversarially reviews a proposed Change *before* a human sees it. The **Change is the handoff artifact**, so no context is lost between agents. Optional, per-environment, may use a different (cheaper or stronger) model than the operator agent.

## Deliberately NOT in this phase

- **One agent per tool.** DevOps tasks cross tools ("deploy flight-ms" touches git, CI, registry, argocd, kubernetes), so a per-tool agent topology forces a handoff at every boundary and loses the diagnosis that lives *between* tools. P8 instead gives **one operator agent many skill packs, routed by task** (F8.4), and reserves genuine multi-agent for the case where it pays: **adversarial review** (F8.9), where the Change is a complete artifact and the second agent's *independence* is the point. See `spec/decisions/D1-agent-topology.md`.
- Team/multi-user RBAC, shared retention, compliance export — the cloud plane (F3.4 / P6).
- `database` and `network` connection kinds — interface declared in F8.2, implementations deferred.
- A model runtime. opslify ships no model and never proxies one; it speaks MCP to whatever the operator points it at.
- **Triggers and runbooks.** Webhook/cron/alert-driven Changes ("agent on-call") and saving a successful Change as a replayable runbook are the natural next phase — they need the Change (F8.6) to exist first, so they are P9, not scope creep here.
- **A desktop app.** See `spec/decisions/D2-ui-delivery-model.md`; if one is ever built it is a thin shell around this same SPA, never a second frontend.

## Cross-cutting guardrails (every feature)

- **Every connection kind must answer "what does the sandbox receive?"** in one line, and it must be the smallest thing that works. A kind that cannot answer it does not ship.
- **No new read path to a secret value.** F8.3 adds listing and rotation only; the vault stays write-only from outside, and the master key stays CLI-only (F7.2).
- **Widening is gated, narrowing is not** — for policy (F8.7) and for connection scope (F8.2). A workspace file may never widen.
- **Provenance or it did not happen.** Every Change records the policy hash, the instruction-set hash, the agent identity and model, and the connection refs used — by reference, never by value.
- **The sandbox boundary does not move.** New surfaces, agents and connection kinds all reach infrastructure through the same guarded execution path; none of them gets a side door.
- **Untrusted content stays data.** Workspace files, memory documents and skill text are written by humans and imported from anywhere; none of them may widen authority. Policy, gates and house rules live in the daemon and are unreachable from the repo.
- **Honest limits stay documented.** Transport blindness does not stop exfiltration by *authorised read* (`vault kv get`, `kubectl get secret`, terraform state). Response-side filtering is the mitigation where we terminate the protocol, and the gap is stated where we do not.
