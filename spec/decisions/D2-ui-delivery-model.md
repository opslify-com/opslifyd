# D2 — UI delivery: localhost browser app, not desktop, not cloud

**Status:** decided · **Phase:** P8 · **Informs:** F8.8, F3.4

## The question
The cockpit needs a delivery model. Three candidates: the existing **localhost browser SPA** served by
the daemon, a **desktop app** (Electron/Tauri), or a **hosted cloud** control plane.

## Decision
**Ship the cockpit as the localhost browser SPA served by the daemon** (extending F3.5/F7.1/F7.4).
No desktop app in P8. No cloud dependency, ever, for core operation.

## Why

**The daemon is the product; the UI is a view over it.** It runs as root on a Linux host, holds the
vault and the signing identity, and is the only thing that touches infrastructure. A UI that ships
*inside that binary* has three properties nothing else offers: **zero install**, **zero version skew**
(the UI cannot be older than the daemon it drives), and **no new privileged path** — it reuses the
loopback bind, DNS-rebind Host-guard and per-launch token already designed and QA'd in F7.1.

**Remote access is already solved, and solved the way this audience expects.** The daemon lives on a
server; administering a server over an SSH tunnel is the normal, correct move:
`ssh -L 4646:127.0.0.1:4646 host`. That is safer than any listener we could add, and it needs no code.

**Cross-platform comes free.** The daemon is Linux-only by nature (namespaces, seccomp, nftables). A
browser UI means an operator on macOS or Windows drives a Linux daemon with no client build at all —
which is a better cross-platform story than three signed desktop binaries.

## Why not desktop (for now)

The honest case for desktop is **one feature**: OS notifications when a Change is waiting for
approval. That is genuinely valuable — an approval nobody sees is a stalled pipeline.

But it does not justify an Electron/Tauri app in P8:
- A desktop app talking to a root daemon is **new privileged surface**, plus signing, updates and
  distribution for three OSes, plus a second place for version skew.
- The notification need has cheaper answers that get most of the value: the **browser Notification
  API** from the already-open cockpit tab, and an `opslify notify` hook (webhook / ntfy / Slack) for
  when no tab is open — which also covers the headless-server case a desktop app would not.

**If desktop is built later it must be a thin Tauri shell around the same SPA** — tray, notifications,
multi-host switching — never a second UI codebase. That upgrade path stays open precisely because we
are not forking the frontend now.

## Why not cloud (as a requirement)

A hosted control plane would contradict the product's core claim. Self-hosted, local-first,
credential-blind means **prompts, traces and command output stay on the operator's host**. Requiring a
cloud plane to use the cockpit would move exactly the data the product exists to protect.

Cloud stays **optional and additive**, which is where it already sits in the roadmap (F3.4 / P6):
shared audit retention, multi-user RBAC, fleet views across hosts. It is also the natural commercial
tier — and it is more sellable *because* the local product works completely without it.

## Consequences

- F8.8 builds on the existing SPA and its auth; no new client stack, no new install path.
- Approval notification is in scope as **browser Notification API + an `opslify notify` webhook hook**,
  not as a desktop client.
- The SPA stays self-contained (no external asset host) so it works air-gapped, per F3.5.
- Multi-host fleet management is explicitly *not* solved here; it is a cloud-plane concern.

## Revisit if

- Operators report missing approvals often enough that in-tab notifications plus webhooks are
  demonstrably insufficient — then a thin Tauri shell, reusing the SPA.
- Managing several daemons on several hosts becomes routine — that is the cloud plane's job, not a
  desktop app's.
