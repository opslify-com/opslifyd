# Security model

opslifyd's job is to let an AI agent do real operational work **without** trusting the agent
with your shell, your credentials, or your filesystem. This page states what it guarantees,
how, and where the boundaries are.

## Threat model

The agent is treated as **untrusted** — it may be wrong, buggy, or prompt-injected. The
goals are:

1. an agent cannot run code on your host outside a sandbox;
2. an agent cannot read or exfiltrate your credentials;
3. an agent cannot exceed the operations your policy allows;
4. you can prove, after the fact, exactly what happened.

Out of scope: a malicious **operator** (you), kernel 0-days beneath the isolation tier, and
physical access to the host.

## Isolation

Each session runs in an OCI sandbox that is:

- **rootless** and **user-namespaced** (no real root on the host),
- **read-only rootfs** (only `/workspace` is writable),
- **capability-dropped**, `no-new-privileges`, restrictive **seccomp**,
- **default-deny egress** (nftables), with DNS blocked to the sandbox.

The default tier is **gVisor (`runsc`)** where available (userspace syscall interception);
otherwise **runc**. Commands are executed *into* the sandbox by the daemon — the agent is
never handed a host shell.

## Credential-blindness

Credentials are never placed in the sandbox environment. The daemon injects them at the
**network edge** (on the daemon→upstream leg), so the agent, the sandbox env, the workspace,
and the audit trail contain no token. Key properties:

- fresh **per-session CA** (private key never leaves the daemon);
- credential-injecting listeners bind the **bridge gateway**, **source-scoped** to the
  owning container;
- **fail-closed**: no resolvable credential or no network path ⇒ no injection, no raw-secret
  fallback;
- the vault is **write-only** externally (no route returns a value); the **master key** is
  CLI-only.

## Governance

- **Policy narrows, never widens.** A workspace policy can only shrink what the daemon
  allows. The **resolved** policy is hashed into the audit trail.
- **Human approval** for gated commands, **fail-closed** on timeout.
- **Dry-run** previews destructive ops and pins the plan before apply.

## Tamper-evident audit

Every event is **hash-chained** and the chain is **Ed25519-signed**. `opslify verify` checks
the seal against the *trusted* daemon public key — a forged seal cannot self-validate.
Output is **redacted** (pattern + entropy) before storage.

## The local control surface

The dashboard and socket are local-trust:

- the daemon socket is **group-gated** (`opslify` group, `0660`);
- the dashboard binds **loopback only**, with a **DNS-rebind Host-guard** and a
  **per-launch token** — a random local page can't act, and the audit-signing key is never
  loaded into the browser;
- secret values and raw `/workspace` bytes are never returned to the browser.

## Known limitations / honest caveats

- **`--dev-skip-verify`.** Without `nix`+`cosign`, the daemon runs without a
  cryptographically **signed toolchain** layer (it trusts your base image). Fine for a
  single-host self-serve install; a multi-tenant deployment should bake a signed toolchain
  and drop the flag.
- **Rootful required for the credential-blind egress path.** The gateway must live in the
  daemon's network namespace. Rootless fails closed (no injection), never a downgrade.
- **Direct sandbox egress depends on host NAT.** A host firewall dropping `FORWARD` can block
  non-proxied allowlisted egress (the credential-blind path is unaffected).
- **Isolation is only as strong as the tier.** runc shares the host kernel; gVisor adds a
  syscall boundary but is still software. Choose the tier that matches your risk.

## Reporting a vulnerability

Please report security issues privately via the repository's security policy rather than a
public issue. See [Contributing](../about/contributing.md).
