# Install packages

When a sandbox is missing a tool, an **operator** can install it — allowlisted, routed
through the registry proxy, audited, and **project-local** (into `/workspace`, never the
read-only base image).

## Command

```bash
opslify workspace install <ecosystem> <package>[@version] --session <id>
```

Supported ecosystems (v1): **pip** (Python) and **npm** (Node); Go modules via `GOPROXY`.

```bash
opslify workspace install pip requests --session <id>
opslify workspace install npm left-pad --session <id>
```

## Why it's operator-initiated

Package install is a classic supply-chain foothold — an agent that can `pip install`
anything over open egress could pull malicious code and run its install hooks. So opslifyd
makes install:

1. **operator-only** — the agent has no self-install path;
2. **allowlisted** — a package not on the registry proxy's allowlist is refused *before*
   anything runs;
3. **proxied** — traffic goes through the F5.5 registry proxy (registry auth injected
   server-side, checksum-safe, attested when required);
4. **audited** — each install emits a `pkg.install` event into the verifiable trail;
5. **project-local** — installs land under `/workspace` (e.g. `/workspace/.opslify/pip`),
   captured by the workspace snapshot; the shared base image is never mutated.

## Configure the allowlist

The registry proxy is configured in `/etc/opslify/config.yaml` under `registry_proxy` — its
upstreams and the `allow` list of `{ecosystem, name}` entries. A package (and its
transitive deps) must be allowlisted to install. See [Configuration](../reference/config.md).

## Using what you installed

Project-local installs need the sandbox to find them — e.g. for pip `--target`, set
`PYTHONPATH=/workspace/.opslify/pip`; for npm `--prefix /workspace`, the `node_modules` lives
under `/workspace`. The command output notes the path.

!!! note "Live install over a real registry is environment-specific"
    The wiring, allowlist gate, and audit are unit-proven; a full live install over a real
    bridge (and real Sigstore/cosign attestation) is validated per-host. If a dependency
    isn't allowlisted the proxy denies it (fail-closed) — add it to `allow` and retry.
