# Configuration

The daemon reads `/etc/opslify/config.yaml` (override with `--config`). The installer writes
a working default; this reference documents every field so you can extend it.

## Example

```yaml
image: localhost/opslify-base:latest
session_ttl: 30m
approval_ttl: 10m
warm_pool_size: 1
warm_pool_concurrency: 2
egress_allowlist: [gitlab.com]
workspace_dir: /var/lib/opslify/workspaces
sandbox_network: opslify-net
tier: local-docker
identity_key: /etc/opslify/identity.key
policy_file: /etc/opslify/policy.yaml

vault:
  path: /var/lib/opslify/vault.db
  key_file: /etc/opslify/vault.key

trace:
  dir: /var/lib/opslify/trace

egress_inject:
  - host: gitlab.com
    secret_ref: gitlab-token
    header_name: PRIVATE-TOKEN
    header_format: "%s"
```

## Top-level fields

| Field | Type | Purpose |
|---|---|---|
| `image` | string | Base sandbox image (digest-pinned in production). |
| `session_ttl` | duration | Idle lifetime before a session is reaped. |
| `approval_ttl` | duration | How long a pending approval waits before fail-closed auto-deny. |
| `warm_pool_size` | int | Pre-warmed sandboxes for fast session start. |
| `warm_pool_concurrency` | int | Concurrency for building the warm pool. |
| `egress_allowlist` | list | Daemon-level destinations allowed out (reconciled with policy). |
| `workspace_dir` | path | Host root for per-session/persistent `/workspace` state. |
| `sandbox_network` | string | Podman network sandboxes attach to (gives a routable gateway for the credential-blind path). |
| `tier` | string | Default isolation tier (`local-docker`, `local-hardened`, …). |
| `identity_key` | path | Ed25519 key that signs the audit trail (0600). |
| `toolchain_digest` | string | Signed toolchain layer digest (when using nix/cosign). |
| `policy_file` | path | The authoritative default policy. |

## `vault`

| Field | Purpose |
|---|---|
| `path` | Encrypted vault database file. |
| `key_file` | Vault master key file (0600). Alternatively `key_env` for an env var. |
| `key_env` | Env var name holding the master key (overrides the file). |

## `trace`

| Field | Purpose |
|---|---|
| `dir` | Append-only audit log directory. |
| `fsync` | Durability mode (e.g. `batch`). |
| `ring_buffer_size` | In-memory event buffer size. |
| `cloud_url` | Optional endpoint for the resumable trace uploader (opt-in). |

## `egress_inject` (credential-blind HTTP)

A list of rules; each injects a credential at the network edge for a host:

| Field | Purpose |
|---|---|
| `host` | Upstream host the rule applies to. |
| `secret_ref` | Vault secret to inject. |
| `header_name` | Header to add (e.g. `PRIVATE-TOKEN`, `Authorization`). |
| `header_format` | Format string, e.g. `"%s"` or `"Bearer %s"`. |

A rule activates only when the resolved policy grants the cred **and** egress-allows the host.

## `registry_proxy` (package installs)

| Field | Purpose |
|---|---|
| `cache_dir` | Content-addressed package cache. |
| `upstreams[]` | `{ecosystem, base_url, cred_ref, header_name, header_format, require_attestation}`. |
| `allow[]` | Allowlisted `{ecosystem, name}` packages. |

## `redaction`

| Field | Purpose |
|---|---|
| `entropy_threshold` | Entropy cutoff for secret detection. |
| `entropy_length_floor` | Minimum length considered for entropy scrubbing. |
| `disabled_patterns` | Named patterns to turn off. |

## `oauth2`

A map of service name → OAuth2 service config for device-flow onboarding
(`opslify creds add`).

## Applying changes

Edit the file (needs sudo), then restart the daemon:

```bash
sudo systemctl restart opslifyd
```
