# Authenticate any service (credential-blind)

This is the general recipe for letting an agent (or any sandboxed command) call an
**authenticated** service — any HTTP API, a cloud provider, or a package registry —
**without the agent ever seeing the credential**. It also shows how to **keep track** of
which credential was used, from the audit trail.

If you just want the GitLab example end-to-end, see
[Credential-blind API access](credential-blind-gitlab.md). This page generalizes it to
*any* credential.

## The model in one line

**Store the secret → bind a host to it → the agent calls the host normally → the daemon
injects the credential on the way out → the audit trail records *which* secret was used
(never its value).**

The agent never receives, names, or can exfiltrate the credential. You (the operator)
decide the host → secret binding; the agent cannot choose which credential to use or aim
it elsewhere.

## HTTP APIs — the universal recipe

Most services authenticate with an HTTP header (a bearer token, a private token, an API
key, or Basic auth). opslifyd injects it with an `egress_inject` rule.

### 1. Store the secret

```bash
opslify secrets add <ref> --provider <name>     # value from stdin, never an argument
# e.g.
opslify secrets add github-token --provider github
```

Or add it from the dashboard's **Secrets** pane. Either way the value is write-only — no
route ever returns it.

### 2. Bind a host to it

Add an `egress_inject` rule in `/etc/opslify/config.yaml`:

```yaml
egress_inject:
  - host: api.github.com
    secret_ref: github-token
    header_name: Authorization
    header_format: "Bearer %s"     # single %s is replaced with the resolved secret
```

…and grant it in the policy (`policy_file:`), which must both **allow the host** and
**grant the credential**:

```yaml
egress:
  domains: [api.github.com]
creds:
  - name: github-token
    provider: github
```

Then reload:

```bash
sudo systemctl restart opslifyd
```

### 3. Use it — blind

```bash
opslify run curl -sS https://api.github.com/user/repos
```

The sandbox sends an unauthenticated request; the daemon adds
`Authorization: Bearer <token>` on the leg to `api.github.com`. The token is never in the
sandbox.

## Header recipes for common auth styles

`header_format` is a `printf`-style template with a single `%s` replaced by the stored
secret. Empty/omitted format means the raw secret is used as-is.

| Auth style | `header_name` | `header_format` | Store as the secret |
|---|---|---|---|
| **Bearer token** (GitHub, most modern APIs) | `Authorization` | `Bearer %s` | the token |
| **GitLab PAT** | `PRIVATE-TOKEN` | `%s` (or omit) | the token |
| **GitHub classic** | `Authorization` | `token %s` | the token |
| **API key header** (many SaaS) | `X-API-Key` | `%s` | the key |
| **Custom key header** | `X-Custom-Auth` | `%s` (or a template) | the key |
| **Basic auth** | `Authorization` | `Basic %s` | base64 of `user:password` |
| **Slack bot** | `Authorization` | `Bearer %s` | the `xoxb-…` token |
| **DngoDB / Datadog etc.** | `DD-API-KEY` | `%s` | the key |

!!! tip "Basic auth"
    opslifyd substitutes the secret verbatim into the format string, so for Basic auth
    store the **already base64-encoded** `user:password`:
    ```bash
    printf 'user:password' | base64 | opslify secrets add my-basic --from-file /dev/stdin
    ```
    then `header_name: Authorization`, `header_format: "Basic %s"`.

## Multiple services

Add one rule per host. Each binds its own secret; a request is authenticated only for a
host that has a rule **and** is granted in policy.

```yaml
egress_inject:
  - host: api.github.com
    secret_ref: github-token
    header_name: Authorization
    header_format: "Bearer %s"
  - host: gitlab.example.com
    secret_ref: gitlab-token
    header_name: PRIVATE-TOKEN
    header_format: "%s"
  - host: api.openai.com
    secret_ref: openai-key
    header_name: Authorization
    header_format: "Bearer %s"
```

```yaml
# policy_file
egress:
  domains: [api.github.com, gitlab.example.com, api.openai.com]
creds:
  - { name: github-token, provider: github }
  - { name: gitlab-token, provider: gitlab }
  - { name: openai-key,   provider: openai }
```

## Cloud providers (AWS / GCP / Azure)

Cloud credentials use dedicated broker adapters rather than a static header, so the
sandbox gets **scoped, short-lived** credentials — never your long-lived keys:

- **AWS** — an STS **AssumeRole** adapter serves temporary credentials via the AWS
  container-credentials endpoint (the SDKs pick them up automatically). No static access
  keys in the sandbox.
- **GCP / Azure** — provider adapters via the broker.

Store the backing secret with the matching `provider` (`aws`/`gcp`/`azure`) and grant it in
policy; the broker resolves scoped credentials per session. See
[Credential-blind broker](../concepts/credential-broker.md).

## Package registries (pip / npm / Go)

Registry auth is injected by the registry proxy (server-side, checksum-safe, allowlisted).
Configure `registry_proxy.upstreams[].cred_ref` and use
[`opslify workspace install`](install-packages.md).

## OAuth2-backed services

For services that use OAuth2, onboard with the device flow — no long-lived token to paste,
and tokens are never printed:

```bash
opslify creds add
```

Configure the service under `oauth2:` in the config. See
[Manage secrets](secrets.md).

---

## Keeping track: who used which credential

Every credential use is recorded in the tamper-evident audit trail as a **`cred.resolve`**
event — the secret's **name and provider**, the policy rule that permitted it, and whether
it succeeded. The **value is never recorded**.

Inspect a session's trail:

```bash
opslify verify <session-id>     # confirm the trail is intact + signed
```

A `cred.resolve` event looks like:

```json
{
  "ref": "github-token",
  "provider": "github",
  "policy_rule": "creds:github-token/github",
  "success": true
}
```

So you get full accountability — *which* credential authenticated *which* action, provably
bound to the policy in force — with **zero** exposure of the secret. Grep a trail for the
header name or a token prefix (`Authorization`, `Bearer`, `glpat-`, `xoxb-`, …) and you'll
find nothing: the credential only ever exists on the daemon→upstream leg and in the
encrypted vault.

You can also watch credential use live in the [dashboard](dashboard.md) (the session trace
stream) or `opslify top`.

## Security properties (why this is safe)

- **Write-only vault.** No API/UI/socket/CLI route returns a stored secret value.
- **Operator-pinned bindings.** The agent can't choose or redirect a credential — you
  decide host → secret. A request to a host with no rule gets **no** credential.
- **Fail-closed.** If a secret can't be resolved, or the network path isn't available, no
  header is injected and there is **no** raw-secret fallback.
- **Least privilege for cloud.** Cloud adapters serve scoped, short-lived credentials, not
  your root keys.
- **Full audit.** Every use is recorded by name; the value never is.
