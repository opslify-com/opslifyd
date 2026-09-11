# Providers & secret managers

opslifyd works with any provider through one of a few injection mechanisms, and it stores
the backing secret in its own encrypted vault. This page shows concrete examples for
common clouds and hosting providers, and how it relates to external secret managers
(HashiCorp Vault, Doppler, …).

Two things are separate — keep them straight:

1. **How the credential is injected** into the sandbox's traffic (HTTP header, a cloud
   adapter, a registry proxy, or OAuth2).
2. **Where the secret comes from** — today, opslifyd's own encrypted vault (add with
   `opslify secrets add`). External managers are integrated by *syncing into* that vault
   (see [Secret managers](#external-secret-managers) below).

| Provider | Mechanism | Status |
|---|---|---|
| DigitalOcean, Hetzner Cloud, Linode, Vultr, Cloudflare, most SaaS | HTTP header (`egress_inject`) | ✅ fully supported |
| GitHub, GitLab, Slack, OpenAI, Stripe, … | HTTP header (`egress_inject`) | ✅ fully supported |
| AWS | STS AssumeRole adapter (scoped, short-lived) | ✅ adapter shipped; live wiring is advanced |
| GCP | SA impersonation adapter (short-lived token) | ✅ adapter shipped; live wiring is advanced |
| Azure | Client-credentials / federated adapter | ✅ adapter shipped; live wiring is advanced |
| pip / npm / Go registries | Registry proxy | ✅ (see [Install packages](install-packages.md)) |
| HashiCorp Vault / OpenBao / Doppler / AWS Secrets Manager / Azure Key Vault | External backend | ⏳ sync-into-vault today; native backend on the [roadmap](../about/roadmap.md) |

---

## Header-token providers (DigitalOcean, Hetzner, …)

Most hosting/cloud APIs authenticate with a **Bearer token**. These use the generic
`egress_inject` mechanism — exactly like the [GitLab example](credential-blind-gitlab.md).

### DigitalOcean

```bash
opslify secrets add do-token --provider digitalocean      # paste your API token
```

```yaml
# /etc/opslify/config.yaml
egress_inject:
  - host: api.digitalocean.com
    secret_ref: do-token
    header_name: Authorization
    header_format: "Bearer %s"
```

```yaml
# policy_file
egress:
  domains: [api.digitalocean.com]
creds:
  - { name: do-token, provider: digitalocean }
```

```bash
sudo systemctl restart opslifyd
opslify run curl -sS https://api.digitalocean.com/v2/droplets
```

### Hetzner Cloud (hcloud)

```yaml
egress_inject:
  - host: api.hetzner.cloud
    secret_ref: hcloud-token
    header_name: Authorization
    header_format: "Bearer %s"
```
```yaml
egress: { domains: [api.hetzner.cloud] }
creds: [ { name: hcloud-token, provider: hetzner } ]
```
```bash
opslify run curl -sS https://api.hetzner.cloud/v1/servers
```

### The same shape for others

| Provider | `host` | `header_name` | `header_format` |
|---|---|---|---|
| DigitalOcean | `api.digitalocean.com` | `Authorization` | `Bearer %s` |
| Hetzner Cloud | `api.hetzner.cloud` | `Authorization` | `Bearer %s` |
| Linode | `api.linode.com` | `Authorization` | `Bearer %s` |
| Vultr | `api.vultr.com` | `Authorization` | `Bearer %s` |
| Cloudflare | `api.cloudflare.com` | `Authorization` | `Bearer %s` |
| Fastly | `api.fastly.com` | `Fastly-Key` | `%s` |

See [Authenticate any service](authentication.md) for the full recipe table.

---

## AWS, GCP, Azure (scoped, short-lived)

The big clouds get **dedicated adapters** instead of a static header, so the sandbox
receives **scoped, short-lived** credentials — never your long-lived keys. The durable
source key stays on the daemon; the sandbox only ever sees temporary, downscoped creds.

### AWS — STS AssumeRole

The AWS credential is stored as a small **JSON identity document** (source key + the role
to assume), and the scope-down IAM policy is stored as the secret's `--scope`. The adapter
calls STS AssumeRole per session and serves the temporary credentials via the AWS
container-credentials endpoint — the AWS SDK/CLI in the sandbox picks them up automatically.

```bash
# 1. the scope-down IAM policy (what the session is allowed — an intersection)
cat > /tmp/scope.json <<'JSON'
{ "Version": "2012-10-17",
  "Statement": [ { "Effect": "Allow", "Action": ["s3:GetObject","s3:ListBucket"],
                   "Resource": ["arn:aws:s3:::my-bucket","arn:aws:s3:::my-bucket/*"] } ] }
JSON

# 2. the source doc: a long-lived key that may assume the role, plus the role ARN
cat > /tmp/aws.json <<'JSON'
{ "AccessKeyId": "AKIA...", "SecretAccessKey": "....",
  "RoleArn": "arn:aws:iam::123456789012:role/opslify-scoped", "Region": "us-east-1" }
JSON

# 3. store it (value from file; scope carries the IAM policy)
opslify secrets add aws-scoped --provider aws \
  --scope "$(cat /tmp/scope.json)" --from-file /tmp/aws.json
shred -u /tmp/aws.json /tmp/scope.json
```

Grant it in policy (`creds: [{ name: aws-scoped, provider: aws }]`), then in the sandbox:

```bash
opslify run aws s3 ls s3://my-bucket
```

The SDK gets temporary, downscoped credentials; `s3:PutObject` (not in the scope) is
denied by STS. **An unscoped grant fails closed** — the adapter refuses an AssumeRole with
no session policy.

### GCP — service-account impersonation

Store the source service-account credential (with `--scope` naming the target SA / scopes);
the adapter mints a short-lived access token via IAM Credentials `generateAccessToken` and
serves it to the sandbox.

```bash
opslify secrets add gcp-sa --provider gcp --scope "<target SA / scopes>" --from-file /tmp/gcp-sa.json
```

### Azure — client credentials / federated

Store the client credential; the adapter exchanges it for a short-lived token scoped to the
granted resource.

```bash
opslify secrets add azure-app --provider azure --scope "<resource/role>" --from-file /tmp/azure.json
```

!!! note "Cloud adapters: live wiring is advanced"
    The adapters (SigV4 AssumeRole, GCP JWT exchange, Azure form POST) are implemented in
    pure stdlib and unit-proven. Wiring them end-to-end on a live host (real STS/IAM calls,
    the container-credentials endpoint reachable from the sandbox) is an advanced setup —
    validate it on your host like the [credential-blind GitLab walkthrough](credential-blind-gitlab.md).
    The design guarantees (scope-down required, fail-closed, short TTL) hold regardless.

---

## External secret managers

opslifyd's broker is built around a **`SecretBackend` interface**; the shipped
implementation is the **local encrypted vault**. A native HashiCorp Vault / OpenBao /
Doppler / AWS Secrets Manager / Azure Key Vault backend is a documented extension point on
the [roadmap](../about/roadmap.md), **not shipped yet**.

Until it lands, integrate an external manager by **syncing the secret into opslifyd's
vault** — a one-liner you can run manually or on a schedule. opslifyd's vault is itself an
encrypted store, so the secret is still at rest under your vault master key.

### HashiCorp Vault / OpenBao

```bash
vault kv get -field=token secret/gitlab | opslify secrets add gitlab-token --provider gitlab --overwrite
```

### Doppler

```bash
doppler secrets get GITLAB_TOKEN --plain | opslify secrets add gitlab-token --provider gitlab --overwrite
```

### AWS Secrets Manager

```bash
aws secretsmanager get-secret-value --secret-id gitlab-token --query SecretString --output text \
  | opslify secrets add gitlab-token --provider gitlab --overwrite
```

### Azure Key Vault

```bash
az keyvault secret show --vault-name myvault --name gitlab-token --query value -o tsv \
  | opslify secrets add gitlab-token --provider gitlab --overwrite
```

### Keep it fresh (rotation)

Run the sync on a timer so rotated upstream secrets flow through. A simple systemd timer or
cron entry that re-runs the one-liner (with `--overwrite`) is enough; opslifyd re-encrypts
the new value under your vault master key.

!!! tip "Want a native backend?"
    A pluggable `SecretBackend` (resolve directly from Vault/Doppler at inject time, no
    copy) is the natural next step — the interface already exists. If you need it, open an
    issue describing your manager; see [Contributing](../about/contributing.md).

---

## Summary

- **Header-token providers** (DigitalOcean, Hetzner, …): one `egress_inject` rule — fully
  supported today.
- **AWS/GCP/Azure**: dedicated adapters give the sandbox scoped, short-lived creds; live
  wiring is an advanced, per-host setup.
- **External managers**: sync into opslifyd's vault today; native backends on the roadmap.
- Whatever the provider, the guarantees are the same: the agent never holds the credential,
  and every use is [audited by name](authentication.md#keeping-track-who-used-which-credential).
