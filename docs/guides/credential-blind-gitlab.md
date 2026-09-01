# Credential-blind API access

Let an agent (or a sandboxed command) call an authenticated API **without ever seeing the
token**. This walkthrough uses GitLab; the same pattern works for any HTTP API, and there
are dedicated adapters for AWS/GCP/Azure and package registries.

!!! info "Requires the daemon running as root (the service)"
    The credential-blind egress path binds the bridge gateway and enforces nftables, which
    needs the daemon to run as root — exactly how the installed systemd service runs it.
    Rootless setups fail closed (no injection).

## 1. Add the egress-inject rule to the config

Edit `/etc/opslify/config.yaml` (needs sudo) and add an `egress_inject` rule for the host:

```yaml
egress_inject:
  - host: gitlab.com
    secret_ref: gitlab-token
    header_name: PRIVATE-TOKEN
    header_format: "%s"          # PRIVATE-TOKEN: <raw>. Use "Bearer %s" for Authorization APIs.
```

The rule only activates when the resolved **policy** both **grants** the credential and
**egress-allows** the host. Add a policy file (referenced by `policy_file:` in the config)
containing:

```yaml
egress:
  domains: [gitlab.com]
creds:
  - name: gitlab-token
    provider: gitlab
```

Restart the daemon to pick up the changes:

```bash
sudo systemctl restart opslifyd
```

## 2. Store the token (value never shown again)

As your normal user (no sudo needed for the CLI):

```bash
opslify secrets add gitlab-token --provider gitlab
# paste your PAT (needs read_api or api scope), then Ctrl-D
opslify secrets ls        # shows the NAME only — never the value
```

## 3. Make the blind call

```bash
opslify run curl -sS "https://gitlab.com/api/v4/projects?membership=true&per_page=3"
```

You get your projects back — authenticated — even though the token was never in the
sandbox. The daemon added the `PRIVATE-TOKEN` header on the upstream leg.

## 4. Prove the token is invisible

```bash
SID=$(opslify run --keep true | grep -oE '[0-9a-f]{32}' | head -1)

# no token in the sandbox environment (only HTTPS_PROXY + a CA path):
opslify session exec --socket /run/opslify/opslifyd.sock "$SID" env | grep -i token   # => nothing

# the CA file the sandbox trusts is a certificate, not a secret:
opslify session exec --socket /run/opslify/opslifyd.sock "$SID" head -1 /workspace/.opslify-ca.pem
# => -----BEGIN CERTIFICATE-----
```

The audit trail is likewise token-free (high-entropy secrets are redacted from captured
output).

## How it works

The daemon runs a per-session TLS-terminating egress proxy bound to the bridge gateway. It
injects `HTTPS_PROXY` and a per-session CA into the sandbox (no token), and adds the auth
header itself when the request leaves for `gitlab.com`. See
[Credential-blind broker](../concepts/credential-broker.md) and
[Egress control](../concepts/egress.md).

## Other providers

- **AWS** — an STS AssumeRole adapter serves scoped, TTL-bounded creds via the container
  credentials endpoint (no static keys in the sandbox).
- **GCP / Azure** — cloud adapters via the broker.
- **Package registries** — see [Install packages](install-packages.md).
- **OAuth2 services** — onboard with `opslify creds add` (device flow; tokens never printed).

## Troubleshooting

- **Call times out / empty output** — check `journalctl -u opslifyd` for
  `credential-blind HTTP path active` (vs a `fail-closed` warning). Confirm
  `sandbox_network` is set and the `opslify0` network exists. See
  [Troubleshooting](../reference/troubleshooting.md).
- **401 from the API** — the token is wrong or lacks scope; the injection itself is working
  if you get a real API response rather than a connection error.
