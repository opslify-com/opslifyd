# Manage secrets

Secrets live in an encrypted vault and are **write-only from the outside** — you add and
list *names*, but no route ever returns a value. They're used by the
[credential-blind broker](../concepts/credential-broker.md) to authenticate on the agent's
behalf without the agent ever holding the token.

## Add a secret

The value comes from **stdin** or a file — never a command argument (so it doesn't land in
your shell history or the process table):

```bash
opslify secrets add gitlab-token --provider gitlab
# paste the value, then Ctrl-D

# or from a file:
opslify secrets add gitlab-token --provider gitlab --from-file ./token.txt
```

Flags:

| Flag | Meaning |
|---|---|
| `--from-file <path>` | Read the value from a file instead of stdin. |
| `--provider <name>` | Provider hint (e.g. `gitlab`, `aws`, `github`). |
| `--scope <hint>` | Opaque provider scope hint (audited, never secret). |
| `--ttl <dur>` | Requested token lifetime hint (e.g. `15m`). |
| `--overwrite` | Replace an existing secret with the same ref. |

## List / remove

```bash
opslify secrets ls          # refs + metadata only — never a value
opslify secrets rm <ref>
```

## OAuth2-backed services

For services that use OAuth2, onboard via device flow — tokens are obtained and stored
without you pasting long-lived credentials, and are never printed:

```bash
opslify creds add
```

## The vault master key

Everything is encrypted under the **vault master key**, generated once by `opslify init` and
shown once (save it!). Back it up any time:

```bash
opslify vault key export
```

The key is **CLI-only** — no API/UI/socket route returns it. Losing it makes vaulted secrets
unrecoverable by design. See [Credential-blind broker](../concepts/credential-broker.md).

## Using a secret

Secrets aren't handed to the sandbox — they're injected at the network edge for
allowlisted destinations. Wire one up in
[Credential-blind API access](credential-blind-gitlab.md).
