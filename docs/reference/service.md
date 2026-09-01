# Service management

opslifyd runs as a systemd service installed at `/etc/systemd/system/opslifyd.service`.

## Everyday commands

```bash
systemctl status opslifyd            # is it running?
journalctl -u opslifyd -f            # live logs
sudo systemctl restart opslifyd      # after editing /etc/opslify/config.yaml
sudo systemctl stop opslifyd
sudo systemctl start opslifyd
sudo systemctl disable --now opslifyd   # stop + don't start at boot
sudo systemctl enable --now opslifyd    # start now + at boot
```

## The unit

```ini
[Service]
Type=simple
Group=opslify
ExecStart=/usr/local/bin/opslifyd \
  --config /etc/opslify/config.yaml \
  --socket /run/opslify/opslifyd.sock \
  --socket-group opslify \
  --dev-skip-verify
RuntimeDirectory=opslify
RuntimeDirectoryMode=0750
Restart=on-failure
RestartSec=2
```

Key points:

- Runs as **root** (needed for nftables + podman) with primary group **`opslify`**.
- `RuntimeDirectory=opslify` + `Group=opslify` makes `/run/opslify` `root:opslify 0750`, so
  group members can reach the `0660` socket — that's the **no-sudo** mechanism.
- `--dev-skip-verify` is present when there's no cosign-signed toolchain; remove it once you
  bake a signed toolchain (see [Security model](../security/model.md)).

## Daemon flags

| Flag | Default | Purpose |
|---|---|---|
| `--config <path>` | `/etc/opslify/config.yaml` | Config file. |
| `--socket <path>` | `/run/opslify/opslifyd.sock` | Control socket. |
| `--socket-group <group>` | `opslify` | Group that owns the socket (group-gated access). |
| `--env-dir <path>` | `/var/lib/opslify` | Toolchain attestation/artifact root. |
| `--dev-skip-verify` | off | DEV: serve without a signed toolchain digest. |
| `--insecure-no-egress` | off | DEV: run without nftables egress enforcement (never in production). |

## Vault master key at startup

The daemon resolves the vault master key from (in precedence): the `OPSLIFY_VAULT_KEY` env
var, then the `0600` `vault.key` file. The service uses the file (written by the installer).
The daemon fatally exits only if **no** source resolves — so a fresh install just works.

## Health

The daemon exposes a health check on its socket; `opslify session ls` succeeding is a good
liveness probe. Startup logs to look for:

```
egress: default-deny enforcement active (nftables)
secret vault active
listening ... /run/opslify/opslifyd.sock  group=opslify
```

## Common startup failures

| Log line | Cause | Fix |
|---|---|---|
| `identity key permissions must be 0600` | Key not `0600` | `sudo chmod 0600 /etc/opslify/identity.key` |
| `vault master key ... unset` | No key source | Ensure `vault.key` exists (0600) or set `OPSLIFY_VAULT_KEY`. |
| `nft not usable` | Not root / no nftables | The service runs as root; install `nftables`. |

See [Troubleshooting](troubleshooting.md).
