# Uninstall

## Remove the service and binaries (keep your data)

```bash
sudo ./scripts/uninstall.sh
```

This:

- stops and disables the `opslifyd` service and removes its unit,
- removes any per-session sandboxes and leftover nftables tables,
- removes the `opslify` and `opslifyd` binaries,
- **keeps** `/etc/opslify` (keys/config) and `/var/lib/opslify` (vault/state), so your
  secrets remain recoverable and you can reinstall later.

## Full removal (delete everything)

```bash
sudo ./scripts/uninstall.sh --purge
```

`--purge` additionally removes:

- `/etc/opslify` (including your **keys** — vaulted secrets become unrecoverable),
- `/var/lib/opslify` (vault, workspaces, audit logs),
- the `opslify-net` podman network,
- the `localhost/opslify-base` image,
- the `opslify` group.

!!! danger "Purge is irreversible"
    `--purge` deletes your vault master key. Any secrets stored in the vault cannot be
    recovered afterwards. Export anything you need first (`opslify vault key export` to
    back up the master key, and re-store secrets elsewhere).

## Manual cleanup (if you didn't install from the repo)

If you installed via the one-liner and don't have the repo checked out:

```bash
sudo systemctl disable --now opslifyd
sudo rm -f /etc/systemd/system/opslifyd.service && sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/opslify /usr/local/bin/opslifyd
# optional, destroys data:
sudo rm -rf /etc/opslify /var/lib/opslify
sudo podman network rm -f opslify-net
sudo groupdel opslify
```
