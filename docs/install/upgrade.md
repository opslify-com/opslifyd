# Upgrade

Upgrading opslifyd replaces the binaries and restarts the service. Your keys, vault, and
workspaces are preserved.

## Upgrade with the one-liner

```bash
curl -fsSL https://opslify-com.github.io/opslifyd/install.sh | sudo sh
```

The installer is idempotent: it installs the new binaries, rewrites the service unit if
needed, and restarts the daemon. Existing keys and config are left in place.

To pin a specific version:

```bash
curl -fsSL https://opslify-com.github.io/opslifyd/install.sh | sudo OPSLIFY_VERSION=v0.6.0 sh
```

## Upgrade from a clone

```bash
cd opslifyd
git pull
sudo ./scripts/install.sh
```

## Restart after a config change

Editing `/etc/opslify/config.yaml` (e.g. adding an `egress_inject` rule) requires a
restart:

```bash
sudo systemctl restart opslifyd
```

## Verify the upgrade

```bash
opslify --version 2>/dev/null || opslify --help | head -1
systemctl is-active opslifyd
```

!!! note "Keys are never rotated on upgrade"
    Re-running the installer never regenerates your identity or vault keys — so secrets
    stay recoverable and the audit chain stays verifiable across upgrades.
