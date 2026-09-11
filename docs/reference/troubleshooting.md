# Troubleshooting

Symptoms and fixes for the issues you're most likely to hit.

## Install

### The base image build/pull fails

The installer **pulls** a ready image (no `apk` build), which uses the host network. If the
pull fails, the host itself can't reach the registry:

```bash
podman pull docker.io/library/alpine:3.20    # does the host have registry access?
```

Fix host DNS/proxy/VPN, then re-run the installer (idempotent). For an air-gapped host, set
`OPSLIFY_BASE_SRC` to a locally-loaded image.

### `another 'opslify' shadows the installed one`

A stale binary earlier in your `PATH` (often `~/.local/bin/opslify`):

```bash
which -a opslify
rm ~/.local/bin/opslify ~/.local/bin/opslifyd   # remove the stale copy
hash -r
```

## Using the CLI

### `permission denied` on the socket

You're not in the `opslify` group yet in this shell:

```bash
id -nG | grep opslify        # membership recorded?
newgrp opslify               # or open a new terminal / re-login
```

If membership isn't recorded at all, the installer's `usermod` didn't target your user —
re-run `sudo OPSLIFY_USER=<you> ./scripts/install.sh`.

### `unknown command "ui"` (or any command)

A stale/older `opslify` is being used — see the shadow fix above. Confirm the installed one
has it: `/usr/local/bin/opslify --help | grep ui`.

### `session not found` from `session exec`

Put `--socket` **before** the session id — `exec` stops parsing flags after the command
begins:

```bash
opslify session exec --socket /run/opslify/opslifyd.sock <id> <cmd>
```

## The service won't start

```bash
journalctl -u opslifyd -n 50
```

| Log | Fix |
|---|---|
| `identity key permissions must be 0600` | `sudo chmod 0600 /etc/opslify/identity.key /etc/opslify/vault.key` then `sudo systemctl restart opslifyd`. |
| `nft not usable` | Install `nftables`; the service already runs as root. |
| vault key unset | Ensure `/etc/opslify/vault.key` exists (0600) or set `OPSLIFY_VAULT_KEY`. |

## Sandbox networking

### A command in a sandbox can't reach the internet

Two different paths — check which you need:

- **Credential-blind path** (an `egress_inject` host): uses the daemon's network, works even
  if container NAT is down. Check the log for `credential-blind HTTP path active` (not a
  `fail-closed` warning).
- **Direct allowlisted egress**: needs host container NAT. Test it:

```bash
sudo podman run --rm docker.io/library/alpine:3.20 sh -c 'ping -c1 -W3 1.1.1.1 && echo OK || echo FAIL'
```

If `FAIL`:

```bash
cat /proc/sys/net/ipv4/ip_forward           # should be 1
sudo sysctl -w net.ipv4.ip_forward=1
sudo podman network reload --all
```

If it's still `FAIL` with forwarding on, a host firewall (ufw/firewalld) is likely dropping
`FORWARD`, or a VPN is interfering:

```bash
sudo nft list ruleset | grep -i masquerade   # netavark NAT present?
```

### Credential-blind call times out / empty output

- Confirm `sandbox_network` is set in the config and the `opslify0` network exists
  (`sudo podman network inspect opslify-net`).
- Check for the proxy bind in the log: `credential-blind HTTP path active proxy=...`.
- If you `kill -9`'d the daemon at some point, leaked per-session nftables tables can drop
  new sessions. Flush them:

```bash
sudo nft list tables | grep opslify_sess | while read -r _ f t; do sudo nft delete table "$f" "$t"; done
sudo systemctl restart opslifyd
```

### Rootless: `no reachable bridge gateway ... fail-closed`

The credential-blind egress path needs the daemon to run as **root** (the service does). A
rootless daemon fails closed — safe, but the blind path is unavailable. Use the service.

## Still stuck?

Open an issue with the relevant `journalctl -u opslifyd` output and your
`/etc/opslify/config.yaml` (redact secrets — there shouldn't be any in it).
