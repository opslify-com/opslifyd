# Verify the install

After installing, confirm everything is healthy.

## 1. The service is running

```bash
systemctl is-active opslifyd        # => active
systemctl status opslifyd           # details; look for "listening ... /run/opslify/opslifyd.sock"
```

Live logs:

```bash
journalctl -u opslifyd -f
```

## 2. You can use it without sudo

In a new login shell (or after `newgrp opslify`):

```bash
id -nG | tr ' ' '\n' | grep opslify     # confirms group membership
opslify session ls                       # talks to the daemon over the group-gated socket
```

If `opslify session ls` prints a table (even an empty one), the socket and permissions are
correct.

## 3. A sandbox actually runs

```bash
opslify run --mode scratch echo "install ok"
```

Expected output: `install ok`.

## 4. The dashboard launches

```bash
opslify ui --no-open
```

It should print a `http://127.0.0.1:4646/?token=…` URL.

## Common checks

| Symptom | Check |
|---|---|
| `permission denied` on the socket | Are you in the `opslify` group? Did you start a new shell / `newgrp opslify`? |
| `unknown command` | A stale `opslify` earlier in `PATH` (e.g. `~/.local/bin`). Run `which -a opslify`. |
| service inactive | `journalctl -u opslifyd -n 50` — often a key-permission or config issue. |
| sandbox can't reach the internet | Container NAT/`ip_forward` or a host firewall — see [Troubleshooting](../reference/troubleshooting.md). |

See [Troubleshooting](../reference/troubleshooting.md) for fixes to each.
