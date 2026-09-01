# Install script (from a clone)

If you'd rather not pipe a script into a shell, install from a checked-out repository.
This runs the same setup as the [one-liner](one-line.md).

## Install

```bash
git clone https://github.com/opslify-com/opslifyd
cd opslifyd
sudo ./scripts/install.sh
```

By default the script **builds the binaries from source** (requires `go`). To install
prebuilt binaries instead, point it at a directory containing `opslify` and `opslifyd`:

```bash
sudo OPSLIFY_BIN_SRC=/path/to/bin ./scripts/install.sh
```

## Environment variables

`scripts/install.sh` is idempotent (safe to re-run) and configurable:

| Variable | Default | Purpose |
|---|---|---|
| `OPSLIFY_BIN_SRC` | *(build from source)* | Directory with prebuilt `opslify` + `opslifyd`. |
| `OPSLIFY_PREFIX` | `/usr/local/bin` | Binary install location. |
| `OPSLIFY_ETC` | `/etc/opslify` | Config + keys directory. |
| `OPSLIFY_VAR` | `/var/lib/opslify` | State (vault, workspaces, trace). |
| `OPSLIFY_GROUP` | `opslify` | Group that gates the daemon socket. |
| `OPSLIFY_NET` | `opslify-net` | Podman bridge network name. |
| `OPSLIFY_IFACE` | `opslify0` | Bridge interface (used by the credential-blind path). |
| `OPSLIFY_BASE_SRC` | `docker.io/alpine/curl:latest` | Upstream base image (pulled + retagged). |
| `OPSLIFY_BASE_IMAGE` | `localhost/opslify-base:latest` | Local base image tag written into the config. |
| `OPSLIFY_USER` | `$SUDO_USER` | User added to the `opslify` group. |

## Example: install prebuilt binaries into a custom prefix

```bash
sudo OPSLIFY_BIN_SRC=./dist OPSLIFY_PREFIX=/opt/opslify/bin ./scripts/install.sh
```

## Re-running

The script is idempotent — re-run it to upgrade binaries or repair config. It leaves
existing keys untouched, so re-running never rotates your vault key.

## Next

- [What the installer does](what-it-does.md) — the full step list.
- [Verify the install](verify.md) — confirm everything is healthy.
