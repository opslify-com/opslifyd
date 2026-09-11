# One-line install

The fastest way to install opslifyd. It downloads the binaries, sets up a background
service, and configures everything so you can use `opslify` **without sudo** afterwards.

## Install

```bash
curl -fsSL https://opslify-com.github.io/opslifyd/install.sh | sudo sh
```

or with `wget`:

```bash
wget -qO- https://opslify-com.github.io/opslifyd/install.sh | sudo sh
```

!!! warning "Review before you pipe to a shell"
    Piping a script into `sudo sh` runs code as root. It's good practice to read it first:
    ```bash
    curl -fsSL https://opslify-com.github.io/opslifyd/install.sh | less
    ```
    The script is open source — it's [`scripts/get-opslify.sh`](https://github.com/opslify-com/opslifyd/blob/main/scripts/get-opslify.sh) in the repo.

## What it does

1. Checks prerequisites (`podman`, `nftables`, `systemd`) and stops with distro-specific
   guidance if any are missing.
2. Detects your OS/arch and **downloads the matching release binaries** (falls back to
   building from source if `go` is available and no release is reachable).
3. Runs the full setup — group, network, base image, keys, config, systemd service.
   See [What the installer does](what-it-does.md) for the complete list.

## After installing

Group membership takes effect in a new login shell:

```bash
newgrp opslify           # or just open a new terminal
opslify run --mode scratch echo hello    # no sudo
opslify ui
```

## Options

The one-liner honors these environment variables (pass them **before** `sh`, or export
them first):

| Variable | Default | Purpose |
|---|---|---|
| `OPSLIFY_VERSION` | `latest` | Install a specific release tag (e.g. `v0.5.0`). |
| `OPSLIFY_DOWNLOAD_BASE` | GitHub releases | Base URL to fetch binaries from (mirrors/air-gapped). |
| `OPSLIFY_PREFIX` | `/usr/local/bin` | Where the binaries are installed. |
| `OPSLIFY_BASE_SRC` | `docker.io/alpine/curl:latest` | Upstream sandbox base image (retagged locally). |

Example — pin a version:

```bash
curl -fsSL https://opslify-com.github.io/opslifyd/install.sh | sudo OPSLIFY_VERSION=v0.5.0 sh
```

## Prefer not to pipe to a shell?

Use the [install script from a clone](script.md) instead — same result, but you run it
from a checked-out repo.

!!! note "Air-gapped / offline hosts"
    The base image is **pulled** (not built), so the host needs registry access during
    install, but the *sandboxes themselves* do not need container egress to start. For a
    fully offline install, pre-load a base image and set `OPSLIFY_BASE_SRC` to it, and set
    `OPSLIFY_DOWNLOAD_BASE` to a local mirror of the binaries.
