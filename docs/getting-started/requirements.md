# Requirements

opslifyd runs on **Linux** and relies on kernel-level isolation primitives, so the daemon
is Linux-only. The CLI, dashboard, and MCP server are portable, but the daemon (and the
sandboxes it manages) need a Linux host.

## Host requirements

| Requirement | Why | Notes |
|---|---|---|
| **Linux with systemd** | The daemon is installed as a systemd service | Arch, Debian/Ubuntu, Fedora, etc. |
| **podman** | Container runtime for sandboxes | 4.0+ recommended (5.x/6.x fine) |
| **nftables** (`nft`) | Default-deny egress enforcement | Present on most modern distros |
| **IP forwarding** | Container networking (outbound from sandboxes) | The installer enables `net.ipv4.ip_forward` if needed |
| Root **once**, for install | The daemon needs root for isolation + firewalling | **Daily use needs no sudo** — see below |

Optional but recommended:

| Optional | Adds |
|---|---|
| **gVisor (`runsc`)** | A stronger isolation tier (syscall interception) beyond runc |
| **nix + cosign** | A cryptographically **signed toolchain** layer (removes the dev `--dev-skip-verify` flag) |

## Do I need sudo every time?

**No.** The daemon runs once as a background **systemd service** (it needs root for
sandbox isolation and firewall rules). You are added to the `opslify` group, and the
daemon's control socket is group-gated — so you run `opslify run`, `opslify ui`, etc. as
your normal user, exactly like using Docker after being added to the `docker` group.

Only two things need sudo:

- the one-time install (`sudo ./scripts/install.sh` or the `curl | sudo sh` one-liner), and
- service management (`systemctl restart opslifyd`).

## Installing prerequisites

=== "Arch"

    ```bash
    sudo pacman -S podman nftables
    ```

=== "Debian / Ubuntu"

    ```bash
    sudo apt update && sudo apt install -y podman nftables
    ```

=== "Fedora"

    ```bash
    sudo dnf install -y podman nftables
    ```

The installer checks for these and stops with a clear message (and the right package
command for your distro) if any are missing.

## Architecture support

The daemon builds for **linux/amd64** and **linux/arm64**. Sandboxes use OCI images for
your host architecture.

## What about Windows / macOS?

The CLI/dashboard/MCP pieces are portable, but the daemon needs a Linux kernel:

- **Windows** — run the daemon inside **WSL2** (a real Linux kernel; bridge networking
  works as on native Linux).
- **macOS** — run the daemon inside a Linux VM (e.g. `podman machine`).

Native (non-VM) Windows/macOS sandboxing is not supported. See the
[roadmap](../about/roadmap.md).
