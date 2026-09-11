# What the installer does

Both the [one-liner](one-line.md) and the [install script](script.md) perform the same
setup. Understanding it helps you trust it and troubleshoot it.

## Steps

1. **Check prerequisites.** Verifies `podman`, `nftables` (`nft`), and `systemd` are
   present; stops with a distro-specific install hint if not.

2. **Container-egress preflight.** Sandboxes (and any non-proxied allowlisted egress)
   need the host to forward + NAT container traffic. If a test container has no outbound,
   the installer enables `net.ipv4.ip_forward=1` (persisted to
   `/etc/sysctl.d/99-opslify-forward.conf`) and reloads podman's network rules. This fixes
   the classic "container has a route but no internet" case.

3. **Install binaries.** Places `opslify` and `opslifyd` in `/usr/local/bin`
   (from a release download, `OPSLIFY_BIN_SRC`, or a source build). Warns if another
   `opslify` earlier in your `PATH` would shadow it.

4. **Create the group + directories.** Creates the system group `opslify`, adds the
   invoking user to it, and creates `/etc/opslify` and `/var/lib/opslify/{workspaces,trace}`.

5. **Create the bridge network.** `podman network create --interface-name opslify0
   opslify-net` — this gives sandboxes a routable gateway that the credential-blind path
   binds to.

6. **Prepare the base sandbox image.** **Pulls** a ready image that already contains
   `curl` + a CA bundle + a shell, and retags it as `localhost/opslify-base:latest`.
   Pulling (not building) means install needs no *container* egress — only a registry
   pull, which uses the host network.

7. **Generate keys.** Creates the daemon's Ed25519 **identity key** (signs the audit
   trail) and the **vault master key** (encrypts secrets). Both are kept `0600 root:root`.
   The vault master key is **revealed once** — save it; losing it makes vaulted secrets
   unrecoverable.

8. **Write the config.** Generates `/etc/opslify/config.yaml` with the base image,
   `sandbox_network`, vault paths, and trace directory. See
   [Configuration](../reference/config.md).

9. **Install + start the service.** Writes `/etc/systemd/system/opslifyd.service` and runs
   `systemctl enable --now opslifyd`.

## The no-sudo model

The service unit sets **`Group=opslify`**, so:

- the daemon runs as `root` (needed for nftables + podman) with primary group `opslify`;
- systemd creates `/run/opslify` as `root:opslify` (mode `0750`); and
- the daemon creates its socket `0660`, group `opslify`.

Because you're in the `opslify` group, you can traverse `/run/opslify` and read/write the
socket — so `opslify` commands work **without sudo**. This is the same pattern as Docker's
`docker` group.

## Files it creates

| Path | Purpose |
|---|---|
| `/usr/local/bin/opslify`, `/usr/local/bin/opslifyd` | Binaries |
| `/etc/opslify/config.yaml` | Daemon config |
| `/etc/opslify/identity.key` (+ `.pub`) | Audit-signing identity (0600) |
| `/etc/opslify/vault.key` | Vault master key (0600) |
| `/var/lib/opslify/vault.db` | Encrypted secret vault |
| `/var/lib/opslify/workspaces/` | Per-session + persistent workspace state |
| `/var/lib/opslify/trace/` | Append-only audit logs |
| `/etc/systemd/system/opslifyd.service` | The service unit |
| `/etc/sysctl.d/99-opslify-forward.conf` | Enables IP forwarding (if it was off) |

## A note on `--dev-skip-verify`

The service runs `opslifyd` with `--dev-skip-verify` when there is no cosign-signed
toolchain on the host (no `nix`/`cosign`). This is appropriate for a single-host,
self-serve install where you trust your own base image. A multi-tenant production
deployment should bake a **signed toolchain** and drop that flag. See
[Security model](../security/model.md).
