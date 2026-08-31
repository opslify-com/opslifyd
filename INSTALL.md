# Installing opslify

opslify runs DevOps commands for AI agents inside hardened, per-session sandboxes,
with a credential-blind secret broker and a tamper-evident audit trail.

You install it **once** (with sudo). After that you use it **as yourself — no sudo** —
because the daemon runs as a background system service and you talk to it over a
group-gated socket, the same way Docker works.

## Requirements
- Linux with **systemd**
- **podman** and **nftables** installed
  - Arch: `sudo pacman -S podman nftables`
  - Debian/Ubuntu: `sudo apt install podman nftables`
- (to build from source) **Go** — or use a release with prebuilt binaries

## Install (one time)
```bash
sudo ./scripts/install.sh
```
This will:
1. install the `opslify` (CLI) and `opslifyd` (daemon) binaries to `/usr/local/bin`,
2. create the `opslify` group and add **you** to it,
3. create the `opslify-net` bridge network (gives sandboxes a routable gateway),
4. build a base sandbox image (with `curl` + CA certs),
5. generate your keys and **show the vault master key once — save it in a password manager**,
6. write `/etc/opslify/config.yaml`,
7. install + start the `opslifyd` systemd service.

Then activate your group membership (one time) — either log out and back in, or:
```bash
newgrp opslify
```

## Everyday use (no sudo)
```bash
opslify run --mode scratch echo "hello from the sandbox"   # run a command in a fresh sandbox
opslify run --mode workspace --name myapp bash -lc 'python --version'
opslify ui            # open the dashboard (prints a http://127.0.0.1:4646/?token=… URL)
opslify ws ls         # list persistent workspaces
opslify session ls    # list live sessions
```
That's it — create a session/workspace and go. You never type `sudo` for daily use.

## Optional: credential-blind access to a service (e.g. GitLab)
So an agent can call an API **without ever seeing the token**:
1. Add an `egress_inject` rule + a matching policy grant to `/etc/opslify/config.yaml`
   (see `spec/manual-tests/F5.7-credential-blind-gitlab-LIVE.md`), then
   `sudo systemctl restart opslifyd`.
2. Store the secret (value from stdin, never shown again):
   ```bash
   opslify secrets add gitlab-token --provider gitlab
   ```
3. Use it — the daemon injects it on the upstream leg only:
   ```bash
   opslify run curl -sS "https://gitlab.com/api/v4/projects?membership=true"
   ```

## Service management (needs sudo)
```bash
systemctl status opslifyd        # is it running?
journalctl -u opslifyd -f        # live logs
sudo systemctl restart opslifyd  # after editing /etc/opslify/config.yaml
```

## Uninstall
```bash
sudo ./scripts/uninstall.sh            # removes the service + binaries, KEEPS your keys/vault
sudo ./scripts/uninstall.sh --purge    # also removes /etc/opslify, /var/lib/opslify, network, image
```

## Notes
- **Why a service?** The daemon needs root for the sandbox isolation (nftables egress,
  bridge networking). Running it once as a service means *you* never need root — group
  membership on the socket is your access.
- **`--dev-skip-verify`** is set in the service for a single-host self-serve install
  (it runs without a cosign-signed toolchain layer, trusting your own base image). A
  multi-tenant production deployment should bake a signed toolchain and remove that flag.
- **Rootless?** The credential-blind egress path needs the daemon to bind the bridge
  gateway, which requires the daemon to run as root (this service). Rootless setups fail
  **closed** (no injection) — safe, but the blind path is unavailable.
