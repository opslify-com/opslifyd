# Keys & backup

opslifyd has **two** private keys. They do different jobs, are handled differently, and
both are worth backing up. This page explains where they live, how to retrieve/back them
up, and how to restore them.

| Key | File | Protects | Losing it means |
|---|---|---|---|
| **Vault master key** | `/etc/opslify/vault.key` | Encrypts the secret vault | Every stored secret is **permanently unrecoverable** |
| **Identity (signing) key** | `/etc/opslify/identity.key` (+ `.pub`) | Signs the tamper-evident audit trail | You lose signing continuity (old trails still verify against the backed-up public key) |

Both files are `0600 root:root` — readable only by root (the daemon runs as root). Never
loosen their permissions; the daemon refuses to start if the identity key isn't `0600`.

---

## Vault master key

This is the key that encrypts your secrets. It's **CLI-only** — no API, UI, or socket route
ever returns it.

### See it / back it up

`opslify init` reveals it **once** at install. To retrieve it again for backup:

```bash
sudo opslify vault key export
```

It prints the master key once, with a save-it warning:

```
VAULT MASTER KEY (backup copy — handle like a password):

    <64-hex-character key>

Store it in a password manager. It is the ONLY copy — losing it
makes every vaulted secret PERMANENTLY unrecoverable.
```

!!! warning "Needs sudo, treat like a password"
    `vault key export` reads the `0600` key file locally (never over the socket), so it
    needs `sudo`. The output is your master key — put it straight into a password manager;
    don't leave it in shell history or a file. (Prefix the command with a space, or clear
    your history, if your shell logs it.)

### Where it's stored

- File: `/etc/opslify/vault.key` (`0600 root:root`).
- The daemon resolves it at startup from (in precedence): the `OPSLIFY_VAULT_KEY`
  environment variable, then this file. See [Service management](service.md).

### Back up the file directly (alternative)

```bash
sudo cp /etc/opslify/vault.key /root/opslify-vault.key.bak   # then move it somewhere safe + offline
```

### If you lose it

There is **no recovery** — that's by design (the operator holds the only copy). Vaulted
secrets become undecryptable. You'd re-initialize the vault and re-add every secret. So:
**export and store it now**, before you need it.

### Rotation

Rotating the master key re-encrypts the vault under a new key. Keep the old key until
rotation completes, and back up the new one immediately. (Rotation is a broker operation;
losing the key mid-rotation orphans secrets — never regenerate the key file by hand.)

---

## Identity (signing) key

This Ed25519 key signs the tamper-evident audit trail. `opslify verify` checks a session's
seal against the **trusted public key** — so this key is what makes your audit trail
attributable and forgery-resistant.

### Where it is

- Private: `/etc/opslify/identity.key` (`0600 root:root`).
- Public: `/etc/opslify/identity.key.pub` (`0644`).

Unlike the vault key, there is **no `export` command** for the identity private key — it
stays on the daemon and is **never loaded into a browser** or served over any route. You
back it up by copying the files.

### Back it up

```bash
sudo cp /etc/opslify/identity.key     /root/opslify-identity.key.bak
sudo cp /etc/opslify/identity.key.pub /root/opslify-identity.key.pub.bak
# move both to secure, offline storage; keep the private one like a password
```

Keep the **public** key too — it's what verification trusts. If you ever move to a new host
and want old trails to keep verifying, restore the same identity key pair.

### If you lose it

- **Lost private key, kept public:** old trails still **verify** (verification only needs
  the public key). But the daemon can't sign new trails under the same identity — it will
  generate a new identity, and new trails verify under the new public key.
- **Lost both:** you lose the ability to verify old trails against a trusted anchor. Back up
  at least the public key.

---

## Restoring keys on a new host / after a reinstall

1. Install opslifyd but **don't** let it generate fresh keys over your backups — the
   installer keeps existing keys, so place your backups first:

    ```bash
    sudo install -m 600 -o root -g root opslify-vault.key.bak     /etc/opslify/vault.key
    sudo install -m 600 -o root -g root opslify-identity.key.bak  /etc/opslify/identity.key
    sudo install -m 644 -o root -g root opslify-identity.key.pub.bak /etc/opslify/identity.key.pub
    ```

2. Ensure perms are exactly `0600` on the private keys:

    ```bash
    sudo chmod 600 /etc/opslify/vault.key /etc/opslify/identity.key
    ```

3. Restart:

    ```bash
    sudo systemctl restart opslifyd
    ```

With the same vault key, your existing `vault.db` decrypts; with the same identity key, old
trails keep verifying.

---

## Do / don't

- **Do** export the vault key at install and store it in a password manager.
- **Do** back up `identity.key`, `identity.key.pub`, and `vault.key` together, offline.
- **Do** keep every private key `0600 root:root`.
- **Don't** commit any key to git, paste it in chat, or copy it into a sandbox/workspace.
- **Don't** loosen permissions to share access — use the `opslify` group for the *socket*,
  never for the keys.
