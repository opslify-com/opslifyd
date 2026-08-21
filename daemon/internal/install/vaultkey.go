package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/opslify-com/opslifyd/internal/broker"
)

// VaultKeyResult reports what EnsureVaultKey did, for the init summary and tests.
type VaultKeyResult struct {
	// Generated is true when a fresh master key was minted + written this run (and
	// therefore revealed once). False when a key already resolved (idempotent).
	Generated bool
	// KeyFile is the on-disk key file path (empty when the key came from the env).
	KeyFile string
	// FromEnv is true when the resolved key came from the OPSLIFY_VAULT_KEY override
	// rather than the file — init neither wrote nor revealed anything in that case.
	FromEnv bool
}

// EnsureVaultKey is the F7.2 generate + store + one-time-reveal step of `opslify
// init`. It is IDEMPOTENT and fail-closed:
//
//   - If a key already resolves (the env override is set, or the 0600 key file
//     exists), it does NOTHING — no regenerate, no reveal — and reports it.
//   - Otherwise it mints a 256-bit key (crypto/rand), writes it to keyFile at 0600
//     (root/daemon-owned, SEPARATE from the vault db), and reveals it EXACTLY ONCE
//     to w with a loud save-it warning. This is the only automatic reveal; the sole
//     re-reveal path is `opslify vault key export`.
//
// The key is written and revealed but NEVER logged or traced. w is the operator's
// stdout (init's Out) — a real terminal on a real install; the reveal must go
// nowhere else.
func EnsureVaultKey(w io.Writer, keyEnv, keyFile string) (VaultKeyResult, error) {
	if keyEnv == "" {
		keyEnv = broker.DefaultVaultKeyEnv
	}
	if keyFile == "" {
		keyFile = DefaultVaultKeyFilePath
	}
	res := VaultKeyResult{KeyFile: keyFile}

	// Already resolvable? Then do nothing (idempotent). We check the env override
	// and the file directly rather than decoding, so a present-but-broken key file
	// surfaces as an error here instead of being silently overwritten.
	if raw := strings.TrimSpace(os.Getenv(keyEnv)); raw != "" {
		res.FromEnv = true
		fmt.Fprintf(w, "Vault master key: using the %s override (env) — no key file written.\n", keyEnv)
		return res, nil
	}
	if _, err := os.Stat(keyFile); err == nil {
		fmt.Fprintf(w, "Vault master key already present at %s (0600) — not regenerated or re-revealed. Use `opslify vault key export` to back it up.\n", keyFile)
		return res, nil
	} else if !os.IsNotExist(err) {
		return res, fmt.Errorf("install: stat vault key file %s: %w", keyFile, err)
	}

	// Mint, persist 0600, reveal once.
	key, err := broker.GenerateMasterKey()
	if err != nil {
		return res, err
	}
	defer broker.Zeroize(key)
	if err := broker.WriteKeyFile(keyFile, key); err != nil {
		if errors.Is(err, broker.ErrExists) {
			// Raced with another writer; treat as already-present (do not reveal).
			fmt.Fprintf(w, "Vault master key already present at %s — not revealed.\n", keyFile)
			return res, nil
		}
		return res, fmt.Errorf("install: write vault key file: %w", err)
	}
	res.Generated = true
	revealVaultKey(w, key, keyFile)
	return res, nil
}

// revealVaultKey prints the master key EXACTLY ONCE with a loud, unmissable
// warning. It is the one place in init that emits key material; it goes only to w
// (the operator's terminal) and is never logged or traced.
func revealVaultKey(w io.Writer, key []byte, keyFile string) {
	const bar = "============================================================"
	fmt.Fprintf(w, "\n%s\n", bar)
	fmt.Fprintln(w, "VAULT MASTER KEY — SAVE THIS NOW (shown only once):")
	fmt.Fprintf(w, "\n    %s\n\n", broker.EncodeKey(key))
	fmt.Fprintln(w, "Store it in a password manager. It is the ONLY copy — losing it")
	fmt.Fprintln(w, "makes every vaulted secret PERMANENTLY unrecoverable.")
	fmt.Fprintf(w, "A 0600 copy is on the daemon host at %s; the daemon reads it\n", keyFile)
	fmt.Fprintln(w, "automatically. It will not be shown again except via:")
	fmt.Fprintln(w, "    opslify vault key export")
	fmt.Fprintf(w, "%s\n\n", bar)
}
