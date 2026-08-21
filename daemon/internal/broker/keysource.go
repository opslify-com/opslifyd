package broker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ErrKeyAbsent signals that a KeySource has NO key material configured (an unset
// env var, a missing key file) — a signal to a chain to FALL THROUGH to the next
// source, distinct from a present-but-malformed key (a bad hex/base64 value, a
// loose-perms file), which is a FAIL-CLOSED error that stops the chain. A chain
// that exhausts every source returns an error wrapping ErrKeyAbsent so the daemon
// can still fatal (fail-closed) when nothing at all resolves.
var ErrKeyAbsent = errors.New("broker: no vault master key resolved from any source")

// GenerateMasterKey mints a fresh 256-bit (masterKeyLen) master key (KEK) from
// crypto/rand. It is the key `opslify init` writes via FileKeySource when no key
// resolves yet. The bytes are the ONLY copy — the caller reveals them once and
// stores them at rest 0600; they are never logged or traced.
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, masterKeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("broker: generate vault master key: %w", err)
	}
	return key, nil
}

// EncodeKey renders a 32-byte KEK as lowercase hex (64 chars) — the canonical form
// for the key file and the one-time reveal. It is decodable by decodeKey.
func EncodeKey(key []byte) string {
	return hex.EncodeToString(key)
}

// FileKeySource reads the KEK from a 0600 file (hex or base64, 32 bytes) that is
// SEPARATE from the vault db — the pragmatic headless default so the daemon starts
// without an env dance. It mirrors the vault's fail-closed perms gate: a file with
// any group/other bit set is REFUSED (a readable master key defeats at-rest
// encryption), and a missing file returns ErrKeyAbsent so a chain falls through.
type FileKeySource struct {
	// Path is the key file (e.g. /etc/opslify/vault.key). It MUST NOT be the vault
	// db path — the key beside the ciphertext would defeat encryption at rest.
	Path string
}

func (f FileKeySource) MasterKey() ([]byte, error) {
	if f.Path == "" {
		return nil, fmt.Errorf("%w: vault key file path is empty", ErrKeyAbsent)
	}
	info, err := os.Stat(f.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: key file %s does not exist", ErrKeyAbsent, f.Path)
		}
		return nil, fmt.Errorf("broker: stat vault key file %s: %w", f.Path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("broker: vault key file %s has insecure perms %#o (must be 0600) — refusing to read", f.Path, perm)
	}
	raw, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("broker: read vault key file %s: %w", f.Path, err)
	}
	key, err := decodeKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("broker: vault key file %s: %w", f.Path, err)
	}
	return key, nil
}

// WriteKeyFile writes key (hex-encoded) to path atomically at 0600, refusing to
// clobber an existing key file (idempotency / never silently rotate). The parent
// dir is created 0700. This is the write half of FileKeySource, used by
// `opslify init` to persist a freshly generated KEK.
func WriteKeyFile(path string, key []byte) error {
	if path == "" {
		return fmt.Errorf("%w: vault key file path is empty", ErrInvalidInput)
	}
	if len(key) != masterKeyLen {
		return fmt.Errorf("%w: master key must be %d bytes, got %d", ErrInvalidInput, masterKeyLen, len(key))
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: vault key file %s already exists", ErrExists, path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("broker: stat vault key file %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("broker: create vault key dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-key-*.tmp")
	if err != nil {
		return fmt.Errorf("broker: create vault key temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("broker: chmod vault key temp: %w", err)
	}
	if _, err := tmp.WriteString(EncodeKey(key) + "\n"); err != nil {
		tmp.Close()
		return fmt.Errorf("broker: write vault key temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("broker: fsync vault key temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("broker: close vault key temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("broker: install vault key file: %w", err)
	}
	return nil
}

// chainKeySource resolves the KEK from an ordered list of sources, trying each in
// turn. A source that reports ErrKeyAbsent is SKIPPED (fall through); any other
// error is FAIL-CLOSED and stops the chain (a present-but-broken source must never
// be silently bypassed). If every source is absent, it returns an error wrapping
// ErrKeyAbsent so the daemon still fatals rather than serving with no key.
type chainKeySource struct {
	sources []KeySource
	// names parallels sources, for a legible "tried env, file" error.
	names []string
}

func (c chainKeySource) MasterKey() ([]byte, error) {
	tried := make([]string, 0, len(c.sources))
	for i, s := range c.sources {
		name := ""
		if i < len(c.names) {
			name = c.names[i]
		}
		tried = append(tried, name)
		key, err := s.MasterKey()
		if err == nil {
			return key, nil
		}
		if errors.Is(err, ErrKeyAbsent) {
			continue // fall through to the next source
		}
		return nil, err // present but broken → fail closed, do not skip
	}
	return nil, fmt.Errorf("%w (tried, in precedence order: %s)", ErrKeyAbsent, strings.Join(tried, " → "))
}

// ResolveKeySource builds the documented v1 KEK resolution chain in PRECEDENCE
// order:
//
//  1. OPSLIFY_VAULT_KEY env (envVar) — the highest-precedence OVERRIDE, for
//     operators injecting the key from a secrets manager; it keeps the key off the
//     daemon disk entirely.
//  2. FileKeySource at keyFile — the 0600 root-owned key file `opslify init`
//     writes (SEPARATE from the vault db); the pragmatic headless default.
//
// An OS-keyring source is intentionally NOT in the chain for v1 (see the F7.2
// tradeoff note): headless servers rarely run a Secret Service, and a keyring dep
// that fails ungracefully there would be worse than the file. env + file cover the
// headless and secrets-manager cases; a keyring source slots in ahead of the file
// later behind this same interface without changing any caller.
//
// The chain FALLS THROUGH an absent source and FAILS CLOSED on a present-but-broken
// one; if nothing resolves it errors (wrapping ErrKeyAbsent), so the daemon fatals.
func ResolveKeySource(envVar, keyFile string) KeySource {
	if envVar == "" {
		envVar = DefaultVaultKeyEnv
	}
	return chainKeySource{
		sources: []KeySource{
			EnvKeySource{Var: envVar},
			FileKeySource{Path: keyFile},
		},
		names: []string{"env " + envVar, "file " + keyFile},
	}
}
