package install

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultIdentityKeyPath is where the daemon Ed25519 private key lives in
// production. Overridable on InitOptions so tests write to a temp dir and never
// need root.
const DefaultIdentityKeyPath = "/etc/opslify/identity.key"

// Identity is the generated daemon signing identity. The private key never
// leaves the 0600 file; only the public key and fingerprint are returned for
// display and for wiring into config.
type Identity struct {
	// PublicKeyHex is the hex-encoded Ed25519 public key (safe to print/log).
	PublicKeyHex string
	// Fingerprint is a short, human-verifiable id derived from the public key.
	Fingerprint string
	// KeyPath is the path the private key was written to.
	KeyPath string
	// PubKeyPath is the path the public key was written to.
	PubKeyPath string
}

// GenerateIdentity creates an Ed25519 keypair and persists it. The PRIVATE key
// is written PKCS#8/PEM with perms 0600 (owner read/write only); the PUBLIC key
// PKIX/PEM with 0644. The private key material is never returned, logged, or
// printed — only the public half and a fingerprint. Parent dirs are 0700 so the
// key directory is not world-traversable.
func GenerateIdentity(keyPath string) (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("install: generate identity key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Identity{}, fmt.Errorf("install: marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Identity{}, fmt.Errorf("install: marshal public key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return Identity{}, fmt.Errorf("install: create key dir: %w", err)
	}

	// Write the private key with a strict umask-independent 0600 via O_EXCL-free
	// WriteFile, then re-assert perms in case the file pre-existed with looser
	// bits (defence-in-depth; overwrite is gated upstream).
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		return Identity{}, fmt.Errorf("install: write private key: %w", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return Identity{}, fmt.Errorf("install: chmod private key: %w", err)
	}

	pubPath := keyPath + ".pub"
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return Identity{}, fmt.Errorf("install: write public key: %w", err)
	}

	pubHex := hex.EncodeToString(pub)
	return Identity{
		PublicKeyHex: pubHex,
		Fingerprint:  pubHex[:16],
		KeyPath:      keyPath,
		PubKeyPath:   pubPath,
	}, nil
}

// LoadSigningKey loads the daemon Ed25519 PRIVATE key for signing (F3.1 trace
// seals), applying the same fail-fast gate as LoadIdentity: the key must exist
// and be exactly 0600. Unlike LoadIdentity it returns the private key material so
// the caller can sign — the key stays in-process, is never logged, and never
// enters a trace event. The fingerprint (public, safe to log) is returned too so
// a seal is attributable to the daemon identity.
func LoadSigningKey(keyPath string) (ed25519.PrivateKey, string, error) {
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("install: identity key not found at %s: %w", keyPath, err)
	}
	if perm := info.Mode().Perm(); perm != RequiredKeyPerm {
		return nil, "", fmt.Errorf("%w: %s has %#o", ErrIdentityKeyPerms, keyPath, perm)
	}
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("install: read identity key %s: %w", keyPath, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, "", fmt.Errorf("install: identity key %s is not valid PEM", keyPath)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("install: parse identity key %s: %w", keyPath, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, "", fmt.Errorf("install: identity key %s is not Ed25519 (got %T)", keyPath, key)
	}
	pub := priv.Public().(ed25519.PublicKey)
	return priv, hex.EncodeToString(pub)[:16], nil
}

// LoadPublicKey loads a daemon Ed25519 PUBLIC key from a PKIX/PEM file (the
// `.pub` written next to the private key by GenerateIdentity, 0644). It is the
// out-of-band trust anchor `opslify verify` pins a trace seal to. It returns the
// public key and its fingerprint (first 16 hex chars — the same derivation as
// Identity.Fingerprint). No permission gate: a public key is safe to be readable.
func LoadPublicKey(pubPath string) (ed25519.PublicKey, string, error) {
	pemBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, "", fmt.Errorf("install: read public key %s: %w", pubPath, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, "", fmt.Errorf("install: public key %s is not valid PEM", pubPath)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("install: parse public key %s: %w", pubPath, err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("install: public key %s is not Ed25519 (got %T)", pubPath, key)
	}
	return pub, hex.EncodeToString(pub)[:16], nil
}

// RequiredKeyPerm is the exact permission the daemon identity private key must
// carry: owner read/write only. Anything looser is a fail-fast condition.
const RequiredKeyPerm os.FileMode = 0o600

// ErrIdentityKeyPerms is returned by LoadIdentity when the private key file's
// permission bits are not exactly 0600 (world/group readability is a leak of
// the daemon's signing identity).
var ErrIdentityKeyPerms = errors.New("install: identity key permissions must be 0600")

// LoadIdentity loads the daemon Ed25519 identity from the private key at
// keyPath and fails fast if the key is absent or its permission bits are not
// exactly 0600. It returns only the PUBLIC half + fingerprint (safe to log): the
// private key material is parsed to prove it is well-formed, then dropped — it is
// never returned, logged, or printed. This is the daemon's verify-before-serve
// identity gate (F1.1).
func LoadIdentity(keyPath string) (Identity, error) {
	info, err := os.Stat(keyPath)
	if err != nil {
		return Identity{}, fmt.Errorf("install: identity key not found at %s: %w", keyPath, err)
	}
	if perm := info.Mode().Perm(); perm != RequiredKeyPerm {
		return Identity{}, fmt.Errorf("%w: %s has %#o", ErrIdentityKeyPerms, keyPath, perm)
	}

	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return Identity{}, fmt.Errorf("install: read identity key %s: %w", keyPath, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return Identity{}, fmt.Errorf("install: identity key %s is not valid PEM", keyPath)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Identity{}, fmt.Errorf("install: parse identity key %s: %w", keyPath, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return Identity{}, fmt.Errorf("install: identity key %s is not Ed25519 (got %T)", keyPath, key)
	}

	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return Identity{}, fmt.Errorf("install: identity key %s has no Ed25519 public half", keyPath)
	}
	pubHex := hex.EncodeToString(pub)
	return Identity{
		PublicKeyHex: pubHex,
		Fingerprint:  pubHex[:16],
		KeyPath:      keyPath,
		PubKeyPath:   keyPath + ".pub",
	}, nil
}
