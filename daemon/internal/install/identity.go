package install

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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
