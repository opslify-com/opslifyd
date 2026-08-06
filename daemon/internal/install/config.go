package install

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"gopkg.in/yaml.v3"
)

// DefaultConfigPath is the production daemon config path. It is overridable on
// InitOptions so tests never write to real /etc and never need root.
const DefaultConfigPath = "/etc/opslify/config.yaml"

// Default daemon config values (spec F0.1 §4).
const (
	DefaultSessionTTL   = "30m"
	DefaultWarmPoolSize = 1
)

// DefaultWorkspaceDir is the per-session writable workspace root.
const DefaultWorkspaceDir = "/var/lib/opslify/workspaces"

// Config is the daemon config written to config.yaml. It contains no secrets:
// the identity key lives in a separate 0600 file, referenced by path only.
type Config struct {
	// Image is the digest-pinned base image the toolchain layer mounts over.
	Image string `yaml:"image"`
	// SessionTTL is the idle lifetime before the reaper destroys a session.
	SessionTTL string `yaml:"session_ttl"`
	// WarmPoolSize is how many containers are kept warm for fast session start.
	WarmPoolSize int `yaml:"warm_pool_size"`
	// EgressAllowlist is the default-deny allowlist of egress destinations.
	EgressAllowlist []string `yaml:"egress_allowlist"`
	// WorkspaceDir is the host root for per-session writable workspaces.
	WorkspaceDir string `yaml:"workspace_dir"`
	// Tier is the default isolation rung (D2). Defaults to local-hardened.
	Tier string `yaml:"tier"`
	// IdentityKey is the path to the daemon Ed25519 private key (perms 0600).
	IdentityKey string `yaml:"identity_key"`
	// ToolchainDigest is the signed toolchain layer digest produced by F0.2, if
	// the bake step ran. Empty when bake was gated (missing nix/cosign).
	ToolchainDigest string `yaml:"toolchain_digest,omitempty"`
	// FlakeLockHash records the reproducibility hash of the composed environment.
	FlakeLockHash string `yaml:"flake_lock_hash,omitempty"`
}

// DefaultConfig returns a Config populated with the spec defaults.
func DefaultConfig() Config {
	return Config{
		Image:           "",
		SessionTTL:      DefaultSessionTTL,
		WarmPoolSize:    DefaultWarmPoolSize,
		EgressAllowlist: []string{},
		WorkspaceDir:    DefaultWorkspaceDir,
		Tier:            string(runtime.TierLocalHardened),
		IdentityKey:     DefaultIdentityKeyPath,
	}
}

// MarshalConfig renders a Config as YAML bytes.
func MarshalConfig(c Config) ([]byte, error) {
	b, err := yaml.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("install: marshal config: %w", err)
	}
	return b, nil
}

// WriteConfig writes the config to path (creating parent dirs). The config is
// not secret, so it is written 0644; the parent dir is 0755. Callers gate
// overwrite via the idempotency check in Run.
func WriteConfig(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("install: create config dir: %w", err)
	}
	b, err := MarshalConfig(c)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("install: write config: %w", err)
	}
	return nil
}
