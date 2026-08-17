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
	DefaultSessionTTL          = "30m"
	DefaultApprovalTTL         = "10m"
	DefaultWarmPoolSize        = 1
	DefaultWarmPoolConcurrency = 2
)

// DefaultWorkspaceDir is the per-session writable workspace root.
const DefaultWorkspaceDir = "/var/lib/opslify/workspaces"

// DefaultTraceDir is the append-only trace log root (F3.2). It is deliberately
// OUTSIDE the workspace mount, 0700, owned by the daemon user: the sandbox has no
// path to the integrity evidence it produces.
const DefaultTraceDir = "/var/lib/opslify/traces"

// Config is the daemon config written to config.yaml. It contains no secrets:
// the identity key lives in a separate 0600 file, referenced by path only.
type Config struct {
	// Image is the digest-pinned base image the toolchain layer mounts over.
	Image string `yaml:"image"`
	// SessionTTL is the idle lifetime before the reaper destroys a session.
	SessionTTL string `yaml:"session_ttl"`
	// ApprovalTTL is how long a pending human-approval gate (F4.3) waits before it
	// is FAIL-CLOSED auto-denied with reason "timeout". Empty => DefaultApprovalTTL
	// (10m). A Go duration string, e.g. "10m".
	ApprovalTTL string `yaml:"approval_ttl,omitempty"`
	// WarmPoolSize is how many containers are kept warm for fast session start.
	WarmPoolSize int `yaml:"warm_pool_size"`
	// WarmPoolConcurrency caps how many warm containers are (re)built at once.
	WarmPoolConcurrency int `yaml:"warm_pool_concurrency"`
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
	// Redaction configures the F3.3 trace-payload secret scrubber. Omitted from a
	// config => zero value, which buildRedactor fills with fail-safe defaults
	// (redaction ON, all patterns enabled) — an unset config never fails open.
	Redaction RedactionConfig `yaml:"redaction,omitempty"`
	// Trace configures the F3.2 durable transport (append-only log + SSE + optional
	// cloud push). An absent section takes fail-safe defaults: local persistence ON
	// at DefaultTraceDir, batch fsync, no cloud backend.
	Trace TraceConfig `yaml:"trace,omitempty"`
	// PolicyFile is the path to the daemon's trusted DEFAULT policy (F4.1). A
	// per-session workspace policy may only NARROW it. Empty => the built-in
	// policy.Default() (no grants; deny-by-default creds). The daemon fails to
	// start if a configured file is invalid (fail-closed).
	PolicyFile string `yaml:"policy_file,omitempty"`
}

// TraceConfig is the operator-facing F3.2 knob set for durable trace transport.
type TraceConfig struct {
	// Dir is the append-only trace directory; empty => DefaultTraceDir.
	Dir string `yaml:"dir,omitempty"`
	// Fsync is "batch" (default: fsync on exec.end/session.end + seal) or "always".
	Fsync string `yaml:"fsync,omitempty"`
	// RingBufferSize bounds the per-session in-memory SSE catch-up tail. <= 0 =>
	// trace.DefaultRingBufferSize. SSE backfill reads the log when the tail is short.
	RingBufferSize int `yaml:"ring_buffer_size,omitempty"`
	// CloudURL, if set, enables the resumable cloud uploader (F3.4 receiver). Empty
	// => the uploader is a clean no-op; local persistence + SSE are unaffected.
	CloudURL string `yaml:"cloud_url,omitempty"`
}

// RedactionConfig is the operator-facing F3.3 knob set. Fields left unset take
// the code defaults (see trace.RedactorConfig); the pattern set is opt-OUT via
// DisabledPatterns so an empty/absent section keeps every pattern enabled.
type RedactionConfig struct {
	// EntropyThreshold is the min per-char Shannon entropy (bits) for the generic
	// high-entropy catch-all. <= 0 => trace.DefaultEntropyThreshold.
	EntropyThreshold float64 `yaml:"entropy_threshold,omitempty"`
	// EntropyLengthFloor is the min token length the entropy heuristic considers.
	// <= 0 => trace.DefaultEntropyLengthFloor.
	EntropyLengthFloor int `yaml:"entropy_length_floor,omitempty"`
	// DisabledPatterns names redaction buckets to turn OFF (e.g. "entropy"). Empty
	// => all patterns enabled.
	DisabledPatterns []string `yaml:"disabled_patterns,omitempty"`
}

// DefaultConfig returns a Config populated with the spec defaults.
func DefaultConfig() Config {
	return Config{
		Image:               "",
		SessionTTL:          DefaultSessionTTL,
		ApprovalTTL:         DefaultApprovalTTL,
		WarmPoolSize:        DefaultWarmPoolSize,
		WarmPoolConcurrency: DefaultWarmPoolConcurrency,
		EgressAllowlist:     []string{},
		WorkspaceDir:        DefaultWorkspaceDir,
		Tier:                string(runtime.TierLocalHardened),
		IdentityKey:         DefaultIdentityKeyPath,
	}
}

// LoadConfig reads and parses the daemon config at path. It is the read
// counterpart to WriteConfig, used by the daemon at startup. Unknown keys are
// tolerated (forward-compat); a missing file or malformed YAML is a legible,
// layer-tagged error so the operator learns exactly what failed.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("install: read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("install: parse config %s: %w", path, err)
	}
	return c, nil
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
