package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/opslify-com/opslifyd/internal/broker"
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
	// Vault configures the F5.6 local encrypted secret vault (the default broker
	// backend). An absent section takes fail-safe defaults: DefaultVaultPath, master
	// key from the OPSLIFY_VAULT_KEY env. The vault holds NO plaintext at rest and
	// its master key is NEVER a plaintext file beside the db.
	Vault VaultConfig `yaml:"vault,omitempty"`
	// OAuth2 configures the F5.4 Tier-2 OAuth2 services, keyed by service name
	// (e.g. "github"). One generic adapter serves them all; adding a service is a
	// config entry here plus `opslify creds add <service>` (device flow). The map
	// holds NO secret — only public {auth_url, token_url, device_url, scopes,
	// client_id}; the durable refresh token lives encrypted in the vault. Each
	// entry is validated fail-closed at daemon startup.
	OAuth2 map[string]broker.OAuth2ServiceConfig `yaml:"oauth2,omitempty"`
	// RegistryProxy configures the F5.5 caching package registry proxy (pip/npm/go).
	// An absent section => the proxy is OFF (no behavior change): the daemon does not
	// stand one up and nothing is routed through it. When present it is entirely
	// daemon-authoritative (upstreams, allowlist, attestation policy); a workspace
	// can never introduce or widen it.
	RegistryProxy RegistryProxyConfig `yaml:"registry_proxy,omitempty"`
	// EgressInject is the F5.7 daemon-authoritative list mapping an egress host to a
	// vaulted secret + an auth header the L7 proxy (F5.2) injects at the network
	// boundary for that host — so a granted `curl https://<host>/...` inside the
	// sandbox reaches the real host with the token added AFTER traffic leaves the
	// sandbox (the agent never sees it). It is entirely daemon-owned: a workspace can
	// never introduce or widen a host here (F4.1), and a rule only lights up when the
	// session's RESOLVED policy both grants the cred and egress-allows the host. An
	// absent section => no proxy is built and no proxy env is injected (opt-in, no
	// regression). Validated FAIL-CLOSED at startup (ValidateEgressInject).
	EgressInject []EgressInjectRule `yaml:"egress_inject,omitempty"`
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

// VaultConfig is the operator-facing F5.6 knob set for the local encrypted vault.
// It intentionally holds NO key material — only the db path and the NAME of the
// env var the 32-byte master key is read from (never the key itself).
type VaultConfig struct {
	// Path is the encrypted vault db (0600, daemon-user). Empty => broker.DefaultVaultPath.
	Path string `yaml:"path,omitempty"`
	// KeyEnv is the environment variable the 32-byte master key (hex/base64) is read
	// from. Empty => broker.DefaultVaultKeyEnv (OPSLIFY_VAULT_KEY). The key is NEVER
	// stored in config or in a plaintext file beside the db.
	KeyEnv string `yaml:"key_env,omitempty"`
	// KeyFile is the path to the F7.2 0600 root-owned master-key file — SEPARATE
	// from Path (the key must never sit beside the ciphertext). Empty =>
	// DefaultVaultKeyFilePath (/etc/opslify/vault.key). It is the daemon's automatic
	// key source so a fresh `opslify init` box starts without OPSLIFY_VAULT_KEY set;
	// the env still overrides it (documented precedence: env → file).
	KeyFile string `yaml:"key_file,omitempty"`
}

// DefaultVaultKeyFilePath is the production F7.2 master-key file. It sits under
// /etc/opslify (0600, root/daemon-owned), DELIBERATELY NOT beside the vault db
// (broker.DefaultVaultPath) — a key file next to the ciphertext would defeat
// encryption at rest. `opslify init` writes it; the daemon reads it at startup.
const DefaultVaultKeyFilePath = "/etc/opslify/vault.key"

// RegistryProxyConfig is the operator-facing F5.5 knob set for the caching package
// registry proxy. It holds NO secret — only routing, the fail-closed package
// allowlist, and the attestation policy; a private-registry credential is a `creds`
// REF (resolved through the F5.6 broker at fetch time), never a value here.
type RegistryProxyConfig struct {
	// CacheDir is the on-disk artifact cache root (daemon-owned, outside any sandbox
	// mount). Empty => caching is off (each fetch goes upstream). Entries are
	// content-addressed, so a crafted package path can never traverse out of it.
	CacheDir string `yaml:"cache_dir,omitempty"`
	// Upstreams maps each served ecosystem (pypi|npm|go) to its real registry.
	Upstreams []RegistryUpstream `yaml:"upstreams"`
	// Allow is the fail-closed package allowlist. An empty allowlist resolves NOTHING
	// (deny-by-default) — the proxy never fails open.
	Allow []RegistryAllowEntry `yaml:"allow"`
}

// RegistryUpstream is one ecosystem's real registry (config face of
// regproxy.Upstream). CredRef is a `creds` ref (never a secret value).
type RegistryUpstream struct {
	Ecosystem          string `yaml:"ecosystem"`
	BaseURL            string `yaml:"base_url"`
	CredRef            string `yaml:"cred_ref,omitempty"`
	HeaderName         string `yaml:"header_name,omitempty"`
	HeaderFormat       string `yaml:"header_format,omitempty"`
	RequireAttestation bool   `yaml:"require_attestation,omitempty"`
}

// RegistryAllowEntry is one allowlisted package (config face of regproxy.AllowEntry).
type RegistryAllowEntry struct {
	Ecosystem string `yaml:"ecosystem"`
	Name      string `yaml:"name"`
}

// Enabled reports whether the registry proxy should be stood up: it is opt-in on
// the presence of at least one configured upstream.
func (r RegistryProxyConfig) Enabled() bool {
	return len(r.Upstreams) > 0
}

// EgressInjectRule is one F5.7 host→secret→header mapping. It holds NO secret —
// SecretRef is a `creds` REF resolved through the F5.6 broker at the network
// boundary; the token never appears in this config, the sandbox env, or the trace.
type EgressInjectRule struct {
	// Host is the exact egress host (no port) the rule injects for, e.g. "gitlab.com".
	Host string `yaml:"host"`
	// SecretRef is the `creds` ref the L7 proxy resolves for this host. It must be a
	// cred the session's resolved policy grants, or the rule is dropped fail-closed.
	SecretRef string `yaml:"secret_ref"`
	// HeaderName is the auth header the proxy sets on the forwarded upstream request,
	// e.g. "PRIVATE-TOKEN" or "Authorization".
	HeaderName string `yaml:"header_name"`
	// HeaderFormat is a single-%s template applied to the resolved secret, e.g.
	// "Bearer %s" or "%s". Empty => the raw secret is the header value.
	HeaderFormat string `yaml:"header_format,omitempty"`
}

// ValidateEgressInject checks every F5.7 egress-inject rule, FAILING CLOSED with a
// legible error naming the offending host/field. The daemon calls this at startup
// so a malformed rule aborts rather than silently serving a broken injection path.
func (c Config) ValidateEgressInject() error {
	seen := map[string]struct{}{}
	for i, r := range c.EgressInject {
		if r.Host == "" {
			return fmt.Errorf("install: egress_inject[%d]: host is required", i)
		}
		if strings.ContainsAny(r.Host, "/: ") {
			return fmt.Errorf("install: egress_inject[%d]: host %q must be a bare hostname (no scheme, port, or path)", i, r.Host)
		}
		host := strings.ToLower(r.Host)
		if _, dup := seen[host]; dup {
			return fmt.Errorf("install: egress_inject: duplicate host %q", r.Host)
		}
		seen[host] = struct{}{}
		if r.SecretRef == "" {
			return fmt.Errorf("install: egress_inject[%d] (%s): secret_ref is required", i, r.Host)
		}
		if r.HeaderName == "" {
			return fmt.Errorf("install: egress_inject[%d] (%s): header_name is required", i, r.Host)
		}
		if r.HeaderFormat != "" {
			if n := strings.Count(r.HeaderFormat, "%"); n != strings.Count(r.HeaderFormat, "%s") || n != 1 {
				return fmt.Errorf("install: egress_inject[%d] (%s): header_format %q must contain exactly one %%s and no other verbs", i, r.Host, r.HeaderFormat)
			}
		}
	}
	return nil
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

// ValidateOAuth2 checks every configured F5.4 OAuth2 service, FAILING CLOSED with
// a legible error that names the offending service and field. The daemon calls
// this at startup so a bad per-service config aborts rather than serving an
// unusable/insecure adapter.
func (c Config) ValidateOAuth2() error {
	for name, svc := range c.OAuth2 {
		if name == "" {
			return fmt.Errorf("install: oauth2 service has an empty name")
		}
		if err := svc.Validate(); err != nil {
			return fmt.Errorf("install: oauth2 service %q: %w", name, err)
		}
	}
	return nil
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
