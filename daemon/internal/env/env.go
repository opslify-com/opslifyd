// Package env implements F0.2 — the Nix/devbox build-time environment composer
// (decision D1). It turns a declared tool selection into a reproducible,
// content-addressed, cosign-signed, read-only toolchain layer that a sandbox
// later mounts. No tool is ever installed inside a live sandbox: all resolution
// happens here, at build time, and the resulting signed digest is the trust
// root the daemon verifies before use.
package env

import (
	"context"
	"errors"
)

// Tool is a single declared tool, optionally pinned to a version. When Version
// is empty the composer lets the pinned nixpkgs input decide (the flake.lock
// still records the exact resolved version + hash).
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// ToolSelection is the declared toolchain for one environment.
type ToolSelection struct {
	Tools []Tool `json:"tools"`
	// BaseImageDigest is the digest-pinned base image the toolchain layer is
	// mounted over. It is folded into the environment identity and the
	// attestation so the chain of trust reaches the base rootfs.
	BaseImageDigest string `json:"base_image_digest,omitempty"`
}

// LockedEnv is the output of Compose: a fully resolved, locked environment.
type LockedEnv struct {
	EnvID string `json:"env_id"`
	// FlakeLock is the raw flake.lock bytes. It fully resolves versions+hashes
	// and becomes part of the audit attestation.
	FlakeLock []byte `json:"-"`
	// FlakeLockHash is the "sha256:<hex>" digest of FlakeLock.
	FlakeLockHash string `json:"flake_lock_hash"`
	// ClosurePath is the local path to the realised Nix closure (the store
	// paths that Bake packs into the read-only layer).
	ClosurePath string `json:"closure_path"`
	// Selection is the normalised selection this env was built from.
	Selection ToolSelection `json:"tool_selection"`
}

// SignedLayer is the output of Bake: a content-addressed, signed OCI layer.
type SignedLayer struct {
	EnvID string `json:"env_id"`
	// LayerDigest is the "sha256:<hex>" content digest of the layer tarball.
	LayerDigest string `json:"layer_digest"`
	// SBOMRef points at the persisted SBOM document (path/ref).
	SBOMRef string `json:"sbom_ref"`
	// Signature is the signature over LayerDigest produced by the Signer. An
	// empty Signature means "unsigned" and MUST fail Verify.
	Signature []byte `json:"signature"`
}

// Attestation is the record persisted per built environment
// (default /var/lib/opslify/envs/<env_id>.json). It feeds the P3 trace and P6
// compliance packs. It deliberately contains no secrets.
type Attestation struct {
	SchemaVersion string        `json:"schema_version"`
	EnvID         string        `json:"env_id"`
	ToolSelection ToolSelection `json:"tool_selection"`
	FlakeLockHash string        `json:"flake_lock_hash"`
	LayerDigest   string        `json:"layer_digest"`
	SBOMRef       string        `json:"sbom_ref"`
	// Signature is the base64-encoded signature over LayerDigest.
	Signature string `json:"signature"`
	CreatedAt string `json:"created_at"`
}

// AttestationSchemaVersion versions the persisted attestation record so P3/P6
// can migrate. Bump on any breaking change to Attestation.
const AttestationSchemaVersion = "v1"

// EnvBuilder is the D1 shared interface (architecture.md §6). Single impl:
// NixEnvBuilder. Do not bypass it; extend via new impls.
type EnvBuilder interface {
	// Compose writes the devbox/flake manifest from the selection, realises the
	// closure via Nix, and captures flake.lock + its hash.
	Compose(ctx context.Context, sel ToolSelection) (LockedEnv, error)
	// Bake exports the closure as a content-addressed OCI layer, attaches an
	// SBOM, cosign-signs the digest, and persists the attestation.
	Bake(ctx context.Context, locked LockedEnv) (SignedLayer, error)
	// Verify re-derives the layer digest from stored content and verifies the
	// signature. It MUST fail on a tampered or unsigned layer.
	Verify(ctx context.Context, layer SignedLayer) error
}

// Sentinel errors. All builder errors are wrapped with the "env:" layer prefix
// (failure legibility: the operator always learns which layer failed).
var (
	// ErrEmptySelection is returned when a ToolSelection declares no tools.
	ErrEmptySelection = errors.New("env: tool selection is empty")
	// ErrUnsignedLayer is returned by Verify for a layer with no signature.
	ErrUnsignedLayer = errors.New("env: layer is unsigned")
	// ErrDigestMismatch is returned by Verify when the recomputed content
	// digest does not match the recorded layer digest (tamper).
	ErrDigestMismatch = errors.New("env: layer digest mismatch (tampered content)")
	// ErrSignatureInvalid is returned when signature verification fails.
	ErrSignatureInvalid = errors.New("env: signature verification failed")
	// ErrLayerNotFound is returned when the stored layer bytes are missing.
	ErrLayerNotFound = errors.New("env: stored layer content not found")
)
