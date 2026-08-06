package env

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ClosureSizeWarnBytes is the closure-size threshold above which Bake emits a
// warning via the WarnFunc hook (Nix closures can be fat — a known cost).
const ClosureSizeWarnBytes = 512 << 20 // 512 MiB

// NixEnvBuilder is the single EnvBuilder impl (D1). It orchestrates the
// injected collaborators (Composer, Baker, SBOMGenerator, Signer) and the
// Store, keeping its own logic pure and testable: identity derivation, hashing,
// content-address verification, and attestation persistence.
type NixEnvBuilder struct {
	composer Composer
	baker    Baker
	sbom     SBOMGenerator
	signer   Signer
	store    *Store

	// workRoot is where per-env manifests are written before realisation.
	workRoot string
	// WarnFunc receives non-fatal warnings (e.g. closure-size). Defaults to a
	// no-op; the CLI wires it to the operator console. Never receives secrets.
	WarnFunc func(string)
}

// Options configures a NixEnvBuilder. All fields are optional; sensible,
// non-root defaults are applied. The production Signer must be set explicitly
// via NewDefault or by passing Signer — there is no silent fallback to the
// local dev signer.
type Options struct {
	BaseDir  string // attestation/artifact root; defaults to DefaultBaseDir
	WorkRoot string // manifest work root; defaults to <BaseDir>/work
	Composer Composer
	Baker    Baker
	SBOM     SBOMGenerator
	Signer   Signer
	WarnFunc func(string)
}

// New builds a NixEnvBuilder from explicit Options. It returns an error if no
// Signer is provided — the signer is the trust root and must be a deliberate
// choice, never a default.
func New(opts Options) (*NixEnvBuilder, error) {
	if opts.Signer == nil {
		return nil, fmt.Errorf("env: a Signer is required (trust root must be explicit)")
	}
	store := NewStore(opts.BaseDir)
	workRoot := opts.WorkRoot
	if workRoot == "" {
		workRoot = filepath.Join(store.BaseDir, "work")
	}
	b := &NixEnvBuilder{
		composer: opts.Composer,
		baker:    opts.Baker,
		sbom:     opts.SBOM,
		signer:   opts.Signer,
		store:    store,
		workRoot: workRoot,
		WarnFunc: opts.WarnFunc,
	}
	if b.baker == nil {
		b.baker = tarBaker{}
	}
	if b.composer == nil {
		b.composer = devboxComposer{}
	}
	if b.sbom == nil {
		// Prefer syft when present; else the documented builtin fallback.
		if toolExists("syft") {
			b.sbom = syftSBOM{}
		} else {
			b.sbom = builtinSBOM{}
		}
	}
	if b.WarnFunc == nil {
		b.WarnFunc = func(string) {}
	}
	return b, nil
}

// NewDefault wires the production collaborators: devbox/nix Compose, tar Bake,
// syft SBOM, and cosign as the signing trust root. It requires cosign on PATH.
func NewDefault(baseDir string, cosignKey, cosignPubKey string) (*NixEnvBuilder, error) {
	if !toolExists("cosign") {
		return nil, fmt.Errorf("env: cosign not found on PATH (required trust root)")
	}
	return New(Options{
		BaseDir: baseDir,
		Signer:  cosignSigner{KeyRef: cosignKey, PubKeyRef: cosignPubKey},
	})
}

var _ EnvBuilder = (*NixEnvBuilder)(nil)

// Compose writes the manifest, realises the closure, and captures flake.lock +
// its hash. The env id is derived deterministically from the normalised
// selection so the same selection is reproducible and retrievable.
func (b *NixEnvBuilder) Compose(ctx context.Context, sel ToolSelection) (LockedEnv, error) {
	sel = normalizeSelection(sel)
	if len(sel.Tools) == 0 {
		return LockedEnv{}, ErrEmptySelection
	}
	envID, err := envIDFor(sel)
	if err != nil {
		return LockedEnv{}, fmt.Errorf("env: derive env id: %w", err)
	}
	workDir := filepath.Join(b.workRoot, envID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return LockedEnv{}, fmt.Errorf("env: create work dir: %w", err)
	}
	flakeLock, closurePath, err := b.composer.Realize(ctx, workDir, sel)
	if err != nil {
		return LockedEnv{}, fmt.Errorf("env: compose (realise closure): %w", err)
	}
	if len(flakeLock) == 0 {
		return LockedEnv{}, fmt.Errorf("env: compose produced empty flake.lock")
	}
	return LockedEnv{
		EnvID:         envID,
		FlakeLock:     flakeLock,
		FlakeLockHash: digestSHA256(flakeLock),
		ClosurePath:   closurePath,
		Selection:     sel,
	}, nil
}

// Bake packs the closure into a content-addressed layer, attaches an SBOM,
// signs the digest, and persists the attestation record.
func (b *NixEnvBuilder) Bake(ctx context.Context, locked LockedEnv) (SignedLayer, error) {
	if locked.EnvID == "" {
		return SignedLayer{}, fmt.Errorf("env: bake requires a composed LockedEnv (empty env id)")
	}
	layerBytes, err := b.baker.BuildLayer(ctx, locked.ClosurePath, locked.Selection)
	if err != nil {
		return SignedLayer{}, fmt.Errorf("env: bake (build layer): %w", err)
	}
	if len(layerBytes) > ClosureSizeWarnBytes {
		b.WarnFunc(fmt.Sprintf("env: toolchain layer for %s is %d bytes (> %d threshold)",
			locked.EnvID, len(layerBytes), ClosureSizeWarnBytes))
	}
	if _, err := b.store.putLayer(locked.EnvID, layerBytes); err != nil {
		return SignedLayer{}, err
	}
	digest := digestSHA256(layerBytes)

	sbomBytes, err := b.sbom.Generate(ctx, locked.ClosurePath, locked.Selection)
	if err != nil {
		return SignedLayer{}, fmt.Errorf("env: bake (sbom): %w", err)
	}
	sbomRef, err := b.store.putSBOM(locked.EnvID, sbomBytes)
	if err != nil {
		return SignedLayer{}, err
	}

	sig, err := b.signer.Sign(ctx, digest)
	if err != nil {
		return SignedLayer{}, fmt.Errorf("env: bake (sign): %w", err)
	}
	if len(sig) == 0 {
		return SignedLayer{}, fmt.Errorf("env: signer returned empty signature")
	}

	layer := SignedLayer{
		EnvID:       locked.EnvID,
		LayerDigest: digest,
		SBOMRef:     sbomRef,
		Signature:   sig,
	}
	if err := b.store.putAttestation(locked, layer); err != nil {
		return SignedLayer{}, err
	}
	return layer, nil
}

// Verify re-derives the layer's content digest from the stored bytes and checks
// it against the recorded digest (tamper detection), then verifies the
// signature over that digest. An unsigned layer or a flipped byte fails.
func (b *NixEnvBuilder) Verify(ctx context.Context, layer SignedLayer) error {
	if len(layer.Signature) == 0 {
		return ErrUnsignedLayer
	}
	stored, err := b.store.getLayer(layer.EnvID)
	if err != nil {
		return err
	}
	recomputed := digestSHA256(stored)
	if recomputed != layer.LayerDigest {
		return fmt.Errorf("%w: recorded=%s recomputed=%s", ErrDigestMismatch, layer.LayerDigest, recomputed)
	}
	if err := b.signer.VerifySignature(ctx, layer.LayerDigest, layer.Signature); err != nil {
		return err
	}
	return nil
}

// Store exposes the underlying attestation store (e.g. to retrieve a record by
// env_id). Read-only accessor; the builder owns writes.
func (b *NixEnvBuilder) Store() *Store { return b.store }
