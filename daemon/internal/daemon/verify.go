package daemon

import (
	"context"
	"fmt"

	"github.com/opslify-com/opslifyd/internal/env"
)

// ToolchainVerifier is the verify-before-serve seam (F1.1). The daemon calls it
// exactly once at startup and refuses to serve if it returns an error — an
// unsigned or digest-mismatched toolchain is non-negotiable (D1). It is an
// interface so tests can exercise pass/fail without cosign or nix, and so the
// production adapter (env.EnvBuilder.Verify) stays injectable.
type ToolchainVerifier interface {
	// VerifyToolchain returns nil only if the configured toolchain layer is
	// present, signed, and its content digest matches. Any error is a legible,
	// layer-tagged refusal reason.
	VerifyToolchain(ctx context.Context) error
}

// VerifierFunc adapts a plain function to ToolchainVerifier (used by tests and
// by callers wiring a closed-over environment).
type VerifierFunc func(ctx context.Context) error

// VerifyToolchain implements ToolchainVerifier.
func (f VerifierFunc) VerifyToolchain(ctx context.Context) error { return f(ctx) }

// envVerifier is the production adapter: it re-checks a specific SignedLayer via
// F0.2's EnvBuilder.Verify (which re-derives the content digest from stored
// bytes and checks the signature). It reuses F0.2 wholesale — no verification
// logic is duplicated here.
type envVerifier struct {
	builder env.EnvBuilder
	layer   env.SignedLayer
}

// NewEnvVerifier wraps an EnvBuilder + the SignedLayer the daemon must verify
// before serving. The builder carries the trust root (cosign signer); the layer
// is resolved from the daemon config's toolchain digest at startup.
func NewEnvVerifier(builder env.EnvBuilder, layer env.SignedLayer) ToolchainVerifier {
	return envVerifier{builder: builder, layer: layer}
}

// VerifyToolchain delegates to the F0.2 verifier.
func (v envVerifier) VerifyToolchain(ctx context.Context) error {
	if err := v.builder.Verify(ctx, v.layer); err != nil {
		return fmt.Errorf("daemon: verify-before-serve refused toolchain %s: %w", v.layer.LayerDigest, err)
	}
	return nil
}

// DenyVerifier is a fail-closed verifier: it always refuses with the given
// reason. The daemon wires it when no signed toolchain is configured, so the
// default posture is refusal rather than silently serving an unverified
// toolchain.
func DenyVerifier(reason string) ToolchainVerifier {
	return VerifierFunc(func(context.Context) error {
		return fmt.Errorf("daemon: verify-before-serve refused: %s", reason)
	})
}
