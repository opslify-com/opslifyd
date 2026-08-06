package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/opslify-com/opslifyd/internal/env"
)

// fakeBuilder is a minimal EnvBuilder that only exercises Verify. Compose/Bake
// are unused by the verify-before-serve seam.
type fakeBuilder struct {
	verifyErr error
	gotLayer  env.SignedLayer
}

func (f *fakeBuilder) Compose(context.Context, env.ToolSelection) (env.LockedEnv, error) {
	return env.LockedEnv{}, errors.New("unused")
}
func (f *fakeBuilder) Bake(context.Context, env.LockedEnv) (env.SignedLayer, error) {
	return env.SignedLayer{}, errors.New("unused")
}
func (f *fakeBuilder) Verify(_ context.Context, l env.SignedLayer) error {
	f.gotLayer = l
	return f.verifyErr
}

func TestEnvVerifierPass(t *testing.T) {
	fb := &fakeBuilder{}
	layer := env.SignedLayer{EnvID: "e1", LayerDigest: "sha256:abc", Signature: []byte("sig")}
	v := NewEnvVerifier(fb, layer)
	if err := v.VerifyToolchain(context.Background()); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
	if fb.gotLayer.LayerDigest != "sha256:abc" {
		t.Fatalf("builder received wrong layer: %+v", fb.gotLayer)
	}
}

func TestEnvVerifierRefusesUnsigned(t *testing.T) {
	fb := &fakeBuilder{verifyErr: env.ErrUnsignedLayer}
	v := NewEnvVerifier(fb, env.SignedLayer{LayerDigest: "sha256:x"})
	err := v.VerifyToolchain(context.Background())
	if !errors.Is(err, env.ErrUnsignedLayer) {
		t.Fatalf("expected ErrUnsignedLayer wrapped, got %v", err)
	}
}

func TestEnvVerifierRefusesTamper(t *testing.T) {
	fb := &fakeBuilder{verifyErr: env.ErrDigestMismatch}
	v := NewEnvVerifier(fb, env.SignedLayer{LayerDigest: "sha256:x"})
	if err := v.VerifyToolchain(context.Background()); !errors.Is(err, env.ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch wrapped, got %v", err)
	}
}

func TestDenyVerifier(t *testing.T) {
	v := DenyVerifier("no toolchain configured")
	if err := v.VerifyToolchain(context.Background()); err == nil {
		t.Fatal("DenyVerifier must always refuse")
	}
}
