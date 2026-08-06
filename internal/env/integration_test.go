package env

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestIntegration_ComposeBakeVerify exercises the real devbox/nix Compose path
// against actual binaries. It is gated: it skips (never fails) unless the tools
// exist AND OPSLIFY_INTEGRATION=1 is set, because it needs build-time network
// access to resolve nixpkgs. This proves AC-1 (real flake.lock) end to end.
func TestIntegration_ComposeBakeVerify(t *testing.T) {
	if os.Getenv("OPSLIFY_INTEGRATION") != "1" {
		t.Skip("set OPSLIFY_INTEGRATION=1 to run (needs build-time network)")
	}
	for _, bin := range []string{"devbox", "nix"} {
		if !toolExists(bin) {
			t.Skipf("required binary %q not on PATH", bin)
		}
	}

	signer, err := newLocalEd25519Signer() // real cosign gated separately below
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Options{
		BaseDir:  t.TempDir(),
		Signer:   signer,
		Composer: devboxComposer{},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sel := ToolSelection{Tools: []Tool{{Name: "jq"}}}
	locked, err := b.Compose(ctx, sel)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if len(locked.FlakeLock) == 0 || locked.FlakeLockHash == "" {
		t.Fatal("no flake.lock produced")
	}
	layer, err := b.Bake(ctx, locked)
	if err != nil {
		t.Fatalf("Bake: %v", err)
	}
	if err := b.Verify(ctx, layer); err != nil {
		t.Fatalf("Verify intact: %v", err)
	}
}

// TestIntegration_Cosign exercises the real cosign sign/verify round trip when
// cosign is present and a keypair is provided via env. Gated and skipping.
func TestIntegration_Cosign(t *testing.T) {
	if os.Getenv("OPSLIFY_INTEGRATION") != "1" {
		t.Skip("set OPSLIFY_INTEGRATION=1 to run")
	}
	if !toolExists("cosign") {
		t.Skip("cosign not on PATH")
	}
	key := os.Getenv("OPSLIFY_COSIGN_KEY")
	pub := os.Getenv("OPSLIFY_COSIGN_PUBKEY")
	if key == "" || pub == "" {
		t.Skip("set OPSLIFY_COSIGN_KEY and OPSLIFY_COSIGN_PUBKEY (test keys only)")
	}
	s := cosignSigner{KeyRef: key, PubKeyRef: pub}
	digest := digestSHA256([]byte("integration-digest"))
	sig, err := s.Sign(context.Background(), digest)
	if err != nil {
		t.Fatalf("cosign sign: %v", err)
	}
	if err := s.VerifySignature(context.Background(), digest, sig); err != nil {
		t.Fatalf("cosign verify: %v", err)
	}
}
