package env

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// integrationSigner returns the real cosign signer when test keys are provided
// (CI path), else the offline dev signer. Keys are test-only, never real.
func integrationSigner(t *testing.T) Signer {
	t.Helper()
	key, pub := os.Getenv("OPSLIFY_COSIGN_KEY"), os.Getenv("OPSLIFY_COSIGN_PUBKEY")
	if key != "" && pub != "" && toolExists("cosign") {
		return cosignSigner{KeyRef: key, PubKeyRef: pub}
	}
	s, err := newLocalEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func integrationBuilder(t *testing.T) *NixEnvBuilder {
	t.Helper()
	b, err := New(Options{
		BaseDir:  t.TempDir(),
		Signer:   integrationSigner(t),
		Composer: devboxComposer{},
		// Baker/SBOM left as defaults: ociBaker + syft (when present).
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func requireIntegration(t *testing.T, bins ...string) {
	t.Helper()
	if os.Getenv("OPSLIFY_INTEGRATION") != "1" {
		t.Skip("set OPSLIFY_INTEGRATION=1 to run (needs build-time network + tools)")
	}
	for _, bin := range bins {
		if !toolExists(bin) {
			t.Skipf("required binary %q not on PATH", bin)
		}
	}
}

// AC1 (real): Compose on {terraform,kubectl,jq} produces a real flake.lock and
// recorded hash, and the closure actually resolves all three binaries.
// AC2 (real): Bake produces a real cosign-signed (when keys present), OCI layer
// with a syft SBOM; Verify passes on the intact layer.
func TestIntegration_ComposeBakeVerify(t *testing.T) {
	requireIntegration(t, "devbox", "nix")
	b := integrationBuilder(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Optional digest-pinned base for the OCI chain of trust (CI provides it).
	sel := ToolSelection{
		Tools:           []Tool{{Name: "terraform"}, {Name: "kubectl"}, {Name: "jq"}},
		BaseImageDigest: os.Getenv("OPSLIFY_BASE_IMAGE"), // "repo@sha256:..." or empty
	}

	locked, err := b.Compose(ctx, sel)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if len(locked.FlakeLock) == 0 || locked.FlakeLockHash == "" {
		t.Fatal("no flake.lock / hash produced")
	}
	// The realised closure must actually contain all three tools.
	for _, tool := range []string{"terraform", "kubectl", "jq"} {
		if _, err := os.Stat(filepath.Join(locked.ClosurePath, "bin", tool)); err != nil {
			t.Fatalf("closure missing resolved tool %q: %v", tool, err)
		}
	}

	layer, err := b.Bake(ctx, locked)
	if err != nil {
		t.Fatalf("Bake: %v", err)
	}
	if err := b.Verify(ctx, layer); err != nil {
		t.Fatalf("Verify intact: %v", err)
	}

	// SBOM (syft) must list the declared tools + their transitive deps.
	if toolExists("syft") {
		sbom, err := os.ReadFile(layer.SBOMRef)
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range []string{"terraform", "kubectl", "jq"} {
			if !bytes.Contains(sbom, []byte(tool)) {
				t.Fatalf("syft SBOM missing declared tool %q", tool)
			}
		}
	}
}

// AC4/AC5 (real): same selection -> same layer digest across two clean nix
// builds; a different selection -> a different digest and a different closure.
func TestIntegration_ReproducibleAndDistinct(t *testing.T) {
	requireIntegration(t, "devbox", "nix")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	bake := func(sel ToolSelection) SignedLayer {
		b := integrationBuilder(t)
		locked, err := b.Compose(ctx, sel)
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}
		layer, err := b.Bake(ctx, locked)
		if err != nil {
			t.Fatalf("Bake: %v", err)
		}
		return layer
	}

	selA := ToolSelection{Tools: []Tool{{Name: "jq"}}}
	selB := ToolSelection{Tools: []Tool{{Name: "jq"}, {Name: "kubectl"}}}

	a1 := bake(selA)
	a2 := bake(selA)
	if a1.LayerDigest != a2.LayerDigest {
		t.Fatalf("AC4: non-reproducible digest across clean runs: %s vs %s", a1.LayerDigest, a2.LayerDigest)
	}
	b1 := bake(selB)
	if a1.LayerDigest == b1.LayerDigest {
		t.Fatalf("AC5: distinct selections shared a layer digest: %s", a1.LayerDigest)
	}
}

// Real cosign sign/verify round trip (CI). Gated on keys + binary.
func TestIntegration_Cosign(t *testing.T) {
	requireIntegration(t, "cosign")
	key, pub := os.Getenv("OPSLIFY_COSIGN_KEY"), os.Getenv("OPSLIFY_COSIGN_PUBKEY")
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
	// Tamper: a signature over a different digest must fail.
	if err := s.VerifySignature(context.Background(), digestSHA256([]byte("other")), sig); err == nil {
		t.Fatal("cosign verified a signature over the wrong digest")
	}
}
