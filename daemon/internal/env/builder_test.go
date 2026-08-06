package env

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// fakeComposer realises a deterministic closure: one file per tool whose
// content depends only on the tool. Same selection -> identical closure bytes,
// which lets the real tarBaker prove digest reproducibility with no Nix.
type fakeComposer struct {
	flakeLock []byte
}

func (f fakeComposer) Realize(_ context.Context, workDir string, sel ToolSelection) ([]byte, string, error) {
	closure := filepath.Join(workDir, "closure")
	if err := os.MkdirAll(closure, 0o700); err != nil {
		return nil, "", err
	}
	for _, t := range normalizeSelection(sel).Tools {
		content := "bin:" + t.Name + "@" + t.Version
		if err := os.WriteFile(filepath.Join(closure, t.Name), []byte(content), 0o600); err != nil {
			return nil, "", err
		}
	}
	lock := f.flakeLock
	if lock == nil {
		// Fold the selection into the lock so different selections lock
		// differently (mirrors flake.lock resolving distinct versions).
		b, _ := canonicalJSON(normalizeSelection(sel))
		lock = append([]byte(`{"nodes":{"nixpkgs":{}},"sel":`), b...)
		lock = append(lock, '}')
	}
	return lock, closure, nil
}

func newTestBuilder(t *testing.T) (*NixEnvBuilder, *localEd25519Signer) {
	t.Helper()
	signer, err := newLocalEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	b, err := New(Options{
		BaseDir:  base,
		Composer: fakeComposer{},
		Signer:   signer, // explicit dev signer; not the production trust root
	})
	if err != nil {
		t.Fatal(err)
	}
	return b, signer
}

func TestNew_RequiresSigner(t *testing.T) {
	if _, err := New(Options{BaseDir: t.TempDir()}); err == nil {
		t.Fatal("expected error when no signer provided")
	}
}

func TestCompose_EmptySelection(t *testing.T) {
	b, _ := newTestBuilder(t)
	if _, err := b.Compose(context.Background(), ToolSelection{}); !errors.Is(err, ErrEmptySelection) {
		t.Fatalf("want ErrEmptySelection, got %v", err)
	}
}

// AC: Compose on {terraform,kubectl,jq} produces flake.lock + recorded hash.
func TestCompose_ProducesLockAndHash(t *testing.T) {
	b, _ := newTestBuilder(t)
	sel := ToolSelection{Tools: []Tool{{Name: "terraform"}, {Name: "kubectl"}, {Name: "jq"}}}
	locked, err := b.Compose(context.Background(), sel)
	if err != nil {
		t.Fatal(err)
	}
	if len(locked.FlakeLock) == 0 {
		t.Fatal("empty flake.lock")
	}
	if locked.FlakeLockHash != digestSHA256(locked.FlakeLock) {
		t.Fatal("flake lock hash does not match content")
	}
	if len(locked.Selection.Tools) != 3 {
		t.Fatalf("selection not carried: %+v", locked.Selection)
	}
}

// AC: Bake produces a signed, digest-pinned layer with an attached SBOM;
// attestation persisted and retrievable by env_id.
func TestBake_SignsAndPersistsAttestation(t *testing.T) {
	b, _ := newTestBuilder(t)
	sel := ToolSelection{Tools: []Tool{{Name: "terraform"}, {Name: "kubectl"}, {Name: "jq"}}}
	locked, err := b.Compose(context.Background(), sel)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := b.Bake(context.Background(), locked)
	if err != nil {
		t.Fatal(err)
	}
	if layer.LayerDigest == "" || len(layer.Signature) == 0 {
		t.Fatalf("unsigned or undigested layer: %+v", layer)
	}
	if layer.SBOMRef == "" {
		t.Fatal("no SBOM ref")
	}
	if _, err := os.Stat(layer.SBOMRef); err != nil {
		t.Fatalf("SBOM not written: %v", err)
	}
	rec, err := b.Store().GetAttestation(locked.EnvID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.LayerDigest != layer.LayerDigest || rec.FlakeLockHash != locked.FlakeLockHash {
		t.Fatalf("attestation mismatch: %+v", rec)
	}
	if rec.SchemaVersion != AttestationSchemaVersion {
		t.Fatalf("schema version = %q", rec.SchemaVersion)
	}
}

// AC: Verify returns error for a tampered layer and success for an intact one.
// QA: tampered layer fails; unsigned layer fails.
func TestVerify_IntactTamperedUnsigned(t *testing.T) {
	b, _ := newTestBuilder(t)
	sel := ToolSelection{Tools: []Tool{{Name: "jq"}}}
	locked, err := b.Compose(context.Background(), sel)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := b.Bake(context.Background(), locked)
	if err != nil {
		t.Fatal(err)
	}

	// Intact -> success.
	if err := b.Verify(context.Background(), layer); err != nil {
		t.Fatalf("intact layer failed verify: %v", err)
	}

	// Unsigned -> ErrUnsignedLayer.
	unsigned := layer
	unsigned.Signature = nil
	if err := b.Verify(context.Background(), unsigned); !errors.Is(err, ErrUnsignedLayer) {
		t.Fatalf("want ErrUnsignedLayer, got %v", err)
	}

	// Tampered: flip a byte in the stored layer file.
	lp := b.Store().layerPath(layer.EnvID)
	raw, err := os.ReadFile(lp)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xFF
	if err := os.WriteFile(lp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(context.Background(), layer); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch on tampered layer, got %v", err)
	}
}

// A signature over a different digest must fail verification.
func TestVerify_WrongSignature(t *testing.T) {
	b, signer := newTestBuilder(t)
	locked, err := b.Compose(context.Background(), ToolSelection{Tools: []Tool{{Name: "jq"}}})
	if err != nil {
		t.Fatal(err)
	}
	layer, err := b.Bake(context.Background(), locked)
	if err != nil {
		t.Fatal(err)
	}
	badSig, _ := signer.Sign(context.Background(), "sha256:deadbeef")
	layer.Signature = badSig
	if err := b.Verify(context.Background(), layer); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("want ErrSignatureInvalid, got %v", err)
	}
}

// AC: Same ToolSelection run twice yields the same layer_digest.
func TestBake_Reproducible(t *testing.T) {
	sel := ToolSelection{Tools: []Tool{{Name: "terraform"}, {Name: "kubectl"}, {Name: "jq"}}}
	digest := func() string {
		b, _ := newTestBuilder(t)
		locked, err := b.Compose(context.Background(), sel)
		if err != nil {
			t.Fatal(err)
		}
		layer, err := b.Bake(context.Background(), locked)
		if err != nil {
			t.Fatal(err)
		}
		return layer.LayerDigest
	}
	if d1, d2 := digest(), digest(); d1 != d2 {
		t.Fatalf("non-reproducible digest: %s vs %s", d1, d2)
	}
}

// AC: Two different selections yield different digests and different closures.
func TestBake_DistinctSelectionsDistinctDigests(t *testing.T) {
	bake := func(sel ToolSelection) (string, string) {
		b, _ := newTestBuilder(t)
		locked, err := b.Compose(context.Background(), sel)
		if err != nil {
			t.Fatal(err)
		}
		layer, err := b.Bake(context.Background(), locked)
		if err != nil {
			t.Fatal(err)
		}
		return layer.LayerDigest, locked.EnvID
	}
	d1, id1 := bake(ToolSelection{Tools: []Tool{{Name: "jq"}}})
	d2, id2 := bake(ToolSelection{Tools: []Tool{{Name: "jq"}, {Name: "kubectl"}}})
	if d1 == d2 {
		t.Fatalf("distinct selections shared a digest: %s", d1)
	}
	if id1 == id2 {
		t.Fatalf("distinct selections shared an env id: %s", id1)
	}
}

// QA: SBOM lists exactly the declared tools (builtin fallback path).
func TestBuiltinSBOM_ListsDeclaredTools(t *testing.T) {
	sel := ToolSelection{Tools: []Tool{{Name: "terraform"}, {Name: "kubectl"}, {Name: "jq"}}}
	if got := packageCount(sel); got != 3 {
		t.Fatalf("package count = %d, want 3", got)
	}
	doc, err := builtinSBOM{}.Generate(context.Background(), "", sel)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"terraform", "kubectl", "jq"} {
		if !contains(doc, name) {
			t.Fatalf("SBOM missing declared tool %q: %s", name, doc)
		}
	}
}

func contains(hay []byte, needle string) bool {
	return len(hay) >= len(needle) && (indexOf(hay, needle) >= 0)
}

func indexOf(hay []byte, needle string) int {
	n := []byte(needle)
outer:
	for i := 0; i+len(n) <= len(hay); i++ {
		for j := range n {
			if hay[i+j] != n[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

// ociBaker determinism at the packer level, independent of the builder.
func TestOCIBaker_Deterministic(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a"), []byte("aaa"), 0o600)
	os.WriteFile(filepath.Join(dir, "b"), []byte("bbb"), 0o600)
	l1, err := ociBaker{}.BuildLayer(context.Background(), dir, ToolSelection{})
	if err != nil {
		t.Fatal(err)
	}
	l2, err := ociBaker{}.BuildLayer(context.Background(), dir, ToolSelection{})
	if err != nil {
		t.Fatal(err)
	}
	if digestSHA256(l1) != digestSHA256(l2) {
		t.Fatal("oci layer not deterministic")
	}
}

// A Nix closure is a symlink farm: the layer MUST contain directories and
// symlinks (targets preserved), not just regular files — and stay reproducible.
func TestClosureTar_IncludesDirsAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	// nested dir + regular file
	nested := filepath.Join(dir, "nix", "store", "abc-jq", "bin")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	realBin := filepath.Join(nested, "jq")
	if err := os.WriteFile(realBin, []byte("ELF-ish"), 0o755); err != nil {
		t.Fatal(err)
	}
	// symlink farm entry: /bin/jq -> ../nix/store/abc-jq/bin/jq
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	linkTarget := "../nix/store/abc-jq/bin/jq"
	if err := os.Symlink(linkTarget, filepath.Join(binDir, "jq")); err != nil {
		t.Fatal(err)
	}

	tarBytes, err := deterministicClosureTar(dir)
	if err != nil {
		t.Fatal(err)
	}

	names := map[string]*tar.Header{}
	tr := tar.NewReader(bytes.NewReader(tarBytes))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names[hdr.Name] = hdr
	}
	// directory present
	if h, ok := names["nix/"]; !ok || h.Typeflag != tar.TypeDir {
		t.Fatalf("directory 'nix/' missing or not a dir: %+v", names)
	}
	if h, ok := names["nix/store/abc-jq/bin/"]; !ok || h.Typeflag != tar.TypeDir {
		t.Fatal("nested directory missing")
	}
	// symlink present with target preserved
	link, ok := names["bin/jq"]
	if !ok {
		t.Fatalf("symlink 'bin/jq' missing; entries: %v", keysOf(names))
	}
	if link.Typeflag != tar.TypeSymlink || link.Linkname != linkTarget {
		t.Fatalf("symlink not preserved: type=%d target=%q", link.Typeflag, link.Linkname)
	}
	// regular file present
	if h, ok := names["nix/store/abc-jq/bin/jq"]; !ok || h.Typeflag != tar.TypeReg {
		t.Fatal("regular file missing")
	}
	// reproducible across two runs
	again, err := deterministicClosureTar(dir)
	if err != nil {
		t.Fatal(err)
	}
	if digestSHA256(tarBytes) != digestSHA256(again) {
		t.Fatal("closure tar not reproducible across runs")
	}
}

func keysOf(m map[string]*tar.Header) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
