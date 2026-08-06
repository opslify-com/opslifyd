package env

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// The external tools (devbox/nix, syft, cosign) sit behind these narrow
// interfaces so they can be faked in unit tests and gated in integration tests.
// Missing binaries never break the build — they surface as skipped integration
// tests or an explicit error at call time.

// Composer realises a Nix closure from a selection: it writes the manifest into
// workDir, invokes devbox/nix, and returns the flake.lock bytes plus the local
// closure path.
type Composer interface {
	Realize(ctx context.Context, workDir string, sel ToolSelection) (flakeLock []byte, closurePath string, err error)
}

// Baker packs a realised closure into a deterministic, content-addressed layer
// tarball. The default impl (tarBaker) is pure Go and needs no external tools.
type Baker interface {
	BuildLayer(ctx context.Context, closurePath string, sel ToolSelection) ([]byte, error)
}

// SBOMGenerator produces an SBOM document for a closure.
type SBOMGenerator interface {
	Generate(ctx context.Context, closurePath string, sel ToolSelection) ([]byte, error)
}

// Signer is the trust root for D1: it signs the layer digest and verifies that
// signature. The production impl is cosign (cosignSigner). Tests and offline
// dev use localEd25519Signer — which is explicitly NOT the production trust
// root and is never selected silently.
type Signer interface {
	Sign(ctx context.Context, digest string) ([]byte, error)
	VerifySignature(ctx context.Context, digest string, sig []byte) error
}

// ---------------------------------------------------------------------------
// Layer packing — deterministic tar + real OCI layer (go-containerregistry).
// ---------------------------------------------------------------------------

// deterministicClosureTar walks closurePath and emits a reproducible, ordered
// tar of the WHOLE tree: directories, regular files, AND symlinks (targets
// preserved). A Nix closure is a symlink farm, so dropping symlinks/dirs would
// produce a non-functional layer — all three entry kinds are packed. All
// entries are sorted and their mtime/uid/gid/uname/gname zeroed so the same
// closure always produces byte-identical tar output (content-addressing).
func deterministicClosureTar(closurePath string) ([]byte, error) {
	var paths []string
	err := filepath.WalkDir(closurePath, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("env: walk closure: %w", err)
	}
	sort.Strings(paths)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, p := range paths {
		rel, err := filepath.Rel(closurePath, p)
		if err != nil {
			return nil, fmt.Errorf("env: relpath: %w", err)
		}
		if rel == "." {
			continue // don't emit the root itself
		}
		name := filepath.ToSlash(rel)
		// Lstat so symlinks are described, never followed.
		info, err := os.Lstat(p)
		if err != nil {
			return nil, fmt.Errorf("env: lstat closure entry: %w", err)
		}
		hdr := &tar.Header{Name: name}
		switch {
		case info.IsDir():
			hdr.Typeflag = tar.TypeDir
			hdr.Name = name + "/"
			hdr.Mode = 0o555 // read-only, traversable
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return nil, fmt.Errorf("env: readlink: %w", err)
			}
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = filepath.ToSlash(target)
			hdr.Mode = 0o777
		case info.Mode().IsRegular():
			hdr.Typeflag = tar.TypeReg
			hdr.Mode = 0o444 // read-only toolchain
			hdr.Size = info.Size()
		default:
			// Skip sockets/devices/pipes: never valid in a toolchain layer.
			continue
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("env: tar header: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg {
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("env: read closure file: %w", err)
			}
			if _, err := tw.Write(data); err != nil {
				return nil, fmt.Errorf("env: tar write: %w", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("env: tar close: %w", err)
	}
	return buf.Bytes(), nil
}

// ociBaker assembles a real OCI layer with go-containerregistry
// (github.com/google/go-containerregistry, Apache-2.0 — the only external Go
// dep, chosen because it is the canonical OCI layer/image builder and lets us
// mount the toolchain onto a digest-pinned base). It returns the compressed
// layer blob bytes; the returned bytes' sha256 IS the OCI layer digest, so the
// builder's content-address (digestSHA256) matches the layer's own digest and
// Verify can re-derive it from stored bytes. gzip via stdlib zeroes its
// timestamp, so the blob is reproducible.
//
// When sel.BaseImageDigest is set (a full "repo@sha256:..." ref) the toolchain
// layer is appended onto that digest-pinned base, realising the chain of trust
// base(signed) -> toolchain(signed). An empty BaseImageDigest uses an empty
// base image (offline/unit path) and still yields a valid single-layer image.
type ociBaker struct{}

func (ociBaker) BuildLayer(ctx context.Context, closurePath string, sel ToolSelection) ([]byte, error) {
	tarBytes, err := deterministicClosureTar(closurePath)
	if err != nil {
		return nil, err
	}
	layer, err := tarball.LayerFromOpener(
		func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(tarBytes)), nil },
	)
	if err != nil {
		return nil, fmt.Errorf("env: build oci layer: %w", err)
	}

	// Assemble the image (base + toolchain) to realise and validate the OCI
	// chain of trust. The image is realised so a broken base ref fails here.
	base := empty.Image
	if d := normalizeSelection(sel).BaseImageDigest; d != "" {
		ref, err := name.NewDigest(d)
		if err != nil {
			return nil, fmt.Errorf("env: base image must be digest-pinned (repo@sha256:...): %w", err)
		}
		base, err = remote.Image(ref, remote.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("env: pull digest-pinned base: %w", err)
		}
	}
	img, err := mutate.AppendLayers(base, layer)
	if err != nil {
		return nil, fmt.Errorf("env: append toolchain layer: %w", err)
	}
	if _, err := img.Digest(); err != nil { // force realisation
		return nil, fmt.Errorf("env: realise oci image: %w", err)
	}

	// Return the compressed layer blob: its digest is the content-addressed
	// toolchain layer digest the sandbox mounts and the daemon verifies.
	rc, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("env: open layer blob: %w", err)
	}
	defer rc.Close()
	blob, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("env: read layer blob: %w", err)
	}
	return blob, nil
}

// ---------------------------------------------------------------------------
// builtinSBOM — minimal fallback SBOM from the declared selection.
// ---------------------------------------------------------------------------

// builtinSBOM emits a minimal SPDX-ish JSON listing the declared tools. It is a
// documented fallback for when syft is unavailable: it captures the declared
// tools but NOT their transitive dependencies. Production uses syftSBOM.
type builtinSBOM struct{}

func (builtinSBOM) Generate(_ context.Context, _ string, sel ToolSelection) ([]byte, error) {
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
	}
	doc := struct {
		Format          string `json:"format"`
		Note            string `json:"note"`
		BaseImageDigest string `json:"base_image_digest,omitempty"`
		Packages        []pkg  `json:"packages"`
	}{
		Format:          "opslify-builtin-sbom/v1",
		Note:            "declared tools only; transitive deps require syft",
		BaseImageDigest: sel.BaseImageDigest,
	}
	for _, t := range normalizeSelection(sel).Tools {
		doc.Packages = append(doc.Packages, pkg{Name: t.Name, Version: t.Version})
	}
	return json.MarshalIndent(doc, "", "  ")
}

// packageCount is a small helper kept for readability of SBOM assertions.
func packageCount(sel ToolSelection) int { return len(normalizeSelection(sel).Tools) }

// ---------------------------------------------------------------------------
// localEd25519Signer — dev/test signer. NOT the production trust root.
// ---------------------------------------------------------------------------

// localEd25519Signer signs digests with an in-process Ed25519 key. It exists so
// the full Bake/Verify flow is exercisable offline and in unit tests. It is
// never selected silently by the production constructor — callers pass it
// explicitly, acknowledging it is not cosign.
type localEd25519Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newLocalEd25519Signer() (*localEd25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("env: generate signing key: %w", err)
	}
	return &localEd25519Signer{priv: priv, pub: pub}, nil
}

func (s *localEd25519Signer) Sign(_ context.Context, digest string) ([]byte, error) {
	return ed25519.Sign(s.priv, []byte(digest)), nil
}

func (s *localEd25519Signer) VerifySignature(_ context.Context, digest string, sig []byte) error {
	if !ed25519.Verify(s.pub, []byte(digest), sig) {
		return ErrSignatureInvalid
	}
	return nil
}
