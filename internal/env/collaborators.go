package env

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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
// tarBaker — pure-Go, deterministic, content-addressed layer packer.
// ---------------------------------------------------------------------------

// tarBaker walks closurePath and emits a deterministic tar (entries sorted,
// mtimes/uids/gids zeroed) so the same closure always hashes to the same
// digest. Uncompressed tar is used deliberately: gzip embeds a timestamp/OS
// byte that would break content-addressing. P1 swaps this for a full
// go-containerregistry OCI layer; the content-addressing contract is identical.
type tarBaker struct{}

func (tarBaker) BuildLayer(_ context.Context, closurePath string, _ ToolSelection) ([]byte, error) {
	var files []string
	err := filepath.WalkDir(closurePath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("env: walk closure: %w", err)
	}
	sort.Strings(files)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, p := range files {
		rel, err := filepath.Rel(closurePath, p)
		if err != nil {
			return nil, fmt.Errorf("env: relpath: %w", err)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("env: read closure file: %w", err)
		}
		hdr := &tar.Header{
			Name: filepath.ToSlash(rel),
			Mode: 0o444, // read-only toolchain
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("env: tar header: %w", err)
		}
		if _, err := tw.Write(data); err != nil {
			return nil, fmt.Errorf("env: tar write: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("env: tar close: %w", err)
	}
	return buf.Bytes(), nil
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
