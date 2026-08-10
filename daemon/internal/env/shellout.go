package env

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// runCommand runs an external tool and returns stdout. stderr is folded into
// the error (never into logs) so failures name the failing binary without
// leaking anything into a log sink. No secrets are ever passed as args here.
func runCommand(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("env: %s failed: %w: %s", name, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// toolExists reports whether a binary is on PATH.
func toolExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// ---------------------------------------------------------------------------
// devboxComposer — real Compose via devbox/nix.
// ---------------------------------------------------------------------------

// devboxComposer writes a devbox.json from the selection, runs `devbox install`
// to realise the closure, and reads the generated lock. Requires network at
// build time (never at run time) — hence it is exercised only by gated
// integration tests.
type devboxComposer struct{}

func (devboxComposer) Realize(ctx context.Context, workDir string, sel ToolSelection) ([]byte, string, error) {
	manifest, err := devboxManifest(sel)
	if err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(filepath.Join(workDir, "devbox.json"), manifest, 0o600); err != nil {
		return nil, "", fmt.Errorf("env: write devbox.json: %w", err)
	}
	if _, err := runCommand(ctx, workDir, "devbox", "install"); err != nil {
		return nil, "", err
	}
	// devbox generates devbox.lock (and a flake under .devbox). Prefer the
	// flake.lock if present, else fall back to devbox.lock — both fully resolve
	// versions+hashes for the attestation.
	for _, cand := range []string{
		filepath.Join(workDir, ".devbox", "gen", "flake", "flake.lock"),
		filepath.Join(workDir, "devbox.lock"),
	} {
		if b, err := os.ReadFile(cand); err == nil {
			profile := filepath.Join(workDir, ".devbox", "nix", "profile", "default")
			return b, profile, nil
		}
	}
	return nil, "", fmt.Errorf("env: no lock file produced by devbox in %s", workDir)
}

// devboxManifest renders a devbox.json from a selection. Tool "name@version"
// syntax pins the version when provided.
func devboxManifest(sel ToolSelection) ([]byte, error) {
	sel = normalizeSelection(sel)
	pkgs := make([]string, 0, len(sel.Tools))
	for _, t := range sel.Tools {
		if t.Version != "" {
			pkgs = append(pkgs, t.Name+"@"+t.Version)
		} else {
			pkgs = append(pkgs, t.Name+"@latest")
		}
	}
	doc := map[string]any{"packages": pkgs}
	return json.MarshalIndent(doc, "", "  ")
}

// ---------------------------------------------------------------------------
// syftSBOM — real SBOM via syft (transitive deps included).
// ---------------------------------------------------------------------------

type syftSBOM struct{}

func (syftSBOM) Generate(ctx context.Context, closurePath string, _ ToolSelection) ([]byte, error) {
	return runCommand(ctx, "", "syft", "scan", "dir:"+closurePath, "-o", "spdx-json")
}

// ---------------------------------------------------------------------------
// cosignSigner — production trust root (D1). Keyless/key modes per deployment.
// ---------------------------------------------------------------------------

// cosignSigner shells out to cosign to sign and verify the layer digest. It is
// the trust root: the daemon refuses layers this cannot verify. Key material is
// referenced by path/OIDC per shared-engineering.md §5 and never logged.
type cosignSigner struct {
	// KeyRef is a cosign key reference (e.g. "cosign.key", KMS URI). Empty uses
	// keyless/OIDC signing. Never inline a private key here.
	KeyRef string
	// PubKeyRef is the verification key reference.
	PubKeyRef string
}

// cosign contract note (verified against cosign GitVersion v3.1.1, the version
// resolved from current nixpkgs). cosign 3.x flipped sign-blob's defaults so
// that verification material is emitted as a Sigstore bundle: --use-signing-config
// now defaults to true and *requires* --bundle, so the old
// `sign-blob --yes [--key K] <file>` (which streamed a bare base64 signature to
// stdout and paired with `verify-blob --signature <sig> ...`) now aborts with
// "must specify --bundle with --new-bundle-format". The signature artifact is
// therefore the *bundle file*, not a bare signature.
//
// We do offline, key-based (not keyless/OIDC) signing, so we opt out of the TUF
// signing-config lookup (--use-signing-config=false) and the Rekor transparency
// log (--tlog-upload=false on sign, --insecure-ignore-tlog on verify) — both
// would require network and neither is our trust root here; the key is. The
// bundle binds the signed payload (our digest string) internally, so verify
// fails on a tampered digest or a tampered/wrong bundle exactly as before.
//
//   sign:   cosign sign-blob --yes [--key K] --bundle <bundle> \
//                            --use-signing-config=false --tlog-upload=false <blob>
//   verify: cosign verify-blob [--key P] --bundle <bundle> \
//                              --insecure-ignore-tlog <blob>

func (c cosignSigner) Sign(ctx context.Context, digest string) ([]byte, error) {
	args := []string{"sign-blob", "--yes", "--use-signing-config=false", "--tlog-upload=false"}
	if c.KeyRef != "" {
		args = append(args, "--key", c.KeyRef)
	}
	// cosign sign-blob reads the payload from a file/stdin; we sign the digest
	// string written to a temp file so nothing sensitive hits argv.
	f, err := os.CreateTemp("", "opslify-digest-*")
	if err != nil {
		return nil, fmt.Errorf("env: temp digest file: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(digest); err != nil {
		f.Close()
		return nil, fmt.Errorf("env: write digest: %w", err)
	}
	f.Close()

	// The Sigstore bundle (signature + verification material) is written to this
	// file; its bytes are the opaque signature artifact returned to the caller.
	bundle, err := os.CreateTemp("", "opslify-bundle-*")
	if err != nil {
		return nil, fmt.Errorf("env: temp bundle file: %w", err)
	}
	bundlePath := bundle.Name()
	bundle.Close()
	defer os.Remove(bundlePath)

	args = append(args, "--bundle", bundlePath, f.Name())
	if _, err := runCommand(ctx, "", "cosign", args...); err != nil {
		return nil, err
	}
	return os.ReadFile(bundlePath)
}

func (c cosignSigner) VerifySignature(ctx context.Context, digest string, sig []byte) error {
	if len(sig) == 0 {
		return ErrUnsignedLayer
	}
	// sig is the Sigstore bundle produced by Sign; write it back to a file.
	bundleFile, err := os.CreateTemp("", "opslify-bundle-*")
	if err != nil {
		return fmt.Errorf("env: temp bundle file: %w", err)
	}
	defer os.Remove(bundleFile.Name())
	if _, err := bundleFile.Write(sig); err != nil {
		bundleFile.Close()
		return fmt.Errorf("env: write bundle: %w", err)
	}
	bundleFile.Close()

	digestFile, err := os.CreateTemp("", "opslify-digest-*")
	if err != nil {
		return fmt.Errorf("env: temp digest file: %w", err)
	}
	defer os.Remove(digestFile.Name())
	if _, err := digestFile.WriteString(digest); err != nil {
		digestFile.Close()
		return fmt.Errorf("env: write digest: %w", err)
	}
	digestFile.Close()

	args := []string{"verify-blob", "--bundle", bundleFile.Name(), "--insecure-ignore-tlog"}
	if c.PubKeyRef != "" {
		args = append(args, "--key", c.PubKeyRef)
	}
	args = append(args, digestFile.Name())
	if _, err := runCommand(ctx, "", "cosign", args...); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}
