package env

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
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
			// The devbox/nix profile is a symlink farm: its bin/* point into
			// /nix/store, so the profile dir itself contains no real tool files.
			// Baking/scanning it directly would pack dangling symlinks (no tools
			// in the layer, no tools in the SBOM, and a digest that doesn't vary
			// with the selection). Assemble a staging rootfs of the FULL
			// transitive store closure — real files — and return THAT as the
			// closure path, so ociBaker/syft (generic "dir of real files") work
			// unchanged and produce a functional, reproducible, selection-distinct
			// layer.
			staging, err := assembleStoreClosure(ctx, workDir, profile)
			if err != nil {
				return nil, "", err
			}
			return b, staging, nil
		}
	}
	return nil, "", fmt.Errorf("env: no lock file produced by devbox in %s", workDir)
}

// assembleStoreClosure builds a staging rootfs directory of REAL files that is
// the full transitive nix store closure of the devbox profile. The result S has
// the shape:
//
//	S/nix/store/<hash>-*   real file trees of every requisite (copied)
//	S/bin, S/lib, ...      the profile's own tree, with every absolute
//	                       /nix/store symlink rewritten to a path RELATIVE to S
//
// so S/bin/terraform resolves within S to a real binary under S/nix/store,
// `syft scan dir:S` finds the tools + transitive deps, and the packed layer
// contains actual binaries. It is deterministic (content comes from nix; the
// tar layer sorts + zeroes metadata), so the same selection yields the same
// digest and distinct selections yield distinct closures/digests.
func assembleStoreClosure(ctx context.Context, workDir, profile string) (string, error) {
	// Resolve the profile symlink to its real store path, then query the full
	// transitive closure (the profile store path itself is included).
	realProfile, err := filepath.EvalSymlinks(profile)
	if err != nil {
		return "", fmt.Errorf("env: resolve profile %q: %w", profile, err)
	}
	out, err := runCommand(ctx, workDir, "nix-store", "--query", "--requisites", realProfile)
	if err != nil {
		return "", err
	}
	var storePaths []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if p := strings.TrimSpace(line); p != "" {
			storePaths = append(storePaths, p)
		}
	}
	if len(storePaths) == 0 {
		return "", fmt.Errorf("env: empty closure for profile %q", realProfile)
	}
	sort.Strings(storePaths)

	// Fresh staging rootfs under the workDir.
	staging := filepath.Join(workDir, ".opslify-closure")
	if err := os.RemoveAll(staging); err != nil {
		return "", fmt.Errorf("env: reset staging: %w", err)
	}
	storeDir := filepath.Join(staging, "nix", "store")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		return "", fmt.Errorf("env: mkdir staging store: %w", err)
	}

	// Copy each requisite store path as REAL files. Done in pure Go (no reliance
	// on a coreutils cp being on PATH in the minimal nix image): directories are
	// recreated, symlinks preserved verbatim, and regular files HARDLINKED to the
	// read-only store entry when possible (instant, no data copy) or data-copied
	// across a device boundary. The tar layer zeroes mtime/uid/gid, so copy
	// metadata never affects the digest.
	for _, sp := range storePaths {
		dst := filepath.Join(storeDir, filepath.Base(sp))
		if _, err := os.Lstat(dst); err == nil {
			continue // already staged
		}
		if err := cloneTree(sp, dst); err != nil {
			return "", fmt.Errorf("env: stage store path %q: %w", sp, err)
		}
	}

	// Mirror the profile's own tree into the staging root, rewriting every
	// absolute /nix/store symlink target to a path relative to its location in
	// the staging rootfs so it resolves WITHIN S (not against the host store).
	if err := mirrorProfileTree(realProfile, staging); err != nil {
		return "", err
	}
	return staging, nil
}

// cloneTree replicates the file tree at src into dst: dirs are recreated,
// symlinks copied verbatim, and regular files hardlinked to the (read-only)
// source when the filesystem allows, else data-copied. Store paths are
// immutable, so hardlinking is safe and avoids copying multi-GB closures.
func cloneTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := dst
		if rel != "." {
			target = filepath.Join(dst, rel)
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			return os.Symlink(link, target)
		case d.Type().IsRegular():
			if err := os.Link(p, target); err == nil {
				return nil // hardlink succeeded (same filesystem)
			}
			return copyFile(p, target)
		default:
			return nil // skip sockets/devices/fifos
		}
	})
}

// copyFile data-copies src to dst, preserving the source's mode bits.
func copyFile(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// mirrorProfileTree recreates the directory structure of the profile store path
// under dst. Directories become real dirs; symlinks are recreated with their
// targets rewritten from an absolute /nix/store path to a path relative to the
// symlink's own location within dst (so it points into dst/nix/store/...).
// Regular files (rare at the profile top level) are copied.
func mirrorProfileTree(profileRoot, dst string) error {
	return filepath.WalkDir(profileRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(profileRoot, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil // dst root already exists
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return fmt.Errorf("env: readlink profile entry: %w", err)
			}
			if strings.HasPrefix(link, "/nix/store/") {
				// Point at the staged copy, relative to this symlink's dir.
				staged := filepath.Join(dst, "nix", "store", link[len("/nix/store/"):])
				relTarget, err := filepath.Rel(filepath.Dir(target), staged)
				if err != nil {
					return fmt.Errorf("env: relativise symlink: %w", err)
				}
				link = relTarget
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			return os.Symlink(link, target)
		case d.Type().IsRegular():
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			in, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(target, in, 0o644)
		default:
			return nil
		}
	})
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
