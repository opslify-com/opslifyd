package install

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/opslify-com/opslifyd/internal/env"
)

// InitOptions configures a single `opslify init` run. Every path and external
// seam is overridable so tests run in temp dirs, without a TTY, without root,
// and without any real tools. Nothing here defaults to a root-only location
// unless the caller opts in.
type InitOptions struct {
	// TargetDir is the project directory to detect and write artifacts into.
	TargetDir string
	// ConfigPath overrides DefaultConfigPath (/etc/opslify/config.yaml).
	ConfigPath string
	// IdentityKeyPath overrides DefaultIdentityKeyPath.
	IdentityKeyPath string
	// SystemdUnitPath, when non-empty, is where the rendered unit is written. A
	// blank path prints the unit to Out instead of writing it (non-root path).
	SystemdUnitPath string
	// BaseImageDigest is the digest-pinned base image folded into the selection.
	BaseImageDigest string

	// Prompter drives interactive selection. Required.
	Prompter Prompter
	// Builder is F0.2's EnvBuilder. When nil, Run tries to construct the
	// production builder; if that is unavailable (no cosign), Compose/Bake is
	// skipped with a legible warning and the rest of init still completes.
	Builder env.EnvBuilder
	// Probe overrides the capability probe (defaults to ProbeCapabilities).
	Probe func() Capabilities

	// Force overwrites existing files without prompting.
	Force bool
	// Out receives operator-facing progress and warnings (never secrets).
	Out io.Writer
}

// InitResult reports what a run produced, for display and for tests to assert.
type InitResult struct {
	Detected      DetectResult
	Selection     env.ToolSelection
	Identity      Identity
	Capabilities  Capabilities
	RecommendTier string
	// LayerDigest and FlakeLockHash are set only when the EnvBuilder ran.
	LayerDigest   string
	FlakeLockHash string
	// Baked reports whether the signed toolchain layer was actually produced.
	Baked bool
	// WrittenFiles lists artifacts written (for the summary).
	WrittenFiles []string
}

func (o *InitOptions) out() io.Writer {
	if o.Out != nil {
		return o.Out
	}
	return io.Discard
}

// Run executes the full init flow: detect → prompt → resolve selection → write
// artifacts + config + identity + systemd unit → probe host → drive F0.2. It is
// idempotent: existing files are only overwritten with Force or an interactive
// confirmation. It never requires root and never crashes on a missing tool.
func Run(ctx context.Context, opts InitOptions) (InitResult, error) {
	var res InitResult
	if opts.Prompter == nil {
		return res, fmt.Errorf("install: a Prompter is required")
	}
	if opts.TargetDir == "" {
		opts.TargetDir = "."
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = DefaultConfigPath
	}
	if opts.IdentityKeyPath == "" {
		opts.IdentityKeyPath = DefaultIdentityKeyPath
	}
	if opts.Probe == nil {
		opts.Probe = ProbeCapabilities
	}
	w := opts.out()

	// 1. Detect.
	res.Detected = Detect(opts.TargetDir)
	fmt.Fprintf(w, "Detected project markers → suggested tools: %v\n", res.Detected.Suggested)
	for id, marker := range res.Detected.Evidence {
		fmt.Fprintf(w, "  %-12s (from %s)\n", id, marker)
	}

	// 2. Prompt (headless in tests via ScriptedPrompter).
	toolIDs, err := opts.Prompter.SelectTools(Catalog(), res.Detected.Suggested)
	if err != nil {
		return res, fmt.Errorf("install: tool selection: %w", err)
	}
	custom, err := opts.Prompter.AddCustom()
	if err != nil {
		return res, fmt.Errorf("install: custom packages: %w", err)
	}

	// 3. Resolve selection → env.ToolSelection.
	sel, err := Selection{ToolIDs: toolIDs, Custom: custom}.ToToolSelection(opts.BaseImageDigest)
	if err != nil {
		return res, err
	}
	res.Selection = sel

	// 4. Write project artifacts (idempotent).
	if err := writeGated(ctx, opts, w, filepath.Join(opts.TargetDir, EnvManifestName), func() error {
		return WriteArtifacts(opts.TargetDir, sel)
	}, EnvManifestName, DevboxName, FlakeName); err != nil {
		return res, err
	}
	res.WrittenFiles = append(res.WrittenFiles, EnvManifestName, DevboxName, FlakeName)

	// 5. Probe host capabilities and recommend a tier (warn, never crash).
	res.Capabilities = opts.Probe()
	tier, reason := res.Capabilities.RecommendTier()
	res.RecommendTier = string(tier)
	if !res.Capabilities.Podman {
		fmt.Fprintln(w, "WARNING [runtime]: podman not found on PATH — install Podman before running sessions.")
	}
	if !res.Capabilities.Runsc {
		fmt.Fprintf(w, "WARNING [runtime]: runsc (gVisor) not found — %s\n", reason)
		if res.Capabilities.Runc {
			useRunc, cerr := opts.Prompter.Confirm("Use the runc compatibility rung for now?", true)
			if cerr != nil {
				return res, fmt.Errorf("install: runc fallback prompt: %w", cerr)
			}
			if !useRunc {
				tier, _ = res.Capabilities.RecommendTier()
			}
		}
	}
	res.RecommendTier = string(tier)

	// 6. Write daemon config (idempotent).
	cfg := DefaultConfig()
	cfg.Image = opts.BaseImageDigest
	cfg.Tier = string(tier)
	cfg.IdentityKey = opts.IdentityKeyPath

	// 7. Generate the daemon Ed25519 identity (0600) — idempotent.
	if fileExists(opts.IdentityKeyPath) && !opts.Force {
		ok, cerr := confirmOverwrite(opts, w, opts.IdentityKeyPath)
		if cerr != nil {
			return res, cerr
		}
		if !ok {
			fmt.Fprintf(w, "Keeping existing identity key %s\n", opts.IdentityKeyPath)
		} else {
			if res.Identity, err = GenerateIdentity(opts.IdentityKeyPath); err != nil {
				return res, err
			}
		}
	} else {
		if res.Identity, err = GenerateIdentity(opts.IdentityKeyPath); err != nil {
			return res, err
		}
	}
	if res.Identity.Fingerprint != "" {
		fmt.Fprintf(w, "Daemon identity fingerprint: %s (key: %s, perms 0600)\n", res.Identity.Fingerprint, opts.IdentityKeyPath)
	}

	// 8. Drive F0.2: Compose + Bake the signed toolchain layer, if a builder is
	//    available. Missing nix/cosign is a gated skip, not a failure.
	if err := writeGated(ctx, opts, w, opts.ConfigPath, func() error {
		return WriteConfig(opts.ConfigPath, cfg) // written after bake so digests can be folded in below
	}, filepath.Base(opts.ConfigPath)); err != nil {
		return res, err
	}

	builder := opts.Builder
	if builder == nil {
		builder = tryDefaultBuilder(w)
	}
	if builder != nil {
		locked, cerr := builder.Compose(ctx, sel)
		if cerr != nil {
			fmt.Fprintf(w, "WARNING [env]: compose skipped: %v\n", cerr)
		} else {
			layer, berr := builder.Bake(ctx, locked)
			if berr != nil {
				fmt.Fprintf(w, "WARNING [env]: bake skipped: %v\n", berr)
			} else {
				res.Baked = true
				res.LayerDigest = layer.LayerDigest
				res.FlakeLockHash = locked.FlakeLockHash
				cfg.ToolchainDigest = layer.LayerDigest
				cfg.FlakeLockHash = locked.FlakeLockHash
				// Re-write config with the resolved digests folded in.
				if werr := WriteConfig(opts.ConfigPath, cfg); werr != nil {
					return res, werr
				}
				fmt.Fprintf(w, "Signed toolchain layer: %s\n", layer.LayerDigest)
				fmt.Fprintf(w, "flake.lock hash:        %s\n", locked.FlakeLockHash)
			}
		}
	} else {
		fmt.Fprintln(w, "NOTE [env]: no EnvBuilder available (nix/cosign absent) — wrote manifests; run `opslify init` on a build host to produce the signed layer.")
	}

	// 9. Systemd unit + socket note.
	unit, uerr := RenderSystemdUnit(DefaultSystemdUnitParams(opts.ConfigPath))
	if uerr != nil {
		return res, uerr
	}
	if opts.SystemdUnitPath != "" {
		if err := writeGated(ctx, opts, w, opts.SystemdUnitPath, func() error {
			return os.WriteFile(opts.SystemdUnitPath, []byte(unit), 0o644)
		}, filepath.Base(opts.SystemdUnitPath)); err != nil {
			return res, err
		}
		res.WrittenFiles = append(res.WrittenFiles, opts.SystemdUnitPath)
	} else {
		fmt.Fprintf(w, "\nsystemd unit (write to /etc/systemd/system/opslifyd.service):\n%s\n", unit)
	}
	fmt.Fprintf(w, "NOTE [runtime]: %s\n", SocketPermsNote)

	res.WrittenFiles = append(res.WrittenFiles, opts.ConfigPath)
	return res, nil
}

// tryDefaultBuilder attempts to construct F0.2's production EnvBuilder. It
// requires cosign as the trust root; when cosign is absent it returns nil so the
// caller degrades to a gated skip rather than a hard failure.
func tryDefaultBuilder(w io.Writer) env.EnvBuilder {
	b, err := env.NewDefault("", "", "")
	if err != nil {
		fmt.Fprintf(w, "NOTE [env]: production EnvBuilder unavailable: %v\n", err)
		return nil
	}
	return b
}

// writeGated runs write() unless one of the named files already exists and the
// operator declines to overwrite (idempotency / prompt-before-overwrite).
func writeGated(_ context.Context, opts InitOptions, w io.Writer, probePath string, write func() error, names ...string) error {
	if fileExists(probePath) && !opts.Force {
		ok, err := confirmOverwrite(opts, w, probePath)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintf(w, "Skipping existing %v\n", names)
			return nil
		}
	}
	return write()
}

func confirmOverwrite(opts InitOptions, _ io.Writer, path string) (bool, error) {
	return opts.Prompter.Confirm(fmt.Sprintf("%s already exists — overwrite?", path), false)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
