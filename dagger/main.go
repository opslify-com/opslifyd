// Opslifyd CI/verification pipeline.
//
// One definition that runs identically on a developer's machine and in CI
// (`dagger call <fn> --source=.`). Covers everything containerizable:
//   - graph      : deterministic requirements-graph validation (anti-hallucination gate)
//   - unit       : go build / vet / gofmt / race-enabled unit tests
//   - integration: real nix + devbox + cosign + syft toolchain tests (F0.2 AC1/AC2/AC4/AC5)
//   - all        : graph + unit (the fast gate)
//
// Kernel-isolation verification (gVisor escape, nftables packet-drop, podman
// start/pause) is inherently host/privileged-level and lives in the F1.5 escape
// suite run on a privileged host — see spec/phases/p1-sandbox/features/F1.5.
package main

import (
	"context"

	"dagger/opslifyd/internal/dagger"
)

type Opslifyd struct{}

// goImage matches daemon/go.mod's toolchain; bookworm ships gcc for -race (cgo).
const goImage = "golang:1.26-bookworm"

// goBase mounts the repo at /src, works in the daemon module, and wires
// persistent module + build caches so repeat runs are fast.
func (m *Opslifyd) goBase(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(goImage).
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("opslifyd-gomod")).
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume("opslifyd-gobuild")).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src/daemon")
}

// Graph validates the deterministic requirements graph (cycles, dangling
// Depends on:/Blocks:, missing features). Mirrors the pre-commit gate.
func (m *Opslifyd) Graph(ctx context.Context, source *dagger.Directory) (string, error) {
	return dag.Container().
		From("python:3.12-slim").
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		WithExec([]string{"python3", "spec/tools/specgraph.py", "--check"}).
		Stdout(ctx)
}

// Unit runs build, vet, a gofmt cleanliness check, and the race-enabled unit
// test suite for the whole daemon module. No external tools required.
func (m *Opslifyd) Unit(ctx context.Context, source *dagger.Directory) (string, error) {
	return m.goBase(source).
		WithExec([]string{"go", "build", "./..."}).
		WithExec([]string{"go", "vet", "./..."}).
		WithExec([]string{"sh", "-c", `test -z "$(gofmt -l internal/ cmd/)" || { echo "unformatted:"; gofmt -l internal/ cmd/; exit 1; }`}).
		WithExec([]string{"go", "test", "-race", "-timeout", "300s", "./..."}).
		Stdout(ctx)
}

// Integration exercises the tool-dependent F0.2 acceptance criteria
// (AC1/AC2/AC4/AC5) that need real nix + devbox + cosign + syft: real
// flake.lock resolution, a real OCI layer + cosign signature, and a syft SBOM.
// Uses the nixos/nix base so nix provides go/cosign/syft/bash reproducibly.
//
// Notes: nixos/nix has `nix` on PATH but not a general shell/coreutils, and
// flakes are enabled via NIX_CONFIG (no nix.conf edit, so no shell needed for
// setup). The nix store is cached so repeat runs skip re-downloading closures.
func (m *Opslifyd) Integration(ctx context.Context, source *dagger.Directory) (string, error) {
	// NB: do NOT mount a cache over /nix — the nixos/nix image ships nix itself
	// under /nix/store, and a cache volume there masks the nix binary. Repeat
	// runs re-resolve closures; acceptable for correctness.
	return dag.Container().
		From("nixos/nix:latest").
		WithEnvVariable("NIX_CONFIG", "experimental-features = nix-command flakes").
		// nix is on PATH in this image; install the toolchain into the default
		// profile. (bash/coreutils are already provided by the base image — adding
		// them collides, and no pipeline step needs a shell anyway.)
		WithExec([]string{"nix", "profile", "install",
			"nixpkgs#go", "nixpkgs#gcc", "nixpkgs#cosign", "nixpkgs#syft", "nixpkgs#devbox"}).
		// Put the installed tools (incl. bash) on PATH for subsequent steps.
		WithEnvVariable("PATH", "/root/.nix-profile/bin:${PATH}", dagger.ContainerWithEnvVariableOpts{Expand: true}).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src/daemon").
		WithEnvVariable("OPSLIFY_INTEGRATION", "1").
		WithEnvVariable("COSIGN_PASSWORD", "").
		// Ephemeral cosign keypair written into the workdir; point the test at it.
		WithExec([]string{"cosign", "generate-key-pair"}).
		WithEnvVariable("OPSLIFY_COSIGN_KEY", "/src/daemon/cosign.key").
		WithEnvVariable("OPSLIFY_COSIGN_PUBKEY", "/src/daemon/cosign.pub").
		WithExec([]string{"go", "test", "-v", "-run", "Integration", "./internal/env/..."}).
		Stdout(ctx)
}

// All runs the fast gate: graph validation then the unit suite.
func (m *Opslifyd) All(ctx context.Context, source *dagger.Directory) (string, error) {
	if _, err := m.Graph(ctx, source); err != nil {
		return "", err
	}
	return m.Unit(ctx, source)
}
