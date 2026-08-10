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

// runscURL is the gVisor release download (proven to work on this host's arch).
const runscURL = "https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/runsc"

// EscapeSuite runs the F1.5 container-escape / kernel-identity / toolchain probe
// matrix INSIDE a real hardened sandbox driven by the REAL F0.3 runtime
// (podman create/start/exec with the fixed hardening set), on the runc rung and
// — when runsc initialises under nesting — the gVisor rung. Base is
// quay.io/podman/stable (podman preinstalled); the Go 1.26 toolchain is mounted
// from the golang image so the gated Go tests run natively. Requires privileged
// nesting (podman-in-Dagger).
//
// It emits the machine- + human-readable results matrix under /src/artifacts.
func (m *Opslifyd) EscapeSuite(ctx context.Context, source *dagger.Directory) (string, error) {
	goToolchain := dag.Container().From(goImage).Directory("/usr/local/go")
	// Fetch runsc via the DAGGER ENGINE network (not an in-container curl, which is
	// throttled to storage.googleapis.com here) and mount it executable.
	runsc := dag.HTTP(runscURL)
	// containers.conf that makes the F0.3 GvisorRuntime's plain `podman --runtime
	// runsc` work under nesting: cgroupfs manager (rootful, no systemd) and runsc
	// registered with --ignore-cgroups (runsc rejects NoCgroups otherwise). runc is
	// installed below (podman/stable defaults to crun, so the runc rung needs it).
	containersConf := "[engine]\n" +
		"cgroup_manager = \"cgroupfs\"\n" +
		"[engine.runtimes]\n" +
		"runsc = [\"/usr/local/bin/runsc\", \"--ignore-cgroups\"]\n"
	return dag.Container().
		From("quay.io/podman/stable").
		// Native Go toolchain (avoids a slow dnf golang that may lag 1.26).
		WithMountedDirectory("/usr/local/go", goToolchain).
		WithEnvVariable("PATH", "/usr/local/go/bin:/usr/local/bin:${PATH}", dagger.ContainerWithEnvVariableOpts{Expand: true}).
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("opslifyd-gomod")).
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume("opslifyd-gobuild")).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src/daemon").
		// gVisor/runsc, mounted executable — fetched by the engine, not curl'd inside.
		WithFile("/usr/local/bin/runsc", runsc, dagger.ContainerWithFileOpts{Permissions: 0o755}).
		// runc for the local-docker rung (podman/stable ships crun as default only).
		WithExec([]string{"sh", "-c", "dnf install -y -q runc >/dev/null 2>&1 || true"}).
		WithNewFile("/etc/containers/containers.conf", containersConf).
		// Provision the seccomp profile the hardened base points at (podman ships a
		// default we reuse — the hardening set is never weakened).
		WithExec([]string{"sh", "-c",
			"install -D /usr/share/containers/seccomp.json /etc/opslify/seccomp.json"}).
		// The hardened spec uses user-namespace remapping (--userns=auto), which
		// needs subuid/subgid ranges for the users podman maps into. This nested
		// image ships none — provision generous, non-overlapping ranges so the
		// userns hardening is exercised for real (not disabled).
		WithExec([]string{"sh", "-c",
			`printf 'root:100000:65536\ncontainers:200000:65536\npodman:300000:65536\n' | tee /etc/subuid > /etc/subgid`}).
		WithExec([]string{"mkdir", "-p", "/src/artifacts"}).
		WithEnvVariable("OPSLIFY_ESCAPE", "1").
		WithEnvVariable("OPSLIFY_ESCAPE_IMAGE", "docker.io/library/alpine:3.20").
		WithEnvVariable("OPSLIFY_ESCAPE_MATRIX_OUT", "/src/artifacts/escape-matrix").
		WithExec([]string{"go", "test", "-count=1", "-v", "-timeout", "900s",
			"-run", "TestEscapeSuite", "./internal/escape/"},
			dagger.ContainerWithExecOpts{
				ExperimentalPrivilegedNesting: true,
				InsecureRootCapabilities:      true,
			}).
		Stdout(ctx)
}

// EscapeEgress runs the F1.5 exfil half: it builds a real Linux network
// namespace attached to the opslify0 bridge and programs the REAL F1.4 nftables
// egress ruleset, then asserts direct DNS and non-allowlisted egress are DROPPED
// while the allowlisted host stays reachable — with a no-rules baseline first so
// "blocked" is attributable to the ruleset, not to missing connectivity. Needs
// nft + ip + root/CAP_NET_ADMIN (InsecureRootCapabilities), no podman.
func (m *Opslifyd) EscapeEgress(ctx context.Context, source *dagger.Directory) (string, error) {
	return m.goBase(source).
		// nft, iproute2, dnsutils(dig), netcat for the probes.
		WithExec([]string{"sh", "-c",
			"apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables iproute2 dnsutils netcat-openbsd >/dev/null"}).
		WithExec([]string{"mkdir", "-p", "/src/artifacts"}).
		WithEnvVariable("OPSLIFY_ESCAPE_EGRESS", "1").
		WithEnvVariable("OPSLIFY_ESCAPE_EGRESS_MATRIX_OUT", "/src/artifacts/exfil-matrix").
		WithExec([]string{"go", "test", "-count=1", "-v", "-timeout", "300s",
			"-run", "TestExfilSuite", "./internal/escape/"},
			dagger.ContainerWithExecOpts{InsecureRootCapabilities: true}).
		Stdout(ctx)
}

// All runs the fast gate: graph validation then the unit suite.
func (m *Opslifyd) All(ctx context.Context, source *dagger.Directory) (string, error) {
	if _, err := m.Graph(ctx, source); err != nil {
		return "", err
	}
	return m.Unit(ctx, source)
}
