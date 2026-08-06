// Package runtime implements F0.3 — the isolation-ladder runtime & location
// abstraction (decision D2). It defines the shared Runtime interface
// (architecture.md §6) plus the Tier/Location vocabulary and a ResolveRuntime
// dispatcher, so the ladder (local-docker / local-hardened / cloud-microvm) is
// pluggable from day one even though only the two local Podman-backed impls
// exist now.
//
// Both local impls (RuncRuntime, GvisorRuntime) are thin configs over a single
// podmanRuntime base: the ONLY differences are the --runtime flag (runc vs
// runsc) and, critically, nothing about hardening — the caps-drop /
// no-new-privileges / user-ns remap / read-only rootfs / seccomp flags live in
// the shared base so no impl can forget them (see podman.go, hardeningFlags).
package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Tier selects a rung on the isolation ladder (D2).
type Tier string

// Location selects where the runtime executes: on this host, or on a remote
// cloud node reached over gRPC (the P6 seam).
type Location string

const (
	// TierLocalDocker runs on the local Podman engine with the runc OCI
	// runtime — the compatibility rung for tools gVisor breaks.
	TierLocalDocker Tier = "local-docker"
	// TierLocalHardened runs on the local Podman engine with the gVisor/runsc
	// OCI runtime — the default rung.
	TierLocalHardened Tier = "local-hardened"
	// TierCloudMicroVM runs in a cloud microVM (Firecracker/Kata). P6 stub.
	TierCloudMicroVM Tier = "cloud-microvm"

	// LocationLocal targets the local Podman engine.
	LocationLocal Location = "local"
	// LocationRemote targets the cloud gRPC endpoint. P6 stub.
	LocationRemote Location = "remote"
)

// ResourceLimits bounds a session's resource use. Zero fields mean "engine
// default" (unbounded); the caller/policy layer is expected to set them.
type ResourceLimits struct {
	// MemoryBytes caps RAM (0 = unbounded). Maps to podman --memory.
	MemoryBytes int64
	// CPUs caps CPU quota, e.g. 1.5 (0 = unbounded). Maps to podman --cpus.
	CPUs float64
	// PidsLimit caps the number of processes (0 = unbounded). Maps to
	// podman --pids-limit; a fork-bomb guard.
	PidsLimit int64
}

// SessionSpec describes one sandbox to create (architecture.md §6). It is pure
// data: no secrets belong here (credential injection is the P5 broker's job).
type SessionSpec struct {
	// Tier and Location select the rung and locality. They are informational
	// for the runtime itself (ResolveRuntime already used them to pick this
	// impl) but are recorded on the handle for trace/attestation.
	Tier     Tier
	Location Location
	// Image is the digest-pinned base rootfs the toolchain mounts over.
	Image string
	// ToolchainDigest is the signed, read-only toolchain layer (F0.2 output)
	// mounted read-only at /opt/toolchain. Empty means "base image only".
	ToolchainDigest string
	// Workspace is a host path bind-mounted read-write at /workspace. Empty
	// means no persistent workspace (scratch session).
	Workspace string
	// Limits bounds resource use.
	Limits ResourceLimits
	// Name is an optional stable container name; empty lets the engine assign.
	Name string
	// Entrypoint overrides the image entrypoint (e.g. a sleep loop for a warm
	// container). Empty uses the image default.
	Entrypoint []string
}

// ContainerHandle identifies a created container. It is opaque to callers apart
// from the fields recorded for tracing.
type ContainerHandle struct {
	// ID is the engine-assigned container ID.
	ID string
	// Tier and Runtime record which rung/OCI-runtime produced this container,
	// so a trace can bind the isolation boundary that was actually used.
	Tier    Tier
	Runtime string // "runc" | "runsc"
}

// ExecRequest is a single command to run inside a container. Env carries only
// NON-secret environment; secret injection is the P5 broker's responsibility.
type ExecRequest struct {
	Argv    []string
	Env     []string // "KEY=VALUE"; never secrets (P5 broker injects those)
	Workdir string
}

// ExecStream is the result of an Exec. In F0.3 it is a thin, buffered result;
// F1.2 replaces it with true streaming + a real exit code from the engine.
type ExecStream struct {
	Stdout   io.Reader
	Stderr   io.Reader
	ExitCode int
}

// ImageRef points at a committed image (from Snapshot).
type ImageRef struct {
	Name   string
	Digest string
}

// Runtime is the D2 isolation-ladder interface (architecture.md §6). Impls:
// RuncRuntime, GvisorRuntime, RemoteRuntime (KataRuntime, RemoteFirecracker
// later). Available() is the F0.3 capability probe (recorded in §6).
type Runtime interface {
	Create(ctx context.Context, spec SessionSpec) (ContainerHandle, error)
	Exec(ctx context.Context, h ContainerHandle, req ExecRequest) (ExecStream, error)
	Destroy(ctx context.Context, h ContainerHandle) error
	Snapshot(ctx context.Context, h ContainerHandle, name string) (ImageRef, error) // workspace mode
	// Available reports, with a legible layer-tagged error, whether this
	// runtime can actually run here (engine + OCI runtime present). Callers use
	// it to fall back down the ladder before attempting a Create.
	Available() error
}

// Sentinel errors. All runtime errors are wrapped with the "runtime:" layer
// prefix so the operator always learns which layer failed (failure legibility).
var (
	// ErrNotImplemented is returned by the cloud/remote stub.
	ErrNotImplemented = errors.New("runtime: not implemented")
	// ErrUnknownTier is returned by ResolveRuntime for an unrecognised tier.
	ErrUnknownTier = errors.New("runtime: unknown tier")
	// ErrUnknownLocation is returned by ResolveRuntime for an unrecognised
	// location.
	ErrUnknownLocation = errors.New("runtime: unknown location")
)

// ResolveRuntime maps a (tier, location) pair to a concrete Runtime. It is the
// single dispatch point for the isolation ladder:
//
//   - location "remote"        → RemoteRuntime (P6 cloud gRPC seam; stub now)
//   - local-docker  / local    → RuncRuntime   (compat rung)
//   - local-hardened / local   → GvisorRuntime (default rung)
//   - cloud-microvm            → RemoteRuntime  (stub now)
//
// It never returns nil with a nil error. Resolution is pure and cheap — it does
// not probe the host; call Available() on the result to check the host can run
// it.
func ResolveRuntime(t Tier, l Location) (Runtime, error) {
	switch l {
	case LocationRemote:
		// The remote seam wins regardless of tier: a remote session runs on
		// the cloud node's own runtime, reached over gRPC (P6).
		return NewRemoteRuntime(), nil
	case LocationLocal, "":
		// fall through to tier dispatch
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownLocation, l)
	}

	switch t {
	case TierLocalDocker:
		return NewRuncRuntime(), nil
	case TierLocalHardened:
		return NewGvisorRuntime(), nil
	case TierCloudMicroVM:
		return NewRemoteRuntime(), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownTier, t)
	}
}
