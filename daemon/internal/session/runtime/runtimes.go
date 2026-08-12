package runtime

import (
	"context"
	"fmt"
)

// Compile-time proof that every impl satisfies the shared interface.
var (
	_ Runtime = (*RuncRuntime)(nil)
	_ Runtime = (*GvisorRuntime)(nil)
	_ Runtime = (*RemoteRuntime)(nil)
)

// RuncRuntime is the local-docker (compat) rung: Podman with the runc OCI
// runtime. It embeds the shared podmanRuntime base and adds nothing but its
// runtime flag — no lifecycle or hardening logic of its own.
type RuncRuntime struct {
	*podmanRuntime
}

// NewRuncRuntime builds the compat rung backed by the real Podman CLI.
func NewRuncRuntime() *RuncRuntime { return newRuncRuntime(execRunner{}) }

// newRuncRuntime is the injectable constructor used by tests to supply a fake
// commandRunner (so argv assembly is verifiable without Podman).
func newRuncRuntime(runner commandRunner) *RuncRuntime {
	return &RuncRuntime{&podmanRuntime{
		runtimeFlag:    "runc",
		runtimeBinary:  "", // runc ships with podman; no extra probe needed
		tier:           TierLocalDocker,
		seccompProfile: seccompProfilePath(),
		runner:         runner,
	}}
}

// GvisorRuntime is the local-hardened (default) rung: Podman with the gVisor
// runsc OCI runtime. It is identical to RuncRuntime except for `--runtime runsc`
// and that Available() also probes for the runsc binary — the hardening set is
// inherited unchanged from the shared base.
type GvisorRuntime struct {
	*podmanRuntime
}

// NewGvisorRuntime builds the default rung backed by the real Podman CLI.
func NewGvisorRuntime() *GvisorRuntime { return newGvisorRuntime(execRunner{}) }

// newGvisorRuntime is the injectable constructor used by tests.
func newGvisorRuntime(runner commandRunner) *GvisorRuntime {
	return &GvisorRuntime{&podmanRuntime{
		runtimeFlag:    "runsc",
		runtimeBinary:  "runsc", // Available() probes gVisor is installed
		tier:           TierLocalHardened,
		seccompProfile: seccompProfilePath(),
		runner:         runner,
	}}
}

// RemoteRuntime is the cloud-microvm / remote-location seam (P6). It is a clean
// stub: every method returns ErrNotImplemented with a legible message, and no
// half-wired cloud transport exists. P6 replaces this impl in place.
type RemoteRuntime struct{}

// NewRemoteRuntime builds the remote stub.
func NewRemoteRuntime() *RemoteRuntime { return &RemoteRuntime{} }

func (*RemoteRuntime) Create(context.Context, SessionSpec) (ContainerHandle, error) {
	return ContainerHandle{}, remoteStubErr("create")
}

func (*RemoteRuntime) Exec(context.Context, ContainerHandle, ExecRequest) (ExecStream, error) {
	return ExecStream{}, remoteStubErr("exec")
}

func (*RemoteRuntime) Destroy(context.Context, ContainerHandle) error {
	return remoteStubErr("destroy")
}

func (*RemoteRuntime) Snapshot(context.Context, ContainerHandle, string) (ImageRef, error) {
	return ImageRef{}, remoteStubErr("snapshot")
}

// Available reports the remote runtime is not yet wired, legibly.
func (*RemoteRuntime) Available() error { return remoteStubErr("probe") }

func remoteStubErr(op string) error {
	return fmt.Errorf("runtime: cloud-microvm/remote %s is a P6 stub (cloud gRPC transport not wired): %w",
		op, ErrNotImplemented)
}
