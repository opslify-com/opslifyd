package runtime

import (
	"context"
	"fmt"
)

// Pauser is an OPTIONAL capability a Runtime may implement to freeze and thaw a
// container without destroying it — the basis of F1.3's warm pool, which keeps
// pre-created sandboxes paused (no CPU cost) until a claim thaws one.
//
// It is deliberately kept OUT of the core Runtime interface (architecture.md §6)
// so it is purely additive to F0.3: existing impls and their compile-time
// assertions are untouched. A caller detects support with a type assertion
// (`rt.(Pauser)`); a runtime that cannot pause simply does not implement it and
// the warm pool falls back to keeping the container created-but-unpaused (still
// fully hardened, still claimable) — correctness never depends on Pause.
type Pauser interface {
	// Pause freezes all processes in the container (podman pause). It is
	// idempotent from the caller's view: pausing an already-paused container is
	// surfaced as a legible error, never a panic.
	Pause(ctx context.Context, h ContainerHandle) error
	// Unpause thaws a paused container (podman unpause), making it ready to
	// accept execs. This is the warm-start critical path.
	Unpause(ctx context.Context, h ContainerHandle) error
}

// Starter is an OPTIONAL capability a Runtime may implement to START a
// created-but-not-running container (podman start), running its idle entrypoint
// (e.g. `sleep infinity`). It is the real-engine prerequisite for BOTH paths:
//   - on-demand exec: `podman exec` requires a RUNNING container; a bare
//     `podman create` leaves it in "created", so the first exec would fail.
//   - warm-pool freeze: `podman pause` also requires a RUNNING container, so a
//     warm container must be started before it can be paused (start→pause).
//
// Like Pauser it is kept OUT of the core Runtime interface (purely additive to
// F0.3): a runtime that cannot start simply does not implement it and the
// caller falls back to a created-but-not-started container (the F0.3 unit
// behavior). The shared realize path type-asserts for it so on-demand and warm
// sessions are started identically.
type Starter interface {
	// Start transitions a created container to running (podman start). It is the
	// prerequisite for exec and for pause. Legible, layer-tagged errors.
	Start(ctx context.Context, h ContainerHandle) error
}

// Compile-time proof the local Podman base implements the optional capabilities.
// The remote stub deliberately does not (its warm/lifecycle story is a P6 concern).
var (
	_ Pauser  = (*podmanRuntime)(nil)
	_ Starter = (*podmanRuntime)(nil)
)

// Start runs a created container's entrypoint via `podman start`. Idempotent
// from the caller's view: starting an already-running container is surfaced as a
// legible error, never a panic. The hardening posture is fixed at create time
// (createArgs), so a started container carries exactly the cap-drop / seccomp /
// userns set it was created with.
func (r *podmanRuntime) Start(ctx context.Context, h ContainerHandle) error {
	if h.ID == "" {
		return fmt.Errorf("runtime: start: empty container handle")
	}
	if _, err := r.runner.run(ctx, "podman", "start", h.ID); err != nil {
		return fmt.Errorf("runtime: start container %s: %w", h.ID, err)
	}
	return nil
}

// Pause freezes a container via `podman pause`. The hardening posture is
// unchanged by a pause — the frozen container carries the exact same cap-drop /
// seccomp / userns set it was created with (createArgs), so a thawed warm
// container is byte-for-byte as hardened as an on-demand one.
func (r *podmanRuntime) Pause(ctx context.Context, h ContainerHandle) error {
	if h.ID == "" {
		return fmt.Errorf("runtime: pause: empty container handle")
	}
	if _, err := r.runner.run(ctx, "podman", "pause", h.ID); err != nil {
		return fmt.Errorf("runtime: pause container %s: %w", h.ID, err)
	}
	return nil
}

// Unpause thaws a container via `podman unpause`.
func (r *podmanRuntime) Unpause(ctx context.Context, h ContainerHandle) error {
	if h.ID == "" {
		return fmt.Errorf("runtime: unpause: empty container handle")
	}
	if _, err := r.runner.run(ctx, "podman", "unpause", h.ID); err != nil {
		return fmt.Errorf("runtime: unpause container %s: %w", h.ID, err)
	}
	return nil
}
