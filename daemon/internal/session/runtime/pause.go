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

// Compile-time proof the local Podman base implements the optional capability.
// The remote stub deliberately does not (its warm story is a P6 concern).
var _ Pauser = (*podmanRuntime)(nil)

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
