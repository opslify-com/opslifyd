package runtime

import (
	"context"
	"fmt"
)

// ImageRemover is an OPTIONAL capability a Runtime may implement to delete a
// committed image (from Snapshot). It is the deterministic-cleanup counterpart
// to Snapshot: workspace-mode retention pruning and `ws rm` use it to guarantee
// no orphaned snapshot images are left behind.
//
// Like Pauser/Starter it is kept OUT of the core Runtime interface (purely
// additive to F0.3): a runtime that cannot remove images simply does not
// implement it, and the caller degrades to leaving the image (logged) rather
// than failing. A caller detects support with a type assertion
// (`rt.(ImageRemover)`).
type ImageRemover interface {
	// RemoveImage deletes the named/tagged image (podman rmi --force). Removing a
	// missing image is treated as success so prune/rm are idempotent.
	RemoveImage(ctx context.Context, ref string) error
}

// Compile-time proof the local Podman base implements image removal. The remote
// stub deliberately does not (its snapshot story is a P6 concern).
var _ ImageRemover = (*podmanRuntime)(nil)

// RemoveImage deletes a committed snapshot image via `podman rmi --force`. A
// missing image is not an error (idempotent prune/rm): podman reports it on
// stderr, which we fold into the error, but callers treat removal best-effort.
func (r *podmanRuntime) RemoveImage(ctx context.Context, ref string) error {
	if ref == "" {
		return fmt.Errorf("runtime: remove image: empty ref")
	}
	if _, err := r.runner.run(ctx, "podman", "rmi", "--force", ref); err != nil {
		return fmt.Errorf("runtime: remove image %s: %w", ref, err)
	}
	return nil
}
