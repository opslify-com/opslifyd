package runtime

import "fmt"

// RenderCreateArgs returns the exact `podman create` argv a local rung would
// hand the engine for spec — including the full hardening set from the shared
// base. It is the inspection seam over the (unexported) argv assembly: callers
// outside this package (the F1.2 session manager's hardening flow-through test,
// and later a trace/attestation record binding the isolation boundary that was
// actually requested) can assert or record the container spec without shelling
// out to a real engine.
//
// It is pure and cheap and never touches the host. Only the two local Podman
// rungs assemble argv; a remote/cloud tier has no local argv and returns an
// error.
func RenderCreateArgs(tier Tier, spec SessionSpec) ([]string, error) {
	rt, err := ResolveRuntime(tier, LocationLocal)
	if err != nil {
		return nil, err
	}
	switch r := rt.(type) {
	case *GvisorRuntime:
		return r.createArgs(spec), nil
	case *RuncRuntime:
		return r.createArgs(spec), nil
	default:
		return nil, fmt.Errorf("runtime: tier %q has no local create argv (not a local Podman rung)", tier)
	}
}
