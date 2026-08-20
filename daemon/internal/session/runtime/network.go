package runtime

import (
	"context"
	"fmt"
	"strings"
)

// NetworkInfo is an OPTIONAL capability a Runtime may implement to report a
// running container's own address on the engine's bridge and the bridge
// GATEWAY address the container routes host-bound traffic through. It is the
// F5.8 discovery seam: the session manager uses it to bind the F5.1 creds
// endpoint + F5.7 egress proxy to a CONTAINER-REACHABLE address (the bridge
// gateway, e.g. 10.88.0.1) instead of the daemon's loopback — and to
// source-scope those listeners to the owning container's IP.
//
// Like ImageRemover/Pauser/Starter it is kept OUT of the core Runtime interface
// (purely additive to F0.3): a runtime that cannot report network info simply
// does not implement it, and the caller degrades to its prior behavior (the
// loopback bind used in unit tests). A caller detects support with a type
// assertion (`rt.(NetworkInfo)`).
//
// SCOPE: implemented for the local Podman base (targeting the runc/local-docker
// tier first). The gVisor/runsc netstack presents the same podman-level
// NetworkSettings, so inspect returns the same fields; whether the bridge
// gateway is reachable identically from inside the runsc network namespace is
// environment-specific and is a documented integration follow-up — this
// capability reports the addresses, it does not assert reachability.
type NetworkInfo interface {
	// NetworkInfo returns the container's own IP on the engine bridge and the
	// bridge gateway IP it routes through. Either may be empty when the engine
	// has not (yet) attached the container to a network; the caller treats an
	// empty gateway as "no reachable bind" and FAILS CLOSED (no endpoint, no
	// proxy env — never a loopback bind the container cannot reach, never a
	// raw-secret fallback).
	NetworkInfo(ctx context.Context, h ContainerHandle) (containerIP, gatewayIP string, err error)
}

// Compile-time proof the local Podman base implements network discovery. The
// remote stub deliberately does not (its network story is a P6 concern).
var _ NetworkInfo = (*podmanRuntime)(nil)

// NetworkInfo reports the container's bridge IP + gateway via `podman inspect`.
// It queries the top-level NetworkSettings fields first and then every attached
// network, so a container on the default bridge (top-level IPAddress/Gateway) and
// one on a named network (which populates only .Networks.<name>) both resolve —
// the FIRST pair with a non-empty IP AND gateway wins (the conservative
// multi-network choice F5.8 calls for).
func (r *podmanRuntime) NetworkInfo(ctx context.Context, h ContainerHandle) (string, string, error) {
	if h.ID == "" {
		return "", "", fmt.Errorf("runtime: network info: empty container id")
	}
	// One inspect emits the top-level pair followed by each network's pair, one
	// pair per LINE with the ip and gateway separated by '|', so a single call
	// covers both the default-bridge (top-level fields) and named-network
	// (.Networks map) layouts. The '|'/newline framing is unambiguous: these are
	// string fields, so an unset value renders as an empty token — never a
	// whitespace-bearing "<no value>" that a space-split would mangle.
	const format = `{{.NetworkSettings.IPAddress}}|{{.NetworkSettings.Gateway}}` + "\n" +
		`{{range .NetworkSettings.Networks}}{{.IPAddress}}|{{.Gateway}}` + "\n" + `{{end}}`
	out, err := r.runner.run(ctx, "podman", "inspect", "--format", format, h.ID)
	if err != nil {
		return "", "", fmt.Errorf("runtime: network info for %s: %w", h.ID, err)
	}
	ip, gw := parseNetworkInfo(string(out))
	return ip, gw, nil
}

// parseNetworkInfo reads the pipe/newline-framed inspect output and returns the
// first "ip|gateway" line where BOTH are non-empty (a stray "<no value>" from a
// nil field is also treated as empty). The top-level pair comes first, then one
// per network, so the default bridge wins when present and a named network fills
// in otherwise — the conservative first-complete-pair choice. A half-attached
// pair (ip but no gateway, or vice versa) is skipped rather than yielding an
// unroutable bind.
func parseNetworkInfo(out string) (string, string) {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		if s == "<no value>" {
			return ""
		}
		return s
	}
	for _, line := range strings.Split(out, "\n") {
		ipStr, gwStr, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		ip, gw := norm(ipStr), norm(gwStr)
		if ip != "" && gw != "" {
			return ip, gw
		}
	}
	return "", ""
}
