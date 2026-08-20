package session

import (
	"log/slog"
	"net"
	"net/http"
)

// F5.8 — reachable-bind + source-scope helpers shared by the two per-session
// credential-injecting listeners (the F5.1 creds endpoint and the F5.7 egress
// proxy). Binding those listeners OFF loopback is a trust boundary: they must
// bind ONLY the container-reachable bridge gateway (never 0.0.0.0/::) AND refuse
// any request whose source IP is not the owning container's — so binding to the
// bridge can never let a neighbour container or a LAN host drive the daemon into
// injecting a credential.

// isBindableGateway reports whether host is a concrete, container-reachable
// address safe to bind a credential-injecting listener to. It rejects the empty
// host and every UNSPECIFIED address (0.0.0.0 and ::) — a routable/world bind of
// these listeners is a BLOCKING defect (F5.8), so the guard fails closed rather
// than ever binding a wildcard. A non-IP host is rejected too (the gateway is
// always a numeric address from the runtime).
func isBindableGateway(host string) bool {
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	// 0.0.0.0 and :: (and the v4-mapped form) are unspecified — never bind them.
	return !ip.IsUnspecified()
}

// hostOfRemoteAddr extracts the bare IP from a net/http RemoteAddr ("ip:port").
// It falls back to the raw value if there is no port, so a caller always has a
// host to compare.
func hostOfRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// sourceScoped wraps next so it serves ONLY requests whose source IP equals
// allowIP (the owning container's bridge IP). Any other source — a neighbour
// container on the same bridge, a LAN host — is refused with 403 and no body,
// BEFORE next ever runs. This is enforced on TOP of the F5.1 per-session bearer
// token: even a leaked/valid token from the wrong source is rejected here, so
// binding the listener to the bridge gateway cannot be abused off-container.
//
// A caller that passes an empty allowIP gets next unwrapped — that path is used
// only for the legacy loopback bind (no NetworkInfo capability), where the
// listener is not reachable off-host and source-scoping does not apply.
func sourceScoped(next http.Handler, allowIP string, log *slog.Logger) http.Handler {
	if allowIP == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostOfRemoteAddr(r.RemoteAddr) != allowIP {
			if log != nil {
				log.Warn("credential listener refused off-source request",
					"remote", r.RemoteAddr, "allow_ip", allowIP)
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
