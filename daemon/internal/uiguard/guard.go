// Package uiguard holds the F7.1 browser-facing guards: the per-launch token, the
// DNS-rebinding Host check, and the loopback assertions.
//
// It is a package rather than code inside one binary because BOTH the daemon's
// built-in UI and the separate tower binary must apply exactly these rules. Two
// copies of a security guard drift — one gets a fix the other does not — and the
// one that drifts is reachable by any local page.
package uiguard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// TokenCookie is the HttpOnly cookie the server sets from a valid ?token=, so the
// SPA's own fetches carry it without any token handling in JS.
const TokenCookie = "opslify_ui_token"

// TokenHeader is the header alternative to the cookie, for curl, tests, and any
// client that cannot hold a cookie.
const TokenHeader = "X-Opslify-UI-Token"

// MintToken generates a fresh, cryptographically-random per-launch token
// (256-bit, hex-encoded). It is a DISPOSABLE secret — unrelated to the daemon's
// durable audit key, which is never loaded or used in the UI path.
func MintToken() (string, error) {
	b := make([]byte, 32) // 256 bits of entropy
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("uiguard: mint launch token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// TokenMatches compares a presented token against the launch token in constant
// time, so a network attacker cannot recover it byte-by-byte via timing. Empty
// values never match.
func TokenMatches(want, got string) bool {
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// PresentedToken extracts a candidate token from the request, in preference
// order: the ?token= query (the launch-URL bootstrap), the X-Opslify-UI-Token
// header (curl/tests), an Authorization: Bearer header, then the auth cookie
// (what the browser sends on every same-origin request after bootstrap). The
// bool reports whether the token arrived via the ?token= query, which is the
// only case where the server (re)sets the HttpOnly cookie.
func PresentedToken(r *http.Request) (tok string, fromQuery bool) {
	if q := r.URL.Query().Get("token"); q != "" {
		return q, true
	}
	if h := r.Header.Get(TokenHeader); h != "" {
		return h, false
	}
	if a := r.Header.Get("Authorization"); a != "" {
		if v, ok := strings.CutPrefix(a, "Bearer "); ok && v != "" {
			return v, false
		}
	}
	if c, err := r.Cookie(TokenCookie); err == nil {
		return c.Value, false
	}
	return "", false
}

// TokenAuth requires a valid per-launch token on EVERY route — the SPA
// index, static assets, and all /v1/* proxy routes alike. A request presenting
// no token or a wrong token gets 401. When the token arrives via the ?token=
// launch URL and is valid, the server sets an HttpOnly, SameSite=Strict,
// Path=/ cookie so subsequent same-origin requests authenticate automatically
// without any token handling in JS. This is the gap the Host-guard alone left:
// a DNS-rebind page has a loopback Host but never the token, so it is refused.
func TokenAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, fromQuery := PresentedToken(r)
		if !TokenMatches(token, presented) {
			http.Error(w, "opslify uiguard: missing or invalid launch token (open the ?token= URL printed by `opslify ui`)", http.StatusUnauthorized)
			return
		}
		if fromQuery {
			// Bootstrap: stamp the token into an HttpOnly cookie so the browser
			// carries it on every later fetch and it never touches JS.
			http.SetCookie(w, &http.Cookie{
				Name:     TokenCookie,
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
		}
		next.ServeHTTP(w, r)
	})
}

// LoopbackHost rejects any request whose Host header is not loopback. This
// is the DNS-rebinding defense: even though the socket binds 127.0.0.1, a
// browser tricked by a rebound DNS name would send that name in Host; we require
// 127.0.0.1 / ::1 / localhost (any port) so only a genuinely local origin passes.
func LoopbackHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !HostIsLoopback(r.Host) {
			http.Error(w, "opslify uiguard: refusing request with non-loopback Host header (DNS-rebinding guard)", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HostIsLoopback reports whether an HTTP Host header (host or host:port) names a
// loopback address or "localhost". No DNS is performed — a literal check only.
func HostIsLoopback(hostport string) bool {
	if hostport == "" {
		return false
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport // no port present
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// AssertLoopbackHost rejects any bind host that is not loopback. It resolves
// literal IPs via net.IP (checking IsLoopback) and permits only the "localhost"
// hostname, so the guard is deterministic and needs no DNS. A hostname that
// could resolve off-host (or 0.0.0.0 / a LAN IP) is refused — the local UI must
// never be reachable from another host.
func AssertLoopbackHost(host string) error {
	if host == "" {
		return fmt.Errorf("uiguard: refusing empty bind host; the UI binds loopback only")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("uiguard: refusing non-loopback bind host %q; only 127.0.0.1, ::1, or localhost are allowed", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("uiguard: refusing non-loopback bind %q; the UI must not be reachable off-host (use the cloud plane for remote access)", host)
	}
	return nil
}

// AssertLoopbackAddr re-checks an already-bound address is loopback (defense in
// depth against a host that resolved to a routable IP).
func AssertLoopbackAddr(addr net.Addr) error {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return fmt.Errorf("uiguard: cannot parse bound address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("uiguard: bound address %q is not loopback; refusing to serve", addr)
	}
	return nil
}

// AssertLoopbackBindAddr checks a "host:port" bind address.
//
// It exists because AssertLoopbackHost takes a bare HOST, and every caller
// actually holds a host:port — a flag value, a listener address. Passing the
// whole thing to the host check fails closed, which is safe but useless, and the
// first version of the tower did exactly that. One helper with the right shape
// beats each caller remembering to split.
func AssertLoopbackBindAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port: it may already be a bare host, so try it directly rather than
		// refusing something legitimate.
		return AssertLoopbackHost(addr)
	}
	return AssertLoopbackHost(host)
}
