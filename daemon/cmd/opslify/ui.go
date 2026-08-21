package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// uiTokenCookie is the name of the HttpOnly cookie the server sets from a valid
// ?token= launch URL so the SPA's same-origin fetches carry the token
// automatically — the token never has to live in JS.
const uiTokenCookie = "opslify_ui_token"

// uiTokenHeader is the header alternative to the cookie, for curl/tests and any
// non-browser client that cannot round-trip a Set-Cookie.
const uiTokenHeader = "X-Opslify-UI-Token"

// mintUIToken generates a fresh, cryptographically-random per-launch token
// (256-bit, hex-encoded). It is a DISPOSABLE secret — unrelated to the daemon's
// durable audit key, which is never loaded or used in the UI path.
func mintUIToken() (string, error) {
	b := make([]byte, 32) // 256 bits of entropy
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ui: mint launch token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// tokenMatches compares a presented token against the launch token in constant
// time, so a network attacker cannot recover it byte-by-byte via timing. Empty
// values never match.
func tokenMatches(want, got string) bool {
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// presentedToken extracts a candidate token from the request, in preference
// order: the ?token= query (the launch-URL bootstrap), the X-Opslify-UI-Token
// header (curl/tests), an Authorization: Bearer header, then the auth cookie
// (what the browser sends on every same-origin request after bootstrap). The
// bool reports whether the token arrived via the ?token= query, which is the
// only case where the server (re)sets the HttpOnly cookie.
func presentedToken(r *http.Request) (tok string, fromQuery bool) {
	if q := r.URL.Query().Get("token"); q != "" {
		return q, true
	}
	if h := r.Header.Get(uiTokenHeader); h != "" {
		return h, false
	}
	if a := r.Header.Get("Authorization"); a != "" {
		if v, ok := strings.CutPrefix(a, "Bearer "); ok && v != "" {
			return v, false
		}
	}
	if c, err := r.Cookie(uiTokenCookie); err == nil {
		return c.Value, false
	}
	return "", false
}

// tokenAuthGuard requires a valid per-launch token on EVERY route — the SPA
// index, static assets, and all /v1/* proxy routes alike. A request presenting
// no token or a wrong token gets 401. When the token arrives via the ?token=
// launch URL and is valid, the server sets an HttpOnly, SameSite=Strict,
// Path=/ cookie so subsequent same-origin requests authenticate automatically
// without any token handling in JS. This is the gap the Host-guard alone left:
// a DNS-rebind page has a loopback Host but never the token, so it is refused.
func tokenAuthGuard(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, fromQuery := presentedToken(r)
		if !tokenMatches(token, presented) {
			http.Error(w, "opslify ui: missing or invalid launch token (open the ?token= URL printed by `opslify ui`)", http.StatusUnauthorized)
			return
		}
		if fromQuery {
			// Bootstrap: stamp the token into an HttpOnly cookie so the browser
			// carries it on every later fetch and it never touches JS.
			http.SetCookie(w, &http.Cookie{
				Name:     uiTokenCookie,
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
		}
		next.ServeHTTP(w, r)
	})
}

// webuiFS holds the self-contained SPA served by `opslify ui`. Everything the
// browser loads (HTML/CSS/JS) is embedded here — no CDN, font, image, or script
// is fetched at runtime, so the UI works fully offline / air-gapped (F3.5).
//
//go:embed webui
var webuiFS embed.FS

// uiCmd starts a LOCALHOST-ONLY HTTP server that serves the embedded SPA and
// reverse-proxies /v1/* to the daemon's Unix socket. The daemon stays
// socket-only; the browser talks only to 127.0.0.1. No auth in v1 is a
// deliberate trust boundary (an operator on the host); the bind is 127.0.0.1 and
// a non-loopback bind is refused in code, so the local UI can never be the thing
// exposed to a network.
func uiCmd() *cobra.Command {
	var (
		socket string
		host   string
		port   int
		noOpen bool
	)
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Serve a localhost-only web UI for live sessions (embedded SPA, no cloud)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Enforce the localhost trust boundary in code, not just config: refuse
			// to bind anything but a loopback interface.
			if err := assertLoopbackHost(host); err != nil {
				return err
			}
			// Mint a fresh per-launch token; a new `opslify ui` run mints a new one.
			// It is a disposable same-machine secret — NOT the durable audit key.
			token, err := mintUIToken()
			if err != nil {
				return err
			}
			handler, err := newUIServer(socket, token)
			if err != nil {
				return err
			}

			addr := net.JoinHostPort(host, strconv.Itoa(port))
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("ui: bind %s: %w", addr, err)
			}
			// Belt-and-suspenders: verify the bound address really is loopback.
			if err := assertLoopbackAddr(ln.Addr()); err != nil {
				ln.Close()
				return err
			}

			uiURL := "http://" + ln.Addr().String() + "/"
			// The launch URL carries the token; the browser (or operator) that
			// opens it authenticates. The token is printed ONLY here (CLI stdout)
			// and never logged or traced.
			tokenURL := uiURL + "?token=" + token
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "opslify ui listening on %s (localhost-only, per-launch token auth)\n", uiURL)
			fmt.Fprintf(out, "open this URL (carries the launch token): %s\n", tokenURL)
			fmt.Fprintf(out, "proxying /v1/* to daemon socket %s\n", socket)

			if !noOpen {
				openBrowser(tokenURL) // best-effort; never a hard dependency
			}

			srv := &http.Server{Handler: handler}
			// Serve until the command context is cancelled (Ctrl-C), then drain.
			errCh := make(chan error, 1)
			go func() { errCh <- srv.Serve(ln) }()
			select {
			case <-cmd.Context().Done():
				shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutCtx)
				return nil
			case err := <-errCh:
				if err == http.ErrServerClosed {
					return nil
				}
				return err
			}
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1", "bind host (must be loopback; non-loopback is refused)")
	cmd.Flags().IntVar(&port, "port", 4646, "localhost port to serve the UI on")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "do not attempt to open a browser")
	return cmd
}

// newUIServer builds the localhost HTTP handler: the embedded SPA on / and a
// streaming reverse proxy on /v1/* to the daemon's Unix socket. It introduces NO
// route beyond the existing /v1/* API surface, so the UI adds no new mutation
// path — it can only reach what the CLI already can (read + the existing Kill).
func newUIServer(socketPath, token string) (http.Handler, error) {
	sub, err := fs.Sub(webuiFS, "webui")
	if err != nil {
		return nil, fmt.Errorf("ui: embed subtree: %w", err)
	}

	// A transport that always dials the daemon's Unix socket, regardless of the
	// request URL host (reusing the CLI's socket-dialer pattern).
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	target, _ := url.Parse("http://opslify") // placeholder host; dialer ignores it
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			// Defense in depth: never forward the UI launch token to the daemon.
			// The SPA authenticates via the HttpOnly cookie and never puts ?token=
			// on a /v1 call, but a hand-crafted client could — strip it so the token
			// can't ride the outbound query into the daemon side.
			if q := pr.Out.URL.Query(); q.Has("token") {
				q.Del("token")
				pr.Out.URL.RawQuery = q.Encode()
			}
		},
		Transport: transport,
		// FlushInterval < 0 flushes each write immediately, so the SSE trace
		// stream is forwarded event-by-event (streamed, never buffered to
		// completion). Critical for the < 2s live-output requirement.
		FlushInterval: -1,
	}

	// Restrict the browser-reachable proxy to the read + Kill routes the UI
	// actually uses (list sessions, read a session/its trace stream, kill a
	// session). Every other existing /v1 route — session create, exec, file
	// upload, workspace delete — is refused here, so a page loaded in the
	// operator's browser cannot drive the sandbox through the loopback bridge even
	// though the daemon itself still serves those routes to the CLI.
	guardedProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedProxyRoute(r.Method, r.URL.Path) {
			http.Error(w, "opslify ui: endpoint not exposed by the local UI (read + kill + approve/deny only)", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	mux := http.NewServeMux()
	// Only the allowlisted /v1/* routes are proxied. Nothing else reaches the daemon.
	mux.Handle("/v1/", guardedProxy)
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// Compose two additive guards, outermost first:
	//   1. loopbackHostGuard — a non-loopback Host header is refused (403) as a
	//      DNS-rebinding defense (checked first, so a foreign Host is a 403, not a
	//      token 401).
	//   2. tokenAuthGuard — every route (SPA, assets, /v1/*) requires the valid
	//      per-launch token or gets 401. This closes the gap the Host-guard alone
	//      left: a DNS-rebind page has a loopback Host but never the token.
	return loopbackHostGuard(tokenAuthGuard(token, mux)), nil
}

// allowedProxyRoute is the browser-reachable /v1 allowlist. It permits only:
//   - GET  /v1/sessions                         (live session list)
//   - GET  /v1/sessions/history                 (F3.6 past-session list — read)
//   - GET  /v1/sessions/<id>...                 (a session, its trace stream/replay,
//     and the F3.6 verify verdict — all read, all already-redacted/derived data)
//   - POST /v1/sessions/<id>/approvals/<exec_id> (F3.6/F4.3 approve|deny — the ONE
//     privileged mutation, guarded by the loopback bind + DNS-rebind Host-guard)
//   - DELETE /v1/sessions/<id>                  (Kill — the session resource itself only)
//
// Everything else (session create, exec, file upload, /v1/workspaces, any other
// mutation sub-path) is refused, so the local UI is read + Kill + approve/deny.
func allowedProxyRoute(method, p string) bool {
	if method == http.MethodGet && p == "/v1/sessions" {
		return true
	}
	const pfx = "/v1/sessions/"
	rest, ok := strings.CutPrefix(p, pfx)
	if !ok || rest == "" {
		return false
	}
	switch method {
	case http.MethodGet:
		// EXPLICIT read allowlist — only already-redacted / derived data. A blanket
		// GET would also expose `/v1/sessions/{id}/files` (raw, UNredacted /workspace
		// bytes), letting a local browser page read anything the agent wrote; that is
		// refused here. Permitted GETs:
		//   history                    — the past-session list (metadata only)
		//   {id}/trace   (+ ?from_seq) — the F3.3-redacted trace stream / replay
		//   {id}/verify                — the server-computed verify verdict
		//   {id}/approvals/{exec_id}   — the redacted approval view (poll)
		if rest == "history" {
			return true
		}
		seg := strings.Split(strings.TrimSuffix(rest, "/"), "/")
		if len(seg) == 2 && seg[0] != "" && (seg[1] == "trace" || seg[1] == "verify") {
			return true
		}
		if isApprovalsResolvePath(rest) { // {id}/approvals/{exec_id} — GET poll of the view
			return true
		}
		return false
	case http.MethodPost:
		// ONLY the F4.3 approvals-resolve action: /v1/sessions/{id}/approvals/{exec_id}.
		// No other POST (create is not under this prefix; exec is refused here).
		return isApprovalsResolvePath(rest)
	case http.MethodDelete:
		// Kill only the session resource itself, never a mutation sub-path.
		return !strings.Contains(strings.TrimSuffix(rest, "/"), "/")
	default:
		return false
	}
}

// isApprovalsResolvePath reports whether rest (the path after "/v1/sessions/")
// names exactly the approvals-resolve resource "{id}/approvals/{exec_id}" — three
// non-empty segments with "approvals" in the middle. It deliberately matches
// nothing else (e.g. "{id}/exec"), so POST opens no surface beyond approve/deny.
func isApprovalsResolvePath(rest string) bool {
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	return len(parts) == 3 && parts[0] != "" && parts[1] == "approvals" && parts[2] != ""
}

// loopbackHostGuard rejects any request whose Host header is not loopback. This
// is the DNS-rebinding defense: even though the socket binds 127.0.0.1, a
// browser tricked by a rebound DNS name would send that name in Host; we require
// 127.0.0.1 / ::1 / localhost (any port) so only a genuinely local origin passes.
func loopbackHostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostIsLoopback(r.Host) {
			http.Error(w, "opslify ui: refusing request with non-loopback Host header (DNS-rebinding guard)", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostIsLoopback reports whether an HTTP Host header (host or host:port) names a
// loopback address or "localhost". No DNS is performed — a literal check only.
func hostIsLoopback(hostport string) bool {
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

// assertLoopbackHost rejects any bind host that is not loopback. It resolves
// literal IPs via net.IP (checking IsLoopback) and permits only the "localhost"
// hostname, so the guard is deterministic and needs no DNS. A hostname that
// could resolve off-host (or 0.0.0.0 / a LAN IP) is refused — the local UI must
// never be reachable from another host.
func assertLoopbackHost(host string) error {
	if host == "" {
		return fmt.Errorf("ui: refusing empty bind host; the UI binds loopback only")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ui: refusing non-loopback bind host %q; only 127.0.0.1, ::1, or localhost are allowed", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("ui: refusing non-loopback bind %q; the UI must not be reachable off-host (use the cloud plane for remote access)", host)
	}
	return nil
}

// assertLoopbackAddr re-checks an already-bound address is loopback (defense in
// depth against a host that resolved to a routable IP).
func assertLoopbackAddr(addr net.Addr) error {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return fmt.Errorf("ui: cannot parse bound address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("ui: bound address %q is not loopback; refusing to serve", addr)
	}
	return nil
}

// openBrowser best-effort opens uiURL in the operator's browser. It never fails
// the command: a headless host (no browser) is fully supported (use --no-open or
// just the printed URL / `opslify top`).
func openBrowser(uiURL string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	args = append(args, uiURL)
	_ = exec.Command(cmd, args...).Start()
}
