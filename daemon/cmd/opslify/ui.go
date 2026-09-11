package main

import (
	"context"
	"embed"
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
	"github.com/opslify-com/opslifyd/internal/uiguard"
	"github.com/spf13/cobra"
)

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
			if err := uiguard.AssertLoopbackHost(host); err != nil {
				return err
			}
			// Mint a fresh per-launch token; a new `opslify ui` run mints a new one.
			// It is a disposable same-machine secret — NOT the durable audit key.
			token, err := uiguard.MintToken()
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
			if err := uiguard.AssertLoopbackAddr(ln.Addr()); err != nil {
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
		if reason := admitProxyRequest(r.Method, r.URL); reason != "" {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	// F7.4 directory-linking lives on the UI HOST process, NOT the daemon: the ui
	// server already runs host-side, so it hosts the F7.3 sync engine for a linked
	// dir and the daemon never learns the host path. The /ui/* routes are served
	// here directly and are NEVER proxied to the daemon.
	links := newLinkManager(socketPath)

	mux := http.NewServeMux()
	// The host-side link control plane (never forwarded to the daemon).
	mux.Handle("/ui/", links)
	// Only the allowlisted /v1/* routes are proxied. Nothing else reaches the daemon.
	mux.Handle("/v1/", guardedProxy)
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// Compose two additive guards, outermost first:
	//   1. uiguard.LoopbackHost — a non-loopback Host header is refused (403) as a
	//      DNS-rebinding defense (checked first, so a foreign Host is a 403, not a
	//      token 401).
	//   2. uiguard.TokenAuth — every route (SPA, assets, /v1/*) requires the valid
	//      per-launch token or gets 401. This closes the gap the Host-guard alone
	//      left: a DNS-rebind page has a loopback Host but never the token.
	return uiguard.LoopbackHost(uiguard.TokenAuth(token, mux)), nil
}

// allowedProxyRoute is the browser-reachable /v1 allowlist. Since F7.4 it exposes
// the operator's full CLI parity — BUT every route here is still reached only
// behind the F7.1 uiguard.TokenAuth + uiguard.LoopbackHost, so a random local page (or
// a DNS-rebind attacker) holds none of it. It permits:
//   - GET/POST /v1/sessions                     (live list; F7.4 create)
//   - GET  /v1/sessions/history                 (F3.6 past-session list — read)
//   - GET  /v1/sessions/<id>/{trace,verify}     (read — already-redacted/derived)
//   - GET/POST /v1/sessions/<id>/approvals/<x>  (F3.6/F4.3 approval view + resolve)
//   - POST /v1/sessions/<id>/exec               (F7.4 run — SAME F4 classifier +
//     approval gate as the CLI; no bypass, no second exec path)
//   - DELETE /v1/sessions/<id>                  (Kill — the session resource only)
//   - GET/POST /v1/secrets, DELETE /v1/secrets/<ref…> (F5.6 list-NAMES/add/remove —
//     the list is names/metadata only; no value ever returns to the browser)
//   - GET /v1/workspaces, DELETE /v1/workspaces/<name> (F2.2 ls/rm)
//   - GET /v1/policy                            (F4.1 active-policy view — read)
//
// The raw `GET /v1/sessions/<id>/files` (UNredacted /workspace bytes) stays
// REFUSED — the F3.5/F3.6 raw-workspace-read hole must not reopen. File upload
// (PUT/POST …/files) is likewise not exposed to the browser; host↔sandbox file
// movement is driven only by the guarded `/ui/link` sync path, never a raw proxy.
// admitProxyRequest is the proxy's COMPLETE admission decision: the method/path
// allowlist plus every rule that depends on more than the path. It returns the
// operator-facing refusal reason, or "" to admit.
//
// It exists as one function so a test can exercise the real decision. A test that
// re-implemented "allowlist AND not force" would pass while production checked
// only the allowlist — which is exactly the bug this closes.
func admitProxyRequest(method string, u *url.URL) string {
	if !allowedProxyRoute(method, u.Path) {
		return "opslify ui: endpoint not exposed by the local UI (see the F7.4 allowlist)"
	}
	// The allowlist matches on METHOD and PATH, so a query parameter that changes
	// what a route DOES has to be refused separately. ?force=true turns the guarded
	// secret delete into an unguarded one — F8.3's headline control, bypassed from
	// a browser page. Deliberate narrowing: forcing is a CLI-only action, where the
	// operator is shown exactly which consumers they break before it happens. A
	// page that cannot display that should not be able to do it.
	// Case-INSENSITIVE on purpose. The daemon only honours exactly "force", so
	// "?FORCE=true" is inert today — but that is a coincidence of two independent
	// case decisions agreeing, not a guarantee. A proxy must be at least as strict
	// as the thing it protects, never exactly as strict, or the day someone makes
	// the daemon's parse lenient this quietly becomes a bypass.
	for key := range u.Query() {
		if strings.EqualFold(key, "force") {
			return "opslify ui: ?force is not permitted through the local UI — " +
				"run `opslify secrets rm <ref> --force`, which reports what the removal breaks"
		}
	}
	return ""
}

func allowedProxyRoute(method, p string) bool {
	// --- collection-level routes (exact path) ---
	switch p {
	case "/v1/sessions":
		return method == http.MethodGet || method == http.MethodPost
	case "/v1/policy":
		return method == http.MethodGet
	case "/v1/secrets":
		// GET = list NAMES/metadata (never a value); POST = add a value once.
		return method == http.MethodGet || method == http.MethodPost
	case "/v1/workspaces":
		return method == http.MethodGet
	}
	// --- /v1/secrets/consumers : GET who addresses each ref (metadata only) ---
	// Checked BEFORE the by-ref branch below, which would otherwise classify it as
	// a delete target. The UI needs this: without it the page could force a
	// removal but could not show what the removal would break.
	if p == "/v1/secrets/consumers" {
		return method == http.MethodGet
	}
	// --- /v1/secrets/{ref…} : DELETE by ref (a ref may contain slashes) ---
	if rest, ok := strings.CutPrefix(p, "/v1/secrets/"); ok {
		return method == http.MethodDelete && strings.TrimSuffix(rest, "/") != ""
	}
	// --- /v1/workspaces/{name} : DELETE a single workspace (single segment) ---
	if rest, ok := strings.CutPrefix(p, "/v1/workspaces/"); ok {
		rest = strings.TrimSuffix(rest, "/")
		return method == http.MethodDelete && rest != "" && !strings.Contains(rest, "/")
	}
	// --- /v1/sessions/{id}/… sub-paths ---
	rest, ok := strings.CutPrefix(p, "/v1/sessions/")
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
		// F4.3 approvals-resolve, OR the F7.4 exec runner. Exec goes to the SAME
		// daemon handler as the CLI, so it flows through the F4 pre-spawn classifier
		// and approval gate — there is no second, bypassing exec path. The raw file
		// routes (…/files) are still not a POST target here.
		if isApprovalsResolvePath(rest) {
			return true
		}
		seg := strings.Split(strings.TrimSuffix(rest, "/"), "/")
		return len(seg) == 2 && seg[0] != "" && seg[1] == "exec"
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
