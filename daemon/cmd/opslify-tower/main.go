// Command opslify-tower is the cockpit: the operator's web surface over a running
// opslifyd.
//
// It is a SEPARATE BINARY and a CLIENT of the daemon's socket API, never handlers
// inside the daemon (see spec/decisions/D3-tower-binary-split.md). Three things
// follow from that, and all three are the point:
//
//   - Killing the tower leaves the daemon, its sandboxes and its in-flight
//     Changes untouched. The cockpit is a viewer, not the thing doing the work.
//   - Every action it performs exists as an `opslify` CLI command, asserted by an
//     inventory test. A cockpit-only capability would make the OSS daemon
//     incomplete standalone.
//   - It adds no new mutation path. Every request is proxied to the same daemon
//     endpoint the CLI calls, so the F4 classifier, the approval gates and the
//     audit trail apply identically — there is no second exec path to get wrong.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/opslify-com/opslifyd/internal/uiguard"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "opslify-tower:", err)
		os.Exit(1)
	}
}

func run() error {
	socketPath := flag.String("socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	addr := flag.String("addr", "127.0.0.1:4646", "loopback address to serve the cockpit on")
	flag.Parse()

	// Loopback only, asserted rather than assumed. A cockpit on a routable address
	// is reachable by the network, and the launch token is the only thing that
	// would stand between it and an attacker — one control where there should be
	// two. Remote access is an SSH tunnel, which adds no listener.
	if err := uiguard.AssertLoopbackBindAddr(*addr); err != nil {
		return fmt.Errorf("refusing to serve the cockpit off-loopback: %w", err)
	}
	token, err := uiguard.MintToken()
	if err != nil {
		return err
	}
	handler, err := newTowerServer(*socketPath, token)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	if err := uiguard.AssertLoopbackAddr(ln.Addr()); err != nil {
		_ = ln.Close()
		return err
	}

	url := "http://" + ln.Addr().String() + "/?token=" + token
	fmt.Println("cockpit:", url)
	fmt.Println("the token is per-launch and is not written to disk; restart to rotate it")

	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	// Shut the cockpit down without touching the daemon. Nothing here owns a
	// sandbox or a Change, so there is nothing to tear down but this listener.
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

// newTowerServer builds the cockpit handler: the SPA, and a proxy to the daemon
// restricted to the route allowlist.
func newTowerServer(socketPath, token string) (http.Handler, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/", proxyHandler(client))
	mux.Handle("/", cockpitHandler())

	// Order matters: the Host guard runs OUTSIDE the token guard, so a
	// DNS-rebinding request is refused before it can present a token it stole from
	// a page it should never have been able to load.
	return uiguard.LoopbackHost(uiguard.TokenAuth(token, mux)), nil
}

// proxyHandler forwards an allowlisted request to the daemon.
func proxyHandler(client *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reason := admit(r.Method, r.URL); reason != "" {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
		// The daemon is addressed over the unix socket; the host in the URL is
		// ignored by the dialer and exists only to make a valid request.
		upstream, err := http.NewRequestWithContext(r.Context(), r.Method,
			"http://opslifyd"+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, "opslify tower: build upstream request", http.StatusInternalServerError)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			upstream.Header.Set("Content-Type", ct)
		}
		resp, err := client.Do(upstream)
		if err != nil {
			// Named plainly: the most common cause is the daemon not running, and
			// "connection refused" on its own sends people looking in the wrong place.
			http.Error(w, "opslify tower: cannot reach opslifyd — is it running? ("+err.Error()+")",
				http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}
