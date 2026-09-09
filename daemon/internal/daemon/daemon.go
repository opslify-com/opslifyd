// Package daemon implements F1.1 — the opslifyd daemon bootstrap and REST API
// skeleton. It loads config + identity (reusing F0.1), verifies the signed
// toolchain before serving (reusing F0.2), exposes a versioned REST API over a
// permissioned Unix socket, reports isolation-runtime capability (reusing F0.3),
// and shuts down cleanly on context cancellation.
//
// Every host- or tool-dependent concern is behind an injectable seam — the
// socket path/group, the toolchain verifier, and the runtime probe — so the
// valuable core (socket 0660 perms, verify-before-serve refusal, health/
// capability reporting, graceful shutdown, identity fail-fast) is fully unit
// testable with an HTTP client over a temp Unix socket, needing neither root nor
// podman/runsc/cosign.
package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/install"
)

// DefaultSocketPath is the production daemon socket. Overridable via Options so
// tests bind a temp socket.
const DefaultSocketPath = "/run/opslify/opslifyd.sock"

// DefaultSocketGroup is the group that owns the socket in production; only its
// members can talk to the daemon. Empty in tests (skips chown).
const DefaultSocketGroup = "opslify"

// shutdownGrace bounds how long in-flight requests get to drain on shutdown.
const shutdownGrace = 5 * time.Second

// Options configures a Daemon. Every field that would otherwise require root, a
// real group, or an external tool is injectable so the daemon is unit testable.
type Options struct {
	// Config is the loaded daemon config (F0.1). Tier drives the runtime probe.
	Config install.Config
	// SocketPath is where the Unix socket is created; empty => DefaultSocketPath.
	SocketPath string
	// SocketGroup chowns the socket to this group; empty => no chown (tests).
	SocketGroup string
	// IdentityKeyPath is the daemon Ed25519 private key; startup fails fast if it
	// is absent or not 0600. Empty => Config.IdentityKey.
	IdentityKeyPath string
	// Verifier performs verify-before-serve. Required — the daemon refuses to
	// construct without one so the signed-toolchain gate is never accidentally
	// skipped. Wire DenyVerifier to fail closed when no toolchain is configured.
	Verifier ToolchainVerifier
	// RuntimeProbe reports isolation-runtime availability (F0.3 Available()).
	// nil => a probe of the configured tier's runtime.
	RuntimeProbe func() error
	// Ready is called once the socket is listening (e.g. systemd sd-notify).
	// nil => no-op; kept behind this seam so tests need no systemd.
	Ready func()
	// Version is reported by /v1/health.
	Version string
	// Logger receives structured startup/shutdown logs. nil => slog default.
	Logger *slog.Logger
	// Sessions is the F1.2 session manager backing the /v1/sessions routes. nil
	// keeps the daemon at its F1.1 surface (health only) — the routes 404 —
	// which is what F1.1-scope tests rely on.
	Sessions SessionService
	// Projects is the F8.1 project/environment registry backing the /v1/projects
	// routes. nil keeps those routes 404 (the same opt-in shape as Sessions), so a
	// daemon built without the control tower is unchanged.
	Projects ProjectService
	// Secrets is the F5.6 secret MANAGEMENT surface (Put/List/Delete — the narrow
	// broker.SecretManager, which has NO Get). nil keeps the /v1/secrets routes
	// 404. There is deliberately no route that returns a secret value — Get is
	// daemon-internal (session.Manager.ResolveSecret), not part of this surface.
	Secrets broker.SecretManager
	// SecretsSvc is the F8.3 operator surface over the same vault: listing with
	// consumers, rotation, and a delete guarded by them. It is metadata-only by
	// construction — it holds the same Get-less SecretManager. nil leaves the F8.3
	// routes off and the F5.6 routes unchanged.
	SecretsSvc *broker.SecretsService
}

// Daemon is the running service. Construct with New; drive with Run (or the
// finer-grained Startup/Listen/Serve for tests).
type Daemon struct {
	socketPath   string
	socketGroup  string
	identityPath string
	verifier     ToolchainVerifier
	runtimeProbe func() error
	ready        func()
	log          *slog.Logger
	sessions     SessionService
	projects     ProjectService
	secrets      broker.SecretManager
	secretsSvc   *broker.SecretsService

	version  string
	tier     string
	identity string // public fingerprint, populated at startup (never the key)
	// trustedPub is the daemon's OWN Ed25519 public key, loaded at startup from
	// the identity file. It is the out-of-band trust anchor the F3.6 server-side
	// verify endpoint pins the trace seal against (trace.Verify): the browser only
	// renders the verdict and can never fabricate a ✓, because this key is derived
	// from the daemon's identity, not from the seal the endpoint is checking.
	trustedPub ed25519.PublicKey
}

// New validates Options and builds a Daemon. It applies non-root defaults but
// requires a Verifier (the verify-before-serve gate must be a deliberate wiring,
// never a silent no-op).
func New(opts Options) (*Daemon, error) {
	if opts.Verifier == nil {
		return nil, errors.New("daemon: a ToolchainVerifier is required (verify-before-serve is non-optional)")
	}
	d := &Daemon{
		socketPath:   orDefault(opts.SocketPath, DefaultSocketPath),
		socketGroup:  opts.SocketGroup,
		identityPath: orDefault(opts.IdentityKeyPath, opts.Config.IdentityKey),
		verifier:     opts.Verifier,
		runtimeProbe: opts.RuntimeProbe,
		ready:        opts.Ready,
		log:          opts.Logger,
		sessions:     opts.Sessions,
		projects:     opts.Projects,
		secrets:      opts.Secrets,
		secretsSvc:   opts.SecretsSvc,
		version:      orDefault(opts.Version, "dev"),
		tier:         opts.Config.Tier,
	}
	if d.identityPath == "" {
		d.identityPath = install.DefaultIdentityKeyPath
	}
	if d.log == nil {
		d.log = slog.Default()
	}
	if d.runtimeProbe == nil {
		d.runtimeProbe = probeForTier(d.tier)
	}
	if d.ready == nil {
		d.ready = func() {}
	}
	return d, nil
}

// Startup performs the fail-fast pre-serve gates in order: (1) load + validate
// the identity key (present, 0600); (2) verify the signed toolchain. It creates
// no listener and touches no port, so tests exercise refusal paths directly. On
// success the public identity fingerprint is recorded for /v1/health.
func (d *Daemon) Startup(ctx context.Context) error {
	id, err := install.LoadIdentity(d.identityPath)
	if err != nil {
		return err // already layer-tagged + legible; contains no key material
	}
	d.identity = id.Fingerprint
	// Record the daemon's own public key as the out-of-band trust anchor for
	// server-side trace verification (F3.6). A malformed hex here is non-fatal:
	// the verify endpoint fails closed (a sealed session cannot be anchored, so
	// trace.Verify reports it unverifiable) rather than the daemon refusing to serve.
	if pub, decErr := hex.DecodeString(id.PublicKeyHex); decErr == nil && len(pub) == ed25519.PublicKeySize {
		d.trustedPub = ed25519.PublicKey(pub)
	}
	d.log.Info("identity loaded", "fingerprint", id.Fingerprint, "key_path", d.identityPath)

	if err := d.verifier.VerifyToolchain(ctx); err != nil {
		return err
	}
	d.log.Info("toolchain verified (verify-before-serve passed)")
	return nil
}

// Listen creates the permissioned Unix socket. Separated from Serve so tests can
// assert the socket's perms/group before any request.
func (d *Daemon) Listen() (net.Listener, error) {
	ln, err := listenUnix(d.socketPath, d.socketGroup)
	if err != nil {
		return nil, err
	}
	d.log.Info("listening", "socket", d.socketPath, "perms", SocketPerm.String(), "group", d.socketGroup)
	return ln, nil
}

// Serve serves HTTP on ln until ctx is cancelled, then drains in-flight requests
// within shutdownGrace and returns. A clean shutdown returns nil (not
// http.ErrServerClosed). It calls Ready once serving begins.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: d.Handler()}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	d.ready()

	select {
	case <-ctx.Done():
		d.log.Info("shutdown signal received; draining")
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("daemon: graceful shutdown: %w", err)
		}
		<-serveErr // Serve returns ErrServerClosed after Shutdown
		d.log.Info("shutdown complete")
		return nil
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("daemon: serve: %w", err)
	}
}

// Run is the production entrypoint: Startup gates, then Listen, then Serve until
// ctx is cancelled (SIGTERM in main). The socket is removed on return so no
// orphaned socket file survives a clean shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.Startup(ctx); err != nil {
		return err
	}
	ln, err := d.Listen()
	if err != nil {
		return err
	}
	defer ln.Close() // unix listener unlinks the socket path on Close
	return d.Serve(ctx, ln)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
