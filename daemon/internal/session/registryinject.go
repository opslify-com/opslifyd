package session

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/regproxy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// F7.5 — per-session registry-proxy wiring. This mirrors the F5.7 EgressInjector:
// at session create, when the F5.5 registry proxy is configured, it stands up a
// per-session regproxy.Proxy bound to the session's resolved `creds` grants + the
// session trace recorder, binds the listener to the F5.8 bridge gateway (source-IP
// scoped, never 0.0.0.0), and injects the ecosystem ROUTING env (PIP_INDEX_URL /
// NPM_CONFIG_REGISTRY / GOPROXY -> the gateway proxy URL) so an in-sandbox package
// manager resolves THROUGH the proxy. The injected env carries the gateway URL
// only — NEVER a credential (the proxy injects the upstream credential server-side,
// exactly as F5.5). It is opt-in (no registry_proxy config => no injector => no env
// change) and FAIL-CLOSED (no reachable gateway => no routing env, never an
// open-egress fallback).

// RegistryInjectConfig wires a RegistryInjector. Config is daemon-authoritative
// (a workspace can never introduce or widen an upstream/allowlist); Broker is the
// F5.6 policy-gated resolver the proxy uses on the upstream leg.
type RegistryInjectConfig struct {
	// Config is the daemon F5.5 registry-proxy config (upstreams + allowlist +
	// cache dir). An empty Upstreams set yields a disabled injector (no proxy is
	// ever built, no env injected).
	Config regproxy.Config
	// Broker is the F5.6 credential broker the proxy resolves the upstream
	// credential through (deny-by-default + valueless cred.resolve audit). nil => no
	// injection resolves (public fetch only).
	Broker *broker.Broker
	// Verifier is the F5.5 attestation seam. nil => any RequireAttestation upstream
	// is refused fail-closed (the proxy's own contract).
	Verifier regproxy.AttestationVerifier
	// Upstream is the RoundTripper the proxy uses for the proxy->upstream fetch.
	// nil => http.DefaultTransport (production). Tests inject an in-process stub.
	Upstream http.RoundTripper
	// Logger is the daemon logger. nil => slog.Default.
	Logger *slog.Logger
	// Now is the injected clock (tests). nil => time.Now.
	Now func() time.Time
	// listen builds a per-session listener; nil => a fresh loopback listener. The
	// manager overrides it with the F5.8 gateway bind. Tests may override it too.
	listen func() (net.Listener, error)
}

// RegistryInjector is the daemon-authoritative F7.5 per-session registry-proxy
// factory. A nil injector is a no-op (opt-in). It is enabled only when at least one
// upstream is configured.
type RegistryInjector struct {
	cfg      regproxy.Config
	broker   *broker.Broker
	verifier regproxy.AttestationVerifier
	upstream http.RoundTripper
	log      *slog.Logger
	now      func() time.Time
	listen   func() (net.Listener, error)
	enabled  bool
}

// NewRegistryInjector builds a RegistryInjector from daemon config. When Config
// carries no upstream the injector is DISABLED (buildForSession is a clean no-op),
// so callers may always pass it to the manager without a behavior change.
func NewRegistryInjector(cfg RegistryInjectConfig) *RegistryInjector {
	ri := &RegistryInjector{
		cfg:      cfg.Config,
		broker:   cfg.Broker,
		verifier: cfg.Verifier,
		upstream: cfg.Upstream,
		log:      cfg.Logger,
		now:      cfg.Now,
		listen:   cfg.listen,
		enabled:  len(cfg.Config.Upstreams) > 0,
	}
	if ri.log == nil {
		ri.log = slog.Default()
	}
	if ri.listen == nil {
		ri.listen = func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	}
	return ri
}

// Configured reports whether the registry proxy is enabled on this daemon (at least
// one upstream). The F7.5 CLI uses it to fail-closed ("install unavailable") rather
// than fall back to open-egress when no proxy is configured.
func (ri *RegistryInjector) Configured() bool {
	return ri != nil && ri.enabled
}

// Allowed is the pre-install allowlist gate the operator CLI calls BEFORE running an
// install: it delegates to the daemon-authoritative regproxy allowlist (deny-by-
// default, same normalization the fetch path uses), so a non-allowlisted / typosquat
// name is refused before any exec. A disabled injector reports (false, nil).
func (ri *RegistryInjector) Allowed(eco regproxy.Ecosystem, name string) (bool, error) {
	if !ri.Configured() {
		return false, nil
	}
	return ri.cfg.Allowed(eco, name)
}

// sessionRegistry is one live session's registry-proxy handle: the sandbox-reachable
// listener address, the ecosystem routing env to merge into every exec, and a close
// func that tears the listener down on session end (no cross-session reuse).
type sessionRegistry struct {
	addr  string
	env   []string
	close func()
}

// buildForSession constructs and starts a per-session registry proxy when the proxy
// is configured. It returns:
//   - (nil, nil) when the injector is disabled/absent (opt-in: no env injected);
//   - (sr, nil) with a started listener + the routing env on success;
//   - (nil, err) on a proxy-build/listener failure — the manager then injects NO
//     routing env and NO open-egress fallback (fail-closed).
//
// listen/sourceIP/advertiseHost carry the F5.8 reachable-bind wiring the manager
// supplies (mirroring the egress path):
//   - listen (nil => ri.listen loopback default) binds the listener. The manager
//     passes a bridge-GATEWAY listener so the sandbox can route to it.
//   - sourceIP (empty => no scope, legacy loopback only) restricts the listener to
//     the owning container's IP.
//   - advertiseHost (empty => bound addr as-is) is the gateway host advertised in
//     the routing env, paired with the actual bound port.
func (ri *RegistryInjector) buildForSession(sessionID string, resolved policy.Resolved, rec *trace.Recorder, listen func() (net.Listener, error), sourceIP, advertiseHost string) (*sessionRegistry, error) {
	if ri == nil || !ri.enabled {
		return nil, nil
	}
	// Guard: never advertise (hence bind) a wildcard for this credential-injecting
	// listener. Defense-in-code — a routable/world bind is a BLOCKING defect (F5.8).
	if advertiseHost != "" && !isBindableGateway(advertiseHost) {
		return nil, fmt.Errorf("regproxy: refusing to bind proxy to non-reachable host %q", advertiseHost)
	}
	proxy, err := regproxy.NewProxy(regproxy.Options{
		SessionID: sessionID,
		Config:    ri.cfg,
		Broker:    ri.broker,
		Grants:    resolved.Creds,
		Recorder:  rec,
		Verifier:  ri.verifier,
		Upstream:  ri.upstream,
		Now:       ri.now,
	})
	if err != nil {
		return nil, fmt.Errorf("regproxy: build per-session proxy: %w", err)
	}
	if listen == nil {
		listen = ri.listen
	}
	ln, err := listen()
	if err != nil {
		return nil, fmt.Errorf("regproxy: bind per-session proxy listener: %w", err)
	}
	srv := &http.Server{Handler: sourceScoped(http.HandlerFunc(proxy.ServeHTTP), sourceIP, ri.log)}
	go func() {
		if serr := srv.Serve(ln); serr != nil && serr != http.ErrServerClosed {
			ri.log.Warn("registry proxy listener stopped", "session", sessionID, "err", serr)
		}
	}()
	addr := ln.Addr().String()
	if advertiseHost != "" {
		if _, port, perr := net.SplitHostPort(addr); perr == nil {
			addr = net.JoinHostPort(advertiseHost, port)
		}
	}
	return &sessionRegistry{
		addr:  addr,
		env:   ri.routingEnv("http://" + addr),
		close: func() { _ = srv.Close() },
	}, nil
}

// routingEnv builds the ecosystem routing env pointing the sandbox's package
// managers at the proxy base URL. It emits env ONLY for CONFIGURED ecosystems, so a
// go build in a session with no `go` upstream keeps its default GOPROXY rather than
// being pointed at a proxy that would deny it. The env carries the gateway URL only
// — NEVER a credential (the proxy injects the upstream credential server-side).
func (ri *RegistryInjector) routingEnv(base string) []string {
	var env []string
	for _, u := range ri.cfg.Upstreams {
		switch u.Ecosystem {
		case regproxy.EcosystemPyPI:
			idx := base + "/pypi/simple"
			env = append(env,
				"PIP_INDEX_URL="+idx,
				"PIP_EXTRA_INDEX_URL="+idx,
			)
		case regproxy.EcosystemNPM:
			env = append(env, "NPM_CONFIG_REGISTRY="+base+"/npm/")
		case regproxy.EcosystemGo:
			// GOPROXY consults the proxy directly (no fallthrough to the public
			// proxy) so a fetch is always allowlist-gated + audited.
			env = append(env,
				"GOPROXY="+base+"/go",
				"GOFLAGS=-mod=mod",
			)
		}
	}
	return env
}
