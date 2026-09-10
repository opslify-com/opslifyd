package session

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/egressproxy"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// SandboxCAFileName is the workspace-relative filename the daemon writes the
// per-session egress-proxy CA PEM to. The sandbox reads it via CURL_CA_BUNDLE /
// SSL_CERT_FILE / REQUESTS_CA_BUNDLE / GIT_SSL_CAINFO at <mount>/<name>. It is
// daemon-WRITTEN (never the private key — only the public CA cert): if the agent
// overwrites it, its own TLS to the proxy breaks (self-DoS) but it CANNOT thereby
// obtain the token, which the proxy adds on the upstream leg regardless of the
// client's trust store.
const SandboxCAFileName = ".opslify-ca.pem"

// sandboxWorkspaceMount is where the per-session /workspace host dir is
// bind-mounted inside the sandbox (F0.3). The CA env vars point at the CA file
// under THIS mount path, not the host path.
const sandboxWorkspaceMount = "/workspace"

// EgressInjectConfig wires an EgressInjector. Rules + NeverMITM are
// daemon-authoritative (a workspace can never introduce or widen either); Broker
// is the F5.6 policy-gated resolver the proxy uses at the network boundary.
type EgressInjectConfig struct {
	// Rules are the daemon-config egress-inject rules (F5.7). A rule only lights up
	// for a session whose RESOLVED policy both grants its cred and egress-allows its
	// host (F4.1 narrows-not-widens).
	Rules []egressproxy.InjectRule
	// NeverMITM lists checksum/signature hosts that must be SNI pass-through, never
	// TLS-terminated (F5.2/F5.5). Passed through to the proxy config.
	NeverMITM []string
	// Broker is the F5.6 credential broker the proxy resolves header secrets through
	// (deny-by-default + valueless cred.resolve audit). nil => no injection resolves.
	Broker *broker.Broker
	// Upstream is the RoundTripper the proxy uses for the FORWARDED (injected)
	// request. nil => http.DefaultTransport (production). Tests inject a stub.
	Upstream http.RoundTripper
	// NoProxy are extra NO_PROXY entries injected into the sandbox alongside
	// localhost/127.0.0.1 (e.g. the F5.1 creds endpoint / cloud metadata IP) so those
	// blind-path fetches never route through the egress proxy.
	NoProxy []string
	// Now is the injected clock (tests). nil => time.Now (unused directly today but
	// carried for parity with the rest of the manager's injected clocks).
	Now func() time.Time
	// Logger is the daemon logger. nil => slog.Default.
	Logger *slog.Logger
	// listen builds a per-session listener; nil => a fresh loopback listener. Tests
	// override it only to assert bind failure is fail-closed.
	listen func() (net.Listener, error)
	// dial dials an upstream for a pass-through CONNECT tunnel; nil => a TCP dialer.
	dial func(ctx context.Context, host string) (net.Conn, error)
}

// EgressInjector is the daemon-authoritative F5.7 per-session egress-proxy factory.
// At session create it builds a per-session egressproxy.Proxy (F5.2) bound to the
// session's resolved policy + a fresh per-session CA, starts a sandbox-reachable
// loopback listener that speaks the HTTP forward-proxy protocol (CONNECT for HTTPS
// injection targets), and returns the listener addr + CA PEM so the manager can
// route the sandbox through it. A nil EgressInjector is a no-op (opt-in: no
// egress_inject config => no proxy, no env change).
type EgressInjector struct {
	rules     []egressproxy.InjectRule
	neverMITM []string
	broker    *broker.Broker
	upstream  http.RoundTripper
	noProxy   []string
	now       func() time.Time
	log       *slog.Logger
	listen    func() (net.Listener, error)
	dial      func(ctx context.Context, host string) (net.Conn, error)
	// refs is the set of every rule CredRef, so the manager can EXCLUDE an
	// egress-inject-designated secret from the F5.1 env injector — such a secret is
	// resolved ONLY at the proxy boundary and is never placed in the sandbox env.
	refs map[string]struct{}
}

// NewEgressInjector builds an EgressInjector from daemon config. A nil/empty Rules
// set still returns a usable injector, but it will never build a proxy (nothing to
// inject) — callers should pass nil to the manager when there are no rules.
func NewEgressInjector(cfg EgressInjectConfig) *EgressInjector {
	ei := &EgressInjector{
		rules:     cfg.Rules,
		neverMITM: cfg.NeverMITM,
		broker:    cfg.Broker,
		upstream:  cfg.Upstream,
		noProxy:   cfg.NoProxy,
		now:       cfg.Now,
		log:       cfg.Logger,
		listen:    cfg.listen,
		dial:      cfg.dial,
		refs:      map[string]struct{}{},
	}
	for _, r := range cfg.Rules {
		ei.refs[r.CredRef] = struct{}{}
	}
	if ei.now == nil {
		ei.now = time.Now
	}
	if ei.log == nil {
		ei.log = slog.Default()
	}
	if ei.listen == nil {
		ei.listen = func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	}
	if ei.dial == nil {
		ei.dial = defaultEgressDial
	}
	return ei
}

// sessionEgress is one live session's egress-proxy handle: the sandbox-reachable
// listener address, the per-session CA cert (PEM) to write into the sandbox trust
// store, and a close func that tears the listener down on session end (no
// cross-session reuse — a second session gets a wholly fresh proxy + CA).
type sessionEgress struct {
	addr  string
	caPEM []byte
	close func()
}

// isEgressInjectRef reports whether ref is designated for egress-boundary injection
// (F5.7). Such a secret is resolved ONLY by the proxy on the upstream leg and is
// NEVER handed to the F5.1 env injector — so it can never land in the sandbox env.
func (ei *EgressInjector) isEgressInjectRef(ref string) bool {
	if ei == nil {
		return false
	}
	_, ok := ei.refs[ref]
	return ok
}

// applicable filters the daemon rules to the ones this session's RESOLVED policy
// actually permits: the host must be egress-allowed AND the cred must be granted.
// This is the F4.1 narrows-not-widens gate — a workspace (which can only NARROW the
// resolved policy) can never add or widen an egress-inject host. It mirrors the
// fail-closed drop BuildConfig applies, used here to decide whether to build a
// proxy at all (no applicable rule => no proxy, no env change).
func (ei *EgressInjector) applicable(resolved policy.Resolved) []egressproxy.InjectRule {
	return applicableRules(ei.rules, resolved)
}

// applicableRules filters rules against the RESOLVED policy: a rule only applies
// where the policy both allows the host and grants the cred.
//
// This is what keeps a connection from widening a session. An operator can define
// a connection to any host, but if the resolved policy does not allow that host
// and grant that cred, the rule is dropped — so a connection narrows or matches
// policy and can never exceed it.
func applicableRules(rules []egressproxy.InjectRule, resolved policy.Resolved) []egressproxy.InjectRule {
	allow := map[string]struct{}{}
	for _, d := range resolved.Egress.Domains {
		allow[strings.ToLower(d)] = struct{}{}
	}
	granted := map[string]struct{}{}
	for _, c := range resolved.Creds {
		granted[c.Name] = struct{}{}
	}
	var out []egressproxy.InjectRule
	for _, r := range rules {
		if _, ok := allow[strings.ToLower(r.Host)]; !ok {
			continue
		}
		if _, ok := granted[r.CredRef]; !ok {
			continue
		}
		out = append(out, r)
	}
	return out
}

// buildForSession constructs and starts a per-session egress proxy when the
// session's resolved policy lights up at least one egress-inject rule. It returns:
//   - (nil, nil) when no rule applies (opt-in: the manager injects no proxy env);
//   - (se, nil) with a started listener + the per-session CA PEM on success;
//   - (nil, err) on a proxy-build/listener failure — the manager then injects NO
//     proxy env and NO raw-secret fallback (fail-closed).
//
// listen/sourceIP/advertiseHost carry the F5.8 reachable-bind wiring the manager
// supplies once it has discovered the container's network:
//   - listen (nil => ei.listen, the legacy loopback default used in unit tests
//     and when the runtime exposes no NetworkInfo) binds the listener. The manager
//     passes a bridge-GATEWAY listener so the sandbox can actually route to it.
//   - sourceIP (empty => no scope, legacy loopback only) restricts the listener to
//     the owning container's IP, on top of the proxy's own boundary — a neighbour
//     container or LAN host is refused even off the bridge gateway.
//   - advertiseHost (empty => the bound addr as-is) is the host advertised in the
//     sandbox HTTPS_PROXY env: the gateway address, paired with the actual bound
//     port, since the listener may be bound to an address the daemon-side Addr()
//     does not name literally.
//
// extraRules are per-session header injections contributed by F8.2 connections.
// They are merged with the daemon-config rules rather than replacing them, and a
// session with ONLY connection-derived rules still gets a proxy — otherwise a
// connection would be defined, stored, shown to the operator, and silently do
// nothing.
func (ei *EgressInjector) buildForSession(sessionID string, resolved policy.Resolved, rec *trace.Recorder, listen func() (net.Listener, error), sourceIP, advertiseHost string, extraRules []egressproxy.InjectRule) (*sessionEgress, error) {
	if ei == nil {
		return nil, nil
	}
	rules := append(append([]egressproxy.InjectRule(nil), ei.rules...), extraRules...)
	if len(rules) == 0 {
		return nil, nil
	}
	if len(applicableRules(rules, resolved)) == 0 {
		return nil, nil
	}
	// Guard: never advertise (hence bind) a wildcard for this credential-injecting
	// listener. The manager only sets advertiseHost from a discovered gateway, but
	// this is defense-in-code — a routable/world bind is a BLOCKING defect.
	if advertiseHost != "" && !isBindableGateway(advertiseHost) {
		return nil, fmt.Errorf("egress: refusing to bind proxy to non-reachable host %q", advertiseHost)
	}
	proxy, err := egressproxy.NewSessionProxy(sessionID, resolved, egressproxy.SessionConfig{
		Rules:     rules,
		NeverMITM: ei.neverMITM,
	}, ei.broker, rec, ei.upstream)
	if err != nil {
		return nil, fmt.Errorf("egress: build per-session proxy: %w", err)
	}
	caPEM := proxy.CACertPEM()
	if len(caPEM) == 0 {
		return nil, fmt.Errorf("egress: per-session proxy produced no CA cert")
	}
	if listen == nil {
		listen = ei.listen
	}
	ln, err := listen()
	if err != nil {
		return nil, fmt.Errorf("egress: bind per-session proxy listener: %w", err)
	}
	srv := &http.Server{Handler: sourceScoped(ei.proxyHandler(proxy), sourceIP, ei.log)}
	go func() {
		if serr := srv.Serve(ln); serr != nil && serr != http.ErrServerClosed {
			ei.log.Warn("egress proxy listener stopped", "session", sessionID, "err", serr)
		}
	}()
	addr := ln.Addr().String()
	if advertiseHost != "" {
		if _, port, perr := net.SplitHostPort(addr); perr == nil {
			addr = net.JoinHostPort(advertiseHost, port)
		}
	}
	return &sessionEgress{
		addr:  addr,
		caPEM: caPEM,
		close: func() {
			_ = srv.Close()
		},
	}, nil
}

// proxyHandler adapts the F5.2 Proxy to the HTTP forward-proxy protocol the
// sandbox's HTTPS_PROXY client speaks: a CONNECT is hijacked and handed to
// ServeCONNECT (which TLS-terminates injection targets with the per-session CA and
// SNI-tunnels everything else), and a plain-HTTP proxy request is Forwarded (header
// injected on the upstream clone only). The token is NEVER added to the response or
// visible to the client — it rides only the upstream leg.
func (ei *EgressInjector) proxyHandler(p *egressproxy.Proxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "proxy: connection hijack unsupported", http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				return
			}
			_ = p.ServeCONNECT(r.Context(), r.Host, conn, ei.dial)
			return
		}
		// Plain HTTP forward-proxy request (r.URL is absolute). Forward through the
		// F5.2 boundary; the injected header lands on the upstream clone only.
		resp, err := p.Forward(r.Context(), r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
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

// defaultEgressDial dials the real upstream for a pass-through CONNECT tunnel,
// defaulting to :443 when the authority carries no port.
func defaultEgressDial(ctx context.Context, host string) (net.Conn, error) {
	hp := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		hp = net.JoinHostPort(host, "443")
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", hp)
}
