// Package egressproxy implements F5.2 — the L7 egress proxy that makes generic
// HTTP(S) sandbox traffic credential-blind. All sandbox HTTP(S) egress is routed
// to this daemon-side proxy; a policy-granted auth header is injected at the
// NETWORK BOUNDARY, so the token is added AFTER traffic leaves the sandbox and the
// agent inside never sees it — not in env, files, proc, or the request it sent.
//
// SECURITY POSTURE (read before touching this package):
//   - The injected token is added ONLY to the forwarded upstream request. The
//     sandbox-originated request object is never mutated to carry it, and the token
//     never appears in a trace/log (cred.resolve is valueless).
//   - Two host modes, decided FAIL-CLOSED from the resolved (F4.1-narrowed) policy:
//     TLS-terminate (per-session CA) for header-injection targets, and
//     SNI-validated PASS-THROUGH (never decrypted) for everything else, including
//     checksum/signature-verifying hosts that must NOT be MITM'd (routed to F5.5).
//   - No policy match => ModeDeny, mapping back to F1.4 default-deny. Non-HTTP
//     traffic is never touched here; it stays default-deny + DNS-pinned (F1.4).
//   - Per-session CA is a hard trust boundary: minted per session, key never
//     leaves the daemon, never reused across sessions (see ca.go).
//
// INTEGRATION-GATED (honest scope): the real in-sandbox -> proxy routing, the
// sandbox actually trusting the per-session CA, and end-to-end TLS-terminate
// against a live upstream are integration-gated. This package UNIT-tests the
// decision table, header injection on the forwarded request (and its ABSENCE on
// the sandbox request), SNI pass-through-not-decrypted, per-session CA scoping,
// anomaly emission, and cred.resolve being valueless.
package egressproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// ErrDeny is the layer-tagged sentinel for a proxy default-deny (failure
// legibility: this is an `egress`-layer denial, distinct from sandbox/cred).
var ErrDeny = errors.New("egress: proxy default-deny (no policy match)")

// Proxy is one session's L7 egress proxy. It holds the session's decision table,
// per-session CA, the broker (for policy-gated header-secret resolution), the
// session's resolved `creds` grants, and an injectable upstream transport (a live
// dialer in production, an in-process stub in tests). A single Proxy serves one
// session; the daemon builds one per session at create.
type Proxy struct {
	sessionID string
	cfg       Config
	ca        *SessionCA
	brk       *broker.Broker
	grants    []policy.Cred
	rec       *trace.Recorder
	anomaly   AnomalyConfig
	// upstream is the RoundTripper used for the FORWARDED (injected) request. In
	// production it is a TLS-dialing transport to the real host; tests inject a stub.
	upstream http.RoundTripper
}

// New builds a per-session proxy. A nil broker/recorder is tolerated (fail-closed:
// injection then resolves nothing). A nil upstream defaults to http.DefaultTransport.
func New(sessionID string, cfg Config, ca *SessionCA, brk *broker.Broker, grants []policy.Cred, rec *trace.Recorder, anomaly AnomalyConfig, upstream http.RoundTripper) *Proxy {
	if upstream == nil {
		upstream = http.DefaultTransport
	}
	return &Proxy{
		sessionID: sessionID,
		cfg:       cfg,
		ca:        ca,
		brk:       brk,
		grants:    grants,
		rec:       rec,
		anomaly:   anomaly,
		upstream:  upstream,
	}
}

// SessionConfig is the daemon-authoritative, per-daemon F5.2 configuration the
// session manager combines with a session's RESOLVED policy to build a Proxy. It
// holds the injection rules and the never-MITM (checksum/signature) host list;
// both are daemon-owned so a workspace can never introduce or widen either (the
// rules are additionally dropped fail-closed by BuildConfig against the resolved
// grants).
type SessionConfig struct {
	Rules     []InjectRule
	NeverMITM []string
	Anomaly   AnomalyConfig
}

// NewSessionProxy is the PER-SESSION entrypoint the session manager calls at
// session create (once in-sandbox -> proxy routing + CA trust injection are wired;
// that path is integration-gated). It mints a fresh per-session CA, builds the
// fail-closed decision table from the resolved policy, and returns the ready
// Proxy. upstream nil => http.DefaultTransport.
func NewSessionProxy(sessionID string, resolved policy.Resolved, sc SessionConfig, brk *broker.Broker, rec *trace.Recorder, upstream http.RoundTripper) (*Proxy, error) {
	ca, err := NewSessionCA(sessionID, nil)
	if err != nil {
		return nil, err
	}
	cfg := BuildConfig(resolved, sc.Rules, sc.NeverMITM)
	return New(sessionID, cfg, ca, brk, resolved.Creds, rec, sc.Anomaly, upstream), nil
}

// CACertPEM is the per-session CA cert to inject read-only into the sandbox trust
// store (integration-gated wiring). Nil CA => nil.
func (p *Proxy) CACertPEM() []byte {
	if p.ca == nil {
		return nil
	}
	return p.ca.CertPEM()
}

// Forward is the TLS-TERMINATE injection path, exercised on a request the proxy
// has ALREADY decrypted from the sandbox (via the per-session CA). It is the
// credential-blind boundary:
//
//  1. Decide the mode fail-closed. Only ModeTerminate proceeds here; ModeDeny is
//     an ErrDeny, and a passthrough host must never reach this path (it is not
//     decrypted) — if it does, it is forwarded WITHOUT injection (fail-closed: no
//     header for a non-terminate host).
//  2. Read + bound the outbound body, entropy/cap-scan it, emit egress.anomaly on
//     a trip. The body is never logged.
//  3. Build a SEPARATE upstream request. The auth header (resolved via the broker,
//     deny-by-default + valueless cred.resolve audit) is set ONLY on that upstream
//     request. The sandbox request `sandboxReq` is NEVER mutated to carry it.
//  4. RoundTrip the upstream request and return its response.
//
// The returned response is the upstream's; sandboxReq is left byte-for-byte as the
// sandbox sent it (proof: no token on the sandbox side).
func (p *Proxy) Forward(ctx context.Context, sandboxReq *http.Request) (*http.Response, error) {
	host := hostname(sandboxReq.Host)
	if host == "" {
		host = hostname(sandboxReq.URL.Host)
	}
	dec := p.cfg.Decide(sandboxReq.Method, host, sandboxReq.URL.Path)
	if dec.Mode == ModeDeny {
		return nil, fmt.Errorf("%w: %s %s%s", ErrDeny, sandboxReq.Method, host, sandboxReq.URL.Path)
	}

	// Read + bound the outbound body once, so we can both scan it and replay it
	// upstream. The read is capped at cap+1 so an oversized upload is DETECTED
	// (capped=true) with bounded memory, never streamed unbounded.
	body, err := p.readBounded(sandboxReq.Body)
	if err != nil {
		return nil, fmt.Errorf("egress: read outbound body: %w", err)
	}
	if res := scanBody(body, p.anomaly); res.Flagged {
		emitAnomaly(ctx, p.rec, sandboxReq.Method, host, sandboxReq.URL.Path, res)
	}

	// Build the upstream request as a SEPARATE object cloned from the sandbox
	// request. Header injection happens ONLY on this clone.
	up, err := p.buildUpstream(ctx, sandboxReq, host, body)
	if err != nil {
		return nil, err
	}
	if dec.Mode == ModeTerminate && dec.Inject != nil {
		p.injectHeader(ctx, up, *dec.Inject)
	}
	return p.upstream.RoundTrip(up)
}

// buildUpstream clones sandboxReq into an independent upstream *http.Request with a
// fresh body reader. It intentionally does not copy the sandbox's own auth header
// blindly — but it preserves the sandbox's headers so non-injected APIs still work;
// the injected header is added afterward on the clone only.
func (p *Proxy) buildUpstream(ctx context.Context, sandboxReq *http.Request, host string, body []byte) (*http.Request, error) {
	scheme := sandboxReq.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	url := scheme + "://" + host + sandboxReq.URL.RequestURI()
	up, err := http.NewRequestWithContext(ctx, sandboxReq.Method, url, bytesReader(body))
	if err != nil {
		return nil, fmt.Errorf("egress: build upstream request: %w", err)
	}
	for k, vs := range sandboxReq.Header {
		for _, v := range vs {
			up.Header.Add(k, v)
		}
	}
	up.ContentLength = int64(len(body))
	return up, nil
}

// injectHeader resolves the rule's cred through the broker (deny-by-default,
// valueless cred.resolve audit) and sets the auth header on the UPSTREAM request
// only. It is FAIL-CLOSED: a resolve failure injects NO header (no raw-secret
// leak, no partial header) — the request simply goes upstream without auth. The
// resolved plaintext is Zeroized immediately; only the formatted header string
// (which the upstream needs) is retained, and it never enters a trace/log.
func (p *Proxy) injectHeader(ctx context.Context, up *http.Request, rule InjectRule) {
	if p.brk == nil {
		return
	}
	value, _, err := p.brk.Resolve(ctx, p.rec, p.grants, rule.CredRef)
	if err != nil {
		return // fail-closed: no header
	}
	headerVal := string(value)
	broker.Zeroize(value)
	if rule.HeaderFormat != "" {
		headerVal = fmt.Sprintf(rule.HeaderFormat, headerVal)
	}
	name := rule.HeaderName
	if name == "" {
		name = "Authorization"
	}
	up.Header.Set(name, headerVal)
}

// readBounded reads at most cap+1 bytes from r (so scanBody can see it reached the
// cap), then closes r. A nil body is empty.
func (p *Proxy) readBounded(r io.ReadCloser) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	defer r.Close()
	limit := p.anomaly.cap() + 1
	b, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// ServeCONNECT handles a proxy CONNECT for target authority (host:port). It is the
// HTTPS entrypoint: the sandbox's HTTPS client issues CONNECT, and the proxy then
// either TLS-terminates (if any inject rule could apply to the host) or
// SNI-validates + tunnels un-decrypted. A denied host is refused before any bytes
// flow (fail-closed => F1.4 default-deny).
//
// clientConn is the hijacked client connection (the 200 response must already have
// been written by the caller). dialUpstream dials the real upstream for
// pass-through (injectable for tests). This method is the integration seam; the
// per-mode LOGIC it calls (Decide, sniFromClientHello, LeafFor, Forward) is what
// the unit tests exercise directly.
func (p *Proxy) ServeCONNECT(ctx context.Context, authority string, clientConn net.Conn, dialUpstream func(ctx context.Context, host string) (net.Conn, error)) error {
	host := hostname(authority)
	if !p.cfg.Allowed(host) {
		return fmt.Errorf("%w: CONNECT %s", ErrDeny, host)
	}
	// A host with any terminate rule is MITM'd; otherwise pass-through. Never-MITM
	// hosts are forced to pass-through by Decide/BuildConfig.
	if p.hostTerminates(host) {
		return p.serveTerminate(ctx, host, clientConn)
	}
	return p.servePassthrough(ctx, host, clientConn, dialUpstream)
}

// hostTerminates reports whether the host has at least one injection rule (=> it
// is a TLS-terminate target). A never-MITM host never has one (BuildConfig drops
// it), so this can never select MITM for a checksum host.
func (p *Proxy) hostTerminates(host string) bool {
	for i := range p.cfg.injectByID {
		if p.cfg.injectByID[i].matches("", host, "") {
			return true
		}
		if p.cfg.injectByID[i].Host == host {
			return true
		}
	}
	return false
}

// serveTerminate completes a TLS handshake with the sandbox using a per-session-CA
// leaf for host, then serves each decrypted HTTP request through Forward (which
// injects at the boundary). The leaf is scoped to host and signed by THIS
// session's CA only.
func (p *Proxy) serveTerminate(ctx context.Context, host string, clientConn net.Conn) error {
	if p.ca == nil {
		return fmt.Errorf("egress: no per-session CA for terminate of %s", host)
	}
	leaf, err := p.ca.LeafFor(host)
	if err != nil {
		return err
	}
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("egress: terminate handshake %s: %w", host, err)
	}
	defer tlsConn.Close()
	br := newConnReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("egress: read decrypted request %s: %w", host, err)
		}
		req.Host = host
		req.URL.Scheme = "https"
		req.URL.Host = host
		resp, ferr := p.Forward(ctx, req)
		if ferr != nil {
			_ = writeError(tlsConn, ferr)
			return ferr
		}
		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			return fmt.Errorf("egress: write response %s: %w", host, err)
		}
		resp.Body.Close()
		if req.Close || resp.Close {
			return nil
		}
	}
}

// servePassthrough SNI-validates the ClientHello against the allowlist and then
// TUNNELS the connection to the upstream WITHOUT decrypting it. The bytes are
// spliced verbatim: the proxy never has (or wants) the plaintext, so a
// checksum/signature-verifying host's TLS is preserved end-to-end. A ClientHello
// whose SNI is not egress-allowed (or does not match the CONNECT host) is refused
// before any upstream dial.
func (p *Proxy) servePassthrough(ctx context.Context, host string, clientConn net.Conn, dialUpstream func(ctx context.Context, host string) (net.Conn, error)) error {
	peek, err := peekClientHello(clientConn)
	if err != nil {
		return fmt.Errorf("egress: peek client hello %s: %w", host, err)
	}
	if sni, serr := sniFromClientHello(peek.buffered); serr == nil {
		if !p.cfg.Allowed(sni) || (sni != host) {
			return fmt.Errorf("%w: SNI %q not allowed for CONNECT %s", ErrDeny, sni, host)
		}
	}
	upConn, err := dialUpstream(ctx, host)
	if err != nil {
		return fmt.Errorf("egress: dial upstream %s: %w", host, err)
	}
	defer upConn.Close()
	// Replay the peeked ClientHello bytes, then splice both directions verbatim.
	if _, err := upConn.Write(peek.buffered); err != nil {
		return fmt.Errorf("egress: forward client hello %s: %w", host, err)
	}
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(upConn, peek.rest); errc <- e }()
	go func() { _, e := io.Copy(clientConn, upConn); errc <- e }()
	<-errc
	return nil
}

func bytesReader(b []byte) io.Reader {
	if len(b) == 0 {
		return http.NoBody
	}
	return &sliceReader{b: b}
}

type sliceReader struct {
	b   []byte
	off int
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.off >= len(s.b) {
		return 0, io.EOF
	}
	n := copy(p, s.b[s.off:])
	s.off += n
	return n, nil
}

func writeError(w io.Writer, err error) error {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"X-Opslify-Egress": []string{err.Error()}},
		Body:   http.NoBody,
	}
	return resp.Write(w)
}
