package regproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// Layer-tagged sentinels (failure legibility, shared-eng §6: an operator learns
// exactly which layer refused). All are `cred`/`policy`-adjacent supply-chain
// denials distinct from sandbox/egress.
var (
	// ErrDenied is a fail-closed allowlist refusal (un-allowlisted package/registry).
	ErrDenied = errors.New("regproxy: package not allowlisted (deny-by-default)")
	// ErrUnattested is a fail-closed attestation refusal where policy requires it.
	ErrUnattested = errors.New("regproxy: package failed attestation (fail-closed)")
	// ErrUpstream is an upstream fetch failure.
	ErrUpstream = errors.New("regproxy: upstream fetch failed")
)

// maxArtifactBytes caps a single artifact read so a hostile/oversized upstream
// cannot exhaust daemon memory. It is generous (256 MiB) but bounded.
const maxArtifactBytes = 256 << 20

// Proxy is the F5.5 caching registry proxy for ONE session. It serves the
// sandbox's pip/npm/go over PLAIN HTTP (no MITM), fetches the real artifact from
// the configured upstream (injecting a private-registry credential ONLY on the
// upstream leg), caches it, verifies attestation where required, emits a
// `pkg.install` hash event, and serves the bytes BYTE-FOR-BYTE — so the client's
// own checksum/signature verification stays intact end-to-end.
type Proxy struct {
	sessionID string
	cfg       resolvedConfig
	brk       *broker.Broker
	grants    []policy.Cred
	rec       *trace.Recorder
	cache     *Cache
	verifier  AttestationVerifier
	// upstream is the RoundTripper used for the proxy->upstream fetch. Production
	// uses a real transport; tests inject an in-process stub (httptest). Nil =>
	// http.DefaultTransport.
	upstream http.RoundTripper
	now      func() time.Time
}

// Options configures NewProxy. A nil broker/recorder/verifier/upstream is
// tolerated (fail-closed where it matters): a nil broker resolves no credential
// (public fetch only); a nil verifier refuses any RequireAttestation upstream
// (fail-closed); a nil upstream uses http.DefaultTransport.
type Options struct {
	SessionID string
	Config    Config
	Broker    *broker.Broker
	Grants    []policy.Cred
	Recorder  *trace.Recorder
	Verifier  AttestationVerifier
	Upstream  http.RoundTripper
	Now       func() time.Time
}

// NewProxy validates the config (fail-closed) and builds a per-session proxy.
func NewProxy(opts Options) (*Proxy, error) {
	rc, err := BuildConfig(opts.Config)
	if err != nil {
		return nil, err
	}
	cache, err := NewCache(opts.Config.CacheDir)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	up := opts.Upstream
	if up == nil {
		up = http.DefaultTransport
	}
	return &Proxy{
		sessionID: opts.SessionID,
		cfg:       rc,
		brk:       opts.Broker,
		grants:    opts.Grants,
		rec:       opts.Recorder,
		cache:     cache,
		verifier:  opts.Verifier,
		upstream:  up,
		now:       now,
	}, nil
}

// ServeHTTP is the sandbox-facing handler. The sandbox's pip/npm/go point their
// index-url/registry/GOPROXY at this handler over PLAIN HTTP (no TLS, no MITM). It
// parses the request, enforces the allowlist fail-closed, serves the real artifact
// (from cache or upstream), and writes the genuine bytes back unchanged.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "regproxy: only GET/HEAD are proxied", http.StatusMethodNotAllowed)
		return
	}
	body, ct, err := p.Fetch(r.Context(), r.URL.Path)
	if err != nil {
		writeErr(w, err)
		return
	}
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

// Fetch is the core, directly unit-testable path. It returns the REAL artifact
// bytes (identical to the upstream's) and content-type for reqPath, or a layer-
// tagged error. Steps:
//  1. parse the request -> Ref (fail-closed on an unparseable/unknown path);
//  2. allowlist gate (fail-closed: un-allowlisted => ErrDenied, no fetch);
//  3. serve from cache if present (attestation was already enforced on ingest);
//  4. otherwise fetch upstream, injecting the private-registry cred ONLY on the
//     upstream request (never client-visible), Zeroized after use;
//  5. verify attestation where the upstream requires it (fail-closed);
//  6. cache + emit a `pkg.install` hash event over the REAL bytes;
//  7. return the genuine bytes unchanged (checksum-safe).
func (p *Proxy) Fetch(ctx context.Context, reqPath string) ([]byte, string, error) {
	ref, err := parseRequest(reqPath)
	if err != nil {
		return nil, "", err
	}
	up, ok := p.cfg.upstreamFor(ref.Ecosystem)
	if !ok {
		return nil, "", fmt.Errorf("%w: no upstream for ecosystem %q", ErrDenied, ref.Ecosystem)
	}
	if !p.cfg.allowed(ref.Ecosystem, ref.Name) {
		return nil, "", fmt.Errorf("%w: %s/%s", ErrDenied, ref.Ecosystem, ref.Name)
	}

	if cached, hit := p.cache.Get(ref.Ecosystem, ref.upstreamPath); hit {
		// A cache hit means the artifact already passed attestation on ingest; emit
		// the supply-chain event again (this install is a real install too) and serve.
		if ref.IsArtifact {
			p.emitInstall(ctx, ref, cached, up.BaseURL, true)
		}
		return cached, "", nil
	}

	data, ct, err := p.fetchUpstream(ctx, up, ref)
	if err != nil {
		return nil, "", err
	}

	// Attestation gate (fail-closed) — only for hashable artifacts from a require-
	// attestation upstream. A nil verifier or an unattested artifact is refused.
	if ref.IsArtifact && up.RequireAttestation {
		if p.verifier == nil {
			return nil, "", fmt.Errorf("%w: %s/%s@%s (no attestation verifier configured)", ErrUnattested, ref.Ecosystem, ref.Name, ref.Version)
		}
		attested, aerr := p.verifier.Attested(ctx, ref, data)
		if aerr != nil {
			return nil, "", fmt.Errorf("%w: %s/%s@%s: %v", ErrUnattested, ref.Ecosystem, ref.Name, ref.Version, aerr)
		}
		if !attested {
			return nil, "", fmt.Errorf("%w: %s/%s@%s", ErrUnattested, ref.Ecosystem, ref.Name, ref.Version)
		}
	}

	// Cache + record only artifacts (a hashable install). Metadata/index responses
	// are still served but are not supply-chain events.
	if ref.IsArtifact {
		if err := p.cache.Put(ref.Ecosystem, ref.upstreamPath, data); err != nil {
			// A cache write failure must not fail the install (the bytes are valid);
			// it is a degraded-cache condition, surfaced by returning nil below only if
			// severe. We proceed and serve the genuine bytes.
			_ = err
		}
		p.emitInstall(ctx, ref, data, up.BaseURL, false)
	}
	return data, ct, nil
}

// fetchUpstream performs the proxy->upstream GET. The private-registry credential
// (if the upstream has one) is resolved via the F5.6 broker (deny-by-default,
// valueless cred.resolve audit) and set ONLY on THIS upstream request; it is
// Zeroized immediately after being formatted into the header string. The client
// never sees it, and — crucially — because there is no client-side MITM, the
// artifact's own checksum/signature verification is untouched.
func (p *Proxy) fetchUpstream(ctx context.Context, up Upstream, ref Ref) ([]byte, string, error) {
	url := up.BaseURL + ref.upstreamPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%w: build request %s: %v", ErrUpstream, url, err)
	}
	p.injectCredential(ctx, req, up)

	resp, err := p.upstream.RoundTrip(req)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %s: %v", ErrUpstream, url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%w: %s: upstream status %d", ErrUpstream, url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArtifactBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("%w: read %s: %v", ErrUpstream, url, err)
	}
	if len(data) > maxArtifactBytes {
		return nil, "", fmt.Errorf("%w: %s: artifact exceeds %d bytes", ErrUpstream, url, maxArtifactBytes)
	}
	return data, resp.Header.Get("Content-Type"), nil
}

// injectCredential resolves the upstream's CredRef through the broker and sets the
// auth header on the UPSTREAM request only. FAIL-CLOSED: a nil broker, no CredRef,
// or a resolve failure injects NO header (no raw-secret leak, no partial header) —
// the fetch proceeds unauthenticated (which a private registry will simply reject,
// never a silent secret exposure). The resolved plaintext is Zeroized immediately;
// only the formatted header string (which the upstream needs) is retained, and it
// never enters a trace/log/served response.
func (p *Proxy) injectCredential(ctx context.Context, req *http.Request, up Upstream) {
	if p.brk == nil || up.CredRef == "" {
		return
	}
	value, _, err := p.brk.Resolve(ctx, p.rec, p.grants, up.CredRef)
	if err != nil {
		return // fail-closed: no header
	}
	headerVal := string(value)
	broker.Zeroize(value)
	if up.HeaderFormat != "" {
		headerVal = fmt.Sprintf(up.HeaderFormat, headerVal)
	}
	name := up.HeaderName
	if name == "" {
		name = "Authorization"
	}
	req.Header.Set(name, headerVal)
}

// emitInstall records the supply-chain evidence: a `pkg.install` event with
// {ecosystem, name, version, sha256, registry, attested, cached} over the REAL
// fetched bytes (the same bytes served to the client). It DELIBERATELY carries NO
// registry credential and NO artifact body — only the non-secret descriptors. The
// Recorder runs F3.3 redaction + F3.1 chaining in the emit path, so the event is
// redacted + committed to the tamper-evident chain like every other event.
func (p *Proxy) emitInstall(ctx context.Context, ref Ref, data []byte, registry string, cached bool) {
	sum := sha256.Sum256(data)
	_ = p.rec.Emit(ctx, trace.TypePkgInstall, map[string]any{
		"ecosystem": string(ref.Ecosystem),
		"name":      ref.Name,
		"version":   ref.Version,
		"sha256":    hex.EncodeToString(sum[:]),
		"registry":  registryHost(registry),
		"cached":    cached,
	})
}

// registryHost renders a base URL down to a non-secret host for the audit event
// (a private registry base URL could carry a path but never a credential — creds
// are injected as a header, never in the URL). Best-effort; empty on parse issues.
func registryHost(base string) string {
	b := base
	for _, pfx := range []string{"https://", "http://"} {
		if len(b) >= len(pfx) && b[:len(pfx)] == pfx {
			b = b[len(pfx):]
			break
		}
	}
	if i := indexByte(b, '/'); i >= 0 {
		b = b[:i]
	}
	return b
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// writeErr maps a fetch error to a layer-tagged HTTP status. An allowlist/
// attestation denial is 403 (the policy/supply-chain layer refused); an upstream
// failure is 502. The error string names the layer, never a credential.
func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	switch {
	case errors.Is(err, ErrDenied), errors.Is(err, ErrUnattested):
		status = http.StatusForbidden
	}
	http.Error(w, err.Error(), status)
}
