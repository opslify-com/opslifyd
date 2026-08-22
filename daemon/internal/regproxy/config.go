// Package regproxy implements F5.5 — the daemon-side CACHING PACKAGE REGISTRY
// PROXY: the checksum-safe complement to the F5.2 L7 egress proxy.
//
// WHY THIS EXISTS (read before touching this package):
//
// F5.2 makes generic HTTP(S) egress credential-blind by TLS-MITM'ing the sandbox
// and injecting an auth header on the decrypted, re-encrypted upstream request.
// That is fatal for checksum/signature-verifying tools (pip/npm/go/terraform):
// they pin the artifact's own hash/signature end-to-end, and a MITM either breaks
// that verification or forces the operator to disable it (opening a poisoned-
// dependency hole). So F5.2 marks those hosts NEVER-MITM (SNI pass-through) and
// routes their AUTH need HERE instead.
//
// This proxy resolves the conflict WITHOUT any client-side MITM:
//   - The sandbox's pip/npm/go point their index-url / registry / GOPROXY at this
//     daemon proxy over PLAIN HTTP on the loopback/bridge. There is no TLS to
//     terminate, no per-session CA, nothing to MITM.
//   - The proxy fetches the REAL artifact from the configured upstream. A private-
//     registry credential (F5.6 broker, policy-gated) is injected ONLY on the
//     proxy->upstream request — the client never sees it.
//   - The proxy serves the upstream bytes BYTE-FOR-BYTE unchanged. Because the
//     client was never MITM'd and the bytes are genuine, the package's OWN
//     checksum/signature verification still passes end-to-end. Auth moved to the
//     upstream leg; verification stayed intact. That is the whole point vs F5.2.
//
// It also closes the poisoned-dependency exfil path: an ALLOWLIST (fail-closed)
// gates which ecosystem/package/registry resolve, an ATTESTATION seam refuses
// unattested packages where policy requires it (fail-closed), and a `pkg.install`
// hash event records {ecosystem,name,version,sha256} of the REAL bytes into the
// F3.1 tamper-evident chain — supply-chain evidence, never the credential.
//
// INTEGRATION-GATED (honest scope): pointing the real in-sandbox pip/npm/go at
// this proxy (index-url / registry / GOPROXY env + bridge reachability) and the
// REAL Sigstore/cosign attestation verification are integration-gated. This
// package UNIT-tests, against in-process httptest stub upstreams (NO network):
// the allowlist fail-closed decision, the fetch+cache path, credential injection
// on the upstream leg and its ABSENCE from the served response, byte-for-byte
// checksum-safety, the attestation seam (stub attested/unattested), the
// `pkg.install` hash event, and cache path-traversal/poisoning defense.
package regproxy

import (
	"fmt"
	"strings"
)

// Ecosystem is a supported package ecosystem. It is the routing key: an inbound
// request path's leading segment selects the ecosystem, and the Config's upstream
// for that ecosystem is where the fetch is forwarded.
type Ecosystem string

const (
	EcosystemPyPI Ecosystem = "pypi"
	EcosystemNPM  Ecosystem = "npm"
	EcosystemGo   Ecosystem = "go"
)

// knownEcosystems is the accepted routing vocabulary. An unknown leading segment
// is refused fail-closed (no upstream is guessed).
var knownEcosystems = map[Ecosystem]bool{
	EcosystemPyPI: true,
	EcosystemNPM:  true,
	EcosystemGo:   true,
}

// Upstream is the DAEMON-AUTHORITATIVE configuration for one ecosystem's real
// registry. It holds only non-secret routing + an OPTIONAL credential REFERENCE
// (never a value): the value is resolved through the F5.6 broker at fetch time,
// injected on the proxy->upstream request, and zeroized. A workspace can never
// introduce or widen an Upstream — it is built from daemon config.
type Upstream struct {
	// Ecosystem this upstream serves; also the inbound routing prefix.
	Ecosystem Ecosystem
	// BaseURL is the real registry root, e.g. "https://pypi.org" or a private
	// "https://npm.internal.example". The inbound path (after the ecosystem prefix)
	// is appended to it verbatim. Must be an absolute http(s) URL.
	BaseURL string
	// CredRef, if set, is the F5.6 `creds` ref resolved (deny-by-default, policy-
	// gated) and injected on the proxy->upstream request. Empty => a public registry
	// (no injection). NEVER logged/traced as a value.
	CredRef string
	// HeaderName is the auth header injected on the upstream leg. Empty =>
	// "Authorization".
	HeaderName string
	// HeaderFormat is a single-%s template applied to the resolved secret, e.g.
	// "Bearer %s" or "token %s". Empty => the raw secret is the header value.
	HeaderFormat string
	// RequireAttestation, when true, makes an unattested artifact from this upstream
	// a fail-closed refusal (the AttestationVerifier must positively attest it).
	RequireAttestation bool
}

// AllowEntry is one allowlisted package (fail-closed): only an ecosystem+name pair
// present in the allowlist resolves. It is daemon-authoritative like Upstream.
type AllowEntry struct {
	Ecosystem Ecosystem
	// Name is the exact, normalized package/module name (see normalizeName). No
	// wildcards — an allowlist is an explicit set, never a "*" that would defeat its
	// own purpose.
	Name string
}

// Config is the per-daemon F5.5 configuration: the ecosystem upstreams, the
// package allowlist, and the on-disk cache root. It is assembled from daemon
// config in main.go and is entirely daemon-owned.
type Config struct {
	// Upstreams maps each served ecosystem to its real registry. Built into a lookup
	// by BuildConfig; a request for an ecosystem with no upstream is refused.
	Upstreams []Upstream
	// Allow is the fail-closed package allowlist. An empty allowlist resolves
	// NOTHING (deny-by-default) — the proxy never fails open.
	Allow []AllowEntry
	// CacheDir is the on-disk artifact cache root (daemon-owned, outside any sandbox
	// mount). Entries are content-addressed by a hash of the logical key, so a
	// crafted package path can never traverse out of it or collide with another.
	CacheDir string
}

// resolvedConfig is the validated, indexed form of Config used at request time.
type resolvedConfig struct {
	upstreams map[Ecosystem]Upstream
	allow     map[allowKey]struct{}
	cacheDir  string
}

type allowKey struct {
	eco  Ecosystem
	name string
}

// BuildConfig validates and indexes a Config FAIL-CLOSED: an upstream for an
// unknown ecosystem, a non-absolute BaseURL, or an allow entry for an unknown
// ecosystem is a legible error (the proxy refuses to start rather than serve a
// misconfigured, potentially fail-open registry). The allowlist is normalized so
// matching is name-canonical.
func BuildConfig(cfg Config) (resolvedConfig, error) {
	rc := resolvedConfig{
		upstreams: map[Ecosystem]Upstream{},
		allow:     map[allowKey]struct{}{},
		cacheDir:  cfg.CacheDir,
	}
	for _, u := range cfg.Upstreams {
		if !knownEcosystems[u.Ecosystem] {
			return resolvedConfig{}, fmt.Errorf("regproxy: upstream for unknown ecosystem %q", u.Ecosystem)
		}
		if !strings.HasPrefix(u.BaseURL, "http://") && !strings.HasPrefix(u.BaseURL, "https://") {
			return resolvedConfig{}, fmt.Errorf("regproxy: upstream %s base_url %q must be an absolute http(s) URL", u.Ecosystem, u.BaseURL)
		}
		u.BaseURL = strings.TrimRight(u.BaseURL, "/")
		rc.upstreams[u.Ecosystem] = u
	}
	for _, a := range cfg.Allow {
		if !knownEcosystems[a.Ecosystem] {
			return resolvedConfig{}, fmt.Errorf("regproxy: allow entry for unknown ecosystem %q", a.Ecosystem)
		}
		rc.allow[allowKey{eco: a.Ecosystem, name: normalizeName(a.Ecosystem, a.Name)}] = struct{}{}
	}
	return rc, nil
}

// Allowed is the EXPORTED, pre-install allowlist gate (F7.5): it reports whether
// ecosystem+name is on the daemon-authoritative allowlist so the operator CLI can
// refuse a non-allowlisted package with a clear error BEFORE any install runs,
// rather than only fail-closed at fetch time inside the sandbox. It validates the
// config fail-closed (a misconfigured proxy is never treated as "allowed") and
// applies the SAME normalization the fetch path uses, so the pre-check and the
// fetch-time gate can never disagree. Deny-by-default: an unknown ecosystem, an
// empty allowlist, or an unlisted name yields false.
func (cfg Config) Allowed(eco Ecosystem, name string) (bool, error) {
	if !knownEcosystems[eco] {
		return false, fmt.Errorf("%w: unknown ecosystem %q", ErrDenied, eco)
	}
	rc, err := BuildConfig(cfg)
	if err != nil {
		return false, err
	}
	return rc.allowed(eco, name), nil
}

// allowed reports whether ecosystem+name is on the allowlist. Deny-by-default: an
// unlisted package (or an empty allowlist) is never allowed.
func (rc resolvedConfig) allowed(eco Ecosystem, name string) bool {
	_, ok := rc.allow[allowKey{eco: eco, name: normalizeName(eco, name)}]
	return ok
}

// upstreamFor returns the configured upstream for an ecosystem, or false.
func (rc resolvedConfig) upstreamFor(eco Ecosystem) (Upstream, bool) {
	u, ok := rc.upstreams[eco]
	return u, ok
}

// normalizeName canonicalizes a package name for allowlist matching. PyPI names
// are case-insensitive and treat - _ . as equivalent (PEP 503); npm/go names are
// case-sensitive but we lower-case defensively for go module paths which are
// case-encoded elsewhere. This keeps "Django" and "django" from being two
// different allowlist entries for pip.
func normalizeName(eco Ecosystem, name string) string {
	n := strings.TrimSpace(name)
	switch eco {
	case EcosystemPyPI:
		n = strings.ToLower(n)
		n = strings.NewReplacer("_", "-", ".", "-").Replace(n)
		for strings.Contains(n, "--") {
			n = strings.ReplaceAll(n, "--", "-")
		}
	default:
		// npm scoped names + go module paths are kept as-is (case-sensitive), only
		// trimmed. We do not lower-case: npm is case-sensitive and go encodes case.
	}
	return n
}
