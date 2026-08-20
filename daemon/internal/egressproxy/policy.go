package egressproxy

import (
	"strings"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// Mode is what the proxy does with a target host, decided FAIL-CLOSED from the
// session's resolved policy.
type Mode int

const (
	// ModeDeny is the default for any host/path not positively matched. It maps
	// back to the F1.4 default-deny posture: the proxy refuses to forward, and a
	// non-HTTP flow to the same host stays dropped + DNS-pinned regardless.
	ModeDeny Mode = iota
	// ModeTerminate: the proxy TLS-terminates using the per-session CA and MAY
	// inject an auth header (if an injection rule matches host+method+path). Used
	// only for header-injection targets.
	ModeTerminate
	// ModePassthrough: the proxy validates SNI against the allowlist and TUNNELS
	// the bytes WITHOUT decrypting. Used for everything else, including
	// checksum/signature-verifying hosts that MUST NOT be MITM'd (F5.5 handles
	// their auth). A never-MITM host is ALWAYS this mode and can never be silently
	// upgraded to ModeTerminate.
	ModePassthrough
)

func (m Mode) String() string {
	switch m {
	case ModeTerminate:
		return "terminate"
	case ModePassthrough:
		return "passthrough"
	default:
		return "deny"
	}
}

// InjectRule binds a policy-granted cred to an auth header the proxy adds on the
// FORWARDED (upstream) request, for a specific host + path prefix + method set.
// It is DAEMON-AUTHORITATIVE config assembled from the RESOLVED (F4.1-narrowed)
// policy — a workspace can never introduce or widen one because CredRef must be a
// granted cred and Host must be a resolved-egress domain (see BuildConfig).
type InjectRule struct {
	Host       string   // exact host (no port); required
	PathPrefix string   // "" or "/" matches any path; otherwise a prefix match
	Methods    []string // empty => any method
	CredRef    string   // the policy `creds` ref to Resolve (never logged as a value)
	HeaderName string   // e.g. "Authorization"
	// HeaderFormat is a single-%s template applied to the resolved secret, e.g.
	// "Bearer %s" or "token %s". Empty => the raw secret is the header value.
	HeaderFormat string
}

func (r InjectRule) matches(method, host, path string) bool {
	if !strings.EqualFold(host, r.Host) {
		return false
	}
	if r.PathPrefix != "" && r.PathPrefix != "/" && !strings.HasPrefix(path, r.PathPrefix) {
		return false
	}
	if len(r.Methods) > 0 {
		ok := false
		for _, m := range r.Methods {
			if strings.EqualFold(m, method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Config is the per-session proxy decision table. It is built from the resolved
// policy (BuildConfig) so it inherits the narrows-not-widens invariant: the
// allowlist is the resolved egress domains, injection targets are a subset with a
// granted cred, and never-MITM hosts are forced to pass-through.
type Config struct {
	allow      map[string]struct{} // resolved-egress hosts reachable at all
	neverMITM  map[string]struct{} // hosts that must be SNI pass-through, never MITM
	injectByID []InjectRule        // ordered injection rules (host+path)
}

// BuildConfig assembles the decision table from a session's RESOLVED policy plus
// the daemon-authoritative injection rules and never-MITM list.
//
// Security: rules are DROPPED fail-closed unless (a) their Host is in the resolved
// egress allowlist and (b) their CredRef is a resolved `creds` grant — so a rule
// can never grant a header the policy did not already permit, and a workspace
// (which can only NARROW resolved) can never widen either set. A never-MITM host
// is recorded so decide() forces pass-through for it even if an inject rule also
// names it (a checksum host is never silently MITM'd).
func BuildConfig(resolved policy.Resolved, rules []InjectRule, neverMITM []string) Config {
	cfg := Config{
		allow:     map[string]struct{}{},
		neverMITM: map[string]struct{}{},
	}
	for _, d := range resolved.Egress.Domains {
		cfg.allow[strings.ToLower(d)] = struct{}{}
	}
	granted := map[string]struct{}{}
	for _, c := range resolved.Creds {
		granted[c.Name] = struct{}{}
	}
	for _, h := range neverMITM {
		cfg.neverMITM[strings.ToLower(h)] = struct{}{}
	}
	for _, r := range rules {
		host := strings.ToLower(r.Host)
		if _, ok := cfg.allow[host]; !ok {
			continue // fail-closed: host not egress-allowed
		}
		if _, ok := granted[r.CredRef]; !ok {
			continue // fail-closed: cred not policy-granted
		}
		if _, ok := cfg.neverMITM[host]; ok {
			continue // never-MITM host: no injection rule is honoured (pass-through)
		}
		cfg.injectByID = append(cfg.injectByID, r)
	}
	return cfg
}

// Decision is the fail-closed outcome for one (method, host, path).
type Decision struct {
	Mode Mode
	// Inject is the matched injection rule (only set when Mode==ModeTerminate and
	// an auth header should be added). Nil means terminate-without-injection or a
	// non-terminate mode.
	Inject *InjectRule
}

// Decide is the FAIL-CLOSED policy match on method+host+path:
//   - host not in the egress allowlist        => ModeDeny (F1.4 default-deny).
//   - host in the never-MITM set              => ModePassthrough (never MITM'd).
//   - host+method+path matches an inject rule => ModeTerminate + that rule.
//   - allowed host, no inject match           => ModePassthrough (SNI-validated).
//
// A workspace cannot reach ModeTerminate for a host/cred the daemon did not grant
// because BuildConfig already dropped any such rule.
func (c Config) Decide(method, host, path string) Decision {
	h := strings.ToLower(hostname(host))
	if _, ok := c.allow[h]; !ok {
		return Decision{Mode: ModeDeny}
	}
	if _, ok := c.neverMITM[h]; ok {
		return Decision{Mode: ModePassthrough}
	}
	for i := range c.injectByID {
		if c.injectByID[i].matches(method, h, path) {
			r := c.injectByID[i]
			return Decision{Mode: ModeTerminate, Inject: &r}
		}
	}
	return Decision{Mode: ModePassthrough}
}

// Allowed reports whether a host is reachable at all (egress allowlist). Used to
// SNI-validate a CONNECT tunnel before any bytes flow.
func (c Config) Allowed(host string) bool {
	_, ok := c.allow[strings.ToLower(hostname(host))]
	return ok
}

// hostname strips a :port suffix from an authority, leaving the bare host.
func hostname(hostport string) string {
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		// Guard against IPv6 literals without a port (contain multiple ':').
		if strings.Count(hostport, ":") == 1 {
			return hostport[:i]
		}
	}
	return hostport
}
