package egress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Resolution is the result of resolving one allowlist entry: the current addresses
// and the TTL after which they should be refreshed. TTL is carried so a future
// TTL-aware resolver (e.g. miekg/dns) can drive per-record refresh; the stdlib
// resolver cannot read record TTLs, so DefaultResolver reports a fixed TTL and the
// pinner refreshes on that interval — documented, and honestly not a per-record TTL.
type Resolution struct {
	Addrs []netip.Addr
	TTL   time.Duration
}

// Resolver resolves one allowlist entry (a hostname or a literal IP) to addresses.
// Injectable so tests supply fixed A/AAAA records + custom TTLs with no network.
type Resolver interface {
	Resolve(ctx context.Context, host string) (Resolution, error)
}

// DefaultTTL is the refresh interval DefaultResolver reports (stdlib exposes no
// record TTL). Chosen conservative-but-live so round-robin rotations are picked up
// promptly without hammering DNS.
const DefaultTTL = 60 * time.Second

// DefaultResolver resolves via the host resolver (net.Resolver). It returns ALL
// current A/AAAA records (multi-A / round-robin: every current address is pinned,
// so whichever the sandbox connects to is allowed) and a fixed DefaultTTL.
type DefaultResolver struct {
	res *net.Resolver
	ttl time.Duration
}

// NewDefaultResolver builds a DefaultResolver; ttl<=0 uses DefaultTTL.
func NewDefaultResolver(ttl time.Duration) DefaultResolver {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return DefaultResolver{res: net.DefaultResolver, ttl: ttl}
}

// Resolve returns literal IPs unchanged (no DNS) or every current A/AAAA record.
func (d DefaultResolver) Resolve(ctx context.Context, host string) (Resolution, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return Resolution{Addrs: []netip.Addr{ip.Unmap()}, TTL: d.ttl}, nil
	}
	res := d.res
	if res == nil {
		res = net.DefaultResolver
	}
	addrs, err := res.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return Resolution{}, fmt.Errorf("resolve %q: %w", host, err)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap())
	}
	return Resolution{Addrs: out, TTL: d.ttl}, nil
}

// normalizeHost extracts the DNS name / IP from an allowlist entry, tolerating a
// scheme and a :port so `https://api.example.com`, `api.example.com:443` and
// `api.example.com` all resolve to the same host. Returns "" for entries that
// carry no host (skipped by the pinner).
func normalizeHost(entry string) string {
	s := strings.TrimSpace(entry)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Trim any path/query.
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	// A bracketed IPv6 literal, optionally with a port.
	if strings.HasPrefix(s, "[") {
		if j := strings.Index(s, "]"); j >= 0 {
			return s[1:j]
		}
	}
	// host:port — but not a bare IPv6 literal (which has multiple colons).
	if strings.Count(s, ":") == 1 {
		if h, _, err := net.SplitHostPort(s); err == nil {
			return h
		}
	}
	return s
}

// resolveAll resolves every allowlist entry into a single de-duplicated, sorted IP
// set (the pin), and reports the refresh interval as the MINIMUM TTL across entries
// (so the pin never outlives the shortest-lived record), clamped to [min,max]. A
// single entry that fails to resolve is skipped with its error collected — one bad
// domain must not blank the whole allowlist and strand every session — but if ALL
// entries fail the error is returned so the caller can keep the prior pin.
func resolveAll(ctx context.Context, r Resolver, allowlist []string, minTTL, maxTTL time.Duration) ([]netip.Addr, time.Duration, error) {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	next := maxTTL
	var errs []string
	resolved := 0
	for _, entry := range allowlist {
		host := normalizeHost(entry)
		if host == "" {
			continue
		}
		res, err := r.Resolve(ctx, host)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		resolved++
		if res.TTL > 0 && res.TTL < next {
			next = res.TTL
		}
		for _, a := range res.Addrs {
			a = a.Unmap()
			if a.IsValid() && !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	// Deterministic ordering so an unchanged set never looks changed.
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })

	if next < minTTL {
		next = minTTL
	}
	if next > maxTTL {
		next = maxTTL
	}
	// Only a hard failure (nothing resolved AND we had entries to resolve) is an
	// error; partial success returns what we have so the majority still reach out.
	if resolved == 0 && len(errs) > 0 {
		return nil, next, fmt.Errorf("%w: resolve allowlist: %s", ErrEgress, strings.Join(errs, "; "))
	}
	return out, next, nil
}

// addrsEqual reports whether two IP sets are identical (both are sorted by
// resolveAll, so a positional compare suffices). Used to skip needless reprogramming
// when a refresh returns the same addresses.
func addrsEqual(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
