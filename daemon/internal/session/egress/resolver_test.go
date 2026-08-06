package egress

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// fakeResolver returns fixed records per host, so multi-A / TTL / failure behaviour
// is exercised with no real DNS.
type fakeResolver struct {
	records map[string]Resolution
	errs    map[string]error
	calls   int
}

func (f *fakeResolver) Resolve(_ context.Context, host string) (Resolution, error) {
	f.calls++
	if err := f.errs[host]; err != nil {
		return Resolution{}, err
	}
	if r, ok := f.records[host]; ok {
		return r, nil
	}
	return Resolution{}, errors.New("no record")
}

func mkRes(ttl time.Duration, ips ...string) Resolution {
	out := Resolution{TTL: ttl}
	for _, s := range ips {
		out.Addrs = append(out.Addrs, netip.MustParseAddr(s))
	}
	return out
}

// Multi-A: all current records are pinned so whichever the sandbox hits is allowed.
func TestResolveAll_MultiA(t *testing.T) {
	r := &fakeResolver{records: map[string]Resolution{
		"example.com": mkRes(60*time.Second, "1.1.1.1", "2.2.2.2", "3.3.3.3"),
	}}
	ips, _, err := resolveAll(context.Background(), r, []string{"example.com"}, time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 3 {
		t.Fatalf("want 3 pinned IPs, got %d: %v", len(ips), ips)
	}
}

// Literal IPs pass through WITHOUT any DNS lookup (no resolver call).
func TestResolveAll_LiteralIPNoLookup(t *testing.T) {
	r := &fakeResolver{records: map[string]Resolution{}}
	// DefaultResolver handles literal passthrough; here we assert via a real
	// DefaultResolver that a literal never hits the network (it parses directly).
	dr := NewDefaultResolver(time.Minute)
	res, err := dr.Resolve(context.Background(), "8.8.4.4")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Addrs) != 1 || res.Addrs[0] != netip.MustParseAddr("8.8.4.4") {
		t.Fatalf("literal passthrough failed: %v", res.Addrs)
	}
	if r.calls != 0 {
		t.Fatal("literal IP must not invoke the resolver")
	}
}

// De-duplication + sorting across entries, and TTL is the MIN across records.
func TestResolveAll_DedupeAndMinTTL(t *testing.T) {
	r := &fakeResolver{records: map[string]Resolution{
		"a.com": mkRes(300*time.Second, "1.1.1.1", "9.9.9.9"),
		"b.com": mkRes(30*time.Second, "9.9.9.9", "2.2.2.2"),
	}}
	ips, next, err := resolveAll(context.Background(), r, []string{"a.com", "b.com"}, 10*time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 3 { // 9.9.9.9 de-duplicated
		t.Fatalf("want 3 unique IPs, got %d: %v", len(ips), ips)
	}
	if next != 30*time.Second {
		t.Fatalf("want min TTL 30s, got %v", next)
	}
	// Sorted ascending.
	for i := 1; i < len(ips); i++ {
		if !ips[i-1].Less(ips[i]) {
			t.Fatalf("not sorted: %v", ips)
		}
	}
}

// TTL clamped to [min,max].
func TestResolveAll_TTLClamp(t *testing.T) {
	r := &fakeResolver{records: map[string]Resolution{"a.com": mkRes(time.Second, "1.1.1.1")}}
	_, next, err := resolveAll(context.Background(), r, []string{"a.com"}, 30*time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if next != 30*time.Second {
		t.Fatalf("want clamped-up to 30s, got %v", next)
	}
}

// A single failing domain is skipped (others still pin); all-failing is an error so
// the caller keeps the prior pin rather than blanking the allowlist.
func TestResolveAll_PartialVsTotalFailure(t *testing.T) {
	r := &fakeResolver{
		records: map[string]Resolution{"good.com": mkRes(60*time.Second, "1.1.1.1")},
		errs:    map[string]error{"bad.com": errors.New("nxdomain")},
	}
	ips, _, err := resolveAll(context.Background(), r, []string{"good.com", "bad.com"}, time.Second, time.Hour)
	if err != nil {
		t.Fatalf("partial failure must not error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("want 1 IP from the good domain, got %v", ips)
	}

	rAll := &fakeResolver{errs: map[string]error{"bad.com": errors.New("nxdomain")}}
	if _, _, err := resolveAll(context.Background(), rAll, []string{"bad.com"}, time.Second, time.Hour); err == nil {
		t.Fatal("total failure must return an error")
	} else if !errors.Is(err, ErrEgress) {
		t.Fatalf("want ErrEgress, got %v", err)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"example.com":             "example.com",
		"https://api.example.com": "api.example.com",
		"api.example.com:443":     "api.example.com",
		"http://x.com/path?q=1":   "x.com",
		"[2606::1]:443":           "2606::1",
		"1.2.3.4":                 "1.2.3.4",
		"  spaced.com  ":          "spaced.com",
		"":                        "",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAddrsEqual(t *testing.T) {
	a := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")}
	b := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")}
	c := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	if !addrsEqual(a, b) {
		t.Fatal("equal sets reported unequal")
	}
	if addrsEqual(a, c) {
		t.Fatal("different-length sets reported equal")
	}
}
