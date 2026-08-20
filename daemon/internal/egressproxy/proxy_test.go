package egressproxy

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// ---- test helpers ----

// stubTransport captures the request it is asked to forward and returns a canned
// 200. It IS the upstream: whatever header it sees is what actually left the
// boundary toward the real host.
type stubTransport struct {
	got *http.Request
}

func (s *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.got = r
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       http.NoBody,
		Request:    r,
	}, nil
}

// memSink is a minimal in-memory TraceSink capturing emitted events.
type memSink struct{ events []trace.Event }

func (m *memSink) Append(_ context.Context, e trace.Event) error {
	m.events = append(m.events, e)
	return nil
}
func (m *memSink) Seal(context.Context, string) (trace.Signature, error) {
	return trace.Signature{}, nil
}

// testBroker builds a broker over a vault seeded with a FAKE token under ref.
func testBroker(t *testing.T, ref, fakeToken string) *broker.Broker {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	v, err := broker.OpenVault(dir+"/vault.db", broker.StaticKeySource(key))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(context.Background(), ref, []byte(fakeToken), broker.PutMeta{Provider: "github"}, false); err != nil {
		t.Fatal(err)
	}
	return broker.NewBroker(v)
}

func resolvedWith(domains []string, creds []policy.Cred) policy.Resolved {
	return policy.Resolved{Policy: policy.Policy{
		Egress: policy.Egress{Domains: domains},
		Creds:  creds,
	}}
}

const fakeToken = "ghp_FAKEFAKEFAKEfake000nottreal000000000" // clearly fake

// ---- acceptance: token on the FORWARDED request, NEVER on the sandbox request ----

func TestForward_InjectsOnUpstreamNotSandbox(t *testing.T) {
	ref := "gh-token"
	brk := testBroker(t, ref, fakeToken)
	cfg := BuildConfig(
		resolvedWith([]string{"api.github.com"}, []policy.Cred{{Name: ref, Provider: "github"}}),
		[]InjectRule{{Host: "api.github.com", CredRef: ref, HeaderName: "Authorization", HeaderFormat: "Bearer %s"}},
		nil,
	)
	st := &stubTransport{}
	sink := &memSink{}
	rec := trace.NewRecorder(sink, "sess-1", nil, nil)
	p := New("sess-1", cfg, mustCA(t, "sess-1"), brk, []policy.Cred{{Name: ref, Provider: "github"}}, rec, AnomalyConfig{}, st)

	// The sandbox-originated request carries NO auth header.
	sandboxReq, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	if sandboxReq.Header.Get("Authorization") != "" {
		t.Fatal("precondition: sandbox request should have no auth")
	}
	resp, err := p.Forward(context.Background(), sandboxReq)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	resp.Body.Close()

	// FORWARDED request carries the injected header.
	if got := st.got.Header.Get("Authorization"); got != "Bearer "+fakeToken {
		t.Fatalf("upstream auth = %q, want Bearer <token>", got)
	}
	// SANDBOX request was NOT mutated — the agent never saw a token.
	if got := sandboxReq.Header.Get("Authorization"); got != "" {
		t.Fatalf("sandbox request leaked auth header: %q", got)
	}
}

// ---- acceptance: injection only for granted host+path; ungranted => no header ----

func TestForward_UngrantedPath_NoHeader(t *testing.T) {
	ref := "gh-token"
	brk := testBroker(t, ref, fakeToken)
	cfg := BuildConfig(
		resolvedWith([]string{"api.github.com"}, []policy.Cred{{Name: ref, Provider: "github"}}),
		[]InjectRule{{Host: "api.github.com", PathPrefix: "/repos/", CredRef: ref, HeaderName: "Authorization"}},
		nil,
	)
	st := &stubTransport{}
	p := New("s", cfg, mustCA(t, "s"), brk, []policy.Cred{{Name: ref}}, nil, AnomalyConfig{}, st)

	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil) // not /repos/
	resp, err := p.Forward(context.Background(), req)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	resp.Body.Close()
	if st.got.Header.Get("Authorization") != "" {
		t.Fatal("injected header on an ungranted path")
	}
}

func TestForward_UngrantedHost_Denied(t *testing.T) {
	cfg := BuildConfig(resolvedWith([]string{"api.github.com"}, nil), nil, nil)
	p := New("s", cfg, mustCA(t, "s"), nil, nil, nil, AnomalyConfig{}, &stubTransport{})
	req, _ := http.NewRequest("GET", "https://evil.example.com/x", nil)
	_, err := p.Forward(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "default-deny") {
		t.Fatalf("want default-deny, got %v", err)
	}
}

// ---- acceptance: resolve failure injects NO header (fail-closed, no raw leak) ----

func TestForward_ResolveDenied_NoHeader(t *testing.T) {
	// Broker has the secret, but the session's grants do NOT include the ref, so
	// Resolve denies deny-by-default. The proxy must inject nothing.
	brk := testBroker(t, "gh-token", fakeToken)
	cfg := BuildConfig(
		resolvedWith([]string{"api.github.com"}, []policy.Cred{{Name: "gh-token"}}),
		[]InjectRule{{Host: "api.github.com", CredRef: "gh-token", HeaderName: "Authorization"}},
		nil,
	)
	st := &stubTransport{}
	// grants passed to the proxy are EMPTY => Resolve denies.
	p := New("s", cfg, mustCA(t, "s"), brk, nil, nil, AnomalyConfig{}, st)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	resp, err := p.Forward(context.Background(), req)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	resp.Body.Close()
	if st.got.Header.Get("Authorization") != "" {
		t.Fatal("fail-closed violated: header injected despite denied resolve")
	}
}

// ---- acceptance: no token in any trace/log; cred.resolve valueless ----

func TestForward_NoTokenInTrace(t *testing.T) {
	ref := "gh-token"
	brk := testBroker(t, ref, fakeToken)
	cfg := BuildConfig(
		resolvedWith([]string{"api.github.com"}, []policy.Cred{{Name: ref}}),
		[]InjectRule{{Host: "api.github.com", CredRef: ref, HeaderName: "Authorization", HeaderFormat: "Bearer %s"}},
		nil,
	)
	sink := &memSink{}
	rec := trace.NewRecorder(sink, "s", nil, nil)
	p := New("s", cfg, mustCA(t, "s"), brk, []policy.Cred{{Name: ref}}, rec, AnomalyConfig{}, &stubTransport{})
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	resp, _ := p.Forward(context.Background(), req)
	resp.Body.Close()

	var sawResolve bool
	for _, e := range sink.events {
		blob := stringifyEvent(e)
		if strings.Contains(blob, fakeToken) {
			t.Fatalf("FAKE TOKEN LEAKED into trace event %s: %s", e.Type, blob)
		}
		if e.Type == trace.TypeCredResolve {
			sawResolve = true
			if _, ok := e.Payload["value"]; ok {
				t.Fatal("cred.resolve carried a value field")
			}
		}
	}
	if !sawResolve {
		t.Fatal("expected a cred.resolve audit event")
	}
}

func stringifyEvent(e trace.Event) string {
	var b strings.Builder
	b.WriteString(string(e.Type))
	for k, v := range e.Payload {
		b.WriteString(" ")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(strings.TrimSpace(toStr(v)))
	}
	return b.String()
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}

func mustCA(t *testing.T, sid string) *SessionCA {
	t.Helper()
	ca, err := NewSessionCA(sid, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// verify the leaf actually chains to the session CA (terminate is real TLS).
func TestSessionCA_LeafValidatesUnderOwnPoolOnly(t *testing.T) {
	a := mustCA(t, "sess-A")
	b := mustCA(t, "sess-B")
	leaf, err := a.LeafFor("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	// Validates under session A's own pool + host.
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: a.CertPool(), DNSName: "api.github.com"}); err != nil {
		t.Fatalf("leaf should validate under its own session CA: %v", err)
	}
	// Does NOT validate under a DIFFERENT session's CA (per-session trust boundary).
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: b.CertPool(), DNSName: "api.github.com"}); err == nil {
		t.Fatal("SECURITY: session-A leaf validated under session-B CA — CA reuse across sessions")
	}
	// A different session gets a DIFFERENT CA cert.
	if string(a.CertPEM()) == string(b.CertPEM()) {
		t.Fatal("two sessions share a CA cert")
	}
	// Leaf is scoped to its host: it does not authenticate another host.
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: a.CertPool(), DNSName: "evil.example.com"}); err == nil {
		t.Fatal("SECURITY: host-scoped leaf validated for a different host")
	}
}
