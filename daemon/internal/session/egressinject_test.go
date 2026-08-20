package session

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/egressproxy"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// gitlabTokenMarker is a clearly-fake crown-jewel secret. It must NEVER appear in
// the sandbox env, the daemon-written CA file, or the trace — only on the upstream
// (injected) request the proxy makes.
const gitlabTokenMarker = "FAKE-GITLAB-PAT-crownjewel-do-not-leak"

// captureUpstream is a stub RoundTripper standing in for the real upstream host. It
// records the FORWARDED request's headers so a test can prove the token is injected
// on the upstream leg (and, by inspecting the sandbox-side request separately, that
// it is NOT on the sandbox side).
type captureUpstream struct {
	mu     sync.Mutex
	header http.Header
}

func (c *captureUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.header = r.Header.Clone()
	c.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{},
		Body:   http.NoBody,
	}, nil
}

func (c *captureUpstream) lastHeader() http.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.header
}

// gitlabRule is the daemon-authoritative egress-inject rule under test.
func gitlabRule() egressproxy.InjectRule {
	return egressproxy.InjectRule{
		Host:         "gitlab.com",
		CredRef:      "gitlab-token",
		HeaderName:   "PRIVATE-TOKEN",
		HeaderFormat: "%s",
	}
}

// managerWithEgressInject wires a Manager with a broker + the F5.7 egress injector
// (over a stub upstream so the forwarded request is inspectable) and the given
// resolved-policy inputs. It returns the manager, the vault, the fake runtime, the
// trace sink, and the stub upstream.
func managerWithEgressInject(t *testing.T, domains []string, grants []policy.Cred, upstream http.RoundTripper) (*Manager, *broker.Vault, *fakeRuntime, *trace.MemSink) {
	t.Helper()
	vpath := filepath.Join(t.TempDir(), "vault.db")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	v, err := broker.OpenVault(vpath, broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	brk := broker.NewBroker(v)
	ei := NewEgressInjector(EgressInjectConfig{
		Rules:    []egressproxy.InjectRule{gitlabRule()},
		Broker:   brk,
		Upstream: upstream,
	})
	sink := trace.NewMemSink(nil)
	rt := newFakeRuntime()
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTTL:    30 * time.Minute,
			Limits:        runtime.ResourceLimits{MemoryBytes: 2 << 30, CPUs: 2, PidsLimit: 256},
			DefaultPolicy: policy.Policy{
				Egress: policy.Egress{Domains: domains},
				Creds:  grants,
			},
		},
		Resolve:      func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:        newFakeClock(time.Unix(0, 0)),
		Store:        newMemStore(),
		Trace:        sink,
		Broker:       brk,
		EgressInject: ei,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, v, rt, sink
}

// TestEgressInjectWiresProxyNoToken is the F5.7 acceptance proof: a session granted
// an egress-inject cred gets a per-session proxy + listener; the exec env carries
// HTTPS_PROXY + a CURL_CA_BUNDLE pointing at the daemon-written per-session CA and
// NO raw token; the CA file exists and holds a CERTIFICATE (not the token); and a
// request routed THROUGH the proxy arrives upstream WITH the injected header — while
// the sandbox-originated request never carried it.
func TestEgressInjectWiresProxyNoToken(t *testing.T) {
	ctx := context.Background()
	up := &captureUpstream{}
	m, v, rt, sink := managerWithEgressInject(t,
		[]string{"gitlab.com"},
		[]policy.Cred{{Name: "gitlab-token", Provider: "gitlab"}},
		up,
	)
	if err := v.Put(ctx, "gitlab-token", []byte(gitlabTokenMarker), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.egress == nil {
		t.Fatalf("expected a per-session egress proxy to be built")
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"curl", "https://gitlab.com/api/v4/projects"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	env := rt.lastExecEnv()
	joined := strings.Join(env, "\n")

	// Adversarial: the raw token must be NOWHERE in the exec env.
	if strings.Contains(joined, gitlabTokenMarker) {
		t.Fatalf("SECURITY: raw token leaked into container env: %q", joined)
	}
	proxyURL := "http://" + s.egress.addr
	if !strings.Contains(joined, "HTTPS_PROXY="+proxyURL) {
		t.Fatalf("missing HTTPS_PROXY in env: %q", joined)
	}
	sandboxCA := "/workspace/" + SandboxCAFileName
	if !strings.Contains(joined, "CURL_CA_BUNDLE="+sandboxCA) {
		t.Fatalf("missing/incorrect CURL_CA_BUNDLE in env: %q", joined)
	}
	for _, k := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO"} {
		if !strings.Contains(joined, k+"="+sandboxCA) {
			t.Fatalf("missing %s CA env: %q", k, joined)
		}
	}

	// The daemon-written CA file exists, holds a CERTIFICATE, and NOT the token.
	caPEM, err := os.ReadFile(filepath.Join(s.WorkspaceDir, SandboxCAFileName))
	if err != nil {
		t.Fatalf("read CA file: %v", err)
	}
	if !strings.Contains(string(caPEM), "BEGIN CERTIFICATE") {
		t.Fatalf("CA file is not a certificate: %q", string(caPEM))
	}
	if strings.Contains(string(caPEM), gitlabTokenMarker) {
		t.Fatalf("SECURITY: token leaked into the CA file")
	}

	// Route a request THROUGH the per-session proxy: the token is injected on the
	// upstream leg only. The sandbox client sends NO PRIVATE-TOKEN header.
	pu, _ := url.Parse(proxyURL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	req, _ := http.NewRequest(http.MethodGet, "http://gitlab.com/api/v4/projects", nil)
	if req.Header.Get("PRIVATE-TOKEN") != "" {
		t.Fatalf("sandbox request unexpectedly carried a token")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()
	got := up.lastHeader().Get("PRIVATE-TOKEN")
	if got != gitlabTokenMarker {
		t.Fatalf("upstream PRIVATE-TOKEN = %q, want the injected token", got)
	}

	// The token must not appear anywhere in the trace (cred.resolve is valueless).
	if evs, _, ok := sink.Export(s.ID); ok {
		b, _ := json.Marshal(evs)
		if strings.Contains(string(b), gitlabTokenMarker) {
			t.Fatalf("SECURITY: token leaked into the trace")
		}
	}
}

// TestEgressInjectOptInNoRuleMatch proves the opt-in / fail-closed posture: when the
// session's resolved policy does NOT both grant the cred and egress-allow the host,
// no proxy is built and no proxy env is injected (F1.4 default-deny path unchanged).
func TestEgressInjectOptInNoRuleMatch(t *testing.T) {
	ctx := context.Background()

	// Case A: host granted egress but cred NOT granted → no proxy.
	mA, _, rtA, _ := managerWithEgressInject(t, []string{"gitlab.com"}, nil, &captureUpstream{})
	sA, err := mA.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create A: %v", err)
	}
	if sA.egress != nil {
		t.Fatalf("A: proxy built without a cred grant")
	}
	if err := mA.Exec(ctx, sA.ID, ExecOptions{Argv: []string{"ls"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec A: %v", err)
	}
	assertNoProxyEnv(t, rtA.lastExecEnv())

	// Case B: cred granted but host NOT egress-allowed → no proxy (unmapped host).
	mB, _, rtB, _ := managerWithEgressInject(t, nil, []policy.Cred{{Name: "gitlab-token", Provider: "gitlab"}}, &captureUpstream{})
	sB, err := mB.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create B: %v", err)
	}
	if sB.egress != nil {
		t.Fatalf("B: proxy built for an egress-disallowed host")
	}
	if err := mB.Exec(ctx, sB.ID, ExecOptions{Argv: []string{"ls"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec B: %v", err)
	}
	assertNoProxyEnv(t, rtB.lastExecEnv())
}

// TestEgressInjectNarrowsNotWidens proves the F4.1 gate on the applicable() rule
// filter: a workspace that NARROWS the resolved policy can only lose grants, never
// add or widen an egress-inject host. A resolved policy missing either the host or
// the cred yields no applicable rule.
func TestEgressInjectNarrowsNotWidens(t *testing.T) {
	ei := NewEgressInjector(EgressInjectConfig{Rules: []egressproxy.InjectRule{gitlabRule()}})

	both := policy.ResolveDefault(policy.Policy{
		Egress: policy.Egress{Domains: []string{"gitlab.com"}},
		Creds:  []policy.Cred{{Name: "gitlab-token"}},
	})
	if len(ei.applicable(both)) != 1 {
		t.Fatalf("expected the rule to apply when host+cred are both resolved")
	}

	// Workspace narrows creds away (intersection to empty) → rule drops.
	narrowed := policy.Resolve(
		policy.Policy{Egress: policy.Egress{Domains: []string{"gitlab.com"}}, Creds: []policy.Cred{{Name: "gitlab-token"}}},
		policy.Policy{Creds: []policy.Cred{}}, // explicitly empty => narrow to nothing
	)
	if got := ei.applicable(narrowed); len(got) != 0 {
		t.Fatalf("workspace narrowing should drop the rule, got %d applicable", len(got))
	}

	// A cred granted but host not egress-allowed → no applicable rule.
	credOnly := policy.ResolveDefault(policy.Policy{Creds: []policy.Cred{{Name: "gitlab-token"}}})
	if got := ei.applicable(credOnly); len(got) != 0 {
		t.Fatalf("host not egress-allowed should drop the rule, got %d applicable", len(got))
	}
}

// TestEgressProxyTornDownFreshCASecondSession proves the per-session CA scoping:
// the proxy/listener is torn down on session end (its address stops accepting), and
// a second session gets a WHOLLY FRESH CA (a different cert).
func TestEgressProxyTornDownFreshCASecondSession(t *testing.T) {
	ctx := context.Background()
	grants := []policy.Cred{{Name: "gitlab-token", Provider: "gitlab"}}
	m, v, _, _ := managerWithEgressInject(t, []string{"gitlab.com"}, grants, &captureUpstream{})
	if err := v.Put(ctx, "gitlab-token", []byte(gitlabTokenMarker), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}

	s1, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create s1: %v", err)
	}
	addr1 := s1.egress.addr
	ca1, err := os.ReadFile(filepath.Join(s1.WorkspaceDir, SandboxCAFileName))
	if err != nil {
		t.Fatalf("read ca1: %v", err)
	}
	if err := m.Destroy(ctx, s1.ID); err != nil {
		t.Fatalf("Destroy s1: %v", err)
	}
	// The torn-down listener no longer accepts connections.
	if c, derr := net.DialTimeout("tcp", addr1, 500*time.Millisecond); derr == nil {
		c.Close()
		t.Fatalf("proxy listener still accepting after teardown")
	}

	s2, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create s2: %v", err)
	}
	ca2, err := os.ReadFile(filepath.Join(s2.WorkspaceDir, SandboxCAFileName))
	if err != nil {
		t.Fatalf("read ca2: %v", err)
	}
	if string(ca1) == string(ca2) {
		t.Fatalf("SECURITY: second session reused the first session's CA")
	}
}

// TestEgressInjectFailClosedOnListenerError proves fail-closed: a proxy/listener
// build failure injects NO proxy env and NO raw-secret fallback — the session still
// runs, just without the credential-blind HTTP route.
func TestEgressInjectFailClosedOnListenerError(t *testing.T) {
	ctx := context.Background()
	vpath := filepath.Join(t.TempDir(), "vault.db")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	v, err := broker.OpenVault(vpath, broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	brk := broker.NewBroker(v)
	if err := v.Put(ctx, "gitlab-token", []byte(gitlabTokenMarker), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	ei := NewEgressInjector(EgressInjectConfig{
		Rules:  []egressproxy.InjectRule{gitlabRule()},
		Broker: brk,
	})
	// Force the listener to fail.
	ei.listen = func() (net.Listener, error) { return nil, net.ErrClosed }

	rt := newFakeRuntime()
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTTL:    30 * time.Minute,
			DefaultPolicy: policy.Policy{
				Egress: policy.Egress{Domains: []string{"gitlab.com"}},
				Creds:  []policy.Cred{{Name: "gitlab-token", Provider: "gitlab"}},
			},
		},
		Resolve:      func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:        newFakeClock(time.Unix(0, 0)),
		Store:        newMemStore(),
		Trace:        trace.NewMemSink(nil),
		Broker:       brk,
		EgressInject: ei,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.egress != nil {
		t.Fatalf("expected no egress handle after a listener failure")
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"ls"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	env := rt.lastExecEnv()
	assertNoProxyEnv(t, env)
	if strings.Contains(strings.Join(env, "\n"), gitlabTokenMarker) {
		t.Fatalf("SECURITY: token leaked into env on the fail-closed path")
	}
	// No CA file must have been written on the fail-closed path.
	if _, err := os.Stat(filepath.Join(s.WorkspaceDir, SandboxCAFileName)); err == nil {
		t.Fatalf("CA file written despite fail-closed proxy build")
	}
}

func assertNoProxyEnv(t *testing.T, env []string) {
	t.Helper()
	for _, e := range env {
		for _, k := range []string{"HTTPS_PROXY=", "HTTP_PROXY=", "CURL_CA_BUNDLE=", "SSL_CERT_FILE=", "REQUESTS_CA_BUNDLE=", "GIT_SSL_CAINFO="} {
			if strings.HasPrefix(e, k) {
				t.Fatalf("unexpected proxy env %q", e)
			}
		}
	}
}
