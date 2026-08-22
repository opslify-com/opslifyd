package session

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/regproxy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// registryTokenMarker is a clearly-fake private-registry credential. It must NEVER
// appear in the sandbox routing env or the trace — only on the upstream leg.
const registryTokenMarker = "FAKE-PYPI-TOKEN-crownjewel-do-not-leak"

// wheelUpstream is a stub upstream that serves a fake wheel for any artifact GET and
// records the last forwarded request headers (to prove the credential rides only the
// upstream leg).
type wheelUpstream struct {
	lastAuth string
}

func (w *wheelUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	w.lastAuth = r.Header.Get("Authorization")
	return &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"application/octet-stream"}},
		Body:   http.NoBody,
	}, nil
}

// pypiRegistryConfig is the daemon-authoritative F5.5 config under test: a pypi
// upstream (with a credential REF) and an allowlist of one package.
func pypiRegistryConfig(t *testing.T, credRef string) regproxy.Config {
	t.Helper()
	return regproxy.Config{
		CacheDir: filepath.Join(t.TempDir(), "cache"),
		Upstreams: []regproxy.Upstream{{
			Ecosystem:    regproxy.EcosystemPyPI,
			BaseURL:      "https://pypi.org",
			CredRef:      credRef,
			HeaderName:   "Authorization",
			HeaderFormat: "token %s",
		}},
		Allow: []regproxy.AllowEntry{{Ecosystem: regproxy.EcosystemPyPI, Name: "requests"}},
	}
}

// managerWithRegistry wires a Manager with a broker + the F7.5 registry injector over
// the given config + upstream, and the given resolved-policy grants. It returns the
// manager, the vault, the fake runtime, and the trace sink.
func managerWithRegistry(t *testing.T, cfg regproxy.Config, grants []policy.Cred, upstream http.RoundTripper) (*Manager, *broker.Vault, *fakeRuntime, *trace.MemSink) {
	t.Helper()
	vpath := filepath.Join(t.TempDir(), "vault.db")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	v, err := broker.OpenVault(vpath, broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	brk := broker.NewBroker(v)
	ri := NewRegistryInjector(RegistryInjectConfig{Config: cfg, Broker: brk, Upstream: upstream})
	sink := trace.NewMemSink(nil)
	rt := newFakeRuntime()
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTTL:    30 * time.Minute,
			Limits:        runtime.ResourceLimits{MemoryBytes: 2 << 30, CPUs: 2, PidsLimit: 256},
			DefaultPolicy: policy.Policy{Creds: grants},
		},
		Resolve:        func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:          newFakeClock(time.Unix(0, 0)),
		Store:          newMemStore(),
		Trace:          sink,
		Broker:         brk,
		RegistryInject: ri,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, v, rt, sink
}

// TestRegistryInjectRoutingEnvNoCredential is the F7.5 acceptance proof: a session on
// a daemon with the registry proxy configured gets the ecosystem routing env pointing
// at the per-session proxy — and NO credential in that env. A fetch routed through the
// proxy carries the injected credential on the UPSTREAM leg only, and emits a
// pkg.install event into the session's verifiable chain.
func TestRegistryInjectRoutingEnvNoCredential(t *testing.T) {
	ctx := context.Background()
	up := &wheelUpstream{}
	m, v, rt, sink := managerWithRegistry(t, pypiRegistryConfig(t, "pypi-token"),
		[]policy.Cred{{Name: "pypi-token", Provider: "generic"}}, up)
	if err := v.Put(ctx, "pypi-token", []byte(registryTokenMarker), broker.PutMeta{Provider: "generic"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.registry == nil {
		t.Fatalf("expected a per-session registry proxy to be built")
	}

	// The routing env must point pip at the proxy and carry NO credential.
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"pip", "install", "requests"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	joined := strings.Join(rt.lastExecEnv(), "\n")
	if strings.Contains(joined, registryTokenMarker) {
		t.Fatalf("SECURITY: credential leaked into routing env: %q", joined)
	}
	proxyURL := "http://" + s.registry.addr
	wantIdx := "PIP_INDEX_URL=" + proxyURL + "/pypi/simple"
	if !strings.Contains(joined, wantIdx) {
		t.Fatalf("missing/incorrect PIP_INDEX_URL: got %q, want to contain %q", joined, wantIdx)
	}
	if !strings.Contains(joined, "PIP_EXTRA_INDEX_URL="+proxyURL+"/pypi/simple") {
		t.Fatalf("missing PIP_EXTRA_INDEX_URL: %q", joined)
	}

	// Route an artifact fetch THROUGH the proxy: the credential is injected on the
	// upstream leg only, and a pkg.install event lands in the chain.
	base, _ := url.Parse(proxyURL)
	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, base.String()+"/pypi/packages/ab/requests-2.31.0-py3-none-any.whl", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy fetch: %v", err)
	}
	resp.Body.Close()
	if got := up.lastAuth; got != "token "+registryTokenMarker {
		t.Fatalf("upstream Authorization = %q, want the injected credential", got)
	}

	evs, _, ok := sink.Export(s.ID)
	if !ok {
		t.Fatalf("no trace for session")
	}
	var found bool
	for _, e := range evs {
		if e.Type == trace.TypePkgInstall {
			found = true
			b, _ := json.Marshal(e)
			if !strings.Contains(string(b), "requests") {
				t.Fatalf("pkg.install event missing package name: %s", b)
			}
			if strings.Contains(string(b), registryTokenMarker) {
				t.Fatalf("SECURITY: credential leaked into pkg.install event: %s", b)
			}
		}
	}
	if !found {
		t.Fatalf("expected a pkg.install event in the chain")
	}
	// The credential must not appear anywhere in the trace.
	all, _ := json.Marshal(evs)
	if strings.Contains(string(all), registryTokenMarker) {
		t.Fatalf("SECURITY: credential leaked into the trace")
	}
}

// TestRegistryInjectTornDownOnEnd proves the per-session proxy listener is closed on
// session end (no cross-session reuse, no listener outliving the session).
func TestRegistryInjectTornDownOnEnd(t *testing.T) {
	ctx := context.Background()
	m, _, _, _ := managerWithRegistry(t, pypiRegistryConfig(t, ""), nil, &wheelUpstream{})
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	addr := s.registry.addr
	// Live before teardown.
	if _, err := http.Get("http://" + addr + "/pypi/simple/requests/"); err != nil {
		t.Fatalf("proxy should be live before end: %v", err)
	}
	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if s.registry != nil {
		t.Fatalf("registry handle not cleared on teardown")
	}
	if _, err := http.Get("http://" + addr + "/pypi/simple/requests/"); err == nil {
		t.Fatalf("proxy listener still serving after session end")
	}
}

// TestRegistryInjectDisabledNoConfig proves opt-in: with no upstream configured no
// proxy is built and no routing env is injected (no behavior change).
func TestRegistryInjectDisabledNoConfig(t *testing.T) {
	ctx := context.Background()
	m, _, rt, _ := managerWithRegistry(t, regproxy.Config{}, nil, &wheelUpstream{})
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.registry != nil {
		t.Fatalf("registry proxy built with no upstream configured")
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"ls"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if joined := strings.Join(rt.lastExecEnv(), "\n"); strings.Contains(joined, "PIP_INDEX_URL") {
		t.Fatalf("routing env injected with no proxy configured: %q", joined)
	}
}

// managerWithRegistryNet wires a Manager over a NetworkInfo-capable fake runtime +
// the F5.8 listen seam and the F7.5 registry injector, so a test can assert WHICH
// address the proxy listener binds (the gateway, never loopback/0.0.0.0) and the
// fail-closed no-gateway posture.
func managerWithRegistryNet(t *testing.T, cfg regproxy.Config, containerIP, gatewayIP string) (*Manager, *fakeNetRuntime, *recordingListen) {
	t.Helper()
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
	ri := NewRegistryInjector(RegistryInjectConfig{Config: cfg, Broker: brk, Upstream: &wheelUpstream{}})
	rt := &fakeNetRuntime{fakeRuntime: newFakeRuntime(), containerIP: containerIP, gatewayIP: gatewayIP}
	rl := &recordingListen{}
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTTL:    30 * time.Minute,
			DefaultPolicy: policy.Policy{},
		},
		Resolve:        func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:          newFakeClock(time.Unix(0, 0)),
		Store:          newMemStore(),
		Trace:          trace.NewMemSink(nil),
		Broker:         brk,
		RegistryInject: ri,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.listenTCP = rl.listen
	return m, rt, rl
}

// TestRegistryInjectBindsGatewayNotWildcard proves the F5.8 bind boundary is reused:
// the per-session registry proxy binds the discovered GATEWAY (never 127.0.0.1 /
// 0.0.0.0) and advertises that gateway in the routing env.
func TestRegistryInjectBindsGatewayNotWildcard(t *testing.T) {
	ctx := context.Background()
	m, rt, rl := managerWithRegistryNet(t, pypiRegistryConfig(t, ""), "10.88.0.5", "10.88.0.1")
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.registry == nil {
		t.Fatalf("expected a per-session registry proxy")
	}
	var boundGateway bool
	for _, addr := range rl.requested() {
		host, _, _ := net.SplitHostPort(addr)
		if host == "10.88.0.1" {
			boundGateway = true
		}
		if host == "127.0.0.1" || host == "0.0.0.0" || host == "::" || host == "" {
			t.Fatalf("registry proxy bind host = %q, want the gateway (never loopback/0.0.0.0)", host)
		}
	}
	if !boundGateway {
		t.Fatalf("registry proxy never bound the gateway 10.88.0.1; requested=%v", rl.requested())
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"pip", "install", "requests"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	joined := strings.Join(rt.lastExecEnv(), "\n")
	if !strings.Contains(joined, "PIP_INDEX_URL=http://10.88.0.1:") {
		t.Fatalf("routing env not advertised on the gateway: %q", joined)
	}
	if strings.Contains(joined, "127.0.0.1") || strings.Contains(joined, "0.0.0.0") {
		t.Fatalf("routing env leaked a loopback/wildcard address: %q", joined)
	}
}

// TestRegistryInjectFailClosedNoGateway proves that when the runtime EXPOSES
// NetworkInfo but reports NO reachable gateway, the registry proxy is disabled and NO
// routing env is injected — never an open-egress fallback.
func TestRegistryInjectFailClosedNoGateway(t *testing.T) {
	ctx := context.Background()
	m, rt, _ := managerWithRegistryNet(t, pypiRegistryConfig(t, ""), "10.88.0.5", "0.0.0.0")
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.registry != nil {
		t.Fatalf("registry proxy built despite no reachable gateway (must fail closed)")
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"pip", "install", "requests"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if joined := strings.Join(rt.lastExecEnv(), "\n"); strings.Contains(joined, "PIP_INDEX_URL") {
		t.Fatalf("routing env injected despite fail-closed no-gateway: %q", joined)
	}
}

// TestRegistryAllowedGate proves the pre-install allowlist gate: an allowlisted name
// is allowed, a non-allowlisted (typosquat-style) name is refused, and an unconfigured
// daemon reports configured=false (the CLI then fails closed, never open-egress).
func TestRegistryAllowedGate(t *testing.T) {
	m, _, _, _ := managerWithRegistry(t, pypiRegistryConfig(t, ""), nil, &wheelUpstream{})

	configured, allowed, err := m.RegistryAllowed("pypi", "requests")
	if err != nil || !configured || !allowed {
		t.Fatalf("requests: configured=%v allowed=%v err=%v, want true,true,nil", configured, allowed, err)
	}
	// pip alias normalization is handled at the CLI; the daemon key is pypi.
	configured, allowed, err = m.RegistryAllowed("pypi", "reqeusts") // typosquat
	if err != nil || !configured || allowed {
		t.Fatalf("typosquat: configured=%v allowed=%v err=%v, want true,false,nil", configured, allowed, err)
	}

	// Unconfigured daemon: fail closed.
	mNo, _, _, _ := managerWithRegistry(t, regproxy.Config{}, nil, &wheelUpstream{})
	configured, allowed, _ = mNo.RegistryAllowed("pypi", "requests")
	if configured || allowed {
		t.Fatalf("unconfigured: configured=%v allowed=%v, want false,false", configured, allowed)
	}
}
