package session

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
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

// fakeNetRuntime embeds the capability-absent fakeRuntime and ADDS the F5.8
// NetworkInfo capability, so only tests that want reachability discovery opt in
// (every other test keeps the legacy loopback path via the bare fakeRuntime).
type fakeNetRuntime struct {
	*fakeRuntime
	containerIP string
	gatewayIP   string
	netErr      error
}

func (f *fakeNetRuntime) NetworkInfo(context.Context, runtime.ContainerHandle) (string, string, error) {
	if f.netErr != nil {
		return "", "", f.netErr
	}
	return f.containerIP, f.gatewayIP, nil
}

// recordingListen is an injectable listenTCP seam: it records every REQUESTED
// bind address (so a test can assert the gateway host is bound — never loopback
// or 0.0.0.0) while actually binding a real loopback listener (the test host has
// no 10.88.0.1 interface). It thus proves WHICH address the manager asked to
// bind without needing the gateway to exist.
type recordingListen struct {
	mu    sync.Mutex
	addrs []string
}

func (r *recordingListen) listen(_, addr string) (net.Listener, error) {
	r.mu.Lock()
	r.addrs = append(r.addrs, addr)
	r.mu.Unlock()
	return net.Listen("tcp", "127.0.0.1:0")
}

func (r *recordingListen) requested() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addrs...)
}

// managerWithNet wires a Manager over a network-capable fake runtime + the F5.8
// listen seam, the F5.1 injector (shared CredServer), and an optional F5.7 egress
// injector. It returns the manager, the vault, the fake runtime, and the listen
// recorder.
func managerWithNet(t *testing.T, containerIP, gatewayIP string, netErr error, grants []policy.Cred, domains []string, ei *EgressInjector) (*Manager, *broker.Vault, *fakeNetRuntime, *recordingListen) {
	t.Helper()
	vpath := filepath.Join(t.TempDir(), "vault.db")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 5)
	}
	v, err := broker.OpenVault(vpath, broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	brk := broker.NewBroker(v)
	now := func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }
	server := broker.NewCredServer(now)
	// A shared loopback endpoint (as production wires) — the manager overrides it
	// per session with the gateway bind. baseURL here is the loopback fallback.
	ts := httptest.NewServer(http.HandlerFunc(server.ServeHTTP))
	t.Cleanup(ts.Close)
	injector := broker.NewInjector(brk, server, ts.URL, 15*time.Minute, now)

	if ei != nil {
		ei.broker = brk
	}
	rt := &fakeNetRuntime{fakeRuntime: newFakeRuntime(), containerIP: containerIP, gatewayIP: gatewayIP, netErr: netErr}
	rl := &recordingListen{}
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTTL:    30 * time.Minute,
			DefaultPolicy: policy.Policy{
				Egress: policy.Egress{Domains: domains},
				Creds:  grants,
			},
		},
		Resolve:      func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:        newFakeClock(time.Unix(0, 0)),
		Store:        newMemStore(),
		Trace:        trace.NewMemSink(nil),
		Broker:       brk,
		CredInjector: injector,
		EgressInject: ei,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.listenTCP = rl.listen
	return m, v, rt, rl
}

// TestF58NeverBindsWildcard is the never-0.0.0.0 guard: the bind guard rejects
// every unspecified/empty/non-IP host and accepts a concrete gateway.
func TestF58NeverBindsWildcard(t *testing.T) {
	for _, bad := range []string{"", "0.0.0.0", "::", "0:0:0:0:0:0:0:0", "::ffff:0.0.0.0", "not-an-ip", "gateway.local"} {
		if isBindableGateway(bad) {
			t.Fatalf("isBindableGateway(%q) = true, want false (must never bind a wildcard/world address)", bad)
		}
	}
	for _, good := range []string{"10.88.0.1", "172.17.0.1", "192.168.5.1", "fd00::1"} {
		if !isBindableGateway(good) {
			t.Fatalf("isBindableGateway(%q) = false, want true", good)
		}
	}
}

// TestF58CredsEndpointBindsGateway proves the F5.1 creds endpoint binds the
// discovered GATEWAY (never 127.0.0.1 / 0.0.0.0) and advertises that gateway in
// AWS_CONTAINER_CREDENTIALS_FULL_URI.
func TestF58CredsEndpointBindsGateway(t *testing.T) {
	ctx := context.Background()
	grants := []policy.Cred{{Name: "aws-role", Provider: "aws"}}
	m, v, rt, rl := managerWithNet(t, "10.88.0.5", "10.88.0.1", nil, grants, nil, nil)
	if err := v.Put(ctx, "aws-role", awsCredDoc(t), broker.PutMeta{Provider: "aws"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = m.Destroy(context.Background(), s.ID) })

	// The REQUESTED bind address is the gateway — never loopback, never a wildcard.
	reqs := rl.requested()
	if len(reqs) == 0 {
		t.Fatalf("no listener bind was requested")
	}
	for _, a := range reqs {
		host, _, _ := net.SplitHostPort(a)
		if host != "10.88.0.1" {
			t.Fatalf("bind host = %q, want the gateway 10.88.0.1 (never loopback/0.0.0.0)", host)
		}
		if host == "127.0.0.1" || host == "0.0.0.0" || host == "::" || host == "" {
			t.Fatalf("SECURITY: credential listener bound a forbidden host %q", host)
		}
	}
	if s.credEndpoint == nil {
		t.Fatalf("expected a per-session gateway creds endpoint")
	}

	// The advertised endpoint URI carries the gateway host, not loopback.
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"aws", "sts", "get-caller-identity"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	joined := strings.Join(rt.lastExecEnv(), "\n")
	if !strings.Contains(joined, "AWS_CONTAINER_CREDENTIALS_FULL_URI=http://10.88.0.1:") {
		t.Fatalf("endpoint URI does not advertise the gateway: %q", joined)
	}
	if strings.Contains(joined, "127.0.0.1") || strings.Contains(joined, "0.0.0.0") {
		t.Fatalf("SECURITY: endpoint env advertised loopback/wildcard: %q", joined)
	}
	if strings.Contains(joined, awsSecretMarker) {
		t.Fatalf("SECURITY: raw secret leaked into the exec env: %q", joined)
	}
}

// TestF58SourceIPScope proves a request from the owning container IP with the
// right token is served, while the SAME token from any other source IP is refused
// — the source-IP scope on TOP of the F5.1 token gate.
func TestF58SourceIPScope(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }
	server := broker.NewCredServer(now)
	const sessID = "sess-1"
	const token = "deadbeeftoken"
	server.Register(sessID, token, []byte(`{"ok":true}`), "application/json", now().Add(time.Minute))

	h := sourceScoped(server, "10.88.0.5", nil)

	do := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, broker.CredPath+sessID, nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do("10.88.0.5:44001"); code != http.StatusOK {
		t.Fatalf("owning-IP request = %d, want 200", code)
	}
	if code := do("10.88.0.6:44002"); code != http.StatusForbidden {
		t.Fatalf("neighbour-IP request with a VALID token = %d, want 403", code)
	}
	if code := do("192.168.1.50:44003"); code != http.StatusForbidden {
		t.Fatalf("LAN request with a VALID token = %d, want 403", code)
	}
}

// TestF58EgressProxyBindsGateway proves the F5.7 proxy binds the gateway and
// advertises it in HTTPS_PROXY, source-scoped to the container.
func TestF58EgressProxyBindsGateway(t *testing.T) {
	ctx := context.Background()
	ei := NewEgressInjector(EgressInjectConfig{Rules: []egressproxy.InjectRule{gitlabRule()}})
	grants := []policy.Cred{{Name: "gitlab-token", Provider: "gitlab"}}
	m, v, rt, rl := managerWithNet(t, "10.88.0.5", "10.88.0.1", nil, grants, []string{"gitlab.com"}, ei)
	if err := v.Put(ctx, "gitlab-token", []byte(gitlabTokenMarker), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = m.Destroy(context.Background(), s.ID) })
	if s.egress == nil {
		t.Fatalf("expected a per-session egress proxy")
	}
	// The proxy advertise addr uses the gateway host.
	if host, _, _ := net.SplitHostPort(s.egress.addr); host != "10.88.0.1" {
		t.Fatalf("egress advertise host = %q, want gateway 10.88.0.1", host)
	}
	for _, a := range rl.requested() {
		if host, _, _ := net.SplitHostPort(a); host != "10.88.0.1" {
			t.Fatalf("egress bind host = %q, want gateway 10.88.0.1 (never loopback/0.0.0.0)", host)
		}
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"curl", "https://gitlab.com"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	joined := strings.Join(rt.lastExecEnv(), "\n")
	if !strings.Contains(joined, "HTTPS_PROXY=http://10.88.0.1:") {
		t.Fatalf("HTTPS_PROXY does not advertise the gateway: %q", joined)
	}
	// The proxy URL must never be loopback (NO_PROXY legitimately lists 127.0.0.1).
	if strings.Contains(joined, "PROXY=http://127.0.0.1") || strings.Contains(joined, "proxy=http://127.0.0.1") {
		t.Fatalf("SECURITY: proxy advertised loopback: %q", joined)
	}
	if strings.Contains(joined, gitlabTokenMarker) {
		t.Fatalf("SECURITY: raw token in env: %q", joined)
	}
}

// TestF58FailClosedNoGateway proves that when the runtime EXPOSES NetworkInfo but
// no reachable gateway is discoverable, both credential-blind paths fail closed:
// no AWS endpoint env, no proxy env, no raw secret — and the session still runs.
func TestF58FailClosedNoGateway(t *testing.T) {
	cases := []struct {
		name      string
		gatewayIP string
		netErr    error
	}{
		{"empty-gateway", "", nil},
		{"inspect-error", "10.88.0.1", context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ei := NewEgressInjector(EgressInjectConfig{Rules: []egressproxy.InjectRule{gitlabRule()}})
			grants := []policy.Cred{
				{Name: "aws-role", Provider: "aws"},
				{Name: "gitlab-token", Provider: "gitlab"},
			}
			m, v, rt, rl := managerWithNet(t, "10.88.0.5", tc.gatewayIP, tc.netErr, grants, []string{"gitlab.com"}, ei)
			if err := v.Put(ctx, "aws-role", awsCredDoc(t), broker.PutMeta{Provider: "aws"}, false); err != nil {
				t.Fatalf("Put aws: %v", err)
			}
			if err := v.Put(ctx, "gitlab-token", []byte(gitlabTokenMarker), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
				t.Fatalf("Put gitlab: %v", err)
			}
			s, err := m.Create(ctx, CreateRequest{})
			if err != nil {
				t.Fatalf("Create: %v", err) // the session MUST still run
			}
			t.Cleanup(func() { _ = m.Destroy(context.Background(), s.ID) })
			if s.egress != nil {
				t.Fatalf("expected NO egress proxy on the fail-closed path")
			}
			if s.credEndpoint != nil {
				t.Fatalf("expected NO gateway creds endpoint on the fail-closed path")
			}
			if len(rl.requested()) != 0 {
				t.Fatalf("no listener should be bound when the gateway is unreachable, got %v", rl.requested())
			}
			if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"ls"}}, newCaptureSink()); err != nil {
				t.Fatalf("Exec: %v", err)
			}
			env := rt.lastExecEnv()
			assertNoProxyEnv(t, env)
			joined := strings.Join(env, "\n")
			if strings.Contains(joined, "AWS_CONTAINER_CREDENTIALS_FULL_URI") {
				t.Fatalf("fail-closed path still injected the AWS endpoint: %q", joined)
			}
			if strings.Contains(joined, awsSecretMarker) || strings.Contains(joined, gitlabTokenMarker) {
				t.Fatalf("SECURITY: raw secret leaked on the fail-closed path: %q", joined)
			}
		})
	}
}

// TestF58TeardownClosesCredEndpoint proves the per-session gateway creds endpoint
// is closed on teardown (no listener outlives the session).
func TestF58TeardownClosesCredEndpoint(t *testing.T) {
	ctx := context.Background()
	grants := []policy.Cred{{Name: "aws-role", Provider: "aws"}}
	m, v, _, _ := managerWithNet(t, "10.88.0.5", "10.88.0.1", nil, grants, nil, nil)
	if err := v.Put(ctx, "aws-role", awsCredDoc(t), broker.PutMeta{Provider: "aws"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.credEndpoint == nil {
		t.Fatalf("expected a gateway creds endpoint")
	}
	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if s.credEndpoint != nil {
		t.Fatalf("credEndpoint should be cleared on teardown")
	}
}
