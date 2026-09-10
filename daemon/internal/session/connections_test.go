package session

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// fakeConnection is a Connection whose behaviour each test dictates, so the
// WIRING is under test rather than any particular kind.
type fakeConnection struct {
	kind     broker.Kind
	name     string
	refs     []string
	rules    []broker.HeaderInjectRule
	inj      broker.ConnectionInjection
	buildErr error

	mu       sync.Mutex
	built    bool
	closed   bool
	sawProxy string
	sawCALen int
	sawWSDir string
}

func (f *fakeConnection) Kind() broker.Kind                      { return f.kind }
func (f *fakeConnection) Name() string                           { return f.name }
func (f *fakeConnection) SecretRefs() []string                   { return f.refs }
func (f *fakeConnection) Validate() error                        { return nil }
func (f *fakeConnection) EgressRules() []broker.HeaderInjectRule { return f.rules }

func (f *fakeConnection) BuildForSession(_ context.Context, sc broker.SessionContext) (broker.ConnectionInjection, io.Closer, error) {
	f.mu.Lock()
	f.built = true
	f.sawProxy, f.sawCALen, f.sawWSDir = sc.ProxyAddr, len(sc.ProxyCAPEM), sc.WorkspaceDir
	f.mu.Unlock()
	if f.buildErr != nil {
		return broker.ConnectionInjection{}, nil, f.buildErr
	}
	return f.inj, closerFn(func() error {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		return nil
	}), nil
}

func (f *fakeConnection) wasBuilt() bool  { f.mu.Lock(); defer f.mu.Unlock(); return f.built }
func (f *fakeConnection) wasClosed() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.closed }

type closerFn func() error

func (c closerFn) Close() error { return c() }

// connManager builds a Manager with a connection source wired.
func connManager(t *testing.T, rt runtime.Runtime, src ContextConnectionSource) *Manager {
	t.Helper()
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTier:   runtime.TierLocalHardened,
			DefaultTTL:    30 * time.Minute,
		},
		Resolve:     func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:       newFakeClock(time.Unix(0, 0)),
		Store:       newMemStore(),
		Connections: src,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// --- the exclusion, which is the load-bearing wiring -------------------------

// TestConnectionRefsAreExcludedFromEnvironmentInjection is the reason this wiring
// exists. A ref a connection resolves at its boundary — a proxy header, a
// kubeconfig, an ssh agent — must never ALSO be resolved into the sandbox
// environment by the F5.1 injector. Otherwise the value the connection exists to
// keep out of the sandbox is placed in it anyway, by a different code path.
func TestConnectionRefsAreExcludedFromEnvironmentInjection(t *testing.T) {
	rt := newFakeRuntime()
	conn := &fakeConnection{kind: broker.KindHTTP, name: "gitlab", refs: []string{"gitlab-token"}}
	m := connManager(t, rt, func(string, string) ([]broker.Connection, error) {
		return []broker.Connection{conn}, nil
	})
	s := &Session{ID: "s1", ProjectID: "p", EnvironmentID: "e"}
	if _, err := m.resolveConnections(s); err != nil {
		t.Fatalf("resolveConnections: %v", err)
	}
	if !s.isConnectionRef("gitlab-token") {
		t.Fatal("a ref a connection resolves must be excluded from environment injection")
	}
	if s.isConnectionRef("some-other-token") {
		t.Error("an unrelated ref must not be excluded")
	}
}

// TestNoConnectionSourceExcludesNothing keeps the seam optional: every pre-P8
// path runs without connections and must be unaffected.
func TestNoConnectionSourceExcludesNothing(t *testing.T) {
	m := connManager(t, newFakeRuntime(), nil)
	s := &Session{ID: "s1"}
	conns, err := m.resolveConnections(s)
	if err != nil || len(conns) != 0 {
		t.Fatalf("no source must yield no connections: %v %v", conns, err)
	}
	if s.isConnectionRef("anything") {
		t.Error("with no connections nothing may be excluded")
	}
}

// --- fail closed ---------------------------------------------------------------

// TestSessionRefusesWhenConnectionsCannotBeResolved: a session that silently ran
// without a connection an operator configured would fail later, inside the
// agent's work, as a confusing authorization error.
func TestSessionRefusesWhenConnectionsCannotBeResolved(t *testing.T) {
	rt := newFakeRuntime()
	boom := errors.New("connection store unreadable")
	m := connManager(t, rt, func(string, string) ([]broker.Connection, error) { return nil, boom })

	_, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if !errors.Is(err, boom) {
		t.Fatalf("Create must fail closed, got %v", err)
	}
	// And it must not leak a sandbox: an unregistered container with credentials
	// possibly already injected is the worst kind of leak, since no Destroy will
	// ever reach it.
	rt.mu.Lock()
	created, destroyed := rt.created, rt.destroyed
	rt.mu.Unlock()
	if created != destroyed {
		t.Errorf("%d created, %d destroyed: the refused create leaked a sandbox", created, destroyed)
	}
	if len(m.List()) != 0 {
		t.Errorf("a refused create left a session registered")
	}
}

// TestSessionRefusesWhenAConnectionCannotBeBuilt covers phase two, and asserts
// the whole set is torn down — a partial set is the worst outcome, because the
// agent would have some credentials and not others.
func TestSessionRefusesWhenAConnectionCannotBeBuilt(t *testing.T) {
	rt := newFakeRuntime()
	good := &fakeConnection{kind: broker.KindHTTP, name: "ok", refs: []string{"r1"}}
	bad := &fakeConnection{kind: broker.KindSSH, name: "broken", refs: []string{"r2"},
		buildErr: errors.New("openssh too old for destination constraints")}
	m := connManager(t, rt, func(string, string) ([]broker.Connection, error) {
		return []broker.Connection{good, bad}, nil
	})

	_, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err == nil {
		t.Fatal("a connection that cannot be built must refuse the session")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("the error should name the connection: %v", err)
	}
	if !good.wasClosed() {
		t.Error("a connection built before the failure must be torn down — a partial set is worse than none")
	}
	rt.mu.Lock()
	created, destroyed := rt.created, rt.destroyed
	rt.mu.Unlock()
	if created != destroyed {
		t.Errorf("%d created, %d destroyed: the refused create leaked a sandbox", created, destroyed)
	}
}

// --- phase two receives the proxy ---------------------------------------------

// TestPhaseTwoReceivesTheBoundProxy: a kind that points the sandbox at the proxy
// (the kubernetes kubeconfig) cannot do so unless the address and CA reach it.
func TestPhaseTwoReceivesTheBoundProxy(t *testing.T) {
	rt := newFakeRuntime()
	conn := &fakeConnection{kind: broker.KindKubernetes, name: "cluster", refs: []string{"k8s"}}
	m := connManager(t, rt, func(string, string) ([]broker.Connection, error) {
		return []broker.Connection{conn}, nil
	})
	s := &Session{ID: "s1", WorkspaceDir: t.TempDir()}
	if _, err := m.resolveConnections(s); err != nil {
		t.Fatal(err)
	}
	if err := m.buildConnections(context.Background(), s, []broker.Connection{conn},
		"172.17.0.1:41234", []byte("CA-PEM-BYTES")); err != nil {
		t.Fatalf("buildConnections: %v", err)
	}
	conn.mu.Lock()
	addr, caLen, ws := conn.sawProxy, conn.sawCALen, conn.sawWSDir
	conn.mu.Unlock()
	if addr != "172.17.0.1:41234" {
		t.Errorf("proxy address = %q", addr)
	}
	if caLen == 0 {
		t.Error("the per-session CA must reach the kind, or its client cannot verify the proxy")
	}
	if ws != s.WorkspaceDir {
		t.Errorf("workspace dir = %q, want %q", ws, s.WorkspaceDir)
	}
}

// --- injection application -----------------------------------------------------

// TestConnectionFilesAreWrittenIntoTheWorkspace, with the mode the kind asked for.
func TestConnectionFilesAreWrittenIntoTheWorkspace(t *testing.T) {
	rt := newFakeRuntime()
	conn := &fakeConnection{
		kind: broker.KindKubernetes, name: "cluster", refs: []string{"k8s"},
		inj: broker.ConnectionInjection{
			Env:   map[string]string{"KUBECONFIG": "/workspace/.opslify/kubeconfig"},
			Files: []broker.InjectedFile{{Path: ".opslify/kubeconfig", Mode: 0o600, Content: []byte("apiVersion: v1\n")}},
		},
	}
	m := connManager(t, rt, func(string, string) ([]broker.Connection, error) {
		return []broker.Connection{conn}, nil
	})
	s := &Session{ID: "s1", WorkspaceDir: t.TempDir()}
	if _, err := m.resolveConnections(s); err != nil {
		t.Fatal(err)
	}
	if err := m.buildConnections(context.Background(), s, []broker.Connection{conn}, "1.2.3.4:1", []byte("CA")); err != nil {
		t.Fatalf("buildConnections: %v", err)
	}
	full := filepath.Join(s.WorkspaceDir, ".opslify/kubeconfig")
	info, err := os.Stat(full)
	if err != nil {
		t.Fatalf("the injected file must exist: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
	body, _ := os.ReadFile(full)
	if string(body) != "apiVersion: v1\n" {
		t.Errorf("content = %q", body)
	}
	// And the env reached the sandbox.
	var found bool
	for _, e := range s.credEnv {
		if e == "KUBECONFIG=/workspace/.opslify/kubeconfig" {
			found = true
		}
	}
	if !found {
		t.Errorf("the injected env must reach the sandbox: %v", s.credEnv)
	}
}

// TestConnectionFilesCannotEscapeTheWorkspace: the write path re-checks
// containment so the guarantee is local to the write rather than something a
// future caller must remember to have validated.
func TestConnectionFilesCannotEscapeTheWorkspace(t *testing.T) {
	rt := newFakeRuntime()
	for _, bad := range []string{"../escape", "/etc/passwd", "a/../../b"} {
		conn := &fakeConnection{
			kind: broker.KindHTTP, name: "evil", refs: []string{"r"},
			inj: broker.ConnectionInjection{Files: []broker.InjectedFile{{Path: bad, Content: []byte("x")}}},
		}
		m := connManager(t, rt, func(string, string) ([]broker.Connection, error) {
			return []broker.Connection{conn}, nil
		})
		s := &Session{ID: "s1", WorkspaceDir: t.TempDir()}
		if _, err := m.resolveConnections(s); err != nil {
			t.Fatal(err)
		}
		err := m.buildConnections(context.Background(), s, []broker.Connection{conn}, "1.2.3.4:1", []byte("CA"))
		if err == nil {
			t.Errorf("path %q must be refused", bad)
		}
		if !conn.wasClosed() {
			t.Errorf("path %q: the connection must be torn down on refusal", bad)
		}
	}
}

// TestTwoConnectionsCannotClaimTheSameVariable: one silently overwriting another
// would make which credential is in force depend on iteration order.
func TestTwoConnectionsCannotClaimTheSameVariable(t *testing.T) {
	rt := newFakeRuntime()
	a := &fakeConnection{kind: broker.KindKubernetes, name: "a", refs: []string{"r1"},
		inj: broker.ConnectionInjection{Env: map[string]string{"KUBECONFIG": "/workspace/one"}}}
	b := &fakeConnection{kind: broker.KindKubernetes, name: "b", refs: []string{"r2"},
		inj: broker.ConnectionInjection{Env: map[string]string{"KUBECONFIG": "/workspace/two"}}}
	m := connManager(t, rt, func(string, string) ([]broker.Connection, error) {
		return []broker.Connection{a, b}, nil
	})
	s := &Session{ID: "s1", WorkspaceDir: t.TempDir()}
	if _, err := m.resolveConnections(s); err != nil {
		t.Fatal(err)
	}
	err := m.buildConnections(context.Background(), s, []broker.Connection{a, b}, "1.2.3.4:1", []byte("CA"))
	if !errors.Is(err, broker.ErrConflict) {
		t.Fatalf("conflicting connections must be refused, got %v", err)
	}
	if !a.wasClosed() || !b.wasClosed() {
		t.Error("both connections must be torn down on a conflict")
	}
}

// --- teardown ------------------------------------------------------------------

// TestConnectionsAreTornDownWithTheSession: nothing a kind allocated may outlive
// the session. An ssh agent socket in particular is a live signing endpoint for
// as long as it exists.
func TestConnectionsAreTornDownWithTheSession(t *testing.T) {
	rt := newFakeRuntime()
	conn := &fakeConnection{kind: broker.KindSSH, name: "fleet", refs: []string{"ssh-key"}}
	m := connManager(t, rt, func(string, string) ([]broker.Connection, error) {
		return []broker.Connection{conn}, nil
	})
	ctx := context.Background()
	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !conn.wasBuilt() {
		t.Fatal("the connection should have been built for the session")
	}
	if conn.wasClosed() {
		t.Fatal("the connection must stay up while the session lives")
	}
	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if !conn.wasClosed() {
		t.Fatal("the connection must be torn down with the session")
	}
}

// TestConnectionRulesReachTheProxyBuild: a connection whose host and cred the
// policy allows must contribute a rule; one the policy does not must be dropped.
// That is what keeps a connection from widening a session.
func TestConnectionRulesReachTheProxyBuild(t *testing.T) {
	conn := &fakeConnection{
		kind: broker.KindHTTP, name: "gitlab", refs: []string{"gitlab-token"},
		rules: []broker.HeaderInjectRule{{
			Host: "gitlab.example.com", SecretRef: "gitlab-token",
			HeaderName: "PRIVATE-TOKEN", HeaderFormat: "%s",
		}},
	}
	rules := connectionEgressRules([]broker.Connection{conn})
	if len(rules) != 1 || rules[0].Host != "gitlab.example.com" || rules[0].CredRef != "gitlab-token" {
		t.Fatalf("rules = %+v", rules)
	}

	// A policy that allows the host AND grants the cred keeps it.
	allowed := policy.ResolveDefault(policy.Policy{
		Egress: policy.Egress{Domains: []string{"gitlab.example.com"}},
		Creds:  []policy.Cred{{Name: "gitlab-token"}},
	})
	if got := applicableRules(rules, allowed); len(got) != 1 {
		t.Errorf("an allowed-and-granted rule must apply, got %+v", got)
	}
	// A policy that allows the host but does NOT grant the cred drops it.
	noGrant := policy.ResolveDefault(policy.Policy{
		Egress: policy.Egress{Domains: []string{"gitlab.example.com"}},
	})
	if got := applicableRules(rules, noGrant); len(got) != 0 {
		t.Errorf("a rule whose cred the policy does not grant must be dropped, got %+v", got)
	}
	// A policy that grants the cred but does not allow the host drops it too — a
	// connection cannot reach a host the session may not.
	noHost := policy.ResolveDefault(policy.Policy{Creds: []policy.Cred{{Name: "gitlab-token"}}})
	if got := applicableRules(rules, noHost); len(got) != 0 {
		t.Errorf("a rule to a host the policy does not allow must be dropped, got %+v", got)
	}
}

// TestConnectionCredentialNeverReachesTheSandboxEnvironment is the end-to-end
// form of the exclusion, and the reason the whole wiring exists.
//
// The earlier test in this file asserts isConnectionRef answers correctly, which
// is NOT the same claim: it left the call site untested, so a mutation that
// stopped consulting it survived. This drives a real session with a real vault, a
// real credential injector and a policy that GRANTS the same ref the connection
// resolves — the exact overlap where the value would otherwise be placed in the
// sandbox by the F5.1 path while the connection resolves it at a boundary.
func TestConnectionCredentialNeverReachesTheSandboxEnvironment(t *testing.T) {
	const canary = "CANARY-connection-credential-must-not-be-in-the-env"
	// The policy both allows the host and GRANTS the ref, so the F5.1 injector
	// would resolve it into the environment if nothing excluded it.
	m, v, _ := qaManager(t, []string{"gitlab.example.com"}, []policy.Cred{{Name: "conn-token", Provider: "gitlab"}})
	if err := v.Put(context.Background(), "conn-token", []byte(canary), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	conn := &fakeConnection{
		kind: broker.KindHTTP, name: "gitlab", refs: []string{"conn-token"},
		rules: []broker.HeaderInjectRule{{
			Host: "gitlab.example.com", SecretRef: "conn-token", HeaderName: "PRIVATE-TOKEN", HeaderFormat: "%s",
		}},
	}
	m.connections = func(string, string) ([]broker.Connection, error) {
		return []broker.Connection{conn}, nil
	}

	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer m.Destroy(context.Background(), s.ID)

	for _, e := range s.credEnv {
		if strings.Contains(e, canary) {
			t.Fatalf("the connection's credential was placed in the sandbox environment: %s", e)
		}
	}
	// The exclusion must not have suppressed the connection itself: its rule has
	// to have reached the proxy, or the credential reaches nothing at all and the
	// test would pass for the wrong reason.
	if !conn.wasBuilt() {
		t.Error("the connection was never built")
	}
	var sawProxy bool
	for _, e := range s.credEnv {
		if strings.HasPrefix(e, "HTTPS_PROXY=") {
			sawProxy = true
		}
	}
	if !sawProxy {
		t.Error("a connection contributing an egress rule must cause the proxy to be routed; otherwise the credential reaches nothing and this test proves nothing")
	}
}

// TestAConnectionOnlyRuleStillBuildsTheProxy pins the call site the previous
// mutation exposed. A session with NO daemon-config egress rules but WITH a
// connection must still get a proxy — otherwise a connection is defined, stored,
// shown to the operator, and silently does nothing.
func TestAConnectionOnlyRuleStillBuildsTheProxy(t *testing.T) {
	const canary = "CANARY-connection-only-token"
	// No config rules at all: the injector is built with an empty rule set.
	m, v, _ := qaManagerNoRules(t, []string{"conn.example.com"}, []policy.Cred{{Name: "only-token", Provider: "x"}})
	if err := v.Put(context.Background(), "only-token", []byte(canary), broker.PutMeta{Provider: "x"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	conn := &fakeConnection{
		kind: broker.KindHTTP, name: "only", refs: []string{"only-token"},
		rules: []broker.HeaderInjectRule{{
			Host: "conn.example.com", SecretRef: "only-token", HeaderName: "Authorization", HeaderFormat: "Bearer %s",
		}},
	}
	m.connections = func(string, string) ([]broker.Connection, error) {
		return []broker.Connection{conn}, nil
	}
	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer m.Destroy(context.Background(), s.ID)

	var sawProxy bool
	for _, e := range s.credEnv {
		if strings.HasPrefix(e, "HTTPS_PROXY=") {
			sawProxy = true
		}
		if strings.Contains(e, canary) {
			t.Fatalf("the connection's credential reached the environment: %s", e)
		}
	}
	if !sawProxy {
		t.Fatal("a connection-only rule set must still build the proxy; otherwise the connection silently does nothing")
	}
}
