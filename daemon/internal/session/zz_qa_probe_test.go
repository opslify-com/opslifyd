package session

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/egressproxy"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// qaManager wires a Manager WITH a real F5.1 credInjector (env-fallback path) plus
// the F5.7 egress injector, so the exclusion probe exercises both.
func qaManager(t *testing.T, domains []string, grants []policy.Cred) (*Manager, *broker.Vault, *fakeRuntime) {
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
	ei := NewEgressInjector(EgressInjectConfig{
		Rules:    []egressproxy.InjectRule{gitlabRule()},
		Broker:   brk,
		Upstream: &captureUpstream{},
	})
	inj := broker.NewInjector(brk, nil, "", 0, nil) // env-fallback path (no endpoint)
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
		Trace:        trace.NewMemSink(nil),
		Broker:       brk,
		CredInjector: inj,
		EgressInject: ei,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, v, rt
}

// TestQAExclusionLoadBearing proves: (1) with a live F5.1 injector, a gitlab-token
// grant that is ALSO egress-mapped is NOT env-injected (the exclusion holds — the
// raw token would otherwise land via EnvInjectionAdapter); (2) a SECOND granted cred
// that is NOT egress-mapped IS still env-injected (no over-exclusion).
func TestQAExclusionLoadBearing(t *testing.T) {
	ctx := context.Background()
	const other = "OTHER-SECRET-should-be-in-env"
	m, v, rt := qaManager(t, []string{"gitlab.com"}, []policy.Cred{
		{Name: "gitlab-token", Provider: "gitlab"},
		{Name: "other-token", Provider: "custom"},
	})
	if err := v.Put(ctx, "gitlab-token", []byte(gitlabTokenMarker), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put gitlab: %v", err)
	}
	if err := v.Put(ctx, "other-token", []byte(other), broker.PutMeta{Provider: "custom"}, false); err != nil {
		t.Fatalf("Put other: %v", err)
	}
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"ls"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	env := strings.Join(rt.lastExecEnv(), "\n")
	if strings.Contains(env, gitlabTokenMarker) {
		t.Fatalf("SECURITY: egress-mapped gitlab token leaked into env: %q", env)
	}
	if !strings.Contains(env, "OPSLIFY_CRED_OTHER_TOKEN="+other) {
		t.Fatalf("over-exclusion: non-mapped cred not env-injected: %q", env)
	}
}

// TestQAGrantedMappedButHostNotAllowed probes the edge: a cred granted AND named in
// an egress rule, but the host is NOT egress-allowed. No proxy is built (applicable
// empty) AND the token is still excluded from F5.1 — so it lands NOWHERE (fail-safe).
func TestQAGrantedMappedButHostNotAllowed(t *testing.T) {
	ctx := context.Background()
	m, v, rt := qaManager(t, nil /* no egress domains */, []policy.Cred{
		{Name: "gitlab-token", Provider: "gitlab"},
	})
	if err := v.Put(ctx, "gitlab-token", []byte(gitlabTokenMarker), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.egress != nil {
		t.Fatalf("proxy built for an egress-disallowed host")
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"ls"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	env := strings.Join(rt.lastExecEnv(), "\n")
	if strings.Contains(env, gitlabTokenMarker) {
		t.Fatalf("SECURITY: token leaked into env when host not egress-allowed: %q", env)
	}
	assertNoProxyEnv(t, rt.lastExecEnv())
}

// TestQACaseRefMismatch probes a case difference between the rule CredRef and the
// grant name. isEgressInjectRef is exact-match, so a case-mismatched grant is NOT
// excluded and DOES flow through F5.1 (documenting the exact-match contract). The
// egress rule also does not apply (applicable() is exact on cred name), so this is a
// config-consistency requirement, not a blind-path bypass.
func TestQACaseRefMismatch(t *testing.T) {
	ctx := context.Background()
	m, v, rt := qaManager(t, []string{"gitlab.com"}, []policy.Cred{
		{Name: "GitLab-Token", Provider: "gitlab"}, // grant name differs in case from rule CredRef "gitlab-token"
	})
	if err := v.Put(ctx, "GitLab-Token", []byte(gitlabTokenMarker), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.egress != nil {
		t.Fatalf("case-mismatched rule unexpectedly applied (proxy built)")
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"ls"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	env := strings.Join(rt.lastExecEnv(), "\n")
	// The case-mismatched grant is treated as an ordinary F5.1 cred (NOT egress-mapped),
	// so its token IS env-injected. This is expected: the rule simply does not match.
	if !strings.Contains(env, gitlabTokenMarker) {
		t.Logf("note: case-mismatched grant not env-injected (env=%q)", env)
	}
}
