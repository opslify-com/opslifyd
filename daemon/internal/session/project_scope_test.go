package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/project"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// newScopedManager builds a traced Manager wired to a real project.Service over
// a temp-dir store, so scope resolution is exercised end to end rather than faked.
func newScopedManager(t *testing.T, rt runtime.Runtime, clk Clock) (*Manager, *project.Service, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	st, err := project.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("project store: %v", err)
	}
	svc, err := project.NewService(project.Options{Store: st})
	if err != nil {
		t.Fatalf("project service: %v", err)
	}
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTier:   runtime.TierLocalHardened,
			DefaultTTL:    30 * time.Minute,
		},
		Resolve:  func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:    clk,
		Store:    newMemStore(),
		Trace:    trace.NewMemSink(trace.NewEd25519Signer(priv)),
		Projects: svc,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	svc.SetSandboxes(m)
	return m, svc, pub
}

// AC (F8.1): a session is created in exactly one environment, records BOTH ids,
// and they appear in the session.start trace binding — so every audited action is
// attributable to the scope that governed it.
func TestSessionRecordsScopeInStartBinding(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, svc, trustedPub := newScopedManager(t, rt, clk)
	ctx := context.Background()

	if _, _, err := svc.CreateProject(project.ProjectSpec{
		Name:         "tripon",
		Environments: []project.EnvironmentSpec{{Name: "staging"}},
	}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch, ProjectID: "tripon", EnvironmentID: "staging"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.ProjectID != "tripon" || s.EnvironmentID != "tripon.staging" {
		t.Fatalf("session scope = %q/%q, want tripon/tripon.staging", s.ProjectID, s.EnvironmentID)
	}
	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	events, seal, err := m.TraceExport(ctx, s.ID)
	if err != nil {
		t.Fatalf("TraceExport: %v", err)
	}
	start := events[0]
	if start.Type != trace.TypeSessionStart {
		t.Fatalf("seq0 is %s, want session.start", start.Type)
	}
	if got := start.Payload["project_id"]; got != "tripon" {
		t.Fatalf("session.start project_id = %v, want tripon", got)
	}
	if got := start.Payload["environment_id"]; got != "tripon.staging" {
		t.Fatalf("session.start environment_id = %v, want tripon.staging", got)
	}
	// The scope is COMMITTED, not merely present: the sealed chain still verifies.
	if res := trace.Verify(events, seal, trustedPub); !res.OK {
		t.Fatalf("sealed chain must verify with the scope bound in: %s", res.Reason)
	}
}

// A create naming no scope still succeeds and lands in the default project and
// environment, so everything built before F8.1 keeps working unchanged.
func TestUnscopedCreateGetsDefaultScope(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, _, _ := newScopedManager(t, rt, clk)

	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("unscoped Create must still work: %v", err)
	}
	if s.ProjectID == "" || s.EnvironmentID == "" {
		t.Fatalf("unscoped create must land in the default scope, got %q/%q", s.ProjectID, s.EnvironmentID)
	}
}

// A create naming an environment that does not exist FAILS CLOSED rather than
// silently falling back to the default scope.
func TestCreateWithUnknownScopeFailsClosed(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, _, _ := newScopedManager(t, rt, clk)

	if _, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch, ProjectID: "absent"}); err == nil {
		t.Fatal("a create naming an unknown project must fail closed, not default")
	}
}

// SessionsIn is scope-accurate: it is what RemoveEnvironment/RemoveProject rely
// on to avoid orphaning a live sandbox, so a wrong answer there is a safety bug.
func TestSessionsInIsScopeAccurate(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, svc, _ := newScopedManager(t, rt, clk)
	ctx := context.Background()

	if _, _, err := svc.CreateProject(project.ProjectSpec{
		Name:         "tripon",
		Environments: []project.EnvironmentSpec{{Name: "staging"}, {Name: "prod", Production: true}},
	}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	stg, err := m.Create(ctx, CreateRequest{Mode: ModeScratch, ProjectID: "tripon", EnvironmentID: "staging"})
	if err != nil {
		t.Fatalf("Create staging: %v", err)
	}

	if got := m.SessionsIn("tripon", "tripon.staging"); len(got) != 1 || got[0] != stg.ID {
		t.Fatalf("SessionsIn(staging) = %v, want [%s]", got, stg.ID)
	}
	if got := m.SessionsIn("tripon", "tripon.prod"); len(got) != 0 {
		t.Fatalf("SessionsIn(prod) = %v, want none — a sibling environment's sandbox leaked", got)
	}
	if got := m.SessionsIn("tripon", ""); len(got) != 1 {
		t.Fatalf("SessionsIn(project-wide) = %v, want the one staging sandbox", got)
	}
	if got := m.SessionsIn("other", ""); len(got) != 0 {
		t.Fatalf("SessionsIn(other project) = %v, want none", got)
	}
}

// N-6 (regression): the in-flight counter itself. The project-side test drives a
// fake, so nothing covered the Manager mechanism — deleting the beginCreate call
// entirely left the whole suite green. These pin it against the real Manager.
func TestInFlightCountedDuringCreateAndReleasedAfter(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, svc, _ := newScopedManager(t, rt, clk)
	ctx := context.Background()

	if _, _, err := svc.CreateProject(project.ProjectSpec{
		Name:         "tripon",
		Environments: []project.EnvironmentSpec{{Name: "staging"}, {Name: "prod"}},
	}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	// Block the create INSIDE realize, i.e. after the scope resolved and before
	// the session registers — precisely the window that used to orphan sandboxes.
	release := make(chan struct{})
	observed := make(chan struct{})
	rt.setBeforeCreate(func() {
		close(observed)
		<-release
	})
	done := make(chan error, 1)
	go func() {
		_, err := m.Create(ctx, CreateRequest{Mode: ModeScratch, ProjectID: "tripon", EnvironmentID: "staging"})
		done <- err
	}()
	<-observed

	if got := m.SessionsIn("tripon", "tripon.staging"); len(got) != 0 {
		t.Fatalf("session must NOT be registered yet, got %v", got)
	}
	if n := m.InFlightIn("tripon", "tripon.staging"); n != 1 {
		t.Fatalf("InFlightIn(env) = %d, want 1 during the create window", n)
	}
	if n := m.InFlightIn("tripon", ""); n != 1 {
		t.Fatalf("InFlightIn(project-wide) = %d, want 1", n)
	}
	// Scope matching must be exact: a sibling environment is not in flight.
	if n := m.InFlightIn("tripon", "tripon.prod"); n != 0 {
		t.Fatalf("InFlightIn(sibling env) = %d, want 0", n)
	}
	if n := m.InFlightIn("other", ""); n != 0 {
		t.Fatalf("InFlightIn(other project) = %d, want 0", n)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n := m.InFlightIn("tripon", ""); n != 0 {
		t.Fatalf("counter leaked after a successful create: %d", n)
	}
}

// The counter must be released when a create FAILS, or one bad create wedges
// every future removal of that scope.
func TestInFlightReleasedWhenCreateFails(t *testing.T) {
	rt := newFakeRuntime()
	rt.createErr = errors.New("runtime: boom")
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, svc, _ := newScopedManager(t, rt, clk)

	if _, _, err := svc.CreateProject(project.ProjectSpec{Name: "tripon"}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if _, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch, ProjectID: "tripon"}); err == nil {
		t.Fatal("create was expected to fail")
	}
	if n := m.InFlightIn("tripon", ""); n != 0 {
		t.Fatalf("counter leaked after a failed create: %d", n)
	}
}
