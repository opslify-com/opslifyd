package project

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// newTestService builds a Service over a temp-dir store with a fixed clock.
func newTestService(t *testing.T) (*Service, Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	svc, err := NewService(Options{
		Store: st,
		Clock: func() time.Time { return time.Unix(0, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, st, dir
}

// writePolicy writes a policy layer file and returns its path.
func writePolicy(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// --- store ------------------------------------------------------------------

// Records must survive a daemon restart: a fresh Store over the same dir reads
// back exactly what the previous one wrote.
func TestStoreRoundTripSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	want := Project{
		ID: "tripon", Name: "tripon", Created: time.Unix(100, 0).UTC(),
		RepoURL:      "https://gitlab.example.com/tripon",
		Capabilities: map[string]string{"git": "gitlab", "iac": "terraform"},
	}
	if err := st.SaveProject(want); err != nil {
		t.Fatalf("SaveProject: %v", err)
	}
	env := Environment{ID: "tripon.prod", ProjectID: "tripon", Name: "prod",
		Created: time.Unix(100, 0).UTC(), Production: true}
	if err := st.SaveEnvironment(env); err != nil {
		t.Fatalf("SaveEnvironment: %v", err)
	}

	// A SECOND store over the same dir == the restart path.
	reopened, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok, err := reopened.LoadProject("tripon")
	if err != nil || !ok {
		t.Fatalf("LoadProject after restart: ok=%v err=%v", ok, err)
	}
	if got.ID != want.ID || got.RepoURL != want.RepoURL || got.Capabilities["git"] != "gitlab" {
		t.Fatalf("project did not round-trip: %+v", got)
	}
	gotEnv, ok, err := reopened.LoadEnvironment("tripon.prod")
	if err != nil || !ok {
		t.Fatalf("LoadEnvironment after restart: ok=%v err=%v", ok, err)
	}
	if !gotEnv.Production || gotEnv.ProjectID != "tripon" {
		t.Fatalf("environment did not round-trip: %+v", gotEnv)
	}
}

// A record is written atomically: no partial/temp file is left behind for a
// reader to pick up.
func TestStoreWritesAtomically(t *testing.T) {
	_, st, dir := newTestService(t)
	if err := st.SaveProject(Project{ID: "atomic", Name: "atomic"}); err != nil {
		t.Fatalf("SaveProject: %v", err)
	}
	var stray []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".json") {
			stray = append(stray, p)
		}
		return nil
	})
	if len(stray) != 0 {
		t.Fatalf("temp/partial files left behind: %v", stray)
	}
}

// --- validation -------------------------------------------------------------

func TestValidateNameRejectsUnsafeNames(t *testing.T) {
	bad := []string{"", "-leading", "Upper", "has space", "sla/sh", "dot.ted", "under_score_ok_but_this_is_way_too_long_" + strings.Repeat("x", 64)}
	for _, n := range bad {
		if err := ValidateName("project", n); err == nil {
			t.Errorf("ValidateName(%q) = nil, want error", n)
		}
	}
	for _, n := range []string{"tripon", "a", "web-01", "svc_2"} {
		if err := ValidateName("project", n); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", n, err)
		}
	}
}

// A project owns at least one environment: a spec naming none gets the default,
// so an environment-less project is not representable.
func TestCreateProjectAlwaysOwnsAnEnvironment(t *testing.T) {
	svc, _, _ := newTestService(t)
	_, envs, err := svc.CreateProject(ProjectSpec{Name: "tripon"})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if len(envs) != 1 {
		t.Fatalf("want exactly 1 default environment, got %d", len(envs))
	}
}

// Environment names are unique WITHIN a project.
func TestEnvironmentNameUniqueWithinProject(t *testing.T) {
	svc, _, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{
		Name:         "tripon",
		Environments: []EnvironmentSpec{{Name: "staging"}, {Name: "staging"}},
	}); err == nil {
		t.Fatal("duplicate environment names in one spec must be refused")
	}

	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon",
		Environments: []EnvironmentSpec{{Name: "staging"}}}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if _, err := svc.AddEnvironment("tripon", EnvironmentSpec{Name: "staging"}); err == nil {
		t.Fatal("adding a duplicate environment name must be refused")
	}
	// ...but the SAME name under a DIFFERENT project is fine.
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "yuusr",
		Environments: []EnvironmentSpec{{Name: "staging"}}}); err != nil {
		t.Fatalf("same env name in another project must be allowed: %v", err)
	}
}

// --- the invariant that matters: narrows, never widens ----------------------

// An environment overlay that tries to WIDEN the daemon baseline is clamped, and
// the clamp is recorded and tagged with the layer that over-reached.
func TestOverlayWideningIsClampedAndRecorded(t *testing.T) {
	dir := t.TempDir()
	// The daemon baseline: one domain, one cred.
	base := policy.Policy{
		Egress: policy.Egress{Domains: []string{"gitlab.example.com"}},
		Creds:  []policy.Cred{{Name: "gitlab-token", Provider: "gitlab"}},
	}
	// The overlay reaches for MORE than the baseline allows.
	overlayPath := writePolicy(t, dir, "widen.yaml", `
egress:
  domains: [gitlab.example.com, evil.example.com]
creds:
  - name: gitlab-token
    provider: gitlab
  - name: prod-root-key
    provider: aws
`)
	overlay, err := LoadLayer("environment", overlayPath)
	if err != nil {
		t.Fatalf("LoadLayer: %v", err)
	}

	got := ResolvePolicy(base, Layer{Name: "environment", Policy: overlay})

	for _, d := range got.Policy.Egress.Domains {
		if d == "evil.example.com" {
			t.Fatal("overlay WIDENED egress: evil.example.com survived resolution")
		}
	}
	for _, c := range got.Policy.Creds {
		if c.Name == "prod-root-key" {
			t.Fatal("overlay WIDENED creds: prod-root-key survived resolution")
		}
	}
	if len(got.Notes) == 0 {
		t.Fatal("a clamped widening must be RECORDED in Notes, not silently dropped")
	}
	var tagged bool
	for _, n := range got.Notes {
		if strings.HasPrefix(n, "environment: ") {
			tagged = true
		}
	}
	if !tagged {
		t.Fatalf("clamp notes must name the over-reaching layer, got %v", got.Notes)
	}
}

// A missing layer file is an ERROR, not an empty layer: the operator configured a
// path, so resolving without it would run under a policy nobody chose.
func TestLoadLayerMissingFileFailsClosed(t *testing.T) {
	if _, err := LoadLayer("environment", filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("a configured-but-missing policy layer must fail closed")
	}
}

// With no layers the result is byte-for-byte the pre-F8.1 behaviour.
func TestResolvePolicyNoLayersMatchesDefault(t *testing.T) {
	base := policy.Policy{Egress: policy.Egress{Domains: []string{"gitlab.example.com"}}}
	got := ResolvePolicy(base)
	want := policy.ResolveDefault(base)
	if got.Hash != want.Hash {
		t.Fatalf("no-layer resolution changed the policy hash: got %s want %s", got.Hash, want.Hash)
	}
}

// Cross-environment isolation: a staging session must not resolve a grant that
// only prod's layer carries. Narrowing means a sibling's grant is unreachable.
func TestNoCrossEnvironmentGrantLeakage(t *testing.T) {
	dir := t.TempDir()
	base := policy.Policy{
		Egress: policy.Egress{Domains: []string{"gitlab.example.com", "prod-db.example.com"}},
		Creds: []policy.Cred{
			{Name: "gitlab-token", Provider: "gitlab"},
			{Name: "prod-db-key", Provider: "postgres"},
		},
	}
	stagingPath := writePolicy(t, dir, "staging.yaml", `
egress:
  domains: [gitlab.example.com]
creds:
  - name: gitlab-token
    provider: gitlab
`)
	stagingLayer, err := LoadLayer("environment", stagingPath)
	if err != nil {
		t.Fatalf("LoadLayer: %v", err)
	}
	got := ResolvePolicy(base, Layer{Name: "environment", Policy: stagingLayer})

	for _, c := range got.Policy.Creds {
		if c.Name == "prod-db-key" {
			t.Fatal("staging resolved a prod-only cred — cross-environment leakage")
		}
	}
	for _, d := range got.Policy.Egress.Domains {
		if d == "prod-db.example.com" {
			t.Fatal("staging resolved a prod-only egress host — cross-environment leakage")
		}
	}
}

// --- scope resolution -------------------------------------------------------

// A create that names neither project nor environment still resolves, so nothing
// that existed before F8.1 breaks.
func TestResolveScopeDefaultsForUnscopedCreate(t *testing.T) {
	svc, _, _ := newTestService(t)
	scope, err := svc.ResolveScope(policy.Policy{}, "", "")
	if err != nil {
		t.Fatalf("ResolveScope with no scope must succeed: %v", err)
	}
	if scope.Project.ID == "" || scope.Environment.ID == "" {
		t.Fatalf("default scope must name both ids, got %+v", scope)
	}
	if scope.Environment.ProjectID != scope.Project.ID {
		t.Fatalf("environment %q does not belong to project %q", scope.Environment.ID, scope.Project.ID)
	}
}

func TestResolveScopeUnknownIDsFailClosed(t *testing.T) {
	svc, _, _ := newTestService(t)
	if _, err := svc.ResolveScope(policy.Policy{}, "nope", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown project must be ErrNotFound, got %v", err)
	}
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon"}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if _, err := svc.ResolveScope(policy.Policy{}, "tripon", "tripon.absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown environment must be ErrNotFound, got %v", err)
	}
}

// --- removal ordering -------------------------------------------------------

// fakeSandboxes records teardown order and can report live sessions per scope.
type fakeSandboxes struct {
	mu        sync.Mutex          // the fake is driven from several goroutines in the concurrency tests
	live      map[string][]string // "project|env" -> session ids
	inflight  map[string]int      // "project|env" -> creates that resolved but have not registered
	destroyed []string
	// onDestroy runs inside Destroy, so a test can observe daemon state at the
	// exact moment a sandbox is being torn down.
	onDestroy func(id string) error
}

func (f *fakeSandboxes) SessionsIn(projectID, environmentID string) []string {
	if f.live == nil {
		return nil
	}
	if environmentID != "" {
		return f.live[projectID+"|"+environmentID]
	}
	var out []string
	for k, v := range f.live {
		if strings.HasPrefix(k, projectID+"|") {
			out = append(out, v...)
		}
	}
	return out
}

// InFlightIn reports creates that have resolved a scope but not yet registered.
func (f *fakeSandboxes) InFlightIn(projectID, environmentID string) int {
	if f.inflight == nil {
		return 0
	}
	if environmentID != "" {
		return f.inflight[projectID+"|"+environmentID]
	}
	n := 0
	for k, c := range f.inflight {
		if strings.HasPrefix(k, projectID+"|") {
			n += c
		}
	}
	return n
}

func (f *fakeSandboxes) Destroy(_ context.Context, id string) error {
	f.mu.Lock()
	f.destroyed = append(f.destroyed, id)
	onDestroy := f.onDestroy
	f.mu.Unlock()
	if onDestroy != nil {
		return onDestroy(id)
	}
	return nil
}

// destroyedIDs returns a copy for assertions without racing Destroy.
func (f *fakeSandboxes) destroyedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.destroyed...)
}

// Removing an environment tears down its sandboxes BEFORE the record is dropped,
// so a live sandbox is never left un-attributable to a governing environment.
func TestRemoveEnvironmentTearsDownItsSandboxes(t *testing.T) {
	svc, st, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon",
		Environments: []EnvironmentSpec{{Name: "staging"}, {Name: "prod", Production: true}}}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	// The ordering claim is only meaningful if we observe the record DURING
	// teardown: a sandbox must never be destroyed after its governing record is
	// gone, or it is briefly un-attributable to any environment.
	var recordPresentAtTeardown []bool
	sb := &fakeSandboxes{
		live: map[string][]string{"tripon|tripon.staging": {"sess-a", "sess-b"}},
		onDestroy: func(string) error {
			_, ok, _ := st.LoadEnvironment("tripon.staging")
			recordPresentAtTeardown = append(recordPresentAtTeardown, ok) // single-goroutine in this test
			return nil
		},
	}
	svc.SetSandboxes(sb)

	if err := svc.RemoveEnvironment(context.Background(), "tripon", "tripon.staging"); err != nil {
		t.Fatalf("RemoveEnvironment: %v", err)
	}
	if got := sb.destroyedIDs(); len(got) != 2 {
		t.Fatalf("want both sandboxes torn down, got %v", got)
	}
	if len(recordPresentAtTeardown) != 2 {
		t.Fatalf("onDestroy ran %d times, want 2", len(recordPresentAtTeardown))
	}
	for i, present := range recordPresentAtTeardown {
		if !present {
			t.Fatalf("sandbox %d was destroyed AFTER its environment record was deleted — ordering violated", i)
		}
	}
	if _, ok, _ := st.LoadEnvironment("tripon.staging"); ok {
		t.Fatal("environment record must be gone after removal")
	}
}

// Fail-closed teardown: if a sandbox cannot be destroyed, the record is KEPT so
// the sandbox stays attributable to a governing environment.
func TestRemoveEnvironmentKeepsRecordWhenTeardownFails(t *testing.T) {
	svc, st, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon",
		Environments: []EnvironmentSpec{{Name: "staging"}, {Name: "prod"}}}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	svc.SetSandboxes(&fakeSandboxes{
		live:      map[string][]string{"tripon|tripon.staging": {"sess-a"}},
		onDestroy: func(string) error { return errors.New("runtime: destroy failed") },
	})
	if err := svc.RemoveEnvironment(context.Background(), "tripon", "tripon.staging"); err == nil {
		t.Fatal("a failed teardown must abort the removal")
	}
	if _, ok, _ := st.LoadEnvironment("tripon.staging"); !ok {
		t.Fatal("a failed teardown must KEEP the record — the sandbox is still live")
	}
}

// D-3 (regression): a caller-supplied id must never address a file outside the
// record directory. These entry points reach filepath.Join, and were reachable
// over REST with a percent-encoded traversal.
func TestStoreFacingEntryPointsRefuseTraversal(t *testing.T) {
	svc, _, dir := newTestService(t)

	// Plant a READABLE record at the traversal target. Without this the test
	// cannot tell "refused" from "not found", and passes even with every guard
	// removed — which is exactly how the first version of this test was a false
	// guarantee. The assertions below therefore demand ErrInvalidInput
	// specifically, and check the planted file survives.
	loot := filepath.Join(dir, "loot.json")
	if err := os.WriteFile(loot, []byte(`{"id":"PWNED","name":"PWNED"}`), 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}
	// projects/ and environments/ live under dir, so "../loot" from inside either
	// resolves to the planted file.
	traversals := []string{"../loot", "../../etc/passwd", "a/b", "..", ".", "with\x00nul", "/abs", "./loot", "sub/../loot"}

	mustReject := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: accepted a traversal id", what)
			return
		}
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: got %v, want ErrInvalidInput (a not-found is not a refusal)", what, err)
		}
	}

	for _, id := range traversals {
		_, _, err := svc.Project(id)
		mustReject("Project("+id+")", err)
		_, err = svc.Environments(id)
		mustReject("Environments("+id+")", err)
		mustReject("RemoveProject("+id+")", svc.RemoveProject(context.Background(), id))
		mustReject("RemoveEnvironment(project="+id+")", svc.RemoveEnvironment(context.Background(), id, "staging"))
		_, err = svc.ResolveScope(policy.Policy{}, id, "")
		mustReject("ResolveScope(project="+id+")", err)
	}
	// The fully-qualified environment branch is the one that skipped validation:
	// BOTH halves of "<project>.<env>" must be validated.
	for _, envID := range []string{"default.../../loot", "../loot.y", "default./abs", "default.a/b"} {
		_, err := svc.ResolveScope(policy.Policy{}, DefaultProjectID, envID)
		mustReject("ResolveScope(env="+envID+")", err)
	}

	if _, err := os.Stat(loot); err != nil {
		t.Fatal("the planted file was DELETED through a traversal — arbitrary file delete is live")
	}
	b, err := os.ReadFile(loot)
	if err != nil || !strings.Contains(string(b), "PWNED") {
		t.Fatal("the planted file was modified through a traversal")
	}
}

// D-3 (regression, defence in depth): even if a caller forgets to validate, the
// store itself must refuse an unsafe id rather than read/delete outside its dir.
func TestStoreRefusesUnsafeRecordIDs(t *testing.T) {
	_, st, dir := newTestService(t)
	outside := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(outside, []byte(`{"id":"pwned","name":"pwned"}`), 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}
	for _, id := range []string{"../outside", "../../etc/passwd", "a/b", ".."} {
		if _, ok, err := st.LoadProject(id); ok || err == nil {
			t.Errorf("LoadProject(%q) escaped the store dir (ok=%v err=%v)", id, ok, err)
		}
		if err := st.DeleteProject(id); err == nil {
			t.Errorf("DeleteProject(%q) must be refused", id)
		}
		if _, ok, err := st.LoadEnvironment(id); ok || err == nil {
			t.Errorf("LoadEnvironment(%q) escaped the store dir (ok=%v err=%v)", id, ok, err)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("a refused delete must leave the planted file intact")
	}
}

// D-1 (regression): the >=1-environment invariant must survive CONCURRENT
// removals. The check and the delete were not atomic, so two removals could each
// observe two siblings and both delete.
func TestConcurrentEnvironmentRemovalsKeepAtLeastOne(t *testing.T) {
	svc, st, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon",
		Environments: []EnvironmentSpec{{Name: "staging"}, {Name: "prod"}}}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	// Teardown blocks until both removals are past the first sibling check, which
	// is exactly the interleaving that broke the invariant.
	var wg sync.WaitGroup
	gate := make(chan struct{})
	svc.SetSandboxes(&fakeSandboxes{
		live: map[string][]string{
			"tripon|tripon.staging": {"s1"},
			"tripon|tripon.prod":    {"s2"},
		},
		onDestroy: func(string) error { <-gate; return nil },
	})
	for _, env := range []string{"tripon.staging", "tripon.prod"} {
		wg.Add(1)
		go func(id string) { defer wg.Done(); _ = svc.RemoveEnvironment(context.Background(), "tripon", id) }(env)
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()

	envs, err := st.LoadEnvironments()
	if err != nil {
		t.Fatalf("LoadEnvironments: %v", err)
	}
	var left int
	for _, e := range envs {
		if e.ProjectID == "tripon" {
			left++
		}
	}
	if left == 0 {
		t.Fatal("concurrent removals left project \"tripon\" ENVIRONMENT-LESS — the >=1 invariant broke")
	}
}

// N-3 (regression): a REFUSED removal must be side-effect-free. The loser of a
// concurrent-removal race used to tear its sandboxes down and only then discover
// it had to refuse, which contradicts "a refusal means nothing changed".
func TestRefusedRemovalDestroysNothing(t *testing.T) {
	svc, _, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon",
		Environments: []EnvironmentSpec{{Name: "staging"}, {Name: "prod"}}}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	var wg sync.WaitGroup
	gate := make(chan struct{})
	sb := &fakeSandboxes{
		live: map[string][]string{
			"tripon|tripon.staging": {"s1"},
			"tripon|tripon.prod":    {"s2"},
		},
		onDestroy: func(string) error { <-gate; return nil },
	}
	svc.SetSandboxes(sb)

	errs := make([]error, 2)
	for i, env := range []string{"tripon.staging", "tripon.prod"} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			errs[i] = svc.RemoveEnvironment(context.Background(), "tripon", id)
		}(i, env)
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()

	var refused int
	for _, err := range errs {
		if err != nil {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("one of two concurrent removals must be refused")
	}
	// Exactly one removal proceeded, so exactly its sandbox may have been
	// destroyed. A refused removal that already tore its sandbox down would push
	// this to 2.
	if got := sb.destroyedIDs(); len(got) > 1 {
		t.Fatalf("a refused removal destroyed sandboxes anyway: %v", got)
	}
}

// A second removal of the SAME environment must say so — with ErrInUse, not the
// misleading "is the last environment" (which is a different failure with a
// different HTTP status). Only reproducible in a 2-environment project.
func TestDoubleRemovalReportsInUseNotLastEnvironment(t *testing.T) {
	svc, _, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon",
		Environments: []EnvironmentSpec{{Name: "staging"}, {Name: "prod"}}}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	svc.SetSandboxes(&fakeSandboxes{
		live:      map[string][]string{"tripon|tripon.staging": {"s1"}},
		onDestroy: func(string) error { close(entered); <-release; return nil },
	})
	go func() { _ = svc.RemoveEnvironment(context.Background(), "tripon", "tripon.staging") }()
	<-entered // the first removal now holds the claim

	err := svc.RemoveEnvironment(context.Background(), "tripon", "tripon.staging")
	close(release)
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("second removal of the same environment: got %v, want ErrInUse", err)
	}
}

// D-2 (regression): a removal must refuse while a create has resolved the scope
// but not yet registered, or the governing record is deleted out from under a
// sandbox that lands a moment later.
func TestRemovalRefusesWhileCreateInFlight(t *testing.T) {
	svc, st, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon",
		Environments: []EnvironmentSpec{{Name: "staging"}, {Name: "prod"}}}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	// No REGISTERED sessions — only an in-flight create. SessionsIn cannot see it.
	svc.SetSandboxes(&fakeSandboxes{inflight: map[string]int{"tripon|tripon.staging": 1}})

	if err := svc.RemoveProject(context.Background(), "tripon"); err == nil {
		t.Fatal("RemoveProject must refuse while a create is in flight")
	}
	if _, ok, _ := st.LoadProject("tripon"); !ok {
		t.Fatal("a refused removal must leave the project intact")
	}
	if err := svc.RemoveEnvironment(context.Background(), "tripon", "tripon.staging"); err == nil {
		t.Fatal("RemoveEnvironment must refuse while a create is in flight in that environment")
	}
	if _, ok, _ := st.LoadEnvironment("tripon.staging"); !ok {
		t.Fatal("a refused removal must leave the environment intact")
	}
}

// The >=1-environment invariant holds on the way out too: the last environment
// cannot be removed.
func TestRemoveLastEnvironmentRefused(t *testing.T) {
	svc, _, _ := newTestService(t)
	_, envs, err := svc.CreateProject(ProjectSpec{Name: "tripon"})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if err := svc.RemoveEnvironment(context.Background(), "tripon", envs[0].ID); err == nil {
		t.Fatal("removing the last environment must be refused")
	}
}

// Removing a project REFUSES while a sandbox is live under it.
func TestRemoveProjectRefusedWhileSandboxLive(t *testing.T) {
	svc, st, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon"}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	svc.SetSandboxes(&fakeSandboxes{live: map[string][]string{"tripon|tripon.default": {"sess-live"}}})

	if err := svc.RemoveProject(context.Background(), "tripon"); err == nil {
		t.Fatal("removing a project with a live sandbox must be refused")
	}
	if _, ok, _ := st.LoadProject("tripon"); !ok {
		t.Fatal("a refused removal must leave the project intact")
	}
}

// --- bootstrap --------------------------------------------------------------

// Bootstrapping is idempotent and never overwrites an operator's edits.
func TestBootstrapIdempotentAndNonDestructive(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, err := NewService(Options{Store: st}); err != nil {
		t.Fatalf("NewService: %v", err)
	}
	// Operator edits the default project.
	p, ok, err := st.LoadProject(DefaultProjectID)
	if err != nil || !ok {
		t.Fatalf("default project missing after bootstrap: ok=%v err=%v", ok, err)
	}
	p.Capabilities = map[string]string{"git": "gitlab"}
	if err := st.SaveProject(p); err != nil {
		t.Fatalf("SaveProject: %v", err)
	}
	// Restart.
	if _, err := NewService(Options{Store: st}); err != nil {
		t.Fatalf("second NewService: %v", err)
	}
	again, _, err := st.LoadProject(DefaultProjectID)
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}
	if again.Capabilities["git"] != "gitlab" {
		t.Fatal("bootstrap overwrote an operator's edit to the default project")
	}
}

// TestStateDirIsTightenedEvenIfItAlreadyExists. MkdirAll does not change the mode
// of a directory that already exists, so a state dir created by an earlier
// release — or by hand — would stay world-readable and nothing would say so.
func TestStateDirIsTightenedEvenIfItAlreadyExists(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(dir); err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	for _, p := range []string{dir, filepath.Join(dir, "projects"), filepath.Join(dir, "environments")} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("%s mode = %o, want 0700", p, info.Mode().Perm())
		}
	}
}

// --- F8.8: editing a project's tools after creation ----------------------------
//
// Capabilities used to be settable only at CreateProject, so adding a tool to an
// existing project was impossible from anywhere. These pin the replace semantics
// the wire operation depends on.

func TestSetCapabilitiesReplacesTheWholeMap(t *testing.T) {
	svc, _, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{
		Name:         "tripon",
		Capabilities: map[string]string{"git": "gitlab", "iac": "terraform"},
	}); err != nil {
		t.Fatal(err)
	}

	// Replace, not merge: "iac" is absent from the new map and must be gone.
	p, err := svc.SetCapabilities("tripon", map[string]string{"git": "gitlab", "k8s": "kubernetes"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"git": "gitlab", "k8s": "kubernetes"}
	if len(p.Capabilities) != len(want) {
		t.Fatalf("capabilities = %v, want %v", p.Capabilities, want)
	}
	for k, v := range want {
		if p.Capabilities[k] != v {
			t.Fatalf("capabilities = %v, want %v", p.Capabilities, want)
		}
	}
	if _, still := p.Capabilities["iac"]; still {
		t.Error("iac survived a replace — SetCapabilities must not merge")
	}
}

func TestSetCapabilitiesPersists(t *testing.T) {
	svc, store, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetCapabilities("tripon", map[string]string{"deploy": "argocd"}); err != nil {
		t.Fatal(err)
	}
	// Read through the STORE, not the returned value: a method that reports a
	// change it did not write is the failure this catches.
	got, ok, err := store.LoadProject("tripon")
	if err != nil || !ok {
		t.Fatalf("LoadProject: %v ok=%v", err, ok)
	}
	if got.Capabilities["deploy"] != "argocd" {
		t.Fatalf("persisted capabilities = %v, want deploy=argocd", got.Capabilities)
	}
}

func TestSetCapabilitiesClearsWithAnEmptyMap(t *testing.T) {
	svc, _, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{
		Name: "tripon", Capabilities: map[string]string{"git": "gitlab"},
	}); err != nil {
		t.Fatal(err)
	}
	p, err := svc.SetCapabilities("tripon", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Capabilities) != 0 {
		t.Fatalf("capabilities = %v, want none — removing the last tool must be possible",
			p.Capabilities)
	}
}

func TestSetCapabilitiesValidates(t *testing.T) {
	svc, _, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon"}); err != nil {
		t.Fatal(err)
	}
	// A capability map is rendered into traces and agent context, so an
	// unvalidated value is an injection surface. The create path checks it; this
	// path must check it identically or it becomes the way around that check.
	for _, bad := range []map[string]string{
		{"git": "gitlab; rm -rf /"},
		{"ro le": "gitlab"},
		{"git": ""},
		{"": "gitlab"},
		{"git": "../../etc/passwd"},
		{"git": "a\nb"},
	} {
		if _, err := svc.SetCapabilities("tripon", bad); err == nil {
			t.Errorf("SetCapabilities(%v) was accepted; it must validate as create does", bad)
		}
	}
}

func TestSetCapabilitiesOnAnUnknownProject(t *testing.T) {
	svc, _, _ := newTestService(t)
	_, err := svc.SetCapabilities("nope", map[string]string{"git": "gitlab"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
