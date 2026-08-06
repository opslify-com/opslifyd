package egress

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner records every script applied so tests can assert apply/teardown
// ordering and idempotency with no nft binary and no root.
type fakeRunner struct {
	mu        sync.Mutex
	scripts   []string
	failNext  error
	available error
}

func (r *fakeRunner) Apply(_ context.Context, script string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failNext != nil {
		err := r.failNext
		r.failNext = nil
		return err
	}
	r.scripts = append(r.scripts, script)
	return nil
}

func (r *fakeRunner) Available() error { return r.available }

func (r *fakeRunner) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.scripts...)
}

func (r *fakeRunner) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.scripts) == 0 {
		return ""
	}
	return r.scripts[len(r.scripts)-1]
}

func newTestController(t *testing.T, run *fakeRunner, res Resolver, allow []string) *NftController {
	t.Helper()
	return NewController(Config{
		Runner:    run,
		Resolver:  res,
		Allowlist: allow,
		Bridge:    "opslify0",
		Logger:    discardLogger(),
	})
}

// Setup programs a table with the pinned IPs; Teardown removes it. Ordering + the
// per-session table identity are asserted.
func TestController_SetupTeardownOrdering(t *testing.T) {
	run := &fakeRunner{}
	res := &fakeResolver{records: map[string]Resolution{"api.test": mkRes(time.Minute, "1.2.3.4")}}
	c := newTestController(t, run, res, []string{"api.test"})
	if _, err := c.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := c.SetupSession(ctx, SessionNet{SessionID: "s1", SandboxIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if got := run.last(); !strings.Contains(got, "table inet opslify_sess_s1 {") || !strings.Contains(got, "1.2.3.4") {
		t.Fatalf("setup did not program the pinned allowlist:\n%s", got)
	}

	if err := c.TeardownSession(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	got := run.last()
	mustContainInOrder(t, got, "add table inet opslify_sess_s1", "delete table inet opslify_sess_s1")
	if strings.Contains(got, "chain egress") {
		t.Fatalf("teardown must not re-declare the chain:\n%s", got)
	}
}

// A failed apply on setup rolls the session back so a later refresh won't try to
// reprogram a phantom, and surfaces an ErrEgress-tagged error.
func TestController_SetupFailureRollsBackAndTags(t *testing.T) {
	run := &fakeRunner{failNext: errors.New("nft boom")}
	c := newTestController(t, run, &fakeResolver{}, nil)
	err := c.SetupSession(context.Background(), SessionNet{SessionID: "s1", SandboxIP: "10.0.0.1"})
	if err == nil || !errors.Is(err, ErrEgress) {
		t.Fatalf("want ErrEgress, got %v", err)
	}
	c.mu.Lock()
	_, present := c.sessions["s1"]
	c.mu.Unlock()
	if present {
		t.Fatal("failed setup must not leave the session recorded")
	}
}

// Allowlist change (a refresh returning new IPs) reprograms active sessions with a
// full delete+recreate — so no prior rule leaks — and skips reprogram when unchanged.
func TestController_RefreshReprogramsNoLeak(t *testing.T) {
	run := &fakeRunner{}
	res := &fakeResolver{records: map[string]Resolution{"api.test": mkRes(time.Minute, "1.1.1.1")}}
	c := newTestController(t, run, res, []string{"api.test"})
	if _, err := c.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.SetupSession(context.Background(), SessionNet{SessionID: "s1", SandboxIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	// Unchanged refresh: no extra apply.
	before := len(run.all())
	if _, err := c.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(run.all()) != before {
		t.Fatal("unchanged allowlist must not reprogram")
	}

	// Now the record rotates (DNS round-robin / rebinding): reprogram with a fresh
	// delete+recreate carrying the NEW ip and not the OLD.
	res.records["api.test"] = mkRes(time.Minute, "5.6.7.8")
	if _, err := c.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := run.last()
	if !strings.Contains(got, "5.6.7.8") || strings.Contains(got, "1.1.1.1") {
		t.Fatalf("refresh must swap to new IP with no stale rule:\n%s", got)
	}
	mustContainInOrder(t, got, "add table inet opslify_sess_s1", "delete table inet opslify_sess_s1", "table inet opslify_sess_s1 {")
}

// Teardown is idempotent even for a session that was never set up (reconcile/reap).
func TestController_TeardownUnknownIsSafe(t *testing.T) {
	run := &fakeRunner{}
	c := newTestController(t, run, &fakeResolver{}, nil)
	if err := c.TeardownSession(context.Background(), "never-existed"); err != nil {
		t.Fatalf("teardown of unknown session must be safe: %v", err)
	}
}

func TestController_AvailableDelegates(t *testing.T) {
	c := newTestController(t, &fakeRunner{available: errors.New("no nft")}, &fakeResolver{}, nil)
	if err := c.Available(); err == nil {
		t.Fatal("Available must surface the runner probe error")
	}
}

// Start/Close lifecycle: the refresh goroutine starts and stops cleanly (race-clean).
func TestController_StartClose(t *testing.T) {
	run := &fakeRunner{}
	res := &fakeResolver{records: map[string]Resolution{"api.test": mkRes(time.Minute, "1.1.1.1")}}
	c := NewController(Config{
		Runner:     run,
		Resolver:   res,
		Allowlist:  []string{"api.test"},
		MinRefresh: time.Hour, // keep the loop asleep during the test
		MaxRefresh: time.Hour,
		Logger:     discardLogger(),
	})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.Close() // double-close is safe
}
