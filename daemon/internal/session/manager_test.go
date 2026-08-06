package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// newTestManager builds a Manager over a fake runtime + in-memory store + fake
// clock — the whole lifecycle exercised with no podman/runsc, no root.
func newTestManager(t *testing.T, rt runtime.Runtime, clk Clock, st Store) *Manager {
	t.Helper()
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:           "base@sha256:deadbeef",
			ToolchainDigest: "tool@sha256:cafe",
			WorkspaceRoot:   t.TempDir(),
			DefaultTier:     runtime.TierLocalHardened,
			DefaultTTL:      30 * time.Minute,
			Limits:          runtime.ResourceLimits{MemoryBytes: 2 << 30, CPUs: 2, PidsLimit: 256},
		},
		Resolve: func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:   clk,
		Store:   st,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// AC: POST /sessions creates a ready session; state machine creating→ready.
func TestCreateReady(t *testing.T) {
	rt := newFakeRuntime()
	st := newMemStore()
	m := newTestManager(t, rt, newFakeClock(time.Unix(0, 0)), st)

	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.State != StateReady {
		t.Fatalf("state = %q, want ready", s.State)
	}
	if rt.createdCount() != 1 {
		t.Fatalf("runtime Create calls = %d, want 1", rt.createdCount())
	}
	if st.count() != 1 {
		t.Fatalf("record not persisted; store has %d", st.count())
	}
}

// AC + hardening flow-through: the spec the manager hands the runtime, when fed
// into the real GvisorRuntime argv assembly, carries every hard-spec flag and the
// RO toolchain + rw /workspace. This proves the manager does not bypass F0.3's
// hardening base.
func TestCreateSpecFlowsHardeningToContainer(t *testing.T) {
	rt := newFakeRuntime()
	m := newTestManager(t, rt, newFakeClock(time.Unix(0, 0)), newMemStore())

	if _, err := m.Create(context.Background(), CreateRequest{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	spec := rt.spec()

	// Feed the manager-produced spec through the real hardened rung's argv build.
	args, err := runtime.RenderCreateArgs(runtime.TierLocalHardened, spec)
	if err != nil {
		t.Fatalf("RenderCreateArgs: %v", err)
	}
	joined := strings.Join(args, " ")

	wantHardening := []string{
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--userns=auto",
		"--user=" + runtime.SandboxUser,
		"--read-only",
		"--security-opt=seccomp=" + runtime.DefaultSeccompProfile,
	}
	for _, w := range wantHardening {
		if !strings.Contains(joined, w) {
			t.Errorf("container spec missing hardening flag %q in %v", w, args)
		}
	}
	// Signed toolchain RO + resource caps flowed through.
	if !strings.Contains(joined, "destination=/opt/toolchain,ro=true") {
		t.Errorf("toolchain must be mounted read-only: %v", args)
	}
	if !strings.Contains(joined, ":/workspace:rw") {
		t.Errorf("writable /workspace mount missing: %v", args)
	}
	for _, w := range []string{"--pids-limit", "256", "--memory", "--cpus"} {
		if !strings.Contains(joined, w) {
			t.Errorf("resource cap %q missing: %v", w, args)
		}
	}
}

// AC: runtime unavailable → legible ErrRuntimeUnavailable, no container, no record.
func TestCreateRuntimeUnavailable(t *testing.T) {
	rt := newFakeRuntime()
	rt.available = errors.New("runtime: OCI runtime \"runsc\" unavailable")
	st := newMemStore()
	m := newTestManager(t, rt, newFakeClock(time.Unix(0, 0)), st)

	_, err := m.Create(context.Background(), CreateRequest{})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("err = %v, want ErrRuntimeUnavailable", err)
	}
	if rt.createdCount() != 0 || st.count() != 0 {
		t.Fatalf("must not create/persist when runtime unavailable")
	}
}

// AC: create failure must not leak a record (rollback).
func TestCreatePersistFailureRollsBack(t *testing.T) {
	rt := newFakeRuntime()
	rt.createErr = errors.New("engine boom")
	m := newTestManager(t, rt, newFakeClock(time.Unix(0, 0)), newMemStore())
	if _, err := m.Create(context.Background(), CreateRequest{}); err == nil {
		t.Fatal("expected create error")
	}
}

// AC: exec streams output + exit code; session returns to ready.
func TestExecStreamsAndReturnsReady(t *testing.T) {
	rt := newFakeRuntime()
	rt.nextExec = runtime.ExecStream{
		Stdout:   strings.NewReader("hello world"),
		Stderr:   strings.NewReader("warn"),
		ExitCode: 0,
	}
	m := newTestManager(t, rt, newFakeClock(time.Unix(0, 0)), newMemStore())
	s, _ := m.Create(context.Background(), CreateRequest{})

	sink := newCaptureSink()
	if err := m.Exec(context.Background(), s.ID, ExecOptions{Argv: []string{"echo", "hi"}}, sink); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if string(sink.stdout) != "hello world" {
		t.Errorf("stdout = %q", sink.stdout)
	}
	if string(sink.stderr) != "warn" {
		t.Errorf("stderr = %q", sink.stderr)
	}
	if sink.exit == nil || *sink.exit != 0 {
		t.Errorf("exit = %v, want 0", sink.exit)
	}
	if got := m.List()[0].State; got != StateReady {
		t.Errorf("state after exec = %q, want ready", got)
	}
}

// AC: exec against a missing session is a legible not-found.
func TestExecNotFound(t *testing.T) {
	m := newTestManager(t, newFakeRuntime(), newFakeClock(time.Unix(0, 0)), newMemStore())
	err := m.Exec(context.Background(), "nope", ExecOptions{Argv: []string{"ls"}}, newCaptureSink())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// Boundary: hostile/bad exec inputs are rejected before touching the runtime.
func TestExecInputValidation(t *testing.T) {
	m := newTestManager(t, newFakeRuntime(), newFakeClock(time.Unix(0, 0)), newMemStore())
	s, _ := m.Create(context.Background(), CreateRequest{})
	cases := []ExecOptions{
		{Argv: nil},
		{Argv: []string{"ls"}, Env: []string{"NOEQ"}},
		{Argv: []string{"ls"}, Cwd: "relative"},
		{Argv: []string{"ls\x00"}},
		{Argv: []string{"ls"}, Writable: []string{"/etc/passwd"}},
	}
	for i, c := range cases {
		if err := m.Exec(context.Background(), s.ID, c, newCaptureSink()); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("case %d: err = %v, want ErrInvalidInput", i, err)
		}
	}
	// A grant under /workspace is accepted.
	if err := m.Exec(context.Background(), s.ID, ExecOptions{Argv: []string{"ls"}, Writable: []string{"/workspace/out"}}, newCaptureSink()); err != nil {
		t.Errorf("valid workspace grant rejected: %v", err)
	}
}

// AC: DELETE destroys the container, drops the record, leaves no session.
func TestDestroy(t *testing.T) {
	rt := newFakeRuntime()
	st := newMemStore()
	m := newTestManager(t, rt, newFakeClock(time.Unix(0, 0)), st)
	s, _ := m.Create(context.Background(), CreateRequest{})

	if err := m.Destroy(context.Background(), s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if rt.destroyedCount() != 1 {
		t.Fatalf("container not destroyed")
	}
	if st.count() != 0 {
		t.Fatalf("record not deleted")
	}
	if len(m.List()) != 0 {
		t.Fatalf("session still listed after destroy")
	}
	if err := m.Destroy(context.Background(), s.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double destroy err = %v, want ErrNotFound", err)
	}
}

// AC: GET /sessions lists state/age/ttl_remaining, clock-relative.
func TestListViewAccounting(t *testing.T) {
	rt := newFakeRuntime()
	clk := newFakeClock(time.Unix(1000, 0))
	m := newTestManager(t, rt, clk, newMemStore())
	m.Create(context.Background(), CreateRequest{TTL: 10 * time.Minute})

	clk.advance(2 * time.Minute)
	views := m.List()
	if len(views) != 1 {
		t.Fatalf("want 1 view, got %d", len(views))
	}
	v := views[0]
	if v.AgeSeconds != 120 {
		t.Errorf("age = %d, want 120", v.AgeSeconds)
	}
	if v.TTLRemaining != 480 {
		t.Errorf("ttl_remaining = %d, want 480", v.TTLRemaining)
	}
	if v.State != StateReady {
		t.Errorf("state = %q", v.State)
	}
}

// AC: TTL expiry reaps the idle session (deterministic clock).
func TestReapExpired(t *testing.T) {
	rt := newFakeRuntime()
	clk := newFakeClock(time.Unix(0, 0))
	st := newMemStore()
	m := newTestManager(t, rt, clk, st)
	s, _ := m.Create(context.Background(), CreateRequest{TTL: 5 * time.Minute})

	// Not yet expired.
	if reaped := m.ReapExpired(context.Background(), clk.Now()); len(reaped) != 0 {
		t.Fatalf("reaped early: %v", reaped)
	}
	clk.advance(6 * time.Minute)
	reaped := m.ReapExpired(context.Background(), clk.Now())
	if len(reaped) != 1 || reaped[0] != s.ID {
		t.Fatalf("reaped = %v, want [%s]", reaped, s.ID)
	}
	if rt.destroyedCount() != 1 || st.count() != 0 || len(m.List()) != 0 {
		t.Fatalf("expired session not fully cleaned up")
	}
}

// Reaper does not kill a session with an exec in flight.
func TestReapSkipsExecing(t *testing.T) {
	rt := newFakeRuntime()
	clk := newFakeClock(time.Unix(0, 0))
	m := newTestManager(t, rt, clk, newMemStore())
	s, _ := m.Create(context.Background(), CreateRequest{TTL: time.Minute})
	// Force execing state.
	m.mu.Lock()
	m.sessions[s.ID].State = StateExecing
	m.mu.Unlock()

	clk.advance(2 * time.Minute)
	if reaped := m.ReapExpired(context.Background(), clk.Now()); len(reaped) != 0 {
		t.Fatalf("must not reap an execing session, got %v", reaped)
	}
}

// AC: daemon restart reaps orphaned sandboxes (persisted records).
func TestReconcileReapsOrphans(t *testing.T) {
	rt := newFakeRuntime()
	st := newMemStore()
	// Simulate two sandboxes left by a previous daemon lifetime.
	st.Save(record{ID: "a", Tier: runtime.TierLocalHardened, Handle: runtime.ContainerHandle{ID: "ctr-a"}, Mode: ModeScratch})
	st.Save(record{ID: "b", Tier: runtime.TierLocalHardened, Handle: runtime.ContainerHandle{ID: "ctr-b"}, Mode: ModeScratch})

	m := newTestManager(t, rt, newFakeClock(time.Unix(0, 0)), st)
	reaped, err := m.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(reaped) != 2 {
		t.Fatalf("reaped %d orphans, want 2", len(reaped))
	}
	if rt.destroyedCount() != 2 {
		t.Fatalf("orphan containers destroyed = %d, want 2", rt.destroyedCount())
	}
	if st.count() != 0 {
		t.Fatalf("orphan records not cleared: %d", st.count())
	}
}

// Shutdown destroys every live session (no leaks on clean stop).
func TestShutdownDestroysAll(t *testing.T) {
	rt := newFakeRuntime()
	st := newMemStore()
	m := newTestManager(t, rt, newFakeClock(time.Unix(0, 0)), st)
	m.Create(context.Background(), CreateRequest{})
	m.Create(context.Background(), CreateRequest{})

	m.Shutdown(context.Background())
	if rt.destroyedCount() != 2 || st.count() != 0 || len(m.List()) != 0 {
		t.Fatalf("shutdown left sandboxes: destroyed=%d records=%d live=%d", rt.destroyedCount(), st.count(), len(m.List()))
	}
}

// The reaper goroutine (StartReaper) actually reaps an expired session and
// stops cleanly. Uses a short tick + advanced fake clock; polls rather than
// sleeps on a fixed duration to stay non-flaky under -race.
func TestReaperGoroutine(t *testing.T) {
	rt := newFakeRuntime()
	clk := newFakeClock(time.Unix(0, 0))
	m := newTestManager(t, rt, clk, newMemStore())
	m.Create(context.Background(), CreateRequest{TTL: time.Minute})
	clk.advance(2 * time.Minute) // now past the idle deadline

	m.StartReaper(2 * time.Millisecond)
	defer m.StopReaper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if len(m.List()) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reaper goroutine did not reap the expired session")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if rt.destroyedCount() != 1 {
		t.Fatalf("reaper did not destroy the container")
	}
}

// Invalid mode is rejected.
func TestCreateBadMode(t *testing.T) {
	m := newTestManager(t, newFakeRuntime(), newFakeClock(time.Unix(0, 0)), newMemStore())
	if _, err := m.Create(context.Background(), CreateRequest{Mode: "bogus"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}
