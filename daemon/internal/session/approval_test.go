package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// approvalManager wires a traced manager whose default policy gates any command
// matching `kubectl delete`, on a manually-advanced fakeClock (deterministic
// approval timeouts). Returns the manager, the runtime double, the fake clock, and
// the trust key for chain verification.
func approvalManager(t *testing.T) (*Manager, *fakeRuntime, *fakeClock, []byte) {
	t.Helper()
	rt := newFakeRuntime()
	clk := newFakeClock(time.Unix(1700000000, 0).UTC())
	m, _, pub := newTracedManager(t, rt, clk)
	m.cfg.DefaultPolicy = policy.Policy{ApprovalRequired: []string{`kubectl delete`}}
	m.cfg.ApprovalTTL = 10 * time.Minute
	return m, rt, clk, pub
}

// gate runs a command expected to hit an approval gate and returns its exec_id.
func gate(t *testing.T, ctx context.Context, m *Manager, id string, argv ...string) string {
	t.Helper()
	err := m.Exec(ctx, id, ExecOptions{Argv: argv}, newCaptureSink())
	var ape *ApprovalPendingError
	if !errors.As(err, &ape) {
		t.Fatalf("expected ApprovalPendingError, got %v", err)
	}
	return ape.ExecID
}

func sessionState(t *testing.T, m *Manager, id string) State {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id].State
}

func hasEvent(events []trace.Event, typ trace.EventType) *trace.Event {
	for i := range events {
		if events[i].Type == typ {
			return &events[i]
		}
	}
	return nil
}

// AC: a gated command pauses in awaiting_approval; the process is NOT spawned; an
// approval.requested event is emitted (and thus streamable to the UI).
func TestApproval_PausesAndEmitsRequested(t *testing.T) {
	m, rt, _, _ := approvalManager(t)
	ctx := context.Background()
	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	execID := gate(t, ctx, m, s.ID, "kubectl", "delete", "pod", "x")

	if st := sessionState(t, m, s.ID); st != StateAwaitingApproval {
		t.Fatalf("session state = %s, want awaiting_approval", st)
	}
	if rt.execCalls() != 0 {
		t.Fatalf("pause must NOT spawn (execCalls=%d)", rt.execCalls())
	}
	events, _, _ := m.TraceExport(ctx, s.ID)
	ev := hasEvent(events, trace.TypeApprovalRequested)
	if ev == nil {
		t.Fatal("no approval.requested event emitted")
	}
	if ev.Payload["exec_id"] != execID {
		t.Fatalf("approval.requested exec_id = %v, want %s", ev.Payload["exec_id"], execID)
	}
	// The pending gate is listed for the operator.
	if list := m.ListApprovals(); len(list) != 1 || list[0].ExecID != execID {
		t.Fatalf("ListApprovals = %+v, want one pending %s", list, execID)
	}
}

// AC: approve → the command runs and returns output; the resolution emits a
// chained policy.decision(approved) carrying the approver comment; the whole chain
// verifies.
func TestApproval_ApproveRunsAndReturnsOutput(t *testing.T) {
	m, rt, _, pub := approvalManager(t)
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader("pod deleted\n"), Stderr: strings.NewReader(""), ExitCode: 0}
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "kubectl", "delete", "pod", "x")

	view, err := m.ResolveApproval(ctx, s.ID, execID, DecisionApprove, "ok by SRE")
	if err != nil {
		t.Fatalf("ResolveApproval: %v", err)
	}
	if view.Status != ApprovalApproved || !view.Ran {
		t.Fatalf("view = %+v, want approved+ran", view)
	}
	if !strings.Contains(view.Stdout, "pod deleted") {
		t.Fatalf("approved run stdout = %q, want the command output", view.Stdout)
	}
	if rt.execCalls() != 1 {
		t.Fatalf("approve must spawn exactly once (execCalls=%d)", rt.execCalls())
	}
	if st := sessionState(t, m, s.ID); st != StateReady {
		t.Fatalf("session state after approve = %s, want ready", st)
	}

	// The resolution is a chained, verifiable policy.decision(approved) with comment.
	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	events, seal, _ := m.TraceExport(ctx, s.ID)
	if res := trace.Verify(events, seal, pub); !res.OK {
		t.Fatalf("chain verify failed at seq %d: %s", res.BrokenSeq, res.Reason)
	}
	var approved *trace.Event
	for i := range events {
		if events[i].Type == trace.TypePolicyDecision && events[i].Payload["decision"] == "approved" {
			approved = &events[i]
		}
	}
	if approved == nil {
		t.Fatal("no policy.decision(approved) event")
	}
	if approved.Payload["comment"] != "ok by SRE" {
		t.Fatalf("approved comment = %v, want the approver comment", approved.Payload["comment"])
	}
}

// AC: deny → the agent gets a structured denial with the reason/comment; no spawn;
// a policy.decision(denied) with the comment is traced.
func TestApproval_DenyReturnsDenial(t *testing.T) {
	m, rt, _, _ := approvalManager(t)
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "kubectl", "delete", "pod", "x")

	view, err := m.ResolveApproval(ctx, s.ID, execID, DecisionDeny, "too risky")
	if err != nil {
		t.Fatalf("ResolveApproval deny: %v", err)
	}
	if view.Status != ApprovalDenied || view.DenyReason != "operator" || view.Comment != "too risky" {
		t.Fatalf("deny view = %+v", view)
	}
	if rt.execCalls() != 0 {
		t.Fatalf("deny must NOT spawn (execCalls=%d)", rt.execCalls())
	}
	if st := sessionState(t, m, s.ID); st != StateReady {
		t.Fatalf("session state after deny = %s, want ready", st)
	}
	events, _, _ := m.TraceExport(ctx, s.ID)
	var denied *trace.Event
	for i := range events {
		if events[i].Type == trace.TypePolicyDecision && events[i].Payload["decision"] == "denied" {
			denied = &events[i]
		}
	}
	if denied == nil || denied.Payload["comment"] != "too risky" {
		t.Fatalf("expected policy.decision(denied) with comment, got %+v", denied)
	}
}

// AC/QA: timeout (clock advanced past TTL) → auto-deny reason "timeout"; a LATE
// approval after the timeout is rejected (no resurrection); no spawn.
func TestApproval_TimeoutAutoDeny(t *testing.T) {
	m, rt, clk, _ := approvalManager(t)
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "kubectl", "delete", "pod", "x")

	// Not yet expired: sweeping does nothing.
	clk.advance(5 * time.Minute)
	if got := m.ExpireApprovals(ctx, clk.Now()); len(got) != 0 {
		t.Fatalf("premature expiry: %v", got)
	}
	// Past the TTL: fail-closed auto-deny with reason timeout.
	clk.advance(6 * time.Minute)
	if got := m.ExpireApprovals(ctx, clk.Now()); len(got) != 1 || got[0] != execID {
		t.Fatalf("ExpireApprovals = %v, want [%s]", got, execID)
	}
	v, _ := m.GetApproval(ctx, s.ID, execID)
	if v.Status != ApprovalDenied || v.DenyReason != "timeout" {
		t.Fatalf("timed-out gate = %+v, want denied/timeout", v)
	}
	// A late approval must be rejected — no resurrection, no spawn.
	if _, err := m.ResolveApproval(ctx, s.ID, execID, DecisionApprove, "late"); !errors.Is(err, ErrApprovalResolved) {
		t.Fatalf("late approve err = %v, want ErrApprovalResolved", err)
	}
	if rt.execCalls() != 0 {
		t.Fatalf("timed-out gate must never spawn (execCalls=%d)", rt.execCalls())
	}
}

// AC: a session ending while an approval is pending cancels it cleanly (fail-closed
// auto-deny, no leaked pending state, no spawn), with the denial chained before
// session.end.
func TestApproval_SessionEndCancels(t *testing.T) {
	m, rt, _, pub := approvalManager(t)
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "kubectl", "delete", "pod", "x")

	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if rt.execCalls() != 0 {
		t.Fatalf("session-end must NOT spawn (execCalls=%d)", rt.execCalls())
	}
	// No leaked pending state.
	if _, err := m.GetApproval(ctx, s.ID, execID); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("pending state leaked after session end: %v", err)
	}
	if list := m.ListApprovals(); len(list) != 0 {
		t.Fatalf("ListApprovals after session end = %+v, want empty", list)
	}
	// The denial is chained + sealed before session.end; verify the whole chain.
	events, seal, _ := m.TraceExport(ctx, s.ID)
	if res := trace.Verify(events, seal, pub); !res.OK {
		t.Fatalf("chain verify failed: %s", res.Reason)
	}
	var deniedSeq, endSeq = -1, -1
	for i := range events {
		if events[i].Type == trace.TypePolicyDecision && events[i].Payload["decision"] == "denied" {
			deniedSeq = int(events[i].Seq)
		}
		if events[i].Type == trace.TypeSessionEnd {
			endSeq = int(events[i].Seq)
		}
	}
	if deniedSeq < 0 || endSeq < 0 || deniedSeq >= endSeq {
		t.Fatalf("denial (seq %d) must precede session.end (seq %d)", deniedSeq, endSeq)
	}
}

// QA: an approve+deny race resolves exactly once — no double-spawn, deterministic.
func TestApproval_ResolveRaceResolvesOnce(t *testing.T) {
	m, rt, _, _ := approvalManager(t)
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader("done\n"), Stderr: strings.NewReader(""), ExitCode: 0}
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "kubectl", "delete", "pod", "x")

	var wg sync.WaitGroup
	var okCount int
	var mu sync.Mutex
	for _, dec := range []ApprovalDecision{DecisionApprove, DecisionDeny} {
		wg.Add(1)
		go func(d ApprovalDecision) {
			defer wg.Done()
			if _, err := m.ResolveApproval(ctx, s.ID, execID, d, ""); err == nil {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}(dec)
	}
	wg.Wait()
	if okCount != 1 {
		t.Fatalf("exactly one resolution must win, got %d", okCount)
	}
	if calls := rt.execCalls(); calls > 1 {
		t.Fatalf("no double-spawn: execCalls=%d", calls)
	}
}

// QA: a second resolution of an already-resolved gate is a no-op error (idempotent).
func TestApproval_DoubleResolveRejected(t *testing.T) {
	m, _, _, _ := approvalManager(t)
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "kubectl", "delete", "pod", "x")

	if _, err := m.ResolveApproval(ctx, s.ID, execID, DecisionDeny, "no"); err != nil {
		t.Fatalf("first deny: %v", err)
	}
	if _, err := m.ResolveApproval(ctx, s.ID, execID, DecisionApprove, "yes"); !errors.Is(err, ErrApprovalResolved) {
		t.Fatalf("second resolve err = %v, want ErrApprovalResolved", err)
	}
}
