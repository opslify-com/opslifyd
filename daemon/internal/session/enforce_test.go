package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// writeWorkspacePolicy pre-creates a workspace host dir and drops a policy file
// at its /workspace root, returning the workspace name.
func writeWorkspacePolicy(t *testing.T, m *Manager, name, body string) {
	t.Helper()
	wsDir := m.workspaceDir(name)
	if err := os.MkdirAll(wsDir, 0o700); err != nil {
		t.Fatalf("mkdir ws: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, policy.DefaultFileName), []byte(body), 0o600); err != nil {
		t.Fatalf("write ws policy: %v", err)
	}
}

// findDecision returns the first policy.decision event, or fails.
func findDecision(t *testing.T, events []trace.Event) trace.Event {
	t.Helper()
	for _, e := range events {
		if e.Type == trace.TypePolicyDecision {
			return e
		}
	}
	t.Fatalf("no policy.decision event in trace")
	return trace.Event{}
}

// execArgv runs one command and returns the manager error (nil sink output is
// discarded — this test cares about the verdict, not the bytes).
func execArgv(ctx context.Context, m *Manager, id string, argv ...string) error {
	return m.Exec(ctx, id, ExecOptions{Argv: argv}, newCaptureSink())
}

// HEADLINE AC: kubectl restricted to an allowed namespace — a cross-namespace
// call is blocked, NO process is spawned, a structured ErrPolicyDenied is
// returned, and a policy.decision: deny is traced carrying the policy_hash.
func TestExec_KubectlCrossNamespaceDenied(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, _, trustedPub := newTracedManager(t, rt, clk)
	// Daemon policy bounds kubectl to namespace "prod-a", verbs get/list.
	m.cfg.DefaultPolicy = policy.Policy{
		Allow: policy.Allow{Kubectl: policy.Kubectl{
			Namespaces: []string{"prod-a"},
			Verbs:      []string{"get", "list"},
		}},
	}
	ctx := context.Background()

	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Allowed namespace → spawns.
	if err := execArgv(ctx, m, s.ID, "kubectl", "get", "pods", "-n", "prod-a"); err != nil {
		t.Fatalf("allowed kubectl should succeed: %v", err)
	}
	if rt.execCalls() != 1 {
		t.Fatalf("allowed exec should spawn exactly once, got %d", rt.execCalls())
	}

	// Cross-namespace → denied, and the runtime is NEVER touched again.
	err = execArgv(ctx, m, s.ID, "kubectl", "get", "pods", "-n", "prod-b")
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("cross-namespace error = %v, want ErrPolicyDenied", err)
	}
	if rt.execCalls() != 1 {
		t.Fatalf("denied exec must NOT spawn (execCalls=%d)", rt.execCalls())
	}

	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// The deny is traced: a policy.decision: deny carrying the session policy_hash,
	// and the sealed chain still verifies (redacted + chained like any event).
	events, seal, err := m.TraceExport(ctx, s.ID)
	if err != nil {
		t.Fatalf("TraceExport: %v", err)
	}
	var sawDeny bool
	wantHash := events[0].Payload["policy_hash"]
	for _, e := range events {
		if e.Type != trace.TypePolicyDecision {
			continue
		}
		if e.Payload["decision"] == "deny" {
			sawDeny = true
			if e.Payload["policy_hash"] != wantHash {
				t.Fatalf("policy.decision policy_hash = %v, want %v", e.Payload["policy_hash"], wantHash)
			}
			if e.Payload["rule"] == "" || e.Payload["rule"] == nil {
				t.Fatalf("policy.decision deny must name the rule that fired")
			}
		}
	}
	if !sawDeny {
		t.Fatalf("expected a policy.decision: deny in the trace")
	}
	if res := trace.Verify(events, seal, trustedPub); !res.OK {
		t.Fatalf("chain verify failed at seq %d: %s", res.BrokenSeq, res.Reason)
	}
}

// AC: strict_exec denies a command not in the allowlist and never spawns it;
// with strict off, an ungated command runs.
func TestExec_StrictExecDeny(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, _, _ := newTracedManager(t, rt, clk)
	m.cfg.DefaultPolicy = policy.Policy{
		StrictExec: true,
		Allow:      policy.Allow{Exec: []string{`^echo( |$)`}},
	}
	ctx := context.Background()
	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := execArgv(ctx, m, s.ID, "echo", "hi"); err != nil {
		t.Fatalf("allowlisted echo should run: %v", err)
	}
	if err := execArgv(ctx, m, s.ID, "curl", "http://evil"); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("strict deny error = %v, want ErrPolicyDenied", err)
	}
	if rt.execCalls() != 1 {
		t.Fatalf("only the allowlisted command should spawn (execCalls=%d)", rt.execCalls())
	}
}

// AC: approval_required routes to a distinct-reason refusal (F4.3 seam) — no
// spawn, no hang.
func TestExec_ApprovalRequiredRefused(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, _, _ := newTracedManager(t, rt, clk)
	m.cfg.DefaultPolicy = policy.Policy{ApprovalRequired: []string{`kubectl delete`}}
	ctx := context.Background()
	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	err = execArgv(ctx, m, s.ID, "kubectl", "delete", "pod", "x")
	if !errors.Is(err, ErrPolicyApproval) {
		t.Fatalf("approval error = %v, want ErrPolicyApproval", err)
	}
	if rt.execCalls() != 0 {
		t.Fatalf("needs_approval must NOT spawn (execCalls=%d)", rt.execCalls())
	}
	events, _, _ := m.TraceExport(ctx, s.ID)
	if findDecision(t, events).Payload["decision"] != "needs_approval" {
		t.Fatalf("expected a policy.decision: needs_approval")
	}
}

// AC: session spin-up refuses a policy-forbidden (weaker) tier with a legible,
// policy-layer reason — and builds no sandbox.
func TestSpinUp_ForbiddenTierRefused(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, _, _ := newTracedManager(t, rt, clk)
	// Daemon POLICY pins the hardened tier; a request for the weaker docker rung
	// must be refused.
	m.cfg.DefaultPolicy = policy.Policy{Session: policy.Session{Tier: "local-hardened"}}
	ctx := context.Background()

	_, err := m.Create(ctx, CreateRequest{Mode: ModeScratch, Tier: "local-docker"})
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("forbidden-tier error = %v, want ErrPolicyDenied", err)
	}
	if rt.createdCount() != 0 {
		t.Fatalf("a refused spin-up must build no sandbox (created=%d)", rt.createdCount())
	}
}

// CARRY-OVER (F4.1 QA): when the daemon policy leaves session.tier/ttl UNSET, a
// workspace policy proposing a WEAKER tier / LONGER ttl must NOT relax the actual
// session — enforcement falls back to the daemon CONFIG bounds, never the
// workspace-supplied value that F4.1's narrowing let pass through.
func TestSpinUp_UnsetDaemonBoundIgnoresWorkspaceWeakening(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, _, _ := newTracedManager(t, rt, clk)
	// Daemon config default is the HARDENED tier + 30m ttl; the daemon POLICY
	// leaves session.* UNSET (the zero policy.Policy).
	m.cfg.DefaultPolicy = policy.Policy{}
	ctx := context.Background()

	// A workspace policy tries to weaken tier to local-docker and lengthen ttl to
	// 12h. F4.1 lets these pass through the resolved model unclamped (daemon bound
	// unset) — F4.2 must ignore them.
	wsName := "sneaky"
	writeWorkspacePolicy(t, m, wsName,
		"session:\n  tier: local-docker\n  ttl: 12h\n")

	// Sanity: the RESOLVED model really did carry the workspace's weaker values
	// (this is the F4.1 pass-through the enforcement must not trust).
	resolved, err := m.resolveCreatePolicy(ModeWorkspace, wsName)
	if err != nil {
		t.Fatalf("resolveCreatePolicy: %v", err)
	}
	if resolved.Session.Tier != "local-docker" || resolved.Session.TTL != "12h" {
		t.Fatalf("precondition: expected resolved to pass through workspace values, got tier=%q ttl=%q",
			resolved.Session.Tier, resolved.Session.TTL)
	}

	s, err := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: wsName})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// The ACTUAL session must use the daemon config bounds, NOT the workspace's.
	if s.Tier != "local-hardened" {
		t.Fatalf("session tier = %q, want daemon-config local-hardened (workspace weakening ignored)", s.Tier)
	}
	if s.TTL != 30*time.Minute {
		t.Fatalf("session ttl = %v, want daemon-config 30m (workspace lengthening ignored)", s.TTL)
	}
}

// When the daemon POLICY does pin a tighter ttl, it is honoured (clamps a longer
// request down) — proving the bound is read when it is trustworthy.
func TestSpinUp_DaemonPolicyTTLClampsRequest(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, _, _ := newTracedManager(t, rt, clk)
	m.cfg.DefaultPolicy = policy.Policy{Session: policy.Session{TTL: "5m"}}
	ctx := context.Background()

	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch, TTL: time.Hour})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.TTL != 5*time.Minute {
		t.Fatalf("session ttl = %v, want clamped-to-policy 5m", s.TTL)
	}
}
