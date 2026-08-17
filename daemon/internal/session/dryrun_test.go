package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// dryRunManager wires a traced manager with F4.4 dry-run interception ENABLED
// (unlike approvalManager, which leaves it off to exercise the pre-F4.4 path). The
// default policy gates terraform apply + kubectl apply/delete via approval_required
// and carries an extra custom dry_run rule (helm) plus a warn/block toggle.
func dryRunManager(t *testing.T, warnOnFailure bool, extraRules ...policy.DryRunRule) (*Manager, *fakeRuntime, *fakeClock, []byte) {
	t.Helper()
	rt := newFakeRuntime()
	clk := newFakeClock(time.Unix(1700000000, 0).UTC())
	m, _, pub := newTracedManager(t, rt, clk)
	m.cfg.DryRun = true
	m.cfg.DefaultPolicy = policy.Policy{
		ApprovalRequired:    []string{`terraform apply`, `kubectl (apply|delete)`, `helm upgrade`},
		DryRun:              extraRules,
		DryRunWarnOnFailure: warnOnFailure,
	}
	m.cfg.ApprovalTTL = 10 * time.Minute
	return m, rt, clk, pub
}

func approvalRequestedEvent(t *testing.T, m *Manager, sessionID string) *trace.Event {
	t.Helper()
	events, _, _ := m.TraceExport(context.Background(), sessionID)
	ev := hasEvent(events, trace.TypeApprovalRequested)
	if ev == nil {
		t.Fatal("no approval.requested event emitted")
	}
	return ev
}

// AC: a gated terraform apply produces a `terraform plan -out=...` preview whose
// diff is attached to approval.requested; on APPROVE the run is
// `terraform apply <saved-plan>` (NOT a fresh apply) — the no-TOCTOU guarantee.
func TestDryRun_TerraformSavedPlan(t *testing.T) {
	m, rt, _, _ := dryRunManager(t, false)
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader("Plan: 1 to add, 0 to change, 0 to destroy.\n"), Stderr: strings.NewReader(""), ExitCode: 0}
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "terraform", "apply", "-var-file=prod.tfvars")

	// The preview ran in-sandbox (execCalls == 1) and is a terraform plan -out.
	if rt.execCalls() != 1 {
		t.Fatalf("preview must run exactly once in-sandbox, execCalls=%d", rt.execCalls())
	}
	view, _ := m.GetApproval(ctx, s.ID, execID)
	if !strings.HasPrefix(view.PreviewCmd, "terraform plan -out=/workspace/.opslify-plan-") {
		t.Fatalf("preview cmd = %q, want terraform plan -out=...", view.PreviewCmd)
	}
	if !strings.Contains(view.PreviewCmd, "-var-file=prod.tfvars") {
		t.Fatalf("preview should carry the original flags: %q", view.PreviewCmd)
	}
	if view.PreviewStatus != "ok" || !strings.Contains(view.PreviewDiff, "Plan: 1 to add") {
		t.Fatalf("preview diff/status not captured: %+v", view)
	}
	// The diff is on the approval.requested event too (for the UI).
	ev := approvalRequestedEvent(t, m, s.ID)
	if !strings.Contains(ev.Payload["preview_diff"].(string), "Plan: 1 to add") {
		t.Fatalf("approval.requested missing preview diff: %v", ev.Payload)
	}

	// APPROVE → the run must be `terraform apply <saved-plan>`, not a fresh apply.
	rt.lastExecReset()
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader("Apply complete!\n"), Stderr: strings.NewReader(""), ExitCode: 0}
	if _, err := m.ResolveApproval(ctx, s.ID, execID, DecisionApprove, "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	ran := rt.lastExecArgv()
	if len(ran) != 3 || ran[0] != "terraform" || ran[1] != "apply" || !strings.HasPrefix(ran[2], "/workspace/.opslify-plan-") {
		t.Fatalf("approved argv = %v, want [terraform apply <saved-plan>]", ran)
	}
}

// Security: the saved plan lives in the agent-writable /workspace. If it is
// altered between the human's review and the approved apply, the daemon-side
// hash-pin must detect it and REFUSE the apply (fail-closed) — the reviewed diff
// can never diverge from what runs without being caught.
func TestDryRun_TerraformSavedPlanTamperRefused(t *testing.T) {
	m, rt, _, _ := dryRunManager(t, false)
	rt.planContent = []byte("PLAN-reviewed")
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader("Plan: 1 to add.\n"), ExitCode: 0}
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "terraform", "apply")

	// Agent tampers the saved plan file after the human reviewed the preview.
	planFile := filepath.Join(rt.spec().Workspace, ".opslify-plan-"+execID+".tfplan")
	if err := os.WriteFile(planFile, []byte("PLAN-SWAPPED-EVIL"), 0o600); err != nil {
		t.Fatalf("tamper write: %v", err)
	}

	rt.lastExecReset()
	view, err := m.ResolveApproval(ctx, s.ID, execID, DecisionApprove, "looked fine")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Apply must NOT have run, and the run must be flagged as a tamper failure.
	if rt.lastExecArgv() != nil {
		t.Fatalf("tampered plan must NOT be applied, got %v", rt.lastExecArgv())
	}
	if !strings.Contains(view.RunErr, "tamper") {
		t.Fatalf("expected tamper-detected run error, got %+v", view)
	}
}

// AC: deny returns the reason to the agent; no destructive run.
func TestDryRun_TerraformDenyReturnsReason(t *testing.T) {
	m, rt, _, _ := dryRunManager(t, false)
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "terraform", "apply")
	rt.lastExecReset()

	view, err := m.ResolveApproval(ctx, s.ID, execID, DecisionDeny, "not now")
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if view.Status != ApprovalDenied || view.Comment != "not now" {
		t.Fatalf("deny view = %+v", view)
	}
	if rt.lastExecArgv() != nil {
		t.Fatalf("deny must not run the apply, got %v", rt.lastExecArgv())
	}
}

// AC: a gated kubectl apply/delete produces a `--dry-run=server` diff beside the
// prompt; approve runs the real command (weaker, honest guarantee).
func TestDryRun_KubectlServerDryRun(t *testing.T) {
	m, rt, _, _ := dryRunManager(t, false)
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader("service/foo configured (server dry run)\n"), Stderr: strings.NewReader(""), ExitCode: 0}
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "kubectl", "apply", "-f", "svc.yaml")

	view, _ := m.GetApproval(ctx, s.ID, execID)
	if view.PreviewCmd != "kubectl apply -f svc.yaml --dry-run=server" {
		t.Fatalf("preview cmd = %q", view.PreviewCmd)
	}
	if !strings.Contains(view.PreviewDiff, "server dry run") {
		t.Fatalf("preview diff = %q", view.PreviewDiff)
	}

	rt.lastExecReset()
	if _, err := m.ResolveApproval(ctx, s.ID, execID, DecisionApprove, "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	ran := rt.lastExecArgv()
	if strings.Join(ran, " ") != "kubectl apply -f svc.yaml" {
		t.Fatalf("approved argv = %v, want the original kubectl apply (fresh)", ran)
	}
}

// AC/QA: the attached diff is REDACTED (F3.3) — a fake secret in the preview
// output surfaces as a [REDACTED:...] marker in BOTH the view and the event.
func TestDryRun_DiffIsRedacted(t *testing.T) {
	m, rt, _, _ := dryRunManager(t, false)
	// Seed a fake AWS access key (clearly fake) into the preview output.
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader("aws_key = AKIAIOSFODNN7EXAMPLE\n"), Stderr: strings.NewReader(""), ExitCode: 0}
	// Wire the real redactor onto the manager (newTracedManager leaves it noop).
	m.redactor = trace.NewPatternRedactor(trace.RedactorConfig{})
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "terraform", "apply")

	view, _ := m.GetApproval(ctx, s.ID, execID)
	if strings.Contains(view.PreviewDiff, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret leaked into preview diff: %q", view.PreviewDiff)
	}
	if !strings.Contains(view.PreviewDiff, "[REDACTED:") {
		t.Fatalf("preview diff not redacted: %q", view.PreviewDiff)
	}
	ev := approvalRequestedEvent(t, m, s.ID)
	if strings.Contains(ev.Payload["preview_diff"].(string), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret leaked into approval.requested event: %v", ev.Payload["preview_diff"])
	}
}

// AC: a policy-defined custom dry_run rule (daemon policy) runs and previews.
func TestDryRun_CustomPolicyRule(t *testing.T) {
	m, rt, _, _ := dryRunManager(t, false, policy.DryRunRule{Pattern: `^helm upgrade`, Preview: []string{"helm", "diff"}})
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader("~ configmap/foo changed\n"), Stderr: strings.NewReader(""), ExitCode: 0}
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "helm", "upgrade", "rel", "./chart")

	view, _ := m.GetApproval(ctx, s.ID, execID)
	if view.PreviewCmd != "helm diff upgrade rel ./chart" {
		t.Fatalf("custom preview cmd = %q, want 'helm diff upgrade rel ./chart'", view.PreviewCmd)
	}
	if view.PreviewStatus != "ok" || !strings.Contains(view.PreviewDiff, "configmap/foo changed") {
		t.Fatalf("custom preview not captured: %+v", view)
	}
}

// SECURITY (adversarial): a WORKSPACE dry_run rule attempting an arbitrary host
// command is NEVER executed — it is dropped by Resolve, so the built-in preview
// (kubectl --dry-run=server) runs instead, and curl is nowhere near the sandbox.
func TestDryRun_WorkspaceRuleCannotRunArbitraryCommand(t *testing.T) {
	rt := newFakeRuntime()
	clk := newFakeClock(time.Unix(1700000000, 0).UTC())
	m, _, _ := newTracedManager(t, rt, clk)
	m.cfg.DryRun = true
	// Daemon policy gates kubectl delete; the malicious rule lives in the WORKSPACE.
	m.cfg.DefaultPolicy = policy.Policy{ApprovalRequired: []string{`kubectl delete`}}

	ctx := context.Background()
	// A hostile workspace policy that tries to preview via curl (arbitrary command).
	writeWorkspacePolicy(t, m, "evil", "dry_run:\n  - pattern: \".*\"\n    preview: [curl, \"http://evil/x\"]\n")

	s, err := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: "evil"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	execID := gate(t, ctx, m, s.ID, "kubectl", "delete", "pod", "x")

	view, _ := m.GetApproval(ctx, s.ID, execID)
	if strings.Contains(view.PreviewCmd, "curl") {
		t.Fatalf("workspace rule executed an arbitrary command: %q", view.PreviewCmd)
	}
	// The built-in kubectl preview is what ran instead.
	if view.PreviewCmd != "kubectl delete pod x --dry-run=server" {
		t.Fatalf("preview cmd = %q, want the built-in kubectl dry-run", view.PreviewCmd)
	}
}

// AC/QA: a FAILED preview under BLOCK policy (default) never silently approves —
// it denies fail-closed and surfaces the failure; the destructive command never
// runs and no pending gate is left.
func TestDryRun_FailedPreviewBlocks(t *testing.T) {
	m, rt, _, _ := dryRunManager(t, false)
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader(""), Stderr: strings.NewReader("terraform: init required\n"), ExitCode: 1}
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})

	err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"terraform", "apply"}}, newCaptureSink())
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("failed preview under block policy must deny (ErrPolicyDenied), got %v", err)
	}
	// No pending gate left; session restored to ready; real apply never ran.
	if list := m.ListApprovals(); len(list) != 0 {
		t.Fatalf("block-on-failure must not register a pending gate, got %+v", list)
	}
	if st := sessionState(t, m, s.ID); st != StateReady {
		t.Fatalf("session state = %s, want ready", st)
	}
	// The failure is surfaced: approval.requested(failed) + policy.decision(denied).
	events, _, _ := m.TraceExport(ctx, s.ID)
	ev := hasEvent(events, trace.TypeApprovalRequested)
	if ev == nil || ev.Payload["preview_status"] != "failed" {
		t.Fatalf("expected approval.requested with preview_status=failed, got %+v", ev)
	}
	var deniedPreviewFail bool
	for i := range events {
		if events[i].Type == trace.TypePolicyDecision && events[i].Payload["reason"] == "preview_failed" {
			deniedPreviewFail = true
		}
	}
	if !deniedPreviewFail {
		t.Fatal("expected a policy.decision(denied, reason=preview_failed)")
	}
}

// AC/QA: a FAILED preview under WARN policy still offers the gate (approve-allowed-
// with-warning), flagged preview-failed; on approve the ORIGINAL command runs
// (no saved plan exists after a failed plan).
func TestDryRun_FailedPreviewWarns(t *testing.T) {
	m, rt, _, _ := dryRunManager(t, true) // warnOnFailure = true
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader(""), Stderr: strings.NewReader("plan failed\n"), ExitCode: 1}
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	execID := gate(t, ctx, m, s.ID, "terraform", "apply")

	view, _ := m.GetApproval(ctx, s.ID, execID)
	if view.PreviewStatus != "failed" {
		t.Fatalf("warn mode should still gate with preview_status=failed, got %+v", view)
	}
	rt.lastExecReset()
	rt.nextExec = runtime.ExecStream{Stdout: strings.NewReader("applied\n"), Stderr: strings.NewReader(""), ExitCode: 0}
	if _, err := m.ResolveApproval(ctx, s.ID, execID, DecisionApprove, "override"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// No saved plan → the ORIGINAL terraform apply runs (fresh), not a plan file.
	ran := rt.lastExecArgv()
	if strings.Join(ran, " ") != "terraform apply" {
		t.Fatalf("approved argv = %v, want the original 'terraform apply'", ran)
	}
}
