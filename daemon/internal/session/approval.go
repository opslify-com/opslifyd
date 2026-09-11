package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// DefaultApprovalTTL is how long a pending human-approval gate waits before it is
// FAIL-CLOSED auto-denied with reason "timeout" (F4.3). Applied when
// ManagerConfig.ApprovalTTL is left zero.
const DefaultApprovalTTL = 10 * time.Minute

// ApprovalStatus is the lifecycle of a pending approval.
type ApprovalStatus string

const (
	// ApprovalPending is the initial state: the exec is paused, not spawned, and a
	// human has neither approved nor denied it (and it has not timed out).
	ApprovalPending ApprovalStatus = "pending"
	// ApprovalApproved means a human approved the gate; the command has run (or is
	// running) and its output is captured for the agent to poll.
	ApprovalApproved ApprovalStatus = "approved"
	// ApprovalDenied means the gate was denied — by a human, by timeout, or by a
	// fail-closed session-end. The command never ran.
	ApprovalDenied ApprovalStatus = "denied"
)

// ApprovalDecision is the operator's resolution of a pending gate.
type ApprovalDecision string

const (
	// DecisionApprove lets the paused command run.
	DecisionApprove ApprovalDecision = "approve"
	// DecisionDeny refuses the paused command.
	DecisionDeny ApprovalDecision = "deny"
)

// Approval-related sentinel errors. Each names a distinct, legible failure so the
// HTTP surface maps it to the right status and the agent/operator gets an
// actionable, non-secret reason.
var (
	// ErrApprovalNotFound is an unknown (session, exec_id) pair.
	ErrApprovalNotFound = errors.New("session: approval not found")
	// ErrApprovalResolved is a resolve/deny attempt on an already-resolved gate
	// (approve+deny race, double-apply, or a LATE approval after timeout). It is the
	// no-resurrection guard: a timed-out or session-ended gate can never be revived.
	ErrApprovalResolved = errors.New("session: approval already resolved")
	// ErrApprovalInvalidDecision is a decision other than approve|deny.
	ErrApprovalInvalidDecision = errors.New("session: approval decision must be approve or deny")
)

// ApprovalPendingError is returned by Manager.Exec when a command matches an
// approval gate. It is NOT a failure — it is the typed, non-blocking pause signal:
// the exec did not spawn, the caller (HTTP → MCP/CLI) surfaces a structured
// `pending` status carrying ExecID, and the human resolves it out-of-band. Because
// Exec returns this promptly (it never waits on a human), the MCP agent is never
// hung — the core F4.3 non-hang contract.
type ApprovalPendingError struct {
	SessionID   string
	ExecID      string
	Rule        string
	Reason      string
	ArgvSummary string
}

func (e *ApprovalPendingError) Error() string {
	return fmt.Sprintf("session: command requires human approval [rule %s] (exec_id %s)", e.Rule, e.ExecID)
}

// approval is the internal pending-gate record. Its own mutex guards the fields
// mutated across the register → resolve/expire/cancel → run lifecycle; the Manager
// serializes the status TRANSITION (pending → approved/denied) under apprMu so a
// gate resolves exactly once (approve+deny/timeout race is deterministic, no
// double-spawn).
type approval struct {
	mu sync.Mutex

	sessionID   string
	execID      string
	argv        []string
	cwd         string
	env         []string
	argvSummary string
	rule        string
	reason      string
	policyHash  string
	requestedAt time.Time
	deadline    time.Time
	rec         *trace.Recorder

	// F4.4 dry-run preview attached to the gate (all redacted before storage).
	previewCmd    string // the preview command that ran (argv joined), "" if none
	previewDiff   string // the captured, REDACTED preview output shown beside the prompt
	previewStatus string // "none" | "ok" | "failed" (warn mode)

	// F4.4 saved-plan integrity (terraform GuaranteeSavedPlan only). The saved plan
	// lives in the agent-writable /workspace, so we pin its SHA-256 (read
	// daemon-side, not in-container) at preview time and re-verify it immediately
	// before the approved apply — a tampered plan fails closed. planRelPath is the
	// workspace-relative path; planHash is empty for kubectl/custom (fresh-apply).
	planRelPath string
	planHash    string

	status     ApprovalStatus
	comment    string
	denyReason string // "timeout" | "session_end" | "operator" (deny) — empty for approve

	// Result of the approved run, captured for the agent to poll.
	ran      bool
	stdout   string
	stderr   string
	exitCode int
	runErr   string
}

// ApprovalView is the exported, JSON-facing projection of an approval — the shape
// the poll/list/resolve API returns. It carries no secrets beyond the (redacted at
// emit) argv summary and comment.
type ApprovalView struct {
	SessionID   string         `json:"session_id"`
	ExecID      string         `json:"exec_id"`
	Status      ApprovalStatus `json:"status"`
	Rule        string         `json:"rule,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	ArgvSummary string         `json:"argv_summary,omitempty"`
	Comment     string         `json:"comment,omitempty"`
	DenyReason  string         `json:"deny_reason,omitempty"`
	// F4.4 dry-run preview (redacted). PreviewCmd/PreviewDiff/PreviewStatus let the
	// F3.5 UI render the diff beside approve/deny.
	PreviewCmd    string    `json:"preview_cmd,omitempty"`
	PreviewDiff   string    `json:"preview_diff,omitempty"`
	PreviewStatus string    `json:"preview_status,omitempty"`
	RequestedAt   time.Time `json:"requested_at"`
	Ran           bool      `json:"ran,omitempty"`
	Stdout        string    `json:"stdout,omitempty"`
	Stderr        string    `json:"stderr,omitempty"`
	ExitCode      *int      `json:"exit_code,omitempty"`
	RunErr        string    `json:"run_err,omitempty"` // why an approved run failed (e.g. tamper detected)
}

// view snapshots the approval under its lock.
func (a *approval) view() ApprovalView {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := ApprovalView{
		SessionID:     a.sessionID,
		ExecID:        a.execID,
		Status:        a.status,
		Rule:          a.rule,
		Reason:        a.reason,
		ArgvSummary:   a.argvSummary,
		Comment:       a.comment,
		DenyReason:    a.denyReason,
		PreviewCmd:    a.previewCmd,
		PreviewDiff:   a.previewDiff,
		PreviewStatus: a.previewStatus,
		RequestedAt:   a.requestedAt,
		Ran:           a.ran,
		RunErr:        a.runErr,
	}
	if a.ran {
		v.Stdout = a.stdout
		v.Stderr = a.stderr
		code := a.exitCode
		v.ExitCode = &code
	}
	return v
}

// approvalKey is the registry key: a session-scoped exec id.
func approvalKey(sessionID, execID string) string { return sessionID + "/" + execID }

// registerApproval creates a pending gate for a command classified needs_approval,
// pauses the session (awaiting_approval), emits approval.requested (pushed to the
// F3.5 UI over the F3.2 SSE stream), and returns the typed, non-blocking
// ApprovalPendingError. The process is NOT spawned. Called from Exec with the
// session already transitioned to execing; this moves it to awaiting_approval.
func (m *Manager) registerApproval(ctx context.Context, sessionID string, opts ExecOptions, rec *trace.Recorder, policyHash string, decision policy.Decision, rt runtime.Runtime, handle runtime.ContainerHandle, resolved policy.Resolved) error {
	execID, err := newID()
	if err != nil {
		return err
	}
	now := m.clock.Now()
	summary := strings.Join(opts.Argv, " ")

	// F4.4 DRY-RUN PREVIEW. Before the gate is registered, rewrite the command into
	// a preview and run it IN-SANDBOX (same session/container/creds — never on the
	// host) so the human approves with the actual diff in front of them. On success
	// the approved run may differ from the original (terraform replays the SAVED
	// plan). A FAILED preview never silently approves: policy decides block vs warn.
	argvToRun := append([]string(nil), opts.Argv...)
	previewCmd, previewDiff, previewStatus := "", "", "none"
	planRelPath, planHash := "", ""
	if m.cfg.DryRun {
		// Per-exec saved-plan path under /workspace (the one writable mount): it
		// survives from the terraform-plan preview to the terraform-apply on approve
		// in the SAME container, so what runs equals what was reviewed.
		planPath := "/workspace/.opslify-plan-" + execID + ".tfplan"
		pv := policy.RewriteForDryRun(opts.Argv, resolved.DryRun, planPath)
		if pv.Matched {
			previewCmd = strings.Join(pv.PreviewArgv, " ")
			diff, ok := m.runPreview(ctx, sessionID, rt, handle, rec, opts, pv.PreviewArgv)
			previewDiff = m.redactString(diff)
			if ok {
				previewStatus = "ok"
				argvToRun = pv.ApprovedArgv // e.g. terraform apply <saved-plan>
				// Saved-plan integrity: pin the plan's hash (read daemon-side from the
				// host workspace, NOT via an in-container command the agent controls)
				// so a tamper between review and apply is detected. If we can't read
				// the plan we just wrote, the guarantee is void → fail closed (block).
				if pv.Guarantee == policy.GuaranteeSavedPlan {
					rel := ".opslify-plan-" + execID + ".tfplan"
					b, rerr := m.ReadFile(ctx, sessionID, rel)
					if rerr != nil {
						return m.blockOnPreviewFailure(ctx, sessionID, rec, decision, policyHash, summary, previewCmd,
							m.redactString("saved plan unreadable after preview: "+rerr.Error()))
					}
					sum := sha256.Sum256(b)
					planRelPath = rel
					planHash = hex.EncodeToString(sum[:])
				}
			} else if resolved.DryRunWarnOnFailure {
				// WARN: still offer the gate, flagged preview-failed. The saved plan
				// does not exist, so approve runs the ORIGINAL command (fresh).
				previewStatus = "failed"
			} else {
				// BLOCK (fail-closed default): a preview that could not run denies the
				// command. Surface the failure (approval.requested + policy.decision)
				// so the UI/agent see WHY, then refuse — never a silent approve.
				return m.blockOnPreviewFailure(ctx, sessionID, rec, decision, policyHash, summary, previewCmd, previewDiff)
			}
		}
	}

	a := &approval{
		sessionID:     sessionID,
		execID:        execID,
		argv:          argvToRun,
		cwd:           opts.Cwd,
		env:           append([]string(nil), opts.Env...),
		argvSummary:   summary,
		rule:          decision.Rule,
		reason:        decision.Reason,
		policyHash:    policyHash,
		requestedAt:   now,
		deadline:      now.Add(m.cfg.ApprovalTTL),
		rec:           rec,
		previewCmd:    previewCmd,
		previewDiff:   previewDiff,
		previewStatus: previewStatus,
		planRelPath:   planRelPath,
		planHash:      planHash,
		status:        ApprovalPending,
	}

	m.apprMu.Lock()
	m.approvals[approvalKey(sessionID, execID)] = a
	m.apprMu.Unlock()

	// Pause the session: execing → awaiting_approval. The Exec defer only restores
	// an execing session, so leaving it awaiting_approval is safe.
	m.mu.Lock()
	if s, ok := m.sessions[sessionID]; ok && s.State == StateExecing {
		s.State = StateAwaitingApproval
	}
	m.mu.Unlock()

	// approval.requested → SSE → F3.5 live prompt. Redacted (F3.3) + chained (F3.1)
	// like every other event: it flows through the session Recorder. The preview_*
	// fields carry the diff shown beside approve/deny (the diff is already redacted;
	// the recorder redacts the whole payload again — idempotent on a redacted diff).
	// F8.6: every gated exec produces a reviewable Change. It is recorded AFTER the
	// gate is registered and the session paused, so a failure here can never leave
	// a command running that should have been gated — the gate is the safety
	// control, the Change is the review surface over it.
	//
	// The plan pinned is argvToRun, not opts.Argv: after an F4.4 dry-run rewrite
	// those differ, and pinning the original would pin something that never runs.
	m.mu.Lock()
	sess := m.sessions[sessionID]
	m.mu.Unlock()
	changeID := m.recordGatedChange(sess, execID, opts, argvToRun, decision, previewDiff,
		blastForExec(argvToRun), inverseForExec(argvToRun))

	_ = rec.Emit(ctx, trace.TypeApprovalRequested, map[string]any{
		"exec_id":        execID,
		"argv_summary":   summary,
		"rule":           decision.Rule,
		"reason":         decision.Reason,
		"preview_cmd":    previewCmd,
		"preview_diff":   previewDiff,
		"preview_status": previewStatus,
		// Links the gate to the Change a human reviews it through. Empty when no
		// Change recorder is wired, which keeps the field's absence meaningful
		// rather than making it look like a lost record.
		"change_id": changeID,
	})

	return &ApprovalPendingError{
		SessionID:   sessionID,
		ExecID:      execID,
		Rule:        decision.Rule,
		Reason:      decision.Reason,
		ArgvSummary: summary,
	}
}

// runPreview runs a dry-run preview command IN-SANDBOX via runExec (the same
// Runtime.Exec seam, container, and creds the real command would use — no host
// execution, no capability widening) and returns the captured (still-raw) diff
// plus whether the preview succeeded (spawned cleanly AND exited 0). Its exec.*
// output is redacted+chained by the session Recorder like any other exec.
func (m *Manager) runPreview(ctx context.Context, sessionID string, rt runtime.Runtime, handle runtime.ContainerHandle, rec *trace.Recorder, opts ExecOptions, previewArgv []string) (string, bool) {
	sink := newBufferSink(m.cfg.OutputCap)
	prevOpts := ExecOptions{Argv: previewArgv, Cwd: opts.Cwd, Env: append([]string(nil), opts.Env...)}
	runErr := m.runExec(ctx, sessionID, rt, handle, rec, prevOpts, sink)
	diff := sink.stdoutString()
	if e := sink.stderrString(); e != "" {
		if diff != "" {
			diff += "\n"
		}
		diff += e
	}
	ok := runErr == nil && sink.exit() == 0
	return diff, ok
}

// blockOnPreviewFailure is the fail-closed path when a preview command fails and
// policy does NOT warn: it emits approval.requested (so the UI still shows the
// failed preview) and a chained policy.decision(denied, reason=preview_failed),
// registers NO pending gate, and returns a typed policy denial. The session is
// left execing so Exec's defer restores it to ready.
func (m *Manager) blockOnPreviewFailure(ctx context.Context, sessionID string, rec *trace.Recorder, decision policy.Decision, policyHash, summary, previewCmd, previewDiff string) error {
	_ = rec.Emit(ctx, trace.TypeApprovalRequested, map[string]any{
		"argv_summary":   summary,
		"rule":           decision.Rule,
		"reason":         decision.Reason,
		"preview_cmd":    previewCmd,
		"preview_diff":   previewDiff,
		"preview_status": "failed",
	})
	_ = rec.Emit(ctx, trace.TypePolicyDecision, map[string]any{
		"decision":     "denied",
		"rule":         decision.Rule,
		"argv_summary": summary,
		"reason":       "preview_failed",
		"policy_hash":  policyHash,
	})
	return fmt.Errorf("%w: dry-run preview failed and policy blocks on preview failure (fail-closed) [rule %s]", ErrPolicyDenied, decision.Rule)
}

// redactString runs the F3.3 redactor over a single diff string so the stored
// approval view AND the emitted event carry identical, redacted content (a plan
// diff can echo vars/secrets). It reuses the payload-map redactor on a one-key map.
func (m *Manager) redactString(s string) string {
	if s == "" {
		return s
	}
	out := m.redactor.Redact(trace.TypeApprovalRequested, map[string]any{"diff": s})
	if v, ok := out["diff"].(string); ok {
		return v
	}
	return "[REDACTED:error]"
}

// GetApproval returns the current state of a gate (the poll path the MCP agent
// re-calls to learn approved+output / denied+reason / still-pending).
func (m *Manager) GetApproval(_ context.Context, sessionID, execID string) (ApprovalView, error) {
	m.apprMu.Lock()
	a, ok := m.approvals[approvalKey(sessionID, execID)]
	m.apprMu.Unlock()
	if !ok {
		return ApprovalView{}, fmt.Errorf("%w: %s/%s", ErrApprovalNotFound, sessionID, execID)
	}
	return a.view(), nil
}

// ListApprovals returns every PENDING gate across sessions (the data behind
// `opslify approvals`), stably ordered by requested time then exec id.
func (m *Manager) ListApprovals() []ApprovalView {
	m.apprMu.Lock()
	views := make([]ApprovalView, 0, len(m.approvals))
	for _, a := range m.approvals {
		v := a.view()
		if v.Status == ApprovalPending {
			views = append(views, v)
		}
	}
	m.apprMu.Unlock()
	sort.Slice(views, func(i, j int) bool {
		if views[i].RequestedAt.Equal(views[j].RequestedAt) {
			return views[i].ExecID < views[j].ExecID
		}
		return views[i].RequestedAt.Before(views[j].RequestedAt)
	})
	return views
}

// claimPending atomically transitions a pending gate to a resolved status under
// apprMu (the single serialization point that makes approve+deny/timeout resolve
// exactly once). It returns the record on success, or ErrApprovalResolved /
// ErrApprovalNotFound. On success the record's status/comment/denyReason are
// already set; the caller performs any side effects (run / trace) OUTSIDE apprMu.
func (m *Manager) claimPending(sessionID, execID string, to ApprovalStatus, comment, denyReason string) (*approval, error) {
	m.apprMu.Lock()
	defer m.apprMu.Unlock()
	a, ok := m.approvals[approvalKey(sessionID, execID)]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrApprovalNotFound, sessionID, execID)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.status != ApprovalPending {
		return nil, fmt.Errorf("%w: %s/%s is %s", ErrApprovalResolved, sessionID, execID, a.status)
	}
	a.status = to
	a.comment = comment
	a.denyReason = denyReason
	return a, nil
}

// ResolveApproval is the HUMAN control-plane action behind
// POST /v1/sessions/{id}/approvals/{exec_id} and `opslify approve|deny`. It is the
// ONLY path that can approve a gate — it is never reachable from inside the sandbox
// or an agent-controlled MCP tool, so the agent cannot self-approve. approve → the
// command runs (real spawn) and its output is captured for the agent to poll; deny
// → a structured denial. Either resolution emits a chained+redacted policy.decision
// carrying the approver comment. Resolving an already-resolved gate is a no-op
// error (idempotent; no double-spawn).
func (m *Manager) ResolveApproval(ctx context.Context, sessionID, execID string, decision ApprovalDecision, comment string) (ApprovalView, error) {
	switch decision {
	case DecisionApprove:
		a, err := m.claimPending(sessionID, execID, ApprovalApproved, comment, "")
		if err != nil {
			return ApprovalView{}, err
		}
		m.emitResolution(ctx, a, "approved")
		m.runApproved(ctx, a)
		return a.view(), nil
	case DecisionDeny:
		a, err := m.claimPending(sessionID, execID, ApprovalDenied, comment, "operator")
		if err != nil {
			return ApprovalView{}, err
		}
		m.emitResolution(ctx, a, "denied")
		m.restoreReady(sessionID)
		return a.view(), nil
	default:
		return ApprovalView{}, fmt.Errorf("%w: %q", ErrApprovalInvalidDecision, decision)
	}
}

// runApproved spawns the approved command and captures its output on the record so
// the agent can poll it. The session is transitioned awaiting_approval → execing →
// ready around the run. If the session has meanwhile ended, the run is skipped and
// runErr records why (fail-closed: no spawn against a gone session, no leak).
func (m *Manager) runApproved(ctx context.Context, a *approval) {
	m.mu.Lock()
	s, ok := m.sessions[a.sessionID]
	if !ok || (s.State != StateAwaitingApproval && s.State != StateReady) {
		m.mu.Unlock()
		a.mu.Lock()
		a.runErr = "session ended before approval could run"
		a.exitCode = -1
		a.ran = true
		a.mu.Unlock()
		return
	}
	rt, err := m.resolve(s.Tier, s.Location)
	if err != nil {
		m.mu.Unlock()
		a.mu.Lock()
		a.runErr = err.Error()
		a.exitCode = -1
		a.ran = true
		a.mu.Unlock()
		return
	}
	s.State = StateExecing
	handle := s.Handle
	rec := s.rec
	m.mu.Unlock()

	// Saved-plan integrity check (F4.4): the approved run replays a plan file in the
	// agent-writable /workspace. Re-hash it daemon-side immediately before apply and
	// compare to the value pinned at preview; a mismatch (or a now-unreadable plan)
	// means the agent altered what the human reviewed → fail closed, do NOT apply.
	// (Residual: a sub-exec race between this read and terraform's own read of the
	// file remains — see the read-only-plan-mount note in the F4.4 spec.)
	if a.planHash != "" {
		b, rerr := m.ReadFile(ctx, a.sessionID, a.planRelPath)
		if rerr != nil || fmt.Sprintf("%x", sha256.Sum256(b)) != a.planHash {
			m.mu.Lock()
			if s, ok := m.sessions[a.sessionID]; ok && s.State == StateExecing {
				s.State = StateReady
			}
			m.mu.Unlock()
			_ = rec.Emit(ctx, trace.TypePolicyDecision, map[string]any{
				"decision": "denied", "rule": a.rule, "reason": "plan_tampered",
				"exec_id": a.execID, "policy_hash": a.policyHash,
			})
			a.mu.Lock()
			a.runErr = "saved plan changed after review (tamper detected); apply refused"
			a.exitCode = -1
			a.ran = true
			a.mu.Unlock()
			return
		}
	}

	sink := newBufferSink(m.cfg.OutputCap)
	opts := ExecOptions{Argv: a.argv, Cwd: a.cwd, Env: a.env}
	runErr := m.runExec(ctx, a.sessionID, rt, handle, rec, opts, sink)

	m.mu.Lock()
	if cur, ok := m.sessions[a.sessionID]; ok && cur.State == StateExecing {
		cur.State = StateReady
		cur.LastActivity = m.clock.Now()
	}
	m.mu.Unlock()

	a.mu.Lock()
	a.ran = true
	a.stdout = sink.stdoutString()
	a.stderr = sink.stderrString()
	a.exitCode = sink.exit()
	if runErr != nil {
		a.runErr = runErr.Error()
	}
	a.mu.Unlock()
}

// ExpireApprovals FAIL-CLOSED auto-denies every pending gate whose deadline has
// passed as of now, with reason "timeout". Called on each reaper tick and directly
// by tests (deterministic via the injected clock — no sleeping). A late approval
// after this can never resurrect the gate (claimPending sees it resolved). Returns
// the exec ids expired.
func (m *Manager) ExpireApprovals(ctx context.Context, now time.Time) []string {
	m.apprMu.Lock()
	var due []*approval
	for _, a := range m.approvals {
		a.mu.Lock()
		expired := a.status == ApprovalPending && !now.Before(a.deadline)
		a.mu.Unlock()
		if expired {
			due = append(due, a)
		}
	}
	m.apprMu.Unlock()

	var expired []string
	for _, a := range due {
		res, err := m.claimPending(a.sessionID, a.execID, ApprovalDenied, "", "timeout")
		if err != nil {
			continue // resolved by a racing approve/deny meanwhile — leave it
		}
		m.emitResolution(ctx, res, "denied")
		m.restoreReady(res.sessionID)
		expired = append(expired, a.execID)
	}
	return expired
}

// cancelSessionApprovals auto-denies every pending gate belonging to an ending
// session (fail-closed: session end / shutdown / reconcile never auto-approves),
// emits its policy.decision(denied, session_end) into the still-open chain via the
// session Recorder, and drops ALL of the session's approval records so no pending
// state leaks. Called from teardown before session.end.
func (m *Manager) cancelSessionApprovals(ctx context.Context, s *Session, reason string) {
	m.apprMu.Lock()
	var owned []*approval
	for k, a := range m.approvals {
		if a.sessionID == s.ID {
			owned = append(owned, a)
			delete(m.approvals, k)
		}
	}
	m.apprMu.Unlock()

	for _, a := range owned {
		a.mu.Lock()
		pending := a.status == ApprovalPending
		if pending {
			a.status = ApprovalDenied
			a.denyReason = reason
		}
		a.mu.Unlock()
		if pending {
			// Use the session's live recorder so the denial chains into THIS session's
			// trace before it is sealed. a.rec is the same recorder.
			m.emitResolution(ctx, a, "denied")
		}
	}
}

// restoreReady returns a paused session to ready after a deny/timeout (the exec
// never ran). A no-op if the session is gone or not awaiting approval.
func (m *Manager) restoreReady(sessionID string) {
	m.mu.Lock()
	if s, ok := m.sessions[sessionID]; ok && s.State == StateAwaitingApproval {
		s.State = StateReady
		s.LastActivity = m.clock.Now()
	}
	m.mu.Unlock()
}

// emitResolution records the resolution as a chained+redacted policy.decision
// carrying the approver comment and policy_hash — the auditable trail for every
// approve/deny/timeout. verdict is "approved" or "denied".
func (m *Manager) emitResolution(ctx context.Context, a *approval, verdict string) {
	a.mu.Lock()
	payload := map[string]any{
		"decision":     verdict,
		"rule":         a.rule,
		"argv_summary": a.argvSummary,
		"comment":      a.comment,
		"policy_hash":  a.policyHash,
		"exec_id":      a.execID,
	}
	if a.denyReason != "" {
		payload["reason"] = a.denyReason
	}
	rec := a.rec
	a.mu.Unlock()
	_ = rec.Emit(ctx, trace.TypePolicyDecision, payload)
}

// bufferSink is an ExecSink that aggregates the approved command's output under a
// per-stream cap (so a hostile flood cannot OOM the daemon), for the agent to poll.
type bufferSink struct {
	mu             sync.Mutex
	cap            int
	stdout, stderr []byte
	stdoutOmit     int
	stderrOmit     int
	trunc          map[string]bool
	code           int
	codeSet        bool
}

func newBufferSink(cap int) *bufferSink {
	if cap <= 0 {
		cap = DefaultOutputCap
	}
	return &bufferSink{cap: cap, trunc: map[string]bool{}, code: -1}
}

func (b *bufferSink) Chunk(stream string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if stream == StreamStderr {
		b.stderr, b.stderrOmit = appendCapped(b.stderr, b.stderrOmit, data, b.cap)
	} else {
		b.stdout, b.stdoutOmit = appendCapped(b.stdout, b.stdoutOmit, data, b.cap)
	}
	return nil
}

func (b *bufferSink) Truncated(stream string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.trunc[stream] = true
	return nil
}

func (b *bufferSink) Exit(code int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.code = code
	b.codeSet = true
	return nil
}

func (b *bufferSink) stdoutString() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return cappedString(b.stdout, b.stdoutOmit, b.trunc[StreamStdout])
}

func (b *bufferSink) stderrString() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return cappedString(b.stderr, b.stderrOmit, b.trunc[StreamStderr])
}

func (b *bufferSink) exit() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.code
}

func appendCapped(buf []byte, omitted int, data []byte, cap int) ([]byte, int) {
	room := cap - len(buf)
	if room <= 0 {
		return buf, omitted + len(data)
	}
	if len(data) <= room {
		return append(buf, data...), omitted
	}
	return append(buf, data[:room]...), omitted + (len(data) - room)
}

func cappedString(buf []byte, omitted int, truncated bool) string {
	s := string(buf)
	if omitted > 0 {
		s += fmt.Sprintf("\n[truncated: %d bytes omitted]", omitted)
	} else if truncated {
		s += "\n[output truncated at cap]"
	}
	return s
}

// compile-time assertion that bufferSink satisfies ExecSink.
var _ ExecSink = (*bufferSink)(nil)
