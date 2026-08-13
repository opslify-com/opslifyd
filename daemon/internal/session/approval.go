package session

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
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
	RequestedAt time.Time      `json:"requested_at"`
	Ran         bool           `json:"ran,omitempty"`
	Stdout      string         `json:"stdout,omitempty"`
	Stderr      string         `json:"stderr,omitempty"`
	ExitCode    *int           `json:"exit_code,omitempty"`
}

// view snapshots the approval under its lock.
func (a *approval) view() ApprovalView {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := ApprovalView{
		SessionID:   a.sessionID,
		ExecID:      a.execID,
		Status:      a.status,
		Rule:        a.rule,
		Reason:      a.reason,
		ArgvSummary: a.argvSummary,
		Comment:     a.comment,
		DenyReason:  a.denyReason,
		RequestedAt: a.requestedAt,
		Ran:         a.ran,
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
func (m *Manager) registerApproval(ctx context.Context, sessionID string, opts ExecOptions, rec *trace.Recorder, policyHash string, decision policy.Decision) error {
	execID, err := newID()
	if err != nil {
		return err
	}
	now := m.clock.Now()
	summary := strings.Join(opts.Argv, " ")
	a := &approval{
		sessionID:   sessionID,
		execID:      execID,
		argv:        append([]string(nil), opts.Argv...),
		cwd:         opts.Cwd,
		env:         append([]string(nil), opts.Env...),
		argvSummary: summary,
		rule:        decision.Rule,
		reason:      decision.Reason,
		policyHash:  policyHash,
		requestedAt: now,
		deadline:    now.Add(m.cfg.ApprovalTTL),
		rec:         rec,
		status:      ApprovalPending,
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
	// like every other event: it flows through the session Recorder.
	_ = rec.Emit(ctx, trace.TypeApprovalRequested, map[string]any{
		"exec_id":      execID,
		"argv_summary": summary,
		"rule":         decision.Rule,
		"reason":       decision.Reason,
	})

	return &ApprovalPendingError{
		SessionID:   sessionID,
		ExecID:      execID,
		Rule:        decision.Rule,
		Reason:      decision.Reason,
		ArgvSummary: summary,
	}
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
