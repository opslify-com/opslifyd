package session

import (
	"time"

	"github.com/opslify-com/opslifyd/internal/agentcontext"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// State is a point on the session lifecycle state machine
// (F1.2: creating → ready → (execing) → ended).
type State string

const (
	// StateCreating is the transient state while the sandbox is being realised.
	StateCreating State = "creating"
	// StateReady means the sandbox exists and can accept mediated execs.
	StateReady State = "ready"
	// StateWarm is a pre-created, paused sandbox held in the warm pool (F1.3),
	// not yet claimed by any caller. It is identical in hardening + toolchain
	// digest to a ready session; a claim thaws it and transitions it to ready.
	// Warm sessions are never in the Manager's live map and never appear in List.
	StateWarm State = "warm"
	// StateExecing means a mediated exec is in flight. It is a sub-state of
	// ready: the session returns to ready when the exec completes.
	StateExecing State = "execing"
	// StateAwaitingApproval means a mediated exec matched an approval gate (F4.3):
	// the process is NOT spawned and the session is paused pending a human
	// approve/deny (or a fail-closed timeout auto-deny). Like execing it is a
	// sub-state of ready — the session returns to ready when the approval resolves.
	// The reaper does not TTL-reap a session in this state; the approval's own TTL
	// resolves the pause first.
	StateAwaitingApproval State = "awaiting_approval"
	// StateEnded is terminal: the sandbox has been destroyed (by DELETE, TTL
	// reaper, or orphan reconciliation). An ended session accepts no execs.
	StateEnded State = "ended"
)

// Mode selects the workspace disposition of a session.
type Mode string

const (
	// ModeScratch is an ephemeral session: its /workspace is discarded on
	// destroy. The default.
	ModeScratch Mode = "scratch"
	// ModeWorkspace keeps /workspace on destroy (snapshot is a later hook).
	ModeWorkspace Mode = "workspace"
)

// Session is the daemon-owned record of one sandbox. It holds only non-secret
// data: enough to drive the lifecycle, stream execs, account TTL, and — crucially
// — reap the underlying container after a daemon restart (persisted via record).
//
// All mutable fields are guarded by the owning Manager's mutex; Session carries
// no lock of its own so the Manager can reason about state transitions and the
// reaper atomically.
type Session struct {
	ID   string
	Mode Mode
	// Name is the workspace name (workspace mode only; empty for scratch). It
	// keys the snapshot committed on end and resumed on the next create.
	Name     string
	Tier     runtime.Tier
	Location runtime.Location
	State    State

	// ProjectID / EnvironmentID are the F8.1 scope this session was created in.
	// A session is ALWAYS in exactly one environment (a create that names none
	// lands in the default scope), so both are non-empty for every live session.
	// They are persisted on the record and bound into the session.start trace
	// event, so audit can filter by project/environment without inference.
	ProjectID     string
	EnvironmentID string

	// Handle is the F0.3 container handle used for Exec/Destroy.
	Handle runtime.ContainerHandle
	// WorkspaceDir is the host path bind-mounted read-write at /workspace.
	WorkspaceDir string

	// Created is when the sandbox was realised; TTL is the idle lifetime.
	Created time.Time
	// LastActivity is bumped on every exec; the reaper measures idleness from it
	// (config SessionTTL is documented as the idle lifetime).
	LastActivity time.Time
	// TTL is the idle lifetime after which the reaper destroys the session.
	TTL time.Duration

	// rec is the per-session trace recorder (F3.1). It is created (with the
	// session's chain rooted at session.start) when the session is registered
	// ready, and is nil for orphan sessions reconstructed on restart (which have
	// no in-memory chain) and when tracing is unwired. A nil *trace.Recorder is a
	// valid no-op, so emit sites need no nil check. Set/read under the Manager
	// mutex or after the session is solely owned (teardown).
	// conns is the F8.2 per-session connection state: the closers that tear down
	// what each kind allocated, and the refs those kinds resolve at a boundary
	// (which must therefore never reach the sandbox environment).
	conns *sessionConnections
	// proxyAddr and proxyCAPEM are the bound per-session proxy, recorded so F8.2
	// phase two can point the sandbox at it. Empty when no proxy was built.
	proxyAddr  string
	proxyCAPEM []byte
	// agentName, agentModel and agentLocality are the F8.5 bound agent, recorded
	// in session.start. Empty when no agent is bound — a valid state, since
	// opslify ships no model.
	agentName     string
	agentModel    string
	agentLocality string

	rec *trace.Recorder

	// assembly is the F8.4 layered instruction set this session runs under. It is
	// resolved BEFORE the sandbox is handed out and emitted as context.assemble at
	// seq 1, so a Change can be replayed against the exact rules the agent had.
	// Nil when no assembler is configured.
	assembly *agentcontext.Assembly

	// policyHash is the F4.1 policy_hash of the RESOLVED policy in force for this
	// session (workspace policy narrowed over the daemon default). It is computed
	// in realize (fail-closed: an invalid workspace policy aborts the create) and
	// emitted into the session.start binding so the trace chains to the exact
	// policy. Empty only when policy resolution is unwired.
	policyHash string

	// policy is the F4.1 RESOLVED policy in force for this session — the model the
	// F4.2 exec interceptor classifies every command against (policy.Classify).
	// It is set in realize alongside policyHash from the same resolution, so the
	// classified policy and the hash bound into the trace are always the same
	// policy. Read on the exec hot path under the Manager mutex.
	policy policy.Resolved

	// credEnv is the F5.1 executor-side credential injection: the process-env
	// entries added to EVERY exec in this session for its policy-granted creds. On
	// the AWS blind path it holds ONLY the container-credentials endpoint URI + a
	// per-session bearer token (NEVER a raw durable secret — that is served by the
	// daemon's token-gated endpoint); on the GCP/Azure v1 fallback it holds a
	// short-lived, agent-visible token. Set once at registerReady (under the Manager
	// mutex) and read on the exec hot path under the same mutex.
	credEnv []string

	// egress is the F5.7 per-session credential-blind HTTP egress handle: the live
	// egressproxy.Proxy's listener + its per-session CA. Non-nil only when the
	// resolved policy lit up an egress-inject rule. It is set once at registerReady
	// (single-owner, before the session is visible) and closed on teardown, so the
	// proxy/CA never outlive the session and are never reused across sessions.
	egress *sessionEgress

	// credEndpoint is the F5.8 per-session creds-endpoint listener: the F5.1
	// CredServer served on a bridge-GATEWAY-bound, source-scoped listener the
	// sandbox can reach (in place of the daemon loopback). Non-nil only when the
	// runtime exposed a reachable gateway (NetworkInfo) and at least one AWS blind
	// cred was injected. Set once at registerReady (single-owner) and closed on
	// teardown so the listener never outlives the session.
	credEndpoint *sessionCredEndpoint

	// registry is the F7.5 per-session registry-proxy handle: the live regproxy.Proxy's
	// listener + the ecosystem routing env. Non-nil only when the F5.5 registry proxy
	// is configured. It is set once at registerReady (single-owner, before the session
	// is visible) and closed on teardown, so the proxy never outlives the session and
	// is never reused across sessions.
	registry *sessionRegistry
}

// sessionCredEndpoint is one session's gateway-bound creds-endpoint listener (F5.8).
type sessionCredEndpoint struct {
	// addr is the sandbox-reachable base the AWS endpoint URI was advertised at
	// (gateway host + bound port). Recorded for tracing/tests.
	addr  string
	close func()
}

// deadline is the instant after which an idle session is reaped.
func (s *Session) deadline() time.Time { return s.LastActivity.Add(s.TTL) }

// expired reports whether the session should be reaped at now.
func (s *Session) expired(now time.Time) bool {
	return s.TTL > 0 && !now.Before(s.deadline())
}

// View is the JSON-facing projection of a session for GET /v1/sessions. It
// carries derived age/ttl_remaining (seconds) rather than raw timestamps so the
// wire contract is stable and clock-relative.
type View struct {
	ID           string `json:"session_id"`
	Mode         Mode   `json:"mode"`
	Tier         string `json:"tier"`
	State        State  `json:"state"`
	AgeSeconds   int64  `json:"age_seconds"`
	TTLRemaining int64  `json:"ttl_remaining_seconds"`
	// ProjectID / EnvironmentID are the F8.1 scope (additive fields: an older
	// client ignoring them is unaffected). They make a session listing filterable
	// by project/environment without a join against the trace.
	ProjectID     string `json:"project_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
}

// view renders a Session as of now.
func (s *Session) view(now time.Time) View {
	var remaining int64
	if s.TTL > 0 {
		remaining = int64(s.deadline().Sub(now).Seconds())
		if remaining < 0 {
			remaining = 0
		}
	}
	return View{
		ID:            s.ID,
		Mode:          s.Mode,
		Tier:          string(s.Tier),
		State:         s.State,
		AgeSeconds:    int64(now.Sub(s.Created).Seconds()),
		TTLRemaining:  remaining,
		ProjectID:     s.ProjectID,
		EnvironmentID: s.EnvironmentID,
	}
}
