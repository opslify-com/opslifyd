package session

import (
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// State is a point on the session lifecycle state machine
// (F1.2: creating → ready → (execing) → ended).
type State string

const (
	// StateCreating is the transient state while the sandbox is being realised.
	StateCreating State = "creating"
	// StateReady means the sandbox exists and can accept mediated execs.
	StateReady State = "ready"
	// StateExecing means a mediated exec is in flight. It is a sub-state of
	// ready: the session returns to ready when the exec completes.
	StateExecing State = "execing"
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
	ID       string
	Mode     Mode
	Tier     runtime.Tier
	Location runtime.Location
	State    State

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
		ID:           s.ID,
		Mode:         s.Mode,
		Tier:         string(s.Tier),
		State:        s.State,
		AgeSeconds:   int64(now.Sub(s.Created).Seconds()),
		TTLRemaining: remaining,
	}
}
