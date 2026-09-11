// Package change makes a Change the unit of work: the infrastructure equivalent
// of a pull request.
//
// Sessions are a runtime detail — humans do not review sessions. Reviewing,
// approving, auditing, reverting, promoting and agent-to-agent handoff all need
// the SAME bundle of facts, so it is one object rather than five views over a
// trace.
//
// Two properties in here are security controls rather than conveniences, and both
// are enforced structurally:
//
//   - The PINNED PREVIEW. Approval is meaningless if the applied plan can differ
//     from the reviewed one, so the pin is re-verified at apply and a mismatch is
//     refused. It is a TOCTOU window and treated as one.
//   - The HONEST INVERSE. Claiming revertibility that does not exist is worse
//     than admitting the limit, because it changes what an operator is willing to
//     approve. An unavailable inverse must carry a reason; the type will not let
//     you omit it.
package change

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ErrInvalidInput marks a malformed record or an impossible request.
var ErrInvalidInput = errors.New("change: invalid input")

// ErrNotFound is returned for an unknown change id.
var ErrNotFound = errors.New("change: not found")

// ErrPinMismatch is returned when the plan at apply time differs from the plan
// that was previewed and approved.
//
// It is its own error because it is the one failure an operator must never see
// treated as a retryable hiccup: it means the thing they approved is not the
// thing about to run.
var ErrPinMismatch = errors.New("change: the plan changed after it was approved")

// ErrInvalidTransition marks an illegal status move.
var ErrInvalidTransition = errors.New("change: invalid status transition")

// Status is where a Change is in its life.
type Status string

const (
	// StatusProposed: an agent or human has stated an intent.
	StatusProposed Status = "proposed"
	// StatusPreviewed: a plan and diff exist and are hash-pinned.
	StatusPreviewed Status = "previewed"
	// StatusAwaitingApproval: a human gate is open.
	StatusAwaitingApproval Status = "awaiting_approval"
	// StatusApplying: the pinned plan is running.
	StatusApplying Status = "applying"
	// StatusApplied: it ran to completion.
	StatusApplied Status = "applied"
	// StatusDenied: a human refused it. TERMINAL — nothing runs after a deny.
	StatusDenied Status = "denied"
	// StatusFailed: it ran and did not complete.
	StatusFailed Status = "failed"
	// StatusReverted: its prepared inverse was applied.
	StatusReverted Status = "reverted"
	// StatusExpired: the approval gate timed out. TERMINAL, like a deny — an
	// unanswered gate must not become an implicit yes.
	StatusExpired Status = "expired"
)

// transitions is the ONLY legal status graph.
//
// Expressed as data rather than as scattered if-statements so the whole life of a
// Change is readable in one place, and so "can this move?" has exactly one
// answer. Terminal states map to nothing: denied, expired and reverted have no
// outgoing edges at all, which is what makes "nothing runs after a deny"
// structural rather than a rule someone has to remember.
var transitions = map[Status][]Status{
	StatusProposed:         {StatusPreviewed, StatusDenied, StatusExpired, StatusFailed},
	StatusPreviewed:        {StatusAwaitingApproval, StatusApplying, StatusDenied, StatusExpired, StatusFailed},
	StatusAwaitingApproval: {StatusApplying, StatusDenied, StatusExpired},
	StatusApplying:         {StatusApplied, StatusFailed},
	StatusApplied:          {StatusReverted},
	StatusFailed:           {StatusReverted},
	StatusDenied:           nil,
	StatusExpired:          nil,
	StatusReverted:         nil,
}

// Terminal reports whether a status has no outgoing transitions.
func (s Status) Terminal() bool {
	next, known := transitions[s]
	return known && len(next) == 0
}

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	_, known := transitions[s]
	return known
}

// CanMoveTo reports whether s may become next.
func (s Status) CanMoveTo(next Status) bool {
	for _, allowed := range transitions[s] {
		if allowed == next {
			return true
		}
	}
	return false
}

// ProposerKind distinguishes who proposed a Change.
type ProposerKind string

const (
	ProposerAgent ProposerKind = "agent"
	ProposerHuman ProposerKind = "human"
)

// Proposer is who proposed the Change.
//
// For an agent this carries the MODEL, because "an agent proposed it" is not an
// attribution anyone can act on — the question after a bad change is which model,
// under which instructions.
type Proposer struct {
	Kind ProposerKind `json:"kind"`
	// Name is the agent name (F8.5) or the human identity.
	Name string `json:"name"`
	// Model is the model hint for an agent proposer; empty for a human.
	Model string `json:"model,omitempty"`
}

// ResourceCount is blast radius in COUNTED resources.
//
// There is deliberately no free-text field here. Blast radius stated in
// adjectives — "minor", "low risk", "small" — is the thing an operator cannot
// check and cannot compare, so adjectives are made unrepresentable rather than
// discouraged.
type ResourceCount struct {
	// Kind is what is affected: deployments, pods, hosts, files, records.
	Kind string `json:"kind"`
	// Count is how many.
	Count int `json:"count"`
}

// InverseKind names how a Change would be undone.
type InverseKind string

const (
	// InverseManifestReapply re-applies the previous Kubernetes manifest.
	InverseManifestReapply InverseKind = "manifest_reapply"
	// InverseGitRevert reverts a commit.
	InverseGitRevert InverseKind = "git_revert"
	// InverseTargetGroupReadd puts a host back in a target group.
	InverseTargetGroupReadd InverseKind = "target_group_readd"
	// InverseCommand is an explicit inverse command prepared at plan time.
	InverseCommand InverseKind = "command"
	// InverseNone means no inverse exists. It REQUIRES a reason.
	InverseNone InverseKind = "none"
)

// Inverse is the prepared undo, or an honest statement that there is none.
//
// The honesty is the point. Claiming revertibility that does not exist changes
// what an operator is willing to approve, which makes a false claim here worse
// than no claim at all — so Validate refuses an unavailable inverse with no
// reason, and refuses an available one with nothing to run.
type Inverse struct {
	Kind InverseKind `json:"kind"`
	// Steps are what running the inverse would do. Empty for InverseNone.
	Steps []Step `json:"steps,omitempty"`
	// Reason explains why no inverse exists. REQUIRED when Kind is none.
	Reason string `json:"reason,omitempty"`
}

// Available reports whether this Change can be reverted.
func (i Inverse) Available() bool { return i.Kind != InverseNone && i.Kind != "" }

// Validate refuses a dishonest inverse.
func (i Inverse) Validate() error {
	switch {
	case i.Kind == "":
		return fmt.Errorf("%w: an inverse must state its kind, or state none with a reason", ErrInvalidInput)
	case i.Kind == InverseNone:
		if strings.TrimSpace(i.Reason) == "" {
			// Without this an operator reads "no inverse" and cannot tell whether
			// nobody prepared one or the tool genuinely cannot undo it — and those
			// lead to different decisions.
			return fmt.Errorf("%w: an unavailable inverse must say WHY (e.g. Terraform state cannot be rolled back by re-apply)", ErrInvalidInput)
		}
		if len(i.Steps) > 0 {
			return fmt.Errorf("%w: an inverse of kind none must have no steps", ErrInvalidInput)
		}
	default:
		if len(i.Steps) == 0 {
			return fmt.Errorf("%w: inverse %q claims to be available but has no steps to run", ErrInvalidInput, i.Kind)
		}
	}
	return nil
}

// Step is one planned action.
type Step struct {
	// Index orders the steps.
	Index int `json:"index"`
	// Argv is the exact command. It is part of the PIN, so it cannot drift
	// between preview and apply.
	Argv []string `json:"argv"`
	// Gated marks the step the human approval gate guards.
	Gated bool `json:"gated,omitempty"`
	// Description is the human-readable summary shown in review.
	Description string `json:"description,omitempty"`
}

// idRe bounds a change id.
var idRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// Change is the reviewable unit of work.
type Change struct {
	ID string `json:"id"`
	// Intent is what a human reads first: what this is for, in their words or the
	// agent's. A Change with no intent is not reviewable, so it is required.
	Intent   string   `json:"intent"`
	Proposer Proposer `json:"proposer"`

	ProjectID     string `json:"project_id"`
	EnvironmentID string `json:"environment_id"`

	// PolicyRule is the rule that gated this, and PolicyEffect its decision.
	PolicyRule   string `json:"policy_rule,omitempty"`
	PolicyEffect string `json:"policy_effect,omitempty"`

	// Steps are the planned actions, in order.
	Steps []Step `json:"steps"`
	// PlanHash pins the plan. See Pin.
	PlanHash string `json:"plan_hash"`
	// Preview is the rendered diff an operator reviews.
	Preview string `json:"preview,omitempty"`

	// BlastRadius is counted resources. Never adjectives — there is no field for
	// one.
	BlastRadius []ResourceCount `json:"blast_radius,omitempty"`
	// Inverse is the prepared undo, or an honest none.
	Inverse Inverse `json:"inverse"`

	// The provenance a Change must carry to be replayable and attributable.
	PolicyHash  string `json:"policy_hash,omitempty"`
	ContextHash string `json:"context_hash,omitempty"`
	AgentName   string `json:"agent_name,omitempty"`
	AgentModel  string `json:"agent_model,omitempty"`
	// ConnectionRefs are the secret REFS the change's connections resolve. Refs,
	// never values — a Change is reviewed, listed and exported, and a value in one
	// would travel everywhere it goes.
	ConnectionRefs []string `json:"connection_refs,omitempty"`

	// SessionID ties the Change to its trace segment.
	SessionID string `json:"session_id,omitempty"`

	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// DecidedBy and DecisionNote record the human decision.
	DecidedBy    string `json:"decided_by,omitempty"`
	DecisionNote string `json:"decision_note,omitempty"`
	// FailureReason explains a failed or expired Change.
	FailureReason string `json:"failure_reason,omitempty"`
}

// Validate checks a record at the trust boundary.
func (c Change) Validate() error {
	if !idRe.MatchString(c.ID) {
		return fmt.Errorf("%w: change id %q must be lowercase alphanumeric with dashes (1-64 chars)", ErrInvalidInput, c.ID)
	}
	if strings.TrimSpace(c.Intent) == "" {
		// A Change with no intent is not reviewable: the first thing a human needs
		// is what this is FOR, and a diff does not supply it.
		return fmt.Errorf("%w: change %q needs an intent — it is the first thing a reviewer reads", ErrInvalidInput, c.ID)
	}
	if len(c.Intent) > 4096 {
		return fmt.Errorf("%w: change %q intent is too long", ErrInvalidInput, c.ID)
	}
	if !c.Status.Valid() {
		return fmt.Errorf("%w: change %q has unknown status %q", ErrInvalidInput, c.ID, c.Status)
	}
	switch c.Proposer.Kind {
	case ProposerAgent, ProposerHuman:
	default:
		return fmt.Errorf("%w: change %q proposer kind %q must be agent or human", ErrInvalidInput, c.ID, c.Proposer.Kind)
	}
	if c.Proposer.Name == "" {
		return fmt.Errorf("%w: change %q needs a proposer", ErrInvalidInput, c.ID)
	}
	for _, b := range c.BlastRadius {
		if b.Kind == "" {
			return fmt.Errorf("%w: change %q has a blast-radius entry with no resource kind", ErrInvalidInput, c.ID)
		}
		if b.Count < 0 {
			return fmt.Errorf("%w: change %q blast radius for %s is negative", ErrInvalidInput, c.ID, b.Kind)
		}
	}
	// The inverse is required from PREVIEW onward, not before. At proposal time
	// only an intent exists — there is no plan yet, so whether it can be undone is
	// not yet a knowable fact, and demanding it would force a guess. By preview the
	// plan is known, which is exactly when the question has an answer and when an
	// operator needs it: before they approve, not after a failed revert.
	if c.Status != StatusProposed {
		if err := c.Inverse.Validate(); err != nil {
			return fmt.Errorf("change %q: %w", c.ID, err)
		}
	}
	for i, s := range c.Steps {
		if len(s.Argv) == 0 {
			return fmt.Errorf("%w: change %q step %d has no command", ErrInvalidInput, c.ID, i)
		}
	}
	return nil
}

// Revertible reports whether this Change can be reverted, and why not if it
// cannot.
//
// Exposed as one call so the UI states it BEFORE approval rather than after a
// failed revert — an operator's willingness to approve depends on it.
func (c Change) Revertible() (bool, string) {
	if !c.Inverse.Available() {
		return false, c.Inverse.Reason
	}
	switch c.Status {
	case StatusApplied, StatusFailed:
		return true, ""
	case StatusReverted:
		return false, "this change has already been reverted"
	default:
		return false, fmt.Sprintf("a change in status %q has not run, so there is nothing to revert", c.Status)
	}
}

// TotalBlast sums the counted resources, for a one-line summary.
func (c Change) TotalBlast() int {
	total := 0
	for _, b := range c.BlastRadius {
		total += b.Count
	}
	return total
}

// BlastSummary renders the blast radius as counted resources, sorted for a
// stable read.
func (c Change) BlastSummary() string {
	if len(c.BlastRadius) == 0 {
		return "none counted"
	}
	parts := make([]string, 0, len(c.BlastRadius))
	sorted := append([]ResourceCount(nil), c.BlastRadius...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Kind < sorted[j].Kind })
	for _, b := range sorted {
		parts = append(parts, fmt.Sprintf("%d %s", b.Count, b.Kind))
	}
	return strings.Join(parts, ", ")
}
