package session

import (
	"strings"

	"github.com/opslify-com/opslifyd/internal/change"
	"github.com/opslify-com/opslifyd/internal/policy"
)

// ChangeRecorder is the seam through which a gated exec becomes a reviewable
// Change.
//
// A seam so this package keeps no knowledge of how Changes are stored, and so
// every pre-P8 path runs with it nil and is unaffected.
type ChangeRecorder interface {
	// Propose records a new Change.
	Propose(c change.Change) (change.Change, error)
	// Preview attaches the plan, pins it, and records the blast radius and the
	// prepared inverse.
	Preview(id string, steps []change.Step, preview string, blast []change.ResourceCount, inv change.Inverse) (change.Change, error)
	// RequestApproval opens the human gate.
	RequestApproval(id string) (change.Change, error)
}

// recordGatedChange turns a paused approval gate into a Change.
//
// Every gated exec produces one. That is the point of the object: the thing a
// human reviews is the Change, not a session and not a trace, and if a gate could
// open without producing one there would be gates nobody could review through the
// review surface.
//
// It is BEST-EFFORT with respect to the gate: a failure here logs and returns,
// leaving the approval gate itself intact. The gate is the safety control and the
// Change is the review surface over it — degrading the surface must not remove
// the control, and refusing the exec because bookkeeping failed would turn a
// recording problem into an outage.
func (m *Manager) recordGatedChange(s *Session, execID string, opts ExecOptions, argvToRun []string,
	decision policy.Decision, previewDiff string, blast []change.ResourceCount, inv change.Inverse) string {
	if m.changes == nil || s == nil {
		return ""
	}
	id := "chg-" + execID

	proposer := change.Proposer{Kind: change.ProposerAgent, Name: s.agentName, Model: s.agentModel}
	if proposer.Name == "" {
		// No agent bound. The exec still came from something, and recording an
		// empty proposer would fail validation — so it is attributed to the session
		// itself, which is the honest answer: we know it ran here, not who chose it.
		proposer = change.Proposer{Kind: change.ProposerAgent, Name: "unattributed-session:" + s.ID}
	}

	c := change.Change{
		ID: id,
		// The intent is the command as the agent asked for it. It is a weak intent —
		// a command is what, not why — and F8.9 will let a proposer supply a real
		// one. Recording the command is still better than recording nothing, and it
		// is honest about being the command rather than dressed up as a rationale.
		Intent:   "run: " + strings.Join(opts.Argv, " "),
		Proposer: proposer,

		ProjectID:     s.ProjectID,
		EnvironmentID: s.EnvironmentID,
		PolicyRule:    decision.Rule,
		PolicyEffect:  string(decision.Verdict),

		PolicyHash:  s.policyHash,
		ContextHash: s.contextHash(),
		AgentName:   s.agentName,
		AgentModel:  s.agentModel,
		SessionID:   s.ID,
	}
	if _, err := m.changes.Propose(c); err != nil {
		m.log.Warn("session: could not record a Change for this gate; the approval gate itself is unaffected",
			"session", s.ID, "exec", execID, "err", err)
		return ""
	}

	// The plan is what will ACTUALLY run — argvToRun, not the original argv. After
	// an F4.4 dry-run rewrite those differ (terraform plan becomes terraform apply
	// of the saved plan), and pinning the original would pin something that is
	// never executed.
	steps := []change.Step{{
		Index:       0,
		Argv:        argvToRun,
		Gated:       true,
		Description: decision.Reason,
	}}
	if _, err := m.changes.Preview(id, steps, previewDiff, blast, inv); err != nil {
		m.log.Warn("session: could not attach the plan to a Change", "change", id, "err", err)
		return id
	}
	if _, err := m.changes.RequestApproval(id); err != nil {
		m.log.Warn("session: could not open the review gate on a Change", "change", id, "err", err)
	}
	return id
}

// contextHash returns the F8.4 instruction-set hash for this session, if one was
// assembled.
func (s *Session) contextHash() string {
	if s == nil || s.assembly == nil {
		return ""
	}
	return s.assembly.Hash
}

// inverseForExec states honestly whether this command can be undone.
//
// The default is NO, with a reason. That asymmetry is deliberate: claiming
// revertibility that does not exist changes what an operator is willing to
// approve, so an unknown command must not inherit an optimistic default. A kind
// earns "revertible" by having a prepared inverse, not by not being recognised.
func inverseForExec(argv []string) change.Inverse {
	if len(argv) == 0 {
		return change.Inverse{Kind: change.InverseNone, Reason: "no command to invert"}
	}
	switch argv[0] {
	case "terraform":
		// Named specifically because it is the case the spec calls out: Terraform
		// state cannot be rolled back by re-applying an old plan, and pretending
		// otherwise would be the most damaging false claim available here.
		return change.Inverse{Kind: change.InverseNone,
			Reason: "terraform state cannot be rolled back by re-apply; use a targeted plan or state surgery"}
	default:
		return change.Inverse{Kind: change.InverseNone,
			Reason: "no inverse has been prepared for this command; revert manually if needed"}
	}
}

// blastForExec counts what a command affects.
//
// It counts only what can be counted from the command itself, and reports NOTHING
// rather than guessing. An invented count is worse than an absent one: an
// operator reading "1 deployment" acts on it, and if the number came from a guess
// they have been misled at exactly the moment they are deciding.
func blastForExec(argv []string) []change.ResourceCount {
	if len(argv) < 2 || argv[0] != "kubectl" {
		return nil
	}
	// A single named resource is the one shape that can be counted honestly from
	// argv alone. Anything with a selector, --all, or a namespace sweep affects an
	// unknown number, and that is reported as uncounted.
	for _, a := range argv {
		if a == "--all" || a == "-A" || a == "--all-namespaces" || strings.HasPrefix(a, "-l") || strings.HasPrefix(a, "--selector") {
			return nil
		}
	}
	switch argv[1] {
	case "rollout", "scale", "restart", "delete", "apply", "patch":
		for _, a := range argv[2:] {
			if kind, _, ok := strings.Cut(a, "/"); ok && kind != "" {
				return []change.ResourceCount{{Kind: pluralise(kind), Count: 1}}
			}
		}
	}
	return nil
}

// pluralise renders a kubectl resource kind for a human-readable count.
func pluralise(kind string) string {
	if strings.HasSuffix(kind, "s") {
		return kind
	}
	return kind + "s"
}
