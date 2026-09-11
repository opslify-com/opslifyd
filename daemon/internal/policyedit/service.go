package policyedit

import (
	"fmt"
	"sync"

	"github.com/opslify-com/opslifyd/internal/change"
	"github.com/opslify-com/opslifyd/internal/policy"
)

// LayerStore reads and writes the policy documents this surface owns.
type LayerStore interface {
	// Load returns the current policy for a scope, and whether one exists.
	Load(s Scope) (policy.Policy, bool, error)
	// Save writes it. Called only after the direction has been decided.
	Save(s Scope, p policy.Policy) error
}

// ChangeGate is the F8.6 surface a widening edit is routed through.
type ChangeGate interface {
	Propose(c change.Change) (change.Change, error)
	Preview(id string, steps []change.Step, preview string, blast []change.ResourceCount, inv change.Inverse) (change.Change, error)
	RequestApproval(id string) (change.Change, error)
	Get(id string) (change.Change, error)
}

// Service applies policy edits according to their direction.
type Service struct {
	store LayerStore
	gate  ChangeGate
	newID func() string
	mu    sync.Mutex
	// pending holds the policy a widening Change would apply, keyed by change id.
	//
	// Held here rather than reconstructed at approval time on purpose: the thing
	// applied must be the thing classified and reviewed. Re-deriving it from a
	// stored patch would reintroduce the gap between what was approved and what
	// runs.
	pending map[string]pendingEdit
}

type pendingEdit struct {
	scope Scope
	to    policy.Policy
}

// NewService wires the service. newID generates change ids; nil uses a counter
// suitable only for tests.
func NewService(store LayerStore, gate ChangeGate, newID func() string) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("policyedit: a layer store is required")
	}
	if newID == nil {
		var n int
		newID = func() string { n++; return fmt.Sprintf("chg-policy-%d", n) }
	}
	return &Service{store: store, gate: gate, newID: newID, pending: map[string]pendingEdit{}}, nil
}

// Submit classifies an edit and either applies it or opens a Change.
//
// The classification happens BEFORE anything is written, and the write for a
// widening happens only in Apply. There is no path through this function that
// writes a widening.
func (s *Service) Submit(e Edit, proposer change.Proposer) (Outcome, error) {
	if err := e.Scope.Validate(); err != nil {
		return Outcome{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	from, _, err := s.store.Load(e.Scope)
	if err != nil {
		return Outcome{}, err
	}
	class := policy.ClassifyEdit(from, e.To)

	if class.Direction != policy.DirectionWidening {
		// Narrowing and equivalent both apply now. An equivalent edit is still
		// written: it may differ in a field the classifier considers cosmetic, and
		// refusing it would leave an operator unable to reformat their own policy.
		if err := s.store.Save(e.Scope, e.To); err != nil {
			return Outcome{}, err
		}
		return Outcome{Applied: true, Classification: class}, nil
	}

	if s.gate == nil {
		// No Change surface wired means no way to govern a widening — so refuse
		// rather than apply it ungoverned. A widening that slips through because
		// the review surface is missing is the failure this whole feature exists to
		// prevent.
		return Outcome{Classification: class}, fmt.Errorf("%w (no change surface is wired)", ErrNeedsApproval)
	}

	id := s.newID()
	c := change.Change{
		ID:        id,
		Intent:    intentFor(e, class),
		Proposer:  proposer,
		ProjectID: e.Scope.ProjectID, EnvironmentID: e.Scope.EnvironmentID,
		PolicyRule:   "policy-edit:" + string(e.Scope.Layer),
		PolicyEffect: string(class.Direction),
	}
	if _, err := s.gate.Propose(c); err != nil {
		return Outcome{Classification: class}, err
	}
	// The "plan" is the edit itself. Pinning it means an approval cannot be
	// carried onto a different policy than the one reviewed — the same guarantee a
	// command plan gets.
	steps := []change.Step{{
		Index:       0,
		Argv:        planArgv(e),
		Gated:       true,
		Description: "apply this policy edit",
	}}
	blast := []change.ResourceCount{{Kind: "policy widenings", Count: len(class.Widenings)}}
	// A policy edit IS revertible: the previous document is right here, and
	// re-applying it restores the guardrails exactly.
	inv := change.Inverse{Kind: change.InverseCommand, Steps: []change.Step{{
		Index: 0, Argv: planArgv(Edit{Scope: e.Scope}),
		Description: "restore the previous policy document",
	}}}
	if _, err := s.gate.Preview(id, steps, previewFor(class), blast, inv); err != nil {
		return Outcome{Classification: class}, err
	}
	if _, err := s.gate.RequestApproval(id); err != nil {
		return Outcome{Classification: class}, err
	}
	s.pending[id] = pendingEdit{scope: e.Scope, to: e.To}
	return Outcome{Applied: false, ChangeID: id, Classification: class}, nil
}

// Apply writes the policy a widening Change carried, once it has been approved.
//
// It re-checks the Change's status rather than trusting the caller: this is the
// function that actually loosens a guardrail, and it must be impossible to reach
// with an unapproved id even by mistake.
func (s *Service) Apply(changeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pend, ok := s.pending[changeID]
	if !ok {
		return fmt.Errorf("%w: no pending policy edit for change %q", ErrInvalidInput, changeID)
	}
	if s.gate == nil {
		return fmt.Errorf("%w (no change surface is wired)", ErrNeedsApproval)
	}
	c, err := s.gate.Get(changeID)
	if err != nil {
		return err
	}
	switch c.Status {
	case change.StatusApplying, change.StatusApplied:
		// Approved: an approver moved it out of the gate.
	default:
		return fmt.Errorf("%w: change %q is %s, not approved", ErrNeedsApproval, changeID, c.Status)
	}
	if err := s.store.Save(pend.scope, pend.to); err != nil {
		return err
	}
	delete(s.pending, changeID)
	return nil
}

// intentFor renders what a reviewer reads first.
func intentFor(e Edit, class policy.Classification) string {
	head := fmt.Sprintf("widen the %s policy", e.Scope.Layer)
	if e.Scope.EnvironmentID != "" {
		head += " for " + e.Scope.EnvironmentID
	} else if e.Scope.ProjectID != "" {
		head += " for " + e.Scope.ProjectID
	}
	if e.Reason != "" {
		head += ": " + e.Reason
	}
	return head
}

// previewFor renders the diff an approver reviews: every loosening, then every
// tightening, in the operator's words.
func previewFor(class policy.Classification) string {
	var b []string
	for _, w := range class.Widenings {
		b = append(b, "+ "+w)
	}
	for _, n := range class.Narrowings {
		b = append(b, "- "+n)
	}
	return joinLines(b)
}

func planArgv(e Edit) []string {
	return []string{"opslify", "policy", "apply", string(e.Scope.Layer), scopeID(e.Scope)}
}

func scopeID(s Scope) string {
	if s.EnvironmentID != "" {
		return s.EnvironmentID
	}
	return s.ProjectID
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}
