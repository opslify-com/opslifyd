package change

import (
	"fmt"
	"sync"
	"time"
)

// Store persists Changes.
type Store interface {
	Save(c Change) error
	Load(id string) (Change, bool, error)
	List() ([]Change, error)
}

// Service owns the Change lifecycle: the status machine, the pin, and the
// decisions a human makes.
type Service struct {
	store Store
	now   func() time.Time
	// mu serialises read-modify-write on a Change. Without it two concurrent
	// approvals could each read "awaiting" and both move to applying, running the
	// plan twice.
	mu sync.Mutex
}

// NewService wires the service.
func NewService(store Store, now func() time.Time) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("change: a store is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}, nil
}

// Propose records a new Change in StatusProposed.
func (s *Service) Propose(c Change) (Change, error) {
	c.Status = StatusProposed
	c.CreatedAt = s.now().UTC()
	c.UpdatedAt = c.CreatedAt
	if err := c.Validate(); err != nil {
		return Change{}, err
	}
	if _, found, err := s.store.Load(c.ID); err != nil {
		return Change{}, err
	} else if found {
		return Change{}, fmt.Errorf("%w: change %q already exists", ErrInvalidInput, c.ID)
	}
	if err := s.store.Save(c); err != nil {
		return Change{}, err
	}
	return c, nil
}

// Preview attaches the plan, pins it, and moves to previewed.
//
// The pin is computed HERE, from the steps as previewed, and never recomputed
// from the steps as applied — recomputing at apply would make the check compare a
// value with itself.
func (s *Service) Preview(id string, steps []Step, preview string, blast []ResourceCount, inv Inverse) (Change, error) {
	return s.mutate(id, StatusPreviewed, func(c *Change) error {
		if len(steps) == 0 {
			return fmt.Errorf("%w: a preview needs at least one step", ErrInvalidInput)
		}
		if err := inv.Validate(); err != nil {
			return err
		}
		c.Steps = steps
		c.PlanHash = Pin(steps)
		c.Preview = preview
		c.BlastRadius = blast
		c.Inverse = inv
		return nil
	})
}

// RequestApproval opens the human gate.
func (s *Service) RequestApproval(id string) (Change, error) {
	return s.mutate(id, StatusAwaitingApproval, func(c *Change) error {
		if c.PlanHash == "" {
			return fmt.Errorf("%w: change %q has no pinned plan to approve", ErrInvalidInput, id)
		}
		return nil
	})
}

// Approve records a human decision and moves toward applying.
//
// It re-verifies the pin BEFORE the transition. The steps passed here are the
// ones about to run, and if they differ from what was reviewed the approval does
// not apply to them — that is the whole point of pinning, and the check belongs
// on the far side of the approval window, not before it.
func (s *Service) Approve(id, decidedBy, note string, stepsAboutToRun []Step) (Change, error) {
	return s.mutate(id, StatusApplying, func(c *Change) error {
		if decidedBy == "" {
			// An unattributed approval is not an approval. Somebody accepted this
			// blast radius, and the record has to say who.
			return fmt.Errorf("%w: an approval must record who made it", ErrInvalidInput)
		}
		steps := stepsAboutToRun
		if steps == nil {
			steps = c.Steps
		}
		if err := VerifyPin(c.PlanHash, steps); err != nil {
			return err
		}
		c.DecidedBy = decidedBy
		c.DecisionNote = note
		return nil
	})
}

// Deny refuses a Change. TERMINAL: nothing runs afterwards.
func (s *Service) Deny(id, decidedBy, note string) (Change, error) {
	return s.mutate(id, StatusDenied, func(c *Change) error {
		if decidedBy == "" {
			return fmt.Errorf("%w: a denial must record who made it", ErrInvalidInput)
		}
		c.DecidedBy = decidedBy
		c.DecisionNote = note
		return nil
	})
}

// Expire marks an unanswered gate as timed out. TERMINAL, like a deny — an
// unanswered gate must never become an implicit yes.
func (s *Service) Expire(id, reason string) (Change, error) {
	return s.mutate(id, StatusExpired, func(c *Change) error {
		c.FailureReason = reason
		return nil
	})
}

// MarkApplied records successful completion.
func (s *Service) MarkApplied(id string) (Change, error) {
	return s.mutate(id, StatusApplied, nil)
}

// MarkFailed records that the plan ran and did not complete.
func (s *Service) MarkFailed(id, reason string) (Change, error) {
	return s.mutate(id, StatusFailed, func(c *Change) error {
		c.FailureReason = reason
		return nil
	})
}

// Revert applies the prepared inverse.
//
// It refuses honestly where no inverse exists, rather than attempting something
// and failing halfway — a half-applied revert leaves an estate in a state nobody
// planned, which is worse than a clear refusal.
func (s *Service) Revert(id, decidedBy string) (Change, error) {
	return s.mutate(id, StatusReverted, func(c *Change) error {
		if decidedBy == "" {
			return fmt.Errorf("%w: a revert must record who made it", ErrInvalidInput)
		}
		if ok, why := c.Revertible(); !ok {
			return fmt.Errorf("%w: change %q cannot be reverted: %s", ErrInvalidInput, id, why)
		}
		return nil
	})
}

// Get returns one Change.
func (s *Service) Get(id string) (Change, error) {
	c, found, err := s.store.Load(id)
	if err != nil {
		return Change{}, err
	}
	if !found {
		return Change{}, fmt.Errorf("%w: change %q", ErrNotFound, id)
	}
	return c, nil
}

// List returns every Change, newest first.
func (s *Service) List() ([]Change, error) { return s.store.List() }

// mutate applies a status transition under the lock, refusing an illegal move.
func (s *Service) mutate(id string, next Status, apply func(*Change) error) (Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, found, err := s.store.Load(id)
	if err != nil {
		return Change{}, err
	}
	if !found {
		return Change{}, fmt.Errorf("%w: change %q", ErrNotFound, id)
	}
	if !c.Status.CanMoveTo(next) {
		if c.Status.Terminal() {
			// Named distinctly: "it is already decided" is a different thing for an
			// operator to read than "that is not a legal move".
			return Change{}, fmt.Errorf("%w: change %q is %s, which is final — nothing further runs",
				ErrInvalidTransition, id, c.Status)
		}
		return Change{}, fmt.Errorf("%w: change %q cannot move from %s to %s", ErrInvalidTransition, id, c.Status, next)
	}
	if apply != nil {
		if err := apply(&c); err != nil {
			return Change{}, err
		}
	}
	c.Status = next
	c.UpdatedAt = s.now().UTC()
	if err := c.Validate(); err != nil {
		return Change{}, err
	}
	if err := s.store.Save(c); err != nil {
		return Change{}, err
	}
	return c, nil
}
