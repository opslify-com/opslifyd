package change

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// memStore is an in-memory Store.
type memStore struct {
	mu      sync.Mutex
	records map[string]Change
}

func newMemStore() *memStore { return &memStore{records: map[string]Change{}} }

func (m *memStore) Save(c Change) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[c.ID] = c
	return nil
}

func (m *memStore) Load(id string) (Change, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.records[id]
	return c, ok, nil
}

func (m *memStore) List() ([]Change, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Change, 0, len(m.records))
	for _, c := range m.records {
		out = append(out, c)
	}
	return out, nil
}

func newService(t *testing.T) (*Service, *memStore) {
	t.Helper()
	store := newMemStore()
	svc, err := NewService(store, func() time.Time { return time.Unix(1700000000, 0).UTC() })
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

func restartSteps() []Step {
	return []Step{
		{Index: 0, Argv: []string{"kubectl", "get", "deploy", "web"}, Description: "read current state"},
		{Index: 1, Argv: []string{"kubectl", "rollout", "restart", "deploy/web"}, Gated: true, Description: "restart the web deployment"},
	}
}

func goodInverse() Inverse {
	return Inverse{Kind: InverseManifestReapply, Steps: []Step{
		{Index: 0, Argv: []string{"kubectl", "apply", "-f", "previous-web.yaml"}},
	}}
}

func proposed(t *testing.T, svc *Service) Change {
	t.Helper()
	c, err := svc.Propose(Change{
		ID:        "chg-restart-web",
		Intent:    "restart the web deployment to clear the memory pressure seen at 14:02",
		Proposer:  Proposer{Kind: ProposerAgent, Name: "qwen-local", Model: "qwen2.5-coder:32b"},
		ProjectID: "tripon", EnvironmentID: "tripon.prod",
	})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	return c
}

// --- the pin: a security control, not a convenience ---------------------------

// TestApprovedPlanCannotBeSwappedBeforeApply is the BLOCKING QA item. Approval is
// meaningless if the applied plan can differ from the reviewed one, and the gap
// between the two is a TOCTOU window — so the pin is re-verified on the far side
// of it.
func TestApprovedPlanCannotBeSwappedBeforeApply(t *testing.T) {
	svc, _ := newService(t)
	c := proposed(t, svc)
	if _, err := svc.Preview(c.ID, restartSteps(), "diff", []ResourceCount{{Kind: "deployments", Count: 1}}, goodInverse()); err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if _, err := svc.RequestApproval(c.ID); err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	// The plan that actually shows up at apply has one extra, destructive step.
	swapped := append(restartSteps(), Step{
		Index: 2, Argv: []string{"kubectl", "delete", "deploy/web"}, Description: "not reviewed by anyone",
	})
	_, err := svc.Approve(c.ID, "alice", "looks fine", swapped)
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("a swapped plan must be refused with ErrPinMismatch, got %v", err)
	}
	// And the Change must NOT have moved: a refused approval leaves the gate open.
	after, _ := svc.Get(c.ID)
	if after.Status != StatusAwaitingApproval {
		t.Errorf("status = %s, want the gate still open", after.Status)
	}
	if after.DecidedBy != "" {
		t.Error("a refused approval must not record a decision")
	}
}

// TestEveryKindOfPlanDriftIsCaught: argv, order, count, and WHICH step is gated.
func TestEveryKindOfPlanDriftIsCaught(t *testing.T) {
	base := restartSteps()
	approved := Pin(base)

	for _, tc := range []struct {
		name  string
		steps []Step
	}{
		{"an argument changed", []Step{
			base[0],
			{Index: 1, Argv: []string{"kubectl", "rollout", "restart", "deploy/api"}, Gated: true},
		}},
		{"a step added", append(append([]Step{}, base...), Step{Index: 2, Argv: []string{"kubectl", "delete", "ns", "prod"}})},
		{"a step removed", base[:1]},
		{"the order reversed", []Step{base[1], base[0]}},
		{"the gate moved off the destructive step", []Step{
			{Index: 0, Argv: base[0].Argv, Gated: true},
			{Index: 1, Argv: base[1].Argv},
		}},
		{"an empty plan", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyPin(approved, tc.steps); !errors.Is(err, ErrPinMismatch) {
				t.Fatalf("drift must be caught: %v", err)
			}
		})
	}
	// The identical plan passes, or the control is just a broken approval.
	if err := VerifyPin(approved, restartSteps()); err != nil {
		t.Fatalf("an unchanged plan must verify: %v", err)
	}
}

// TestDescriptionsAreNotPinned: re-wording how a plan is DESCRIBED must not
// invalidate an approval already given, while changing what runs must.
func TestDescriptionsAreNotPinned(t *testing.T) {
	base := restartSteps()
	approved := Pin(base)
	reworded := restartSteps()
	reworded[0].Description = "read the current state of the deployment first"
	reworded[1].Description = "restart it"
	if err := VerifyPin(approved, reworded); err != nil {
		t.Errorf("re-wording a description must not invalidate an approval: %v", err)
	}
}

// TestAnUnpinnedPlanCannotBeApproved: treating an empty pin as "matches" would
// make an unpinned plan the easiest way past the control.
func TestAnUnpinnedPlanCannotBeApproved(t *testing.T) {
	if err := VerifyPin("", restartSteps()); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("an empty pin must be refused, got %v", err)
	}
	svc, _ := newService(t)
	c := proposed(t, svc)
	if _, err := svc.RequestApproval(c.ID); err == nil {
		t.Fatal("a change with no pinned plan must not reach the approval gate")
	}
}

// TestPinIsUnambiguous: without length-prefixing, argv ["a","bc"] and ["ab","c"]
// would render the same preimage and two different plans would share a pin.
func TestPinIsUnambiguous(t *testing.T) {
	a := []Step{{Argv: []string{"a", "bc"}}}
	b := []Step{{Argv: []string{"ab", "c"}}}
	if Pin(a) == Pin(b) {
		t.Fatal("two different plans share a pin: the preimage is ambiguous")
	}
	// And the pin is deterministic.
	if Pin(restartSteps()) != Pin(restartSteps()) {
		t.Fatal("the pin is not deterministic")
	}
}

// --- terminal states ------------------------------------------------------------

// TestNothingRunsAfterADeny: denied and expired are terminal, and the type graph
// makes that structural rather than a rule someone has to remember.
func TestNothingRunsAfterADeny(t *testing.T) {
	for _, terminal := range []Status{StatusDenied, StatusExpired, StatusReverted} {
		if !terminal.Terminal() {
			t.Errorf("%s must be terminal", terminal)
		}
		for _, next := range []Status{StatusApplying, StatusApplied, StatusPreviewed, StatusAwaitingApproval} {
			if terminal.CanMoveTo(next) {
				t.Errorf("%s must not be able to move to %s", terminal, next)
			}
		}
	}
	svc, _ := newService(t)
	c := proposed(t, svc)
	if _, err := svc.Preview(c.ID, restartSteps(), "d", nil, goodInverse()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequestApproval(c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Deny(c.ID, "alice", "not during the freeze"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	// Every onward move must be refused.
	if _, err := svc.Approve(c.ID, "bob", "", nil); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("approving a denied change must be refused, got %v", err)
	}
	if _, err := svc.MarkApplied(c.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("applying a denied change must be refused, got %v", err)
	}
	after, _ := svc.Get(c.ID)
	if after.Status != StatusDenied || after.DecidedBy != "alice" {
		t.Errorf("the denial must stand: %+v", after)
	}
}

// TestAnUnansweredGateIsNotAnImplicitYes.
func TestAnUnansweredGateIsNotAnImplicitYes(t *testing.T) {
	svc, _ := newService(t)
	c := proposed(t, svc)
	svc.Preview(c.ID, restartSteps(), "d", nil, goodInverse())
	svc.RequestApproval(c.ID)
	if _, err := svc.Expire(c.ID, "no answer within the approval TTL"); err != nil {
		t.Fatalf("Expire: %v", err)
	}
	if _, err := svc.Approve(c.ID, "alice", "", nil); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("an expired gate must not be approvable afterwards, got %v", err)
	}
}

// TestDecisionsMustBeAttributed: an unattributed approval is not an approval —
// somebody accepted this blast radius and the record has to say who.
func TestDecisionsMustBeAttributed(t *testing.T) {
	svc, _ := newService(t)
	c := proposed(t, svc)
	svc.Preview(c.ID, restartSteps(), "d", nil, goodInverse())
	svc.RequestApproval(c.ID)
	if _, err := svc.Approve(c.ID, "", "", nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("an unattributed approval must be refused, got %v", err)
	}
	if _, err := svc.Deny(c.ID, "", ""); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("an unattributed denial must be refused, got %v", err)
	}
}

// overlapStore detects whether two read-modify-write cycles were ever in flight
// at the same time.
//
// A barrier inside Load cannot work here: the service holds its lock ACROSS the
// load and the save, so a barrier waiting for N concurrent loads would deadlock
// against the very serialisation it is testing. Instead Load sleeps briefly,
// which widens the window enormously if there is no lock and merely queues if
// there is — and the store records the maximum overlap it ever saw.
type overlapStore struct {
	*memStore
	mu      sync.Mutex
	inside  int
	maxSeen int
}

func newOverlapStore() *overlapStore { return &overlapStore{memStore: newMemStore()} }

// Load measures how many callers are inside it AT ONCE. The service holds its
// lock across load-and-save, so with serialisation this can never exceed one.
//
// The count is balanced inside Load rather than across Load/Save on purpose: most
// of these approvals legitimately FAIL (only one can win), and a failed cycle
// never reaches Save — so a counter decremented in Save would climb forever and
// report an overlap that never happened. That is a property of the instrument,
// not of the code, and it cost me a false failure before I spotted it.
func (o *overlapStore) Load(id string) (Change, bool, error) {
	o.mu.Lock()
	o.inside++
	if o.inside > o.maxSeen {
		o.maxSeen = o.inside
	}
	o.mu.Unlock()

	// Wide enough that unserialised callers reliably overlap.
	time.Sleep(2 * time.Millisecond)
	c, found, err := o.memStore.Load(id)

	o.mu.Lock()
	o.inside--
	o.mu.Unlock()
	return c, found, err
}

func (o *overlapStore) maxOverlap() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.maxSeen
}

// TestConcurrentApprovalsRunThePlanOnce: without serialisation two approvals each
// read "awaiting" and both move to applying — running the plan twice.
func TestConcurrentApprovalsRunThePlanOnce(t *testing.T) {
	store := newOverlapStore()
	svc, err := NewService(store, func() time.Time { return time.Unix(1700000000, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	c := proposed(t, svc)
	svc.Preview(c.ID, restartSteps(), "d", nil, goodInverse())
	svc.RequestApproval(c.ID)

	var wg sync.WaitGroup
	var succeeded int
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := svc.Approve(c.ID, fmt.Sprintf("approver-%d", i), "", nil); err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("%d approvals succeeded; exactly one must win or the plan runs twice", succeeded)
	}
	// The direct claim: the read-modify-write cycle is never interleaved. Without
	// this a future change could keep "one winner" by luck while reintroducing the
	// window.
	if got := store.maxOverlap(); got > 1 {
		t.Fatalf("%d approval cycles were in flight at once; the read-modify-write must be serialised", got)
	}
}

// --- the honest inverse ----------------------------------------------------------

// TestAnUnavailableInverseMustSayWhy. Without a reason an operator cannot tell
// whether nobody prepared one or the tool genuinely cannot undo it — and those
// lead to different decisions.
func TestAnUnavailableInverseMustSayWhy(t *testing.T) {
	if err := (Inverse{Kind: InverseNone}).Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("an unavailable inverse with no reason must be refused, got %v", err)
	}
	ok := Inverse{Kind: InverseNone, Reason: "terraform state cannot be rolled back by re-apply"}
	if err := ok.Validate(); err != nil {
		t.Errorf("an honest unavailable inverse must be accepted: %v", err)
	}
	if ok.Available() {
		t.Error("kind none must not report itself available")
	}
}

// TestAnAvailableInverseMustHaveSomethingToRun: claiming revertibility with no
// steps is the same lie in the other direction.
func TestAnAvailableInverseMustHaveSomethingToRun(t *testing.T) {
	if err := (Inverse{Kind: InverseManifestReapply}).Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("an available inverse with no steps must be refused, got %v", err)
	}
	if err := (Inverse{Kind: InverseNone, Reason: "x", Steps: restartSteps()}).Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("kind none with steps is incoherent and must be refused, got %v", err)
	}
}

// TestRevertibilityIsKnowableBeforeApproval is the QA item: the UI must state
// whether an inverse exists BEFORE approval, not after a failed revert — an
// operator's willingness to approve depends on it.
func TestRevertibilityIsKnowableBeforeApproval(t *testing.T) {
	svc, _ := newService(t)
	c := proposed(t, svc)
	noInverse := Inverse{Kind: InverseNone, Reason: "terraform state cannot be rolled back by re-apply"}
	previewed, err := svc.Preview(c.ID, restartSteps(), "d", nil, noInverse)
	if err != nil {
		t.Fatal(err)
	}
	// Answerable at PREVIEW time, before anyone approves.
	ok, why := previewed.Revertible()
	if ok {
		t.Fatal("a change with no inverse must not report itself revertible")
	}
	if !strings.Contains(why, "terraform") {
		t.Errorf("the reason must reach the operator before approval, got %q", why)
	}
}

// TestRevertRefusesHonestly: a half-applied revert leaves an estate in a state
// nobody planned, which is worse than a clear refusal.
func TestRevertRefusesHonestly(t *testing.T) {
	svc, _ := newService(t)
	c := proposed(t, svc)
	svc.Preview(c.ID, restartSteps(), "d", nil,
		Inverse{Kind: InverseNone, Reason: "terraform state cannot be rolled back"})
	svc.RequestApproval(c.ID)
	svc.Approve(c.ID, "alice", "", nil)
	svc.MarkApplied(c.ID)

	_, err := svc.Revert(c.ID, "alice")
	if err == nil {
		t.Fatal("reverting a change with no inverse must be refused")
	}
	if !strings.Contains(err.Error(), "terraform") {
		t.Errorf("the refusal must carry the honest reason: %v", err)
	}
	after, _ := svc.Get(c.ID)
	if after.Status != StatusApplied {
		t.Errorf("a refused revert must not change the status, got %s", after.Status)
	}
}

// TestRevertWorksWhereAnInverseExists.
func TestRevertWorksWhereAnInverseExists(t *testing.T) {
	svc, _ := newService(t)
	c := proposed(t, svc)
	svc.Preview(c.ID, restartSteps(), "d", nil, goodInverse())
	svc.RequestApproval(c.ID)
	svc.Approve(c.ID, "alice", "", nil)
	svc.MarkApplied(c.ID)

	reverted, err := svc.Revert(c.ID, "alice")
	if err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if reverted.Status != StatusReverted {
		t.Errorf("status = %s", reverted.Status)
	}
	// And it cannot be reverted twice.
	if _, err := svc.Revert(c.ID, "alice"); err == nil {
		t.Error("a reverted change must not be revertible again")
	}
}

// TestCannotRevertSomethingThatNeverRan.
func TestCannotRevertSomethingThatNeverRan(t *testing.T) {
	svc, _ := newService(t)
	c := proposed(t, svc)
	svc.Preview(c.ID, restartSteps(), "d", nil, goodInverse())
	if _, err := svc.Revert(c.ID, "alice"); err == nil {
		t.Fatal("a change that never ran has nothing to revert")
	}
}

// --- blast radius ------------------------------------------------------------------

// TestBlastRadiusCannotBeAnAdjective is asserted structurally: the record has no
// free-text field for it, so "minor" and "low risk" are unrepresentable rather
// than merely discouraged.
func TestBlastRadiusCannotBeAnAdjective(t *testing.T) {
	b, err := json.Marshal(ResourceCount{Kind: "deployments", Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	json.Unmarshal(b, &fields)
	allowed := map[string]bool{"kind": true, "count": true}
	for k := range fields {
		if !allowed[k] {
			t.Errorf("ResourceCount has field %q; blast radius must be counted resources, never prose", k)
		}
	}
	c := Change{BlastRadius: []ResourceCount{
		{Kind: "pods", Count: 12}, {Kind: "deployments", Count: 1},
	}}
	if c.TotalBlast() != 13 {
		t.Errorf("TotalBlast = %d, want 13", c.TotalBlast())
	}
	// Sorted for a stable read.
	if got := c.BlastSummary(); got != "1 deployments, 12 pods" {
		t.Errorf("BlastSummary = %q", got)
	}
	if (Change{}).BlastSummary() != "none counted" {
		t.Error("an uncounted blast radius must say so rather than imply zero impact")
	}
}

// --- provenance ----------------------------------------------------------------------

// TestChangeCarriesItsProvenance: a Change must name the policy, the instructions,
// the agent and the model it ran under, or "why did it do that?" has no answer.
func TestChangeCarriesItsProvenance(t *testing.T) {
	svc, _ := newService(t)
	c, err := svc.Propose(Change{
		ID:             "chg-1",
		Intent:         "scale the api deployment to 5",
		Proposer:       Proposer{Kind: ProposerAgent, Name: "claude", Model: "claude-opus-5"},
		PolicyHash:     "policyhash",
		ContextHash:    "contexthash",
		AgentName:      "claude",
		AgentModel:     "claude-opus-5",
		ConnectionRefs: []string{"k8s-token"},
		SessionID:      "sess-1",
	})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	for name, got := range map[string]string{
		"policy hash":      c.PolicyHash,
		"instruction hash": c.ContextHash,
		"agent":            c.AgentName,
		"model":            c.AgentModel,
		"session":          c.SessionID,
	} {
		if got == "" {
			t.Errorf("a Change must record its %s", name)
		}
	}
	// Connection REFS, never values — a Change is reviewed, listed and exported.
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "glpat-") || strings.Contains(string(b), "BEGIN OPENSSH") {
		t.Error("a Change must carry refs, never values")
	}
}

// TestAChangeWithoutIntentIsNotReviewable: the first thing a human needs is what
// this is FOR, and a diff does not supply it.
func TestAChangeWithoutIntentIsNotReviewable(t *testing.T) {
	svc, _ := newService(t)
	for _, intent := range []string{"", "   ", "\n\t"} {
		_, err := svc.Propose(Change{
			ID: "chg-x", Intent: intent,
			Proposer: Proposer{Kind: ProposerHuman, Name: "alice"},
		})
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("intent %q must be refused, got %v", intent, err)
		}
	}
}

// TestProposerMustBeAttributed: "an agent proposed it" is not an attribution
// anyone can act on.
func TestProposerMustBeAttributed(t *testing.T) {
	svc, _ := newService(t)
	for _, p := range []Proposer{
		{},
		{Kind: ProposerAgent},
		{Name: "someone"},
		{Kind: "robot", Name: "x"},
	} {
		_, err := svc.Propose(Change{ID: "chg-y", Intent: "do a thing", Proposer: p})
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("proposer %+v must be refused, got %v", p, err)
		}
	}
}
