package policyedit

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/change"
	"github.com/opslify-com/opslifyd/internal/policy"
)

// memLayers is an in-memory LayerStore.
type memLayers struct {
	mu      sync.Mutex
	saved   map[string]policy.Policy
	current policy.Policy
	saveErr error
}

func newMemLayers(current policy.Policy) *memLayers {
	return &memLayers{saved: map[string]policy.Policy{}, current: current}
}

func (m *memLayers) Load(s Scope) (policy.Policy, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.saved[key(s)]; ok {
		return p, true, nil
	}
	return m.current, true, nil
}

func (m *memLayers) Save(s Scope, p policy.Policy) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saved[key(s)] = p
	return nil
}

func (m *memLayers) wasSaved(s Scope) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.saved[key(s)]
	return ok
}

func key(s Scope) string { return string(s.Layer) + "/" + s.ProjectID + "/" + s.EnvironmentID }

// realGate is the actual F8.6 service over an in-memory store, so the test
// exercises the real status machine rather than a fake that always says yes.
func realGate(t *testing.T) *change.Service {
	t.Helper()
	store := newChangeMemStore()
	svc, err := change.NewService(store, func() time.Time { return time.Unix(1700000000, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

type changeMemStore struct {
	mu      sync.Mutex
	records map[string]change.Change
}

func newChangeMemStore() *changeMemStore {
	return &changeMemStore{records: map[string]change.Change{}}
}

func (m *changeMemStore) Save(c change.Change) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[c.ID] = c
	return nil
}

func (m *changeMemStore) Load(id string) (change.Change, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.records[id]
	return c, ok, nil
}

func (m *changeMemStore) List() ([]change.Change, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]change.Change, 0, len(m.records))
	for _, c := range m.records {
		out = append(out, c)
	}
	return out, nil
}

func basePolicy() policy.Policy {
	return policy.Policy{
		Session:          policy.Session{TTL: "30m"},
		ApprovalRequired: []string{"^kubectl delete"},
		Egress:           policy.Egress{Domains: []string{"gitlab.example.com"}},
	}
}

func envScope() Scope {
	return Scope{Layer: LayerEnvironment, ProjectID: "tripon", EnvironmentID: "tripon.prod"}
}

func proposer() change.Proposer {
	return change.Proposer{Kind: change.ProposerHuman, Name: "alice"}
}

func newService(t *testing.T, gate ChangeGate) (*Service, *memLayers) {
	t.Helper()
	layers := newMemLayers(basePolicy())
	svc, err := NewService(layers, gate, nil)
	if err != nil {
		t.Fatal(err)
	}
	return svc, layers
}

// --- narrowing applies immediately ---------------------------------------------

// TestNarrowingAppliesImmediately: tightening during an incident must never wait
// for an approver.
func TestNarrowingAppliesImmediately(t *testing.T) {
	svc, layers := newService(t, realGate(t))
	to := basePolicy()
	to.Egress.Domains = nil // remove a host

	out, err := svc.Submit(Edit{Scope: envScope(), To: to}, proposer())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !out.Applied {
		t.Fatal("a narrowing edit must apply immediately")
	}
	if out.ChangeID != "" {
		t.Errorf("a narrowing must not open a Change, got %q", out.ChangeID)
	}
	if !layers.wasSaved(envScope()) {
		t.Fatal("the narrowing was not written")
	}
	// It is still RECORDED, even though it is ungated.
	if len(out.Classification.Narrowings) == 0 {
		t.Error("a narrowing must still be described, so the account is complete")
	}
}

// --- widening needs approval -----------------------------------------------------

// TestWideningDoesNotApplyUntilApproved is the feature's whole point: guardrails
// that can be widened without governance are not guardrails.
func TestWideningDoesNotApplyUntilApproved(t *testing.T) {
	gate := realGate(t)
	svc, layers := newService(t, gate)
	to := basePolicy()
	to.Egress.Domains = append(to.Egress.Domains, "evil.example.com")

	out, err := svc.Submit(Edit{Scope: envScope(), To: to, Reason: "the deploy needs it"}, proposer())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if out.Applied {
		t.Fatal("a widening edit must NOT apply on submission")
	}
	if out.ChangeID == "" {
		t.Fatal("a widening must open a Change")
	}
	if layers.wasSaved(envScope()) {
		t.Fatal("BLOCKING: the widening was written before anyone approved it")
	}

	// Applying before approval must be refused.
	if err := svc.Apply(out.ChangeID); !errors.Is(err, ErrNeedsApproval) {
		t.Fatalf("applying an unapproved widening must be refused, got %v", err)
	}
	if layers.wasSaved(envScope()) {
		t.Fatal("BLOCKING: a refused apply wrote the policy anyway")
	}

	// The Change carries what an approver needs.
	c, err := gate.Get(out.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Intent, "the deploy needs it") {
		t.Errorf("the operator's reason must reach the reviewer: %q", c.Intent)
	}
	if !strings.Contains(c.Preview, "evil.example.com") {
		t.Errorf("the preview must name what is being opened: %q", c.Preview)
	}
	if revertible, _ := c.Revertible(); c.Inverse.Kind == change.InverseNone {
		t.Errorf("a policy edit IS revertible — the previous document is right there (revertible=%v)", revertible)
	}

	// Approve it, then the apply lands.
	if _, err := gate.Approve(out.ChangeID, "bob", "ok for the window", nil); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := svc.Apply(out.ChangeID); err != nil {
		t.Fatalf("Apply after approval: %v", err)
	}
	if !layers.wasSaved(envScope()) {
		t.Fatal("the approved widening did not take effect")
	}
}

// TestADeniedWideningNeverApplies.
func TestADeniedWideningNeverApplies(t *testing.T) {
	gate := realGate(t)
	svc, layers := newService(t, gate)
	to := basePolicy()
	to.ApprovalRequired = nil // remove a gate: the widening that matters most

	out, err := svc.Submit(Edit{Scope: envScope(), To: to}, proposer())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Deny(out.ChangeID, "bob", "not during the freeze"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Apply(out.ChangeID); err == nil {
		t.Fatal("a denied widening must never apply")
	}
	if layers.wasSaved(envScope()) {
		t.Fatal("BLOCKING: a denied widening was written")
	}
}

// TestWideningIsRefusedWithNoChangeSurface: a widening that slips through because
// the review surface is missing is exactly the failure this feature prevents.
func TestWideningIsRefusedWithNoChangeSurface(t *testing.T) {
	svc, layers := newService(t, nil)
	to := basePolicy()
	to.Egress.Domains = append(to.Egress.Domains, "evil.example.com")

	out, err := svc.Submit(Edit{Scope: envScope(), To: to}, proposer())
	if !errors.Is(err, ErrNeedsApproval) {
		t.Fatalf("want ErrNeedsApproval, got %v", err)
	}
	if out.Applied || layers.wasSaved(envScope()) {
		t.Fatal("BLOCKING: a widening applied with no way to govern it")
	}
}

// --- read-only layers --------------------------------------------------------------

// TestDaemonAndWorkspaceLayersAreReadOnly. The daemon baseline is what every
// other layer can only narrow, so an edit surface able to widen it would make the
// precedence model meaningless. The workspace policy is untrusted repo input,
// changed by a reviewed commit.
func TestDaemonAndWorkspaceLayersAreReadOnly(t *testing.T) {
	svc, layers := newService(t, realGate(t))
	for _, layer := range []Layer{LayerDaemon, LayerWorkspace} {
		to := basePolicy()
		to.ApprovalRequired = nil // a widening, so it cannot pass as a harmless edit
		_, err := svc.Submit(Edit{Scope: Scope{Layer: layer, ProjectID: "tripon"}, To: to}, proposer())
		if !errors.Is(err, ErrReadOnlyLayer) {
			t.Errorf("the %s layer must be read-only here, got %v", layer, err)
		}
		// The refusal must explain where the edit DOES belong.
		if err != nil && !strings.Contains(err.Error(), "/etc/opslify") && !strings.Contains(err.Error(), "repo") {
			t.Errorf("the %s refusal should say where to make the edit instead: %v", layer, err)
		}
	}
	if len(layers.saved) != 0 {
		t.Fatal("a read-only layer was written")
	}
	// And a NARROWING of a read-only layer is refused too: the route is wrong
	// regardless of direction.
	narrower := basePolicy()
	narrower.Egress.Domains = nil
	if _, err := svc.Submit(Edit{Scope: Scope{Layer: LayerDaemon}, To: narrower}, proposer()); !errors.Is(err, ErrReadOnlyLayer) {
		t.Errorf("narrowing a read-only layer must still be refused, got %v", err)
	}
}

// TestScopeMustNameItsTarget.
func TestScopeMustNameItsTarget(t *testing.T) {
	svc, _ := newService(t, realGate(t))
	for _, s := range []Scope{
		{},
		{Layer: LayerProject},
		{Layer: LayerEnvironment},
		{Layer: LayerEnvironment, ProjectID: "tripon"},
	} {
		if _, err := svc.Submit(Edit{Scope: s, To: basePolicy()}, proposer()); err == nil {
			t.Errorf("scope %+v must be refused", s)
		}
	}
}

// --- the applied policy is the reviewed policy ---------------------------------------

// TestTheAppliedPolicyIsTheOneThatWasReviewed. The pending document is held as-is
// rather than re-derived at approval time: re-deriving would reintroduce the gap
// between what was approved and what runs.
func TestTheAppliedPolicyIsTheOneThatWasReviewed(t *testing.T) {
	gate := realGate(t)
	svc, layers := newService(t, gate)
	to := basePolicy()
	to.Egress.Domains = append(to.Egress.Domains, "approved.example.com")

	out, err := svc.Submit(Edit{Scope: envScope(), To: to}, proposer())
	if err != nil {
		t.Fatal(err)
	}
	// Someone edits the layer underneath, after review.
	interference := basePolicy()
	interference.Egress.Domains = append(interference.Egress.Domains, "sneaky.example.com")
	if err := layers.Save(envScope(), interference); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Approve(out.ChangeID, "bob", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.Apply(out.ChangeID); err != nil {
		t.Fatal(err)
	}
	got := layers.saved[key(envScope())]
	var sawApproved, sawSneaky bool
	for _, d := range got.Egress.Domains {
		if d == "approved.example.com" {
			sawApproved = true
		}
		if d == "sneaky.example.com" {
			sawSneaky = true
		}
	}
	if !sawApproved {
		t.Error("the approved document must be what lands")
	}
	if sawSneaky {
		t.Fatal("BLOCKING: an edit made after review survived the apply — the approved document is not what landed")
	}
}

// TestApplyingAnUnknownChangeIsRefused.
func TestApplyingAnUnknownChangeIsRefused(t *testing.T) {
	svc, _ := newService(t, realGate(t))
	if err := svc.Apply("chg-nonexistent"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput, got %v", err)
	}
}

// TestAnEquivalentEditStillWrites: it may differ in a field the classifier treats
// as cosmetic, and refusing would leave an operator unable to reformat their own
// policy.
func TestAnEquivalentEditStillWrites(t *testing.T) {
	svc, layers := newService(t, realGate(t))
	out, err := svc.Submit(Edit{Scope: envScope(), To: basePolicy()}, proposer())
	if err != nil {
		t.Fatal(err)
	}
	if !out.Applied {
		t.Error("an equivalent edit should apply")
	}
	if !layers.wasSaved(envScope()) {
		t.Error("an equivalent edit should still be written")
	}
	if !strings.Contains(out.Summary(), "no effective change") {
		t.Errorf("summary = %q", out.Summary())
	}
}
