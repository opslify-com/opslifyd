package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/agents"
	"github.com/opslify-com/opslifyd/internal/change"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// recordingChanges captures what the gate handed the Change service.
type recordingChanges struct {
	mu         sync.Mutex
	proposed   []change.Change
	previewed  map[string][]change.Step
	blast      map[string][]change.ResourceCount
	inverses   map[string]change.Inverse
	opened     []string
	proposeErr error
}

func newRecordingChanges() *recordingChanges {
	return &recordingChanges{
		previewed: map[string][]change.Step{},
		blast:     map[string][]change.ResourceCount{},
		inverses:  map[string]change.Inverse{},
	}
}

func (r *recordingChanges) Propose(c change.Change) (change.Change, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.proposeErr != nil {
		return change.Change{}, r.proposeErr
	}
	// Mimic what the real service does on Propose — stamp the status and times —
	// so what this fake records is what would actually be persisted. Without it the
	// recorded copy is a half-built record and asserting it is valid would be
	// asserting against the fixture rather than the code.
	c.Status = change.StatusProposed
	c.CreatedAt = time.Unix(1700000000, 0).UTC()
	c.UpdatedAt = c.CreatedAt
	r.proposed = append(r.proposed, c)
	return c, nil
}

func (r *recordingChanges) Preview(id string, steps []change.Step, preview string,
	blast []change.ResourceCount, inv change.Inverse) (change.Change, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.previewed[id] = steps
	r.blast[id] = blast
	r.inverses[id] = inv
	return change.Change{ID: id}, nil
}

func (r *recordingChanges) RequestApproval(id string) (change.Change, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened = append(r.opened, id)
	return change.Change{ID: id}, nil
}

func (r *recordingChanges) first() (change.Change, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.proposed) == 0 {
		return change.Change{}, false
	}
	return r.proposed[0], true
}

// gateManager builds a Manager whose policy gates kubectl delete behind approval.
//
// rec is the INTERFACE type, not the concrete one, so a test can pass a true nil.
// Passing a nil *recordingChanges would produce a non-nil interface holding a nil
// pointer — the manager's `changes != nil` check would pass and the first gate
// would panic. That is a real hazard for anyone wiring this, not only for tests.
func gateManager(t *testing.T, rec ChangeRecorder, agentSrc AgentSource) (*Manager, *fakeRuntime) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rt := newFakeRuntime()
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTier:   runtime.TierLocalHardened,
			DefaultTTL:    30 * time.Minute,
			DefaultPolicy: policy.Policy{
				Allow:            policy.Allow{Exec: []string{".*"}},
				ApprovalRequired: []string{"^kubectl (delete|rollout)"},
			},
		},
		Resolve: func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:   &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second},
		Store:   newMemStore(),
		Trace:   trace.NewMemSink(trace.NewEd25519Signer(priv)),
		Changes: rec,
		Agents:  agentSrc,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, rt
}

// gatedExec runs a command that the policy gates, returning the pending error.
func gatedExec(t *testing.T, m *Manager, argv []string) (*Session, *ApprovalPendingError) {
	t.Helper()
	ctx := context.Background()
	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	err = m.Exec(ctx, s.ID, ExecOptions{Argv: argv}, newCaptureSink())
	var pending *ApprovalPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("expected the command to be gated, got %v", err)
	}
	return s, pending
}

// AC (F8.6): every gated exec produces a Change carrying the intent, the policy
// rule, the blast radius and the prepared inverse.
func TestEveryGatedExecProducesAChange(t *testing.T) {
	rec := newRecordingChanges()
	m, _ := gateManager(t, rec, func(string, string) (agents.Agent, error) {
		return agents.Agent{Name: "qwen-local", ModelHint: "qwen2.5-coder:32b", Locality: agents.LocalityLocal}, nil
	})
	s, pending := gatedExec(t, m, []string{"kubectl", "rollout", "restart", "deploy/web"})

	c, ok := rec.first()
	if !ok {
		t.Fatal("a gated exec must produce a Change — it is the thing a human reviews")
	}
	if !strings.Contains(c.Intent, "kubectl rollout restart deploy/web") {
		t.Errorf("intent = %q, want the command", c.Intent)
	}
	if c.PolicyRule == "" {
		t.Error("the Change must name the rule that gated it")
	}
	if c.SessionID != s.ID {
		t.Errorf("session = %q, want %q", c.SessionID, s.ID)
	}
	// Attribution: which agent, which model.
	if c.AgentName != "qwen-local" || c.AgentModel != "qwen2.5-coder:32b" {
		t.Errorf("the Change must attribute the proposal to a model: %+v", c.Proposer)
	}
	if c.PolicyHash == "" {
		t.Error("the Change must record the policy it ran under")
	}
	// The gate and the Change must be linked, or a reviewer cannot get from one to
	// the other.
	if pending.ExecID == "" || !strings.Contains(c.ID, pending.ExecID) {
		t.Errorf("change id %q must reference exec %q", c.ID, pending.ExecID)
	}
	// And the review gate is open.
	rec.mu.Lock()
	opened := len(rec.opened)
	rec.mu.Unlock()
	if opened != 1 {
		t.Errorf("the Change's review gate should be open, opened=%d", opened)
	}
}

// TestThePinnedPlanIsWhatWillActuallyRun. After an F4.4 dry-run rewrite the
// approved argv DIFFERS from the original — terraform plan becomes terraform
// apply of the saved plan — and pinning the original would pin something that is
// never executed.
//
// The two argvs are passed explicitly rather than driven through a real dry-run,
// because with a command that has no rewrite they are identical and the test
// cannot tell the two apart. That is exactly how an earlier version of this test
// let the mutation survive.
func TestThePinnedPlanIsWhatWillActuallyRun(t *testing.T) {
	rec := newRecordingChanges()
	m, _ := gateManager(t, rec, nil)
	s := &Session{ID: "s1", ProjectID: "p", EnvironmentID: "p.e", policyHash: "ph"}

	requested := []string{"terraform", "plan"}
	willRun := []string{"terraform", "apply", "/workspace/.opslify-plan-e1.tfplan"}
	id := m.recordGatedChange(s, "e1", ExecOptions{Argv: requested}, willRun,
		policy.Decision{Rule: "approval_required:terraform", Reason: "gated"}, "diff", nil,
		change.Inverse{Kind: change.InverseNone, Reason: "terraform state cannot be rolled back"})
	if id == "" {
		t.Fatal("a Change should have been recorded")
	}

	rec.mu.Lock()
	steps := rec.previewed[id]
	rec.mu.Unlock()
	if len(steps) != 1 {
		t.Fatalf("want one pinned step, got %v", steps)
	}
	if got := strings.Join(steps[0].Argv, " "); got != strings.Join(willRun, " ") {
		t.Fatalf("pinned argv = %q, want the command that WILL RUN (%q), not the one requested",
			got, strings.Join(willRun, " "))
	}
	if !steps[0].Gated {
		t.Error("the pinned step must be marked as the gated one")
	}
	// The intent still shows what the agent ASKED for, which is what a reviewer
	// recognises; the plan shows what will happen.
	c, _ := rec.first()
	if !strings.Contains(c.Intent, "terraform plan") {
		t.Errorf("intent = %q, want the requested command", c.Intent)
	}
}

// TestAnUnknownCommandIsNotClaimedRevertible. Claiming revertibility that does
// not exist changes what an operator is willing to approve, so an unrecognised
// command must not inherit an optimistic default.
func TestAnUnknownCommandIsNotClaimedRevertible(t *testing.T) {
	for _, argv := range [][]string{
		{"kubectl", "delete", "deploy/web"},
		{"terraform", "apply"},
		{"some-unknown-tool", "--destroy"},
		nil,
	} {
		inv := inverseForExec(argv)
		if inv.Available() {
			t.Errorf("argv %v must not be claimed revertible without a prepared inverse", argv)
		}
		if strings.TrimSpace(inv.Reason) == "" {
			t.Errorf("argv %v: an unavailable inverse must say why", argv)
		}
		if err := inv.Validate(); err != nil {
			t.Errorf("argv %v produced an invalid inverse: %v", argv, err)
		}
	}
	// Terraform is named specifically, because it is the case where a false claim
	// would be most damaging.
	if !strings.Contains(inverseForExec([]string{"terraform", "apply"}).Reason, "terraform state") {
		t.Error("the terraform reason should name why re-apply does not roll back")
	}
}

// TestBlastRadiusIsCountedOrAbsentNeverGuessed. An invented count is worse than
// an absent one: an operator reading "1 deployment" acts on it.
func TestBlastRadiusIsCountedOrAbsentNeverGuessed(t *testing.T) {
	// A single named resource can be counted honestly.
	got := blastForExec([]string{"kubectl", "rollout", "restart", "deploy/web"})
	if len(got) != 1 || got[0].Count != 1 || got[0].Kind != "deploys" {
		t.Errorf("a single named resource should count as one: %+v", got)
	}
	// Anything affecting an unknown number must report NOTHING rather than guess.
	for _, argv := range [][]string{
		{"kubectl", "delete", "pods", "--all"},
		{"kubectl", "delete", "pods", "-l", "app=web"},
		{"kubectl", "delete", "pods", "--selector", "app=web"},
		{"kubectl", "get", "pods", "-A"},
		// A NAMED resource plus a selector: "this one and whatever else matches".
		// Counting the named one as the whole blast radius would understate it,
		// which is the most dangerous direction to be wrong in.
		{"kubectl", "delete", "deploy/web", "-l", "tier=frontend"},
		{"kubectl", "delete", "deploy/web", "--all"},
		{"kubectl", "rollout", "restart", "deploy/web", "--all-namespaces"},
		{"kubectl", "apply", "-f", "everything.yaml"},
		{"terraform", "apply"},
		{"rm", "-rf", "/"},
	} {
		if b := blastForExec(argv); len(b) != 0 {
			t.Errorf("argv %v affects an unknown number and must be uncounted, got %+v", argv, b)
		}
	}
	// And an uncounted radius renders honestly rather than implying zero impact.
	if (change.Change{}).BlastSummary() != "none counted" {
		t.Error("an uncounted blast radius must say so")
	}
}

// TestAChangeFailureNeverOpensTheGate is the safety ordering: the gate is the
// control, the Change is the review surface over it. Degrading the surface must
// not remove the control.
func TestAChangeFailureNeverOpensTheGate(t *testing.T) {
	rec := newRecordingChanges()
	rec.proposeErr = errors.New("change store unwritable")
	m, _ := gateManager(t, rec, nil)

	// The command must STILL be gated: the process is not spawned.
	_, pending := gatedExec(t, m, []string{"kubectl", "delete", "deploy/web"})
	if pending.ExecID == "" {
		t.Fatal("the gate must still be registered when the Change cannot be recorded")
	}
	if c, ok := rec.first(); ok {
		t.Fatalf("no Change should have been recorded: %+v", c)
	}
}

// TestNoChangeRecorderIsNotFatal keeps the seam optional for every pre-P8 path.
func TestNoChangeRecorderIsNotFatal(t *testing.T) {
	m, _ := gateManager(t, nil, nil)
	if _, pending := gatedExec(t, m, []string{"kubectl", "delete", "deploy/web"}); pending.ExecID == "" {
		t.Fatal("a gate must work with no Change recorder wired")
	}
}

// TestAnUnattributedSessionIsSaidToBeUnattributed rather than silently blank: a
// Change with an empty proposer would fail validation, and inventing one would be
// worse than admitting we do not know.
func TestAnUnattributedSessionIsSaidToBeUnattributed(t *testing.T) {
	rec := newRecordingChanges()
	m, _ := gateManager(t, rec, nil) // no agent source: nothing bound
	gatedExec(t, m, []string{"kubectl", "delete", "deploy/web"})

	c, ok := rec.first()
	if !ok {
		t.Fatal("a Change should still be recorded with no agent bound")
	}
	if !strings.Contains(c.Proposer.Name, "unattributed") {
		t.Errorf("proposer = %q; with no agent bound it must say so rather than look attributed", c.Proposer.Name)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("the recorded Change must be valid: %v", err)
	}
}

// TestTheGateEventLinksToTheChange: a reviewer needs to get from one to the other.
func TestTheGateEventLinksToTheChange(t *testing.T) {
	rec := newRecordingChanges()
	m, _ := gateManager(t, rec, nil)
	ctx := context.Background()
	s, pending := gatedExec(t, m, []string{"kubectl", "delete", "deploy/web"})
	_ = m.Destroy(ctx, s.ID)

	events, _, err := m.TraceExport(ctx, s.ID)
	if err != nil {
		t.Fatalf("TraceExport: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.Type != trace.TypeApprovalRequested {
			continue
		}
		found = true
		if got := e.Payload["change_id"]; got != "chg-"+pending.ExecID {
			t.Errorf("approval.requested change_id = %v, want chg-%s", got, pending.ExecID)
		}
	}
	if !found {
		t.Fatal("no approval.requested event was emitted")
	}
}
