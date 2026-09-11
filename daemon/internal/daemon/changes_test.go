package daemon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/change"
)

// fakeChangeService records what the routes asked for.
type fakeChangeService struct {
	rec       change.Change
	approveBy string
	denyBy    string
	revertBy  string
	steps     []change.Step
	err       error
}

func (f *fakeChangeService) Get(id string) (change.Change, error) { return f.rec, f.err }
func (f *fakeChangeService) List() ([]change.Change, error)       { return []change.Change{f.rec}, f.err }

func (f *fakeChangeService) Approve(id, by, note string, steps []change.Step) (change.Change, error) {
	f.approveBy, f.steps = by, steps
	return f.rec, f.err
}
func (f *fakeChangeService) Deny(id, by, note string) (change.Change, error) {
	f.denyBy = by
	return f.rec, f.err
}
func (f *fakeChangeService) Revert(id, by string) (change.Change, error) {
	f.revertBy = by
	return f.rec, f.err
}

func sampleChange() change.Change {
	return change.Change{
		ID: "chg-1", Intent: "restart web", Status: change.StatusAwaitingApproval,
		Proposer:    change.Proposer{Kind: change.ProposerAgent, Name: "qwen", Model: "qwen2.5"},
		BlastRadius: []change.ResourceCount{{Kind: "deployments", Count: 1}},
		Inverse:     change.Inverse{Kind: change.InverseNone, Reason: "terraform state cannot be rolled back"},
		PlanHash:    "abc123",
	}
}

func changeDaemon(t *testing.T, svc ChangeService) *Daemon {
	t.Helper()
	d, err := New(Options{Changes: svc, Verifier: okVerifier()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

// decide posts a decision with an injected peer identity, standing in for the
// kernel-supplied credentials a real unix socket provides.
func decide(t *testing.T, d *Daemon, id, decision, peer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/changes/"+id+"/decision",
		strings.NewReader(`{"decision":"`+decision+`"}`))
	if peer != "" {
		req = req.WithContext(withPeerIdentity(req.Context(), peer))
	}
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, req)
	return rec
}

// TestDecisionIsAttributedToTheSocketPeerNotTheBody. An approval names who
// accepted a blast radius; taking that from the request body would let anyone
// approve as anyone.
func TestDecisionIsAttributedToTheSocketPeerNotTheBody(t *testing.T) {
	svc := &fakeChangeService{rec: sampleChange()}
	d := changeDaemon(t, svc)

	req := httptest.NewRequest(http.MethodPost, "/v1/changes/chg-1/decision",
		strings.NewReader(`{"decision":"approve","note":"ok"}`))
	req = req.WithContext(withPeerIdentity(req.Context(), "alice (uid 1000, pid 42)"))
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(svc.approveBy, "alice") {
		t.Fatalf("approver = %q, want the socket peer", svc.approveBy)
	}
	// A body field claiming a different identity must not be honoured — and since
	// the decoder rejects unknown fields, supplying one is an outright error.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/changes/chg-1/decision",
		strings.NewReader(`{"decision":"approve","decided_by":"root"}`))
	req2 = req2.WithContext(withPeerIdentity(req2.Context(), "alice"))
	rec2 := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("a body-supplied identity must be refused, got %d", rec2.Code)
	}
}

// TestUnattributableDecisionIsRefused: recording a placeholder would make the
// audit trail confidently wrong.
func TestUnattributableDecisionIsRefused(t *testing.T) {
	svc := &fakeChangeService{rec: sampleChange()}
	d := changeDaemon(t, svc)
	rec := decide(t, d, "chg-1", "approve", "") // no peer identity at all
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if svc.approveBy != "" {
		t.Errorf("the service was called despite no attribution: %q", svc.approveBy)
	}
}

// TestApproveNeverAcceptsCallerSuppliedSteps: a caller able to pass the steps
// could pin-match a plan of its own choosing, which is the attack the pin exists
// to stop.
func TestApproveNeverAcceptsCallerSuppliedSteps(t *testing.T) {
	svc := &fakeChangeService{rec: sampleChange()}
	d := changeDaemon(t, svc)
	if rec := decide(t, d, "chg-1", "approve", "alice"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if svc.steps != nil {
		t.Fatalf("the route passed steps (%v); the service must verify against its OWN stored plan", svc.steps)
	}
}

// TestPinMismatchIs409NotBadRequest: nothing about the REQUEST is malformed — the
// world moved underneath it. An operator who sees 400 re-reads their command; one
// who sees 409 goes and looks at what changed.
func TestPinMismatchIs409NotBadRequest(t *testing.T) {
	svc := &fakeChangeService{rec: sampleChange(), err: change.ErrPinMismatch}
	d := changeDaemon(t, svc)
	rec := decide(t, d, "chg-1", "approve", "alice")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

// TestRevertibilityIsAnsweredByTheDaemon: a client deriving it separately could
// derive it differently, and an operator would be reading a second opinion at the
// moment it matters most.
func TestRevertibilityIsAnsweredByTheDaemon(t *testing.T) {
	svc := &fakeChangeService{rec: sampleChange()}
	d := changeDaemon(t, svc)
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/changes/chg-1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"revertible":false`) {
		t.Errorf("the response must answer revertibility: %s", body)
	}
	if !strings.Contains(body, "terraform state cannot be rolled back") {
		t.Errorf("the response must carry the honest reason: %s", body)
	}
	if !strings.Contains(body, `"blast_summary":"1 deployments"`) {
		t.Errorf("blast radius must arrive counted: %s", body)
	}
}

// TestUnknownDecisionIsRefused.
func TestUnknownDecisionIsRefused(t *testing.T) {
	svc := &fakeChangeService{rec: sampleChange()}
	d := changeDaemon(t, svc)
	rec := decide(t, d, "chg-1", "maybe", "alice")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if svc.approveBy != "" || svc.denyBy != "" || svc.revertBy != "" {
		t.Error("an unknown decision reached the service")
	}
}

// TestChangeRoutesAreAbsentWithoutTheService.
func TestChangeRoutesAreAbsentWithoutTheService(t *testing.T) {
	d, err := New(Options{Verifier: okVerifier()})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/changes", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("with no service the change routes must be absent, got %d", rec.Code)
	}
}
