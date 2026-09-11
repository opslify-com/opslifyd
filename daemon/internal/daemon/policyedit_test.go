package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/change"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/policyedit"
)

// fakeEditor records what the routes composed and handed to the service.
type fakeEditor struct {
	current  policy.Policy
	resolved policy.Resolved
	got      policyedit.Edit
	proposer change.Proposer
	out      policyedit.Outcome
	err      error
}

func (f *fakeEditor) Resolved(p, e string) (policy.Resolved, error) { return f.resolved, f.err }
func (f *fakeEditor) Current(s policyedit.Scope) (policy.Policy, error) {
	return f.current, f.err
}
func (f *fakeEditor) Submit(e policyedit.Edit, pr change.Proposer) (policyedit.Outcome, error) {
	f.got, f.proposer = e, pr
	return f.out, f.err
}

func editorDaemon(t *testing.T, ed PolicyEditor) *Daemon {
	t.Helper()
	d, err := New(Options{PolicyEditor: ed, Verifier: okVerifier()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func postEdit(t *testing.T, d *Daemon, body, peer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/edit", strings.NewReader(body))
	if peer != "" {
		req = req.WithContext(withPeerIdentity(req.Context(), peer))
	}
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, req)
	return rec
}

// TestTheRouteComposesAWholeDocument: the wire is additive so an operator need not
// resend everything, but the thing classified and reviewed must be a COMPLETE
// policy — otherwise the approved artefact and the applied one differ.
func TestTheRouteComposesAWholeDocument(t *testing.T) {
	ed := &fakeEditor{
		current: policy.Policy{
			Egress:           policy.Egress{Domains: []string{"a.example.com"}},
			ApprovalRequired: []string{"^kubectl delete"},
		},
		out: policyedit.Outcome{Applied: true, Classification: policy.Classification{Direction: policy.DirectionNarrowing}},
	}
	d := editorDaemon(t, ed)
	rec := postEdit(t, d, `{"environment_id":"tripon.prod","add_egress":["b.example.com"],"remove_gates":["^kubectl delete"]}`, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	to := ed.got.To
	// The existing host must survive, the new one must be added.
	if len(to.Egress.Domains) != 2 {
		t.Fatalf("composed egress = %v, want both the existing and the added host", to.Egress.Domains)
	}
	// The removal must have taken effect.
	if len(to.ApprovalRequired) != 0 {
		t.Errorf("composed gates = %v, want the removal applied", to.ApprovalRequired)
	}
	// And the scope came from the request.
	if ed.got.Scope.EnvironmentID != "tripon.prod" || ed.got.Scope.Layer != policyedit.LayerEnvironment {
		t.Errorf("scope = %+v", ed.got.Scope)
	}
}

// TestCompositionIsOrderIndependent: two operators making the same edit must
// produce the same document, or the policy hash would differ for no reason.
func TestCompositionIsOrderIndependent(t *testing.T) {
	base := policy.Policy{Egress: policy.Egress{Domains: []string{"b.example.com", "a.example.com"}}}
	one := applyPolicyEdit(base, policyEditRequest{AddEgress: []string{"c.example.com", "d.example.com"}})
	two := applyPolicyEdit(base, policyEditRequest{AddEgress: []string{"d.example.com", "c.example.com"}})
	if policy.Hash(one) != policy.Hash(two) {
		t.Fatalf("the same edit in a different order produced different documents:\n%v\n%v",
			one.Egress.Domains, two.Egress.Domains)
	}
	// Adding something already present is a no-op, not a duplicate.
	dup := applyPolicyEdit(base, policyEditRequest{AddEgress: []string{"a.example.com"}})
	if len(dup.Egress.Domains) != 2 {
		t.Errorf("adding an existing host duplicated it: %v", dup.Egress.Domains)
	}
}

// TestAWideningEditIs202NotOK. A 200 reads as "done", which is the one thing a
// pending edit is not.
func TestAWideningEditIs202NotOK(t *testing.T) {
	ed := &fakeEditor{out: policyedit.Outcome{
		Applied: false, ChangeID: "chg-1",
		Classification: policy.Classification{Direction: policy.DirectionWidening,
			Widenings: []string{"egress host allowed: evil.example.com"}},
	}}
	d := editorDaemon(t, ed)
	rec := postEdit(t, d, `{"environment_id":"tripon.prod","add_egress":["evil.example.com"]}`, "alice")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	var out policyEditResponse
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Applied {
		t.Error("a widening must not report itself applied")
	}
	if out.ChangeID != "chg-1" {
		t.Errorf("the response must carry the change to review, got %q", out.ChangeID)
	}
	if len(out.Widenings) == 0 {
		t.Error("the response must name what is being opened")
	}
	// No policy hash: nothing was applied, and returning one would imply otherwise.
	if out.Hash != "" {
		t.Errorf("a pending edit must not report a new policy hash, got %q", out.Hash)
	}
}

// TestAnUnattributableEditIsRefused: an edit that loosens a guardrail must name
// who asked for it.
func TestAnUnattributableEditIsRefused(t *testing.T) {
	ed := &fakeEditor{}
	d := editorDaemon(t, ed)
	rec := postEdit(t, d, `{"environment_id":"tripon.prod","add_egress":["x.example.com"]}`, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ed.proposer.Name != "" {
		t.Error("the editor was called despite no attribution")
	}
}

// TestTheEditIsAttributedToTheSocketPeer.
func TestTheEditIsAttributedToTheSocketPeer(t *testing.T) {
	ed := &fakeEditor{out: policyedit.Outcome{Applied: true}}
	d := editorDaemon(t, ed)
	postEdit(t, d, `{"environment_id":"tripon.prod","add_gates":["^kubectl apply"]}`, "alice (uid 1000, pid 7)")
	if !strings.Contains(ed.proposer.Name, "alice") {
		t.Fatalf("proposer = %q, want the socket peer", ed.proposer.Name)
	}
	if ed.proposer.Kind != change.ProposerHuman {
		t.Errorf("a policy edit is proposed by a human, got %q", ed.proposer.Kind)
	}
}

// TestReadOnlyLayerIs403NotBadRequest: the request is well-formed and the
// operator may have the authority — it is the wrong route, and saying so sends
// them to the right one.
func TestReadOnlyLayerIs403NotBadRequest(t *testing.T) {
	ed := &fakeEditor{err: policyedit.ErrReadOnlyLayer}
	d := editorDaemon(t, ed)
	rec := postEdit(t, d, `{"environment_id":"tripon.prod","add_egress":["x.example.com"]}`, "alice")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// TestShowReportsPrecedenceAndWhatIsEditable: an operator looking at a policy they
// cannot change needs to be told where it comes from, at the moment they look.
func TestShowReportsPrecedenceAndWhatIsEditable(t *testing.T) {
	ed := &fakeEditor{resolved: policy.Resolved{
		Policy: policy.Policy{Egress: policy.Egress{Domains: []string{"a.example.com"}}},
		Hash:   "abc123",
		Notes:  []string{"environment: egress clamped to the daemon set"},
	}}
	d := editorDaemon(t, ed)
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policy?env=tripon.prod", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var out resolvedPolicyResponse
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Layers) != 4 {
		t.Fatalf("want all four layers in the precedence chain, got %d", len(out.Layers))
	}
	var editable int
	for _, l := range out.Layers {
		if l.Editable {
			editable++
		}
		if l.Note == "" {
			t.Errorf("layer %s carries no explanation", l.Layer)
		}
	}
	if editable != 2 {
		t.Errorf("exactly project and environment are editable, got %d", editable)
	}
	// Clamps must be visible: a silently-clamped policy looks like one that was
	// simply ignored.
	if len(out.Clamps) == 0 {
		t.Error("clamps must be reported")
	}
}

// TestDiffComparesResolvedScopes: two identical documents can resolve differently
// under different baselines, so the comparison must be of what is in force.
func TestDiffComparesResolvedScopes(t *testing.T) {
	ed := &fakeEditor{resolved: policy.Resolved{Policy: policy.Policy{}, Hash: "h"}}
	d := editorDaemon(t, ed)
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policy/diff?a=x&b=y", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out policyDiffResponse
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Direction != string(policy.DirectionEquivalent) {
		t.Errorf("two identical resolutions must be equivalent, got %q", out.Direction)
	}
	// Missing scopes are an error, not an empty diff.
	rec2 := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/v1/policy/diff?a=x", nil))
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("a diff with one scope must be refused, got %d", rec2.Code)
	}
}

// TestPolicyRoutesAreAbsentWithoutAnEditor.
func TestPolicyRoutesAreAbsentWithoutAnEditor(t *testing.T) {
	d, err := New(Options{Verifier: okVerifier()})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policy", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("with no editor the policy routes must be absent, got %d", rec.Code)
	}
}
