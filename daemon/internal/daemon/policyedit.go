package daemon

import (
	"errors"
	"net/http"
	"sort"

	"github.com/opslify-com/opslifyd/internal/change"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/policyedit"
)

// PolicyEditor is the narrow view the daemon needs of the F8.7 surface.
type PolicyEditor interface {
	// Resolved returns what is in force for a scope.
	Resolved(projectID, environmentID string) (policy.Resolved, error)
	// Current returns the editable layer's own document, which is what an edit
	// composes onto.
	Current(s policyedit.Scope) (policy.Policy, error)
	Submit(e policyedit.Edit, proposer change.Proposer) (policyedit.Outcome, error)
}

// registerPolicyEditRoutes adds the F8.7 endpoints when the editor is wired.
func (d *Daemon) registerPolicyEditRoutes(mux *http.ServeMux) {
	if d.policyEditor == nil {
		return
	}
	mux.HandleFunc("GET /"+APIVersion+"/policy", d.handlePolicyShow)
	mux.HandleFunc("GET /"+APIVersion+"/policy/diff", d.handlePolicyDiff)
	mux.HandleFunc("POST /"+APIVersion+"/policy/edit", d.handlePolicyEdit)
}

type policyLayerResponse struct {
	Layer    string `json:"layer"`
	Editable bool   `json:"editable"`
	Note     string `json:"note,omitempty"`
}

type resolvedPolicyResponse struct {
	Scope            string                `json:"scope,omitempty"`
	Hash             string                `json:"hash"`
	Layers           []policyLayerResponse `json:"layers"`
	EgressDomains    []string              `json:"egress_domains,omitempty"`
	ApprovalRequired []string              `json:"approval_required,omitempty"`
	SessionTTL       string                `json:"session_ttl,omitempty"`
	StrictExec       bool                  `json:"strict_exec"`
	Clamps           []string              `json:"clamps,omitempty"`
}

// precedence is the fixed layer order, rendered with WHY each is or is not
// editable here.
//
// Shipped with the response rather than documented elsewhere: an operator looking
// at a policy they cannot change needs to be told where it comes from, at the
// moment they are looking at it.
var precedence = []policyLayerResponse{
	{Layer: "daemon", Editable: false, Note: "host-side baseline; every layer below may only narrow it"},
	{Layer: "project", Editable: true, Note: "editable here"},
	{Layer: "environment", Editable: true, Note: "editable here"},
	{Layer: "workspace", Editable: false, Note: "repo-supplied and untrusted; changes by a reviewed commit"},
}

func (d *Daemon) handlePolicyShow(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	env := r.URL.Query().Get("env")
	resolved, err := d.policyEditor.Resolved(project, env)
	if err != nil {
		writePolicyEditError(w, err)
		return
	}
	scope := env
	if scope == "" {
		scope = project
	}
	p := resolved.Policy
	out := resolvedPolicyResponse{
		Scope: scope, Hash: resolved.Hash, Layers: precedence,
		EgressDomains: p.Egress.Domains, ApprovalRequired: p.ApprovalRequired,
		SessionTTL: p.Session.TTL, StrictExec: p.StrictExec,
		Clamps: resolved.Notes,
	}
	writeJSON(w, http.StatusOK, out)
}

type policyDiffResponse struct {
	Direction  string   `json:"direction"`
	Widenings  []string `json:"widenings,omitempty"`
	Narrowings []string `json:"narrowings,omitempty"`
	HashA      string   `json:"hash_a"`
	HashB      string   `json:"hash_b"`
}

// handlePolicyDiff compares two RESOLVED scopes.
//
// Resolved, not the documents on disk: what an operator wants to know is how the
// two environments actually differ in force, and two identical documents can
// resolve differently under different baselines.
func (d *Daemon) handlePolicyDiff(w http.ResponseWriter, r *http.Request) {
	a, b := r.URL.Query().Get("a"), r.URL.Query().Get("b")
	if a == "" || b == "" {
		writeAPIError(w, http.StatusBadRequest, "input", "diff needs two scopes: ?a=<scope>&b=<scope>")
		return
	}
	ra, err := d.policyEditor.Resolved("", a)
	if err != nil {
		writePolicyEditError(w, err)
		return
	}
	rb, err := d.policyEditor.Resolved("", b)
	if err != nil {
		writePolicyEditError(w, err)
		return
	}
	class := policy.ClassifyEdit(ra.Policy, rb.Policy)
	writeJSON(w, http.StatusOK, policyDiffResponse{
		Direction: string(class.Direction), Widenings: class.Widenings,
		Narrowings: class.Narrowings, HashA: ra.Hash, HashB: rb.Hash,
	})
}

// policyEditRequest is additive/subtractive on the wire.
type policyEditRequest struct {
	ProjectID     string   `json:"project_id,omitempty"`
	EnvironmentID string   `json:"environment_id,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	AddEgress     []string `json:"add_egress,omitempty"`
	RemoveEgress  []string `json:"remove_egress,omitempty"`
	AddGates      []string `json:"add_gates,omitempty"`
	RemoveGates   []string `json:"remove_gates,omitempty"`
}

type policyEditResponse struct {
	Applied    bool     `json:"applied"`
	Direction  string   `json:"direction"`
	ChangeID   string   `json:"change_id,omitempty"`
	Widenings  []string `json:"widenings,omitempty"`
	Narrowings []string `json:"narrowings,omitempty"`
	Hash       string   `json:"hash,omitempty"`
}

func (d *Daemon) handlePolicyEdit(w http.ResponseWriter, r *http.Request) {
	var body policyEditRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	// The edit is attributed to the socket peer, like every other human decision.
	// An edit that loosens a guardrail must name who asked for it.
	who := d.peerIdentity(r)
	if who == "" {
		writeAPIError(w, http.StatusForbidden, "policy",
			"cannot attribute this edit: the peer identity could not be determined from the socket")
		return
	}

	scope := policyedit.Scope{Layer: policyedit.LayerEnvironment,
		ProjectID: body.ProjectID, EnvironmentID: body.EnvironmentID}
	if body.EnvironmentID == "" {
		scope.Layer = policyedit.LayerProject
	}
	current, err := d.policyEditor.Current(scope)
	if err != nil {
		writePolicyEditError(w, err)
		return
	}
	// Compose the whole document HERE, then hand a complete policy to the service.
	// The wire is additive so an operator need not resend everything, but the thing
	// classified and reviewed is always a full document.
	to := applyPolicyEdit(current, body)

	out, err := d.policyEditor.Submit(policyedit.Edit{Scope: scope, To: to, Reason: body.Reason},
		change.Proposer{Kind: change.ProposerHuman, Name: who})
	if err != nil {
		writePolicyEditError(w, err)
		return
	}
	resp := policyEditResponse{
		Applied: out.Applied, Direction: string(out.Classification.Direction),
		ChangeID: out.ChangeID, Widenings: out.Classification.Widenings,
		Narrowings: out.Classification.Narrowings,
	}
	if out.Applied {
		resp.Hash = policy.Hash(to)
		writeJSON(w, http.StatusOK, resp)
		return
	}
	// 202 Accepted: the edit was understood and recorded, and is waiting on a
	// human. A 200 would read as "done", which is the one thing it is not.
	writeJSON(w, http.StatusAccepted, resp)
}

// applyPolicyEdit composes the requested additions and removals onto a document.
func applyPolicyEdit(p policy.Policy, req policyEditRequest) policy.Policy {
	p.Egress.Domains = addRemove(p.Egress.Domains, req.AddEgress, req.RemoveEgress)
	p.ApprovalRequired = addRemove(p.ApprovalRequired, req.AddGates, req.RemoveGates)
	return p
}

// addRemove applies a set edit, keeping the result sorted and duplicate-free so
// two operators making the same edit produce the same document.
//
// The sort is redundant for HASHING — policy.normalize sorts every set before the
// preimage is built, so an unsorted document already hashes identically. It is
// kept because the document is also written to disk and read by humans, and a
// file whose line order changes on every edit is a file nobody can diff.
func addRemove(cur, add, remove []string) []string {
	set := map[string]bool{}
	for _, s := range cur {
		set[s] = true
	}
	for _, s := range add {
		if s != "" {
			set[s] = true
		}
	}
	for _, s := range remove {
		delete(set, s)
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// writePolicyEditError maps an edit error to a layer-tagged status.
//
// A read-only layer is 403, not 400: the request is well-formed and the operator
// may well have the authority — it is the wrong ROUTE, and saying so sends them
// to the right one.
func writePolicyEditError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, policyedit.ErrReadOnlyLayer):
		writeAPIError(w, http.StatusForbidden, "policy", err.Error())
	case errors.Is(err, policyedit.ErrNeedsApproval):
		writeAPIError(w, http.StatusForbidden, "policy", err.Error())
	case errors.Is(err, policyedit.ErrInvalidInput):
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "policy", err.Error())
	}
}
