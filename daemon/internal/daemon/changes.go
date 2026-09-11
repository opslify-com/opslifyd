package daemon

import (
	"errors"
	"net/http"

	"github.com/opslify-com/opslifyd/internal/change"
)

// ChangeService is the narrow view the daemon needs of the F8.6 service.
type ChangeService interface {
	Get(id string) (change.Change, error)
	List() ([]change.Change, error)
	Approve(id, decidedBy, note string, stepsAboutToRun []change.Step) (change.Change, error)
	Deny(id, decidedBy, note string) (change.Change, error)
	Revert(id, decidedBy string) (change.Change, error)
}

// registerChangeRoutes adds the F8.6 endpoints when the service is wired.
func (d *Daemon) registerChangeRoutes(mux *http.ServeMux) {
	if d.changes == nil {
		return
	}
	mux.HandleFunc("GET /"+APIVersion+"/changes", d.handleChangeList)
	mux.HandleFunc("GET /"+APIVersion+"/changes/{id}", d.handleChangeGet)
	mux.HandleFunc("POST /"+APIVersion+"/changes/{id}/decision", d.handleChangeDecision)
}

type changeStepResponse struct {
	Index int      `json:"index"`
	Argv  []string `json:"argv"`
	Gated bool     `json:"gated,omitempty"`
}

// changeResponse is a Change on the wire.
//
// Revertibility is computed HERE and sent as an answer plus a reason, rather than
// as raw inverse fields a client would interpret. A client deriving it separately
// could derive it differently, and an operator would be reading a second opinion
// at the moment it matters most.
type changeResponse struct {
	ID             string               `json:"id"`
	Intent         string               `json:"intent"`
	Status         string               `json:"status"`
	ProposerName   string               `json:"proposer_name"`
	ProposerModel  string               `json:"proposer_model,omitempty"`
	ProjectID      string               `json:"project_id,omitempty"`
	EnvironmentID  string               `json:"environment_id,omitempty"`
	BlastSummary   string               `json:"blast_summary"`
	Revertible     bool                 `json:"revertible"`
	RevertReason   string               `json:"revert_reason,omitempty"`
	InverseKind    string               `json:"inverse_kind,omitempty"`
	PolicyRule     string               `json:"policy_rule,omitempty"`
	PolicyEffect   string               `json:"policy_effect,omitempty"`
	PolicyHash     string               `json:"policy_hash,omitempty"`
	ContextHash    string               `json:"context_hash,omitempty"`
	AgentName      string               `json:"agent_name,omitempty"`
	AgentModel     string               `json:"agent_model,omitempty"`
	SessionID      string               `json:"session_id,omitempty"`
	PlanHash       string               `json:"plan_hash,omitempty"`
	ConnectionRefs []string             `json:"connection_refs,omitempty"`
	Steps          []changeStepResponse `json:"steps,omitempty"`
	Preview        string               `json:"preview,omitempty"`
}

func changeResp(c change.Change) changeResponse {
	revertible, reason := c.Revertible()
	out := changeResponse{
		ID: c.ID, Intent: c.Intent, Status: string(c.Status),
		ProposerName: c.Proposer.Name, ProposerModel: c.Proposer.Model,
		ProjectID: c.ProjectID, EnvironmentID: c.EnvironmentID,
		BlastSummary: c.BlastSummary(),
		Revertible:   revertible, RevertReason: reason,
		InverseKind: string(c.Inverse.Kind),
		PolicyRule:  c.PolicyRule, PolicyEffect: c.PolicyEffect,
		PolicyHash: c.PolicyHash, ContextHash: c.ContextHash,
		AgentName: c.AgentName, AgentModel: c.AgentModel,
		SessionID: c.SessionID, PlanHash: c.PlanHash,
		ConnectionRefs: c.ConnectionRefs,
		Preview:        c.Preview,
	}
	for _, s := range c.Steps {
		out.Steps = append(out.Steps, changeStepResponse{Index: s.Index, Argv: s.Argv, Gated: s.Gated})
	}
	return out
}

func (d *Daemon) handleChangeList(w http.ResponseWriter, r *http.Request) {
	list, err := d.changes.List()
	if err != nil {
		writeChangeError(w, err)
		return
	}
	out := make([]changeResponse, 0, len(list))
	for _, c := range list {
		out = append(out, changeResp(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (d *Daemon) handleChangeGet(w http.ResponseWriter, r *http.Request) {
	c, err := d.changes.Get(r.PathValue("id"))
	if err != nil {
		writeChangeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, changeResp(c))
}

// decideChangeRequest is a human decision.
type decideChangeRequest struct {
	Decision string `json:"decision"`
	Note     string `json:"note,omitempty"`
}

func (d *Daemon) handleChangeDecision(w http.ResponseWriter, r *http.Request) {
	var body decideChangeRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	id := r.PathValue("id")
	// The decision is attributed to the authenticated peer. It is taken from the
	// CONNECTION rather than the request body so a caller cannot approve as
	// somebody else — an approval names who accepted the blast radius, and a
	// self-declared identity would make that worthless.
	decidedBy := d.peerIdentity(r)
	if decidedBy == "" {
		// Refuse rather than record a placeholder. An approval whose "who" is a
		// stand-in is not an approval anyone can rely on later, and quietly writing
		// one would make the audit trail confidently wrong.
		writeAPIError(w, http.StatusForbidden, "change",
			"cannot attribute this decision: the peer identity could not be determined from the socket")
		return
	}

	var (
		c   change.Change
		err error
	)
	switch body.Decision {
	case "approve":
		// Steps are nil: the service re-verifies the pin against the change's own
		// stored plan. A caller supplying steps here could pin-match a plan of its
		// own choosing, which is the attack the pin exists to stop.
		c, err = d.changes.Approve(id, decidedBy, body.Note, nil)
	case "deny":
		c, err = d.changes.Deny(id, decidedBy, body.Note)
	case "revert":
		c, err = d.changes.Revert(id, decidedBy)
	default:
		writeAPIError(w, http.StatusBadRequest, "input",
			"decision must be approve, deny or revert")
		return
	}
	if err != nil {
		writeChangeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, changeResp(c))
}

// writeChangeError maps a change error to a layer-tagged status.
//
// A pin mismatch is 409, not 400: nothing about the REQUEST is malformed — the
// world moved underneath it. An operator who sees 400 re-reads their command;
// one who sees 409 goes and looks at what changed, which is the correct next
// action.
func writeChangeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, change.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "change", err.Error())
	case errors.Is(err, change.ErrPinMismatch):
		writeAPIError(w, http.StatusConflict, "change", err.Error())
	case errors.Is(err, change.ErrInvalidTransition):
		writeAPIError(w, http.StatusConflict, "change", err.Error())
	case errors.Is(err, change.ErrInvalidInput):
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "change", err.Error())
	}
}
