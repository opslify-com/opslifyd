package daemon

import (
	"context"
	"errors"
	"net/http"
	"sort"

	"github.com/opslify-com/opslifyd/internal/agents"
)

// AgentRegistry is the narrow view the daemon needs of the F8.5 registry. An
// interface so the HTTP layer is testable without a store or a real MCP command.
type AgentRegistry interface {
	Add(ctx context.Context, a agents.Agent) ([]string, error)
	Test(ctx context.Context, a agents.Agent) ([]string, error)
	List() ([]agents.Agent, error)
	Bindings() (map[string]string, error)
	Use(projectID, environmentID, agentName string) error
	Remove(name string) error
}

// registerAgentRoutes adds the F8.5 endpoints when the registry is wired.
func (d *Daemon) registerAgentRoutes(mux *http.ServeMux) {
	if d.agents == nil {
		return
	}
	mux.HandleFunc("POST /"+APIVersion+"/agents", d.handleAgentAdd)
	mux.HandleFunc("POST /"+APIVersion+"/agents/test", d.handleAgentTest)
	mux.HandleFunc("GET /"+APIVersion+"/agents", d.handleAgentList)
	mux.HandleFunc("POST /"+APIVersion+"/agents/{name}/bind", d.handleAgentBind)
	mux.HandleFunc("DELETE /"+APIVersion+"/agents/{name}", d.handleAgentDelete)
}

// addAgentRequest is the POST body. No credential field, by construction.
type addAgentRequest struct {
	Name        string   `json:"name"`
	Command     string   `json:"command"`
	Args        []string `json:"args,omitempty"`
	ModelHint   string   `json:"model_hint,omitempty"`
	Locality    string   `json:"locality,omitempty"`
	EnvAllow    []string `json:"env_allow,omitempty"`
	Description string   `json:"description,omitempty"`
}

func (r addAgentRequest) agent() agents.Agent {
	loc := agents.Locality(r.Locality)
	if loc == "" {
		// An omitted locality is UNKNOWN, never assumed local: claiming prompts stay
		// on-host when nobody said so would be a lie by default.
		loc = agents.LocalityUnknown
	}
	return agents.Agent{
		Name: r.Name, Command: r.Command, Args: r.Args, ModelHint: r.ModelHint,
		Locality: loc, EnvAllow: r.EnvAllow, Description: r.Description,
	}
}

type agentResponse struct {
	Name       string   `json:"name"`
	ModelHint  string   `json:"model_hint,omitempty"`
	Locality   string   `json:"locality"`
	Disclosure string   `json:"disclosure"`
	Tools      []string `json:"tools,omitempty"`
}

func agentResp(a agents.Agent, tools []string) agentResponse {
	return agentResponse{
		Name: a.Name, ModelHint: a.ModelHint, Locality: string(a.Locality),
		// The disclosure travels with the record so a UI cannot forget to render
		// it, and so it is the same sentence everywhere.
		Disclosure: a.Locality.Discloses(),
		Tools:      tools,
	}
}

type agentBindingResponse struct {
	Scope string `json:"scope"`
	Agent string `json:"agent"`
}

type agentListResponse struct {
	Agents   []agentResponse        `json:"agents"`
	Bindings []agentBindingResponse `json:"bindings,omitempty"`
}

func (d *Daemon) handleAgentAdd(w http.ResponseWriter, r *http.Request) {
	var body addAgentRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	a := body.agent()
	tools, err := d.agents.Add(r.Context(), a)
	if err != nil {
		writeAgentError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, agentResp(a, tools))
}

func (d *Daemon) handleAgentTest(w http.ResponseWriter, r *http.Request) {
	var body addAgentRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	a := body.agent()
	tools, err := d.agents.Test(r.Context(), a)
	if err != nil {
		writeAgentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agentResp(a, tools))
}

func (d *Daemon) handleAgentList(w http.ResponseWriter, r *http.Request) {
	list, err := d.agents.List()
	if err != nil {
		writeAgentError(w, err)
		return
	}
	bindings, err := d.agents.Bindings()
	if err != nil {
		writeAgentError(w, err)
		return
	}
	out := agentListResponse{Agents: make([]agentResponse, 0, len(list))}
	for _, a := range list {
		out.Agents = append(out.Agents, agentResp(a, nil))
	}
	scopes := make([]string, 0, len(bindings))
	for scope := range bindings {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	for _, scope := range scopes {
		out.Bindings = append(out.Bindings, agentBindingResponse{Scope: scope, Agent: bindings[scope]})
	}
	writeJSON(w, http.StatusOK, out)
}

func (d *Daemon) handleAgentBind(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := d.agents.Use(r.URL.Query().Get("project"), r.URL.Query().Get("env"), name); err != nil {
		writeAgentError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *Daemon) handleAgentDelete(w http.ResponseWriter, r *http.Request) {
	if err := d.agents.Remove(r.PathValue("name")); err != nil {
		writeAgentError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeAgentError maps a registry error to a layer-tagged status.
//
// An unusable agent is 422, not 400: the request was well-formed and the record
// is valid — the COMMAND did not answer. Conflating the two would have an
// operator re-reading their flags when the problem is their binary.
func writeAgentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, agents.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "agent", err.Error())
	case errors.Is(err, agents.ErrExists):
		writeAPIError(w, http.StatusConflict, "agent", err.Error())
	case errors.Is(err, agents.ErrInvalidInput):
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
	case errors.Is(err, agents.ErrUnusable):
		writeAPIError(w, http.StatusUnprocessableEntity, "agent", err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "agent", err.Error())
	}
}
