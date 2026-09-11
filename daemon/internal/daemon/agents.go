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
	// AddDriven registers an agent opslify will DRIVE, verified by running it
	// rather than by an MCP handshake. The two directions are opposite: F8.5
	// registers an agent opslify CALLS and proves it with a handshake; a driven
	// agent is an MCP client that calls opslify and need not serve it at all.
	AddDriven(ctx context.Context, a agents.Agent, verify func(context.Context, agents.Agent) error) error
}

// AgentDriver hands a registered agent a prompt and streams what it produces.
// Separate from AgentRegistry because a daemon may have a registry without a
// runner wired (the routes then stay absent rather than 500).
type AgentDriver interface {
	Run(ctx context.Context, name string, req agents.RunRequest, sink agents.RunSink) error
}

// registerAgentRoutes adds the F8.5 endpoints when the registry is wired.
func (d *Daemon) registerAgentRoutes(mux *http.ServeMux) {
	if d.agents == nil {
		return
	}
	mux.HandleFunc("POST /"+APIVersion+"/agents", d.handleAgentAdd)
	mux.HandleFunc("POST /"+APIVersion+"/agents/test", d.handleAgentTest)
	mux.HandleFunc("GET /"+APIVersion+"/agents", d.handleAgentList)
	mux.HandleFunc("GET /"+APIVersion+"/agents/catalogue", d.handleAgentCatalogue)
	mux.HandleFunc("POST /"+APIVersion+"/agents/install", d.handleAgentInstall)
	mux.HandleFunc("POST /"+APIVersion+"/agents/{name}/bind", d.handleAgentBind)
	mux.HandleFunc("DELETE /"+APIVersion+"/agents/{name}", d.handleAgentDelete)
	if d.agentDriver != nil {
		mux.HandleFunc("POST /"+APIVersion+"/agents/{name}/run", d.handleAgentRun)
	}
}

// handleAgentCatalogue lists the agents the daemon knows how to set up, with
// per-host detection. Read-only and safe: it names no filesystem layout beyond
// the resolved path of a binary the operator already installed.
func (d *Daemon) handleAgentCatalogue(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"entries": agents.Catalogue()})
}

// installAgentRequest names a CATALOGUE ENTRY, not a command.
//
// That distinction is the whole reason this route can be reachable from a browser
// while POST /v1/agents cannot. Registering an agent probes it, which runs a
// command on the host; here the command comes from the daemon's compile-time
// catalogue and the request may only choose among them. Name and model are
// caller-supplied because neither is executed.
type installAgentRequest struct {
	Entry string `json:"entry"`
	Name  string `json:"name,omitempty"`
	Model string `json:"model,omitempty"`
	// BaseURL points an OpenAI-compatible agent at its provider. A URL, not a
	// credential.
	BaseURL string `json:"base_url,omitempty"`
	// APIKeyRef names a vault secret. A ref, never a value: a key in this body
	// would be stored in the agent record in clear and rendered into every
	// listing that shows an agent.
	APIKeyRef string `json:"api_key_ref,omitempty"`
}

func (d *Daemon) handleAgentInstall(w http.ResponseWriter, r *http.Request) {
	var body installAgentRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	entry, ok := agents.CatalogueEntryByID(body.Entry)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "input",
			"unknown agent "+body.Entry+"; GET /v1/agents/catalogue lists what this daemon can set up")
		return
	}
	a, found := entry.ResolveWith(body.Name, body.Model, body.BaseURL, body.APIKeyRef)
	if !found {
		writeAPIError(w, http.StatusBadRequest, "agent",
			entry.Title+" is not installed at any location this daemon looks in. "+
				"Install it, or register it by path with `opslify agent add --command /path/to/it`.")
		return
	}
	// Which verification an entry gets is a property of the entry, not a choice
	// made here: a command that serves MCP gets the handshake and its tool list; a
	// command that only consumes MCP gets a liveness check. Reported either way,
	// so an operator can see what was actually established.
	if entry.ServesMCP {
		tools, err := d.agents.Add(r.Context(), a)
		if err != nil {
			writeAgentError(w, err)
			return
		}
		resp := agentResp(a, tools)
		resp.Verified = "mcp-handshake"
		writeJSON(w, http.StatusCreated, resp)
		return
	}
	verifyArgs := entry.VerifyArgs
	err := d.agents.AddDriven(r.Context(), a, func(ctx context.Context, ag agents.Agent) error {
		return agents.VerifyRuns(ctx, ag, verifyArgs)
	})
	if err != nil {
		writeAgentError(w, err)
		return
	}
	resp := agentResp(a, nil)
	resp.Verified = "runs"
	writeJSON(w, http.StatusCreated, resp)
}

// runAgentRequest is the POST /v1/agents/{name}/run body.
type runAgentRequest struct {
	Prompt        string `json:"prompt"`
	ProjectID     string `json:"project_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
}

// handleAgentRun streams the agent's output as newline-delimited JSON, the same
// frame shape as exec — so one reader in the cockpit handles both.
//
// Streaming rather than a single reply is not a nicety. A model working through
// an estate takes minutes, and an operator who cannot see what it is doing until
// it finishes cannot stop it doing the wrong thing.
func (d *Daemon) handleAgentRun(w http.ResponseWriter, r *http.Request) {
	var body runAgentRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	sink := newHTTPSink(w)
	err := d.agentDriver.Run(r.Context(), r.PathValue("name"), agents.RunRequest{
		Prompt:        body.Prompt,
		ProjectID:     body.ProjectID,
		EnvironmentID: body.EnvironmentID,
	}, sink)
	if err != nil {
		if !sink.wrote {
			writeAgentError(w, err)
			return
		}
		_ = sink.errorFrame(err)
	}
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
	Flavour     string   `json:"flavour,omitempty"`
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
		Flavour: agents.Flavour(r.Flavour),
	}
}

type agentResponse struct {
	Name       string   `json:"name"`
	ModelHint  string   `json:"model_hint,omitempty"`
	Locality   string   `json:"locality"`
	Disclosure string   `json:"disclosure"`
	Tools      []string `json:"tools,omitempty"`
	Flavour    string   `json:"flavour,omitempty"`
	BaseURL    string   `json:"base_url,omitempty"`
	APIKeyRef  string   `json:"api_key_ref,omitempty"`
	// Verified says WHAT was established at registration: "mcp-handshake" means
	// the command spoke the protocol and its tools were listed; "runs" means only
	// that the binary started. Stating which keeps a registration from claiming
	// more than it checked.
	Verified string `json:"verified,omitempty"`
	// Drivable says whether this agent can be given a prompt. The cockpit needs
	// it to decide whether the composer is usable, and an operator needs to know
	// why it is not.
	Drivable bool `json:"drivable"`
}

func agentResp(a agents.Agent, tools []string) agentResponse {
	return agentResponse{
		Name: a.Name, ModelHint: a.ModelHint, Locality: string(a.Locality),
		// The disclosure travels with the record so a UI cannot forget to render
		// it, and so it is the same sentence everywhere.
		Disclosure: a.Locality.Discloses(),
		Tools:      tools,
		Flavour:    string(a.Flavour),
		BaseURL:    a.BaseURL,
		APIKeyRef:  a.APIKeyRef,
		Drivable:   a.Drivable(),
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
