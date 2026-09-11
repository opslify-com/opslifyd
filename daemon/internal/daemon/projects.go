package daemon

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/opslify-com/opslifyd/internal/project"
)

// F8.1 project/environment surface. A project gathers a body of work (repo +
// capability map); an environment is a risk rung inside it. Nothing here carries
// a secret: a credential is always a ref resolved through the F5.6 broker, and a
// policy layer is referenced BY PATH, never by content.

// ProjectService is the subset of *project.Service the REST layer drives. It is
// an interface so the handlers are unit-testable with a fake, and so the daemon
// never reaches past the mediated surface.
type ProjectService interface {
	CreateProject(spec project.ProjectSpec) (project.Project, []project.Environment, error)
	Projects() ([]project.Project, error)
	Project(id string) (project.Project, []project.Environment, error)
	AddEnvironment(projectID string, spec project.EnvironmentSpec) (project.Environment, error)
	Environments(projectID string) ([]project.Environment, error)
	// RemoveEnvironment tears down the environment's sandboxes, then its record.
	RemoveEnvironment(ctx context.Context, projectID, environmentID string) error
	// RemoveProject refuses while anything under the project is live.
	RemoveProject(ctx context.Context, projectID string) error
	// SetCapabilities replaces the role → tool map.
	SetCapabilities(projectID string, caps map[string]string) (project.Project, error)
}

// registerProjectRoutes adds the F8.1 endpoints to mux. With no project service
// wired the routes stay 404 (the same opt-in shape as the session and secret
// surfaces).
func (d *Daemon) registerProjectRoutes(mux *http.ServeMux) {
	if d.projects == nil {
		return
	}
	mux.HandleFunc("POST /"+APIVersion+"/projects", d.handleProjectCreate)
	mux.HandleFunc("GET /"+APIVersion+"/projects", d.handleProjectList)
	mux.HandleFunc("GET /"+APIVersion+"/projects/{id}", d.handleProjectGet)
	mux.HandleFunc("DELETE /"+APIVersion+"/projects/{id}", d.handleProjectDelete)
	mux.HandleFunc("POST /"+APIVersion+"/projects/{id}/environments", d.handleEnvironmentAdd)
	mux.HandleFunc("GET /"+APIVersion+"/projects/{id}/environments", d.handleEnvironmentList)
	mux.HandleFunc("DELETE /"+APIVersion+"/projects/{id}/environments/{env}", d.handleEnvironmentDelete)
	mux.HandleFunc("PUT /"+APIVersion+"/projects/{id}/capabilities", d.handleCapabilitiesSet)
}

// createProjectRequest is the POST /v1/projects body.
type createProjectRequest struct {
	Name         string                  `json:"name"`
	RepoURL      string                  `json:"repo_url,omitempty"`
	Capabilities map[string]string       `json:"capabilities,omitempty"`
	PolicyFile   string                  `json:"policy_file,omitempty"`
	Environments []addEnvironmentRequest `json:"environments,omitempty"`
}

// addEnvironmentRequest is the POST /v1/projects/{id}/environments body (and one
// entry of a create's environment list).
type addEnvironmentRequest struct {
	Name          string `json:"name"`
	PolicyOverlay string `json:"policy_overlay,omitempty"`
	DefaultTier   string `json:"default_tier,omitempty"`
	DefaultTTL    string `json:"default_ttl,omitempty"`
	Production    bool   `json:"production,omitempty"`
}

func (r addEnvironmentRequest) spec() project.EnvironmentSpec {
	return project.EnvironmentSpec{
		Name:          r.Name,
		PolicyOverlay: r.PolicyOverlay,
		DefaultTier:   r.DefaultTier,
		DefaultTTL:    r.DefaultTTL,
		Production:    r.Production,
	}
}

// projectResponse is a project plus its environments — the GET /v1/projects/{id}
// body and the POST /v1/projects reply.
type projectResponse struct {
	ID           string                `json:"id"`
	Name         string                `json:"name"`
	Created      time.Time             `json:"created"`
	RepoURL      string                `json:"repo_url,omitempty"`
	Capabilities map[string]string     `json:"capabilities,omitempty"`
	PolicyFile   string                `json:"policy_file,omitempty"`
	Environments []environmentResponse `json:"environments"`
}

// environmentResponse is one environment record.
type environmentResponse struct {
	ID            string    `json:"id"`
	ProjectID     string    `json:"project_id"`
	Name          string    `json:"name"`
	Created       time.Time `json:"created"`
	PolicyOverlay string    `json:"policy_overlay,omitempty"`
	DefaultTier   string    `json:"default_tier,omitempty"`
	DefaultTTL    string    `json:"default_ttl,omitempty"`
	Production    bool      `json:"production"`
}

func environmentResp(e project.Environment) environmentResponse {
	return environmentResponse{
		ID:            e.ID,
		ProjectID:     e.ProjectID,
		Name:          e.Name,
		Created:       e.Created,
		PolicyOverlay: e.PolicyOverlay,
		DefaultTier:   e.DefaultTier,
		DefaultTTL:    e.DefaultTTL,
		Production:    e.Production,
	}
}

func projectResp(p project.Project, envs []project.Environment) projectResponse {
	out := projectResponse{
		ID:           p.ID,
		Name:         p.Name,
		Created:      p.Created,
		RepoURL:      p.RepoURL,
		Capabilities: p.Capabilities,
		PolicyFile:   p.PolicyFile,
		Environments: make([]environmentResponse, 0, len(envs)),
	}
	for _, e := range envs {
		out.Environments = append(out.Environments, environmentResp(e))
	}
	return out
}

func (d *Daemon) handleProjectCreate(w http.ResponseWriter, r *http.Request) {
	var body createProjectRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	spec := project.ProjectSpec{
		Name:         body.Name,
		RepoURL:      body.RepoURL,
		Capabilities: body.Capabilities,
		PolicyFile:   body.PolicyFile,
	}
	for _, e := range body.Environments {
		spec.Environments = append(spec.Environments, e.spec())
	}
	p, envs, err := d.projects.CreateProject(spec)
	if err != nil {
		writeProjectError(w, err)
		return
	}
	// Give the project a workspace immediately. Without it the Memory and
	// Workspace panels both read empty on a project that was just created, which
	// looks like a broken UI rather than a directory nobody has made yet.
	//
	// A scaffold failure is logged, not fatal: the project record is the thing
	// that was asked for, and a daemon with no workspace root configured is a
	// valid deployment.
	if d.workspaces != nil {
		if _, err := d.workspaces.Scaffold(p.ID); err != nil {
			d.log.Warn("workspace scaffold failed", "project", p.ID, "error", err)
		}
	}
	writeJSON(w, http.StatusCreated, projectResp(p, envs))
}

func (d *Daemon) handleProjectList(w http.ResponseWriter, r *http.Request) {
	ps, err := d.projects.Projects()
	if err != nil {
		writeProjectError(w, err)
		return
	}
	out := make([]projectResponse, 0, len(ps))
	for _, p := range ps {
		envs, err := d.projects.Environments(p.ID)
		if err != nil {
			writeProjectError(w, err)
			return
		}
		out = append(out, projectResp(p, envs))
	}
	writeJSON(w, http.StatusOK, out)
}

func (d *Daemon) handleProjectGet(w http.ResponseWriter, r *http.Request) {
	p, envs, err := d.projects.Project(r.PathValue("id"))
	if err != nil {
		writeProjectError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, projectResp(p, envs))
}

// handleProjectDelete removes a project. It fails CLOSED while anything under it
// is live: deleting a project must never orphan a running sandbox that holds
// connections.
func (d *Daemon) handleProjectDelete(w http.ResponseWriter, r *http.Request) {
	if err := d.projects.RemoveProject(r.Context(), r.PathValue("id")); err != nil {
		writeProjectError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *Daemon) handleEnvironmentAdd(w http.ResponseWriter, r *http.Request) {
	var body addEnvironmentRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	e, err := d.projects.AddEnvironment(r.PathValue("id"), body.spec())
	if err != nil {
		writeProjectError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, environmentResp(e))
}

// setCapabilitiesRequest is the PUT /v1/projects/{id}/capabilities body. It
// carries the WHOLE desired map, so the result is a function of the request and
// retrying one is safe.
type setCapabilitiesRequest struct {
	Capabilities map[string]string `json:"capabilities"`
}

func (d *Daemon) handleCapabilitiesSet(w http.ResponseWriter, r *http.Request) {
	var body setCapabilitiesRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	p, err := d.projects.SetCapabilities(r.PathValue("id"), body.Capabilities)
	if err != nil {
		writeProjectError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, projectResp(p, nil))
}

func (d *Daemon) handleEnvironmentList(w http.ResponseWriter, r *http.Request) {
	envs, err := d.projects.Environments(r.PathValue("id"))
	if err != nil {
		writeProjectError(w, err)
		return
	}
	out := make([]environmentResponse, 0, len(envs))
	for _, e := range envs {
		out = append(out, environmentResp(e))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleEnvironmentDelete tears an environment down: its sandboxes first (ordered,
// fail-closed), then the record.
func (d *Daemon) handleEnvironmentDelete(w http.ResponseWriter, r *http.Request) {
	if err := d.projects.RemoveEnvironment(r.Context(), r.PathValue("id"), r.PathValue("env")); err != nil {
		writeProjectError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeProjectError maps a project-service error to an HTTP status + layered
// envelope. The layer is "project" so an operator can tell a scope problem from a
// sandbox, policy, or egress one at a glance (failure legibility).
func writeProjectError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, project.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "project", err.Error())
	case errors.Is(err, project.ErrExists):
		writeAPIError(w, http.StatusConflict, "project", err.Error())
	case errors.Is(err, project.ErrInUse):
		writeAPIError(w, http.StatusConflict, "project", err.Error())
	case errors.Is(err, project.ErrInvalidInput):
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "project", err.Error())
	}
}
