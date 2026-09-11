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
	if d.toolchains != nil {
		mux.HandleFunc("POST /"+APIVersion+"/projects/{id}/toolchain", d.handleToolchainBuild)
	}
}

// createProjectRequest is the POST /v1/projects body.
type createProjectRequest struct {
	Name         string            `json:"name"`
	RepoURL      string            `json:"repo_url,omitempty"`
	Capabilities map[string]string `json:"capabilities,omitempty"`
	PolicyFile   string            `json:"policy_file,omitempty"`
	// WorkspacePath binds this project to a host directory the operator chose, so
	// they can open the same files their agent is working on. Empty leaves it
	// daemon-managed.
	WorkspacePath string                  `json:"workspace_path,omitempty"`
	Environments  []addEnvironmentRequest `json:"environments,omitempty"`
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
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Created       time.Time         `json:"created"`
	RepoURL       string            `json:"repo_url,omitempty"`
	Capabilities  map[string]string `json:"capabilities,omitempty"`
	PolicyFile    string            `json:"policy_file,omitempty"`
	WorkspacePath string            `json:"workspace_path,omitempty"`
	Toolchain     project.Toolchain `json:"toolchain,omitempty"`
	// ToolchainAvailable says whether this host can build one. False means a
	// request would be recorded as "unavailable" rather than attempted, which is
	// a different thing from a build that failed.
	ToolchainAvailable bool `json:"toolchain_available"`
	// WorkspaceWarnings names credential-shaped files found in a chosen
	// directory. A bind mount has no deny-list, so this is the only moment the
	// exposure can be reported.
	WorkspaceWarnings []project.SecretFinding `json:"workspace_warnings,omitempty"`
	Environments      []environmentResponse   `json:"environments"`
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
		ID:            p.ID,
		Name:          p.Name,
		Created:       p.Created,
		RepoURL:       p.RepoURL,
		Capabilities:  p.Capabilities,
		PolicyFile:    p.PolicyFile,
		WorkspacePath: p.WorkspacePath,
		Toolchain:     p.Toolchain,
		Environments:  make([]environmentResponse, 0, len(envs)),
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
		Name:          body.Name,
		RepoURL:       body.RepoURL,
		Capabilities:  body.Capabilities,
		PolicyFile:    body.PolicyFile,
		WorkspacePath: body.WorkspacePath,
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
	resp := d.projectView(p, envs)
	// A bind mount has NO deny-list — unlike F7.3's copy-in path, which filters
	// credential-shaped files on the way through. Everything in the chosen
	// directory is visible to every sandbox for the project, and this is the only
	// moment that exposure can be reported to the person who chose it.
	if p.WorkspacePath != "" {
		if findings, err := project.ScanForSecrets(p.WorkspacePath, 50); err == nil && len(findings) > 0 {
			resp.WorkspaceWarnings = findings
			d.log.Warn("workspace contains credential-shaped files",
				"project", p.ID, "path", p.WorkspacePath, "count", len(findings))
		}
	}
	writeJSON(w, http.StatusCreated, resp)
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
		out = append(out, d.projectView(p, envs))
	}
	writeJSON(w, http.StatusOK, out)
}

func (d *Daemon) handleProjectGet(w http.ResponseWriter, r *http.Request) {
	p, envs, err := d.projects.Project(r.PathValue("id"))
	if err != nil {
		writeProjectError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d.projectView(p, envs))
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
	writeJSON(w, http.StatusOK, d.projectView(p, nil))
}

// ToolchainBuilder composes a project's own set of CLIs. nil => the route is
// absent and every project uses the daemon-wide toolchain.
type ToolchainBuilder interface {
	// Build starts an asynchronous build and returns the project with its status
	// already moved to "building".
	Build(projectID string, tools []string) (project.Project, error)
	// Available reports whether this host can build one at all.
	Available() bool
}

type buildToolchainRequest struct {
	// Tools are nix package names. The WHOLE set: a build produces one layer, and
	// an "add this tool" endpoint would need the previous list to mean anything.
	Tools []string `json:"tools"`
}

// handleToolchainBuild starts a build. 202, not 201: nothing is built yet, and a
// created-status on a request that will take minutes invites a caller to assume
// the tools are there.
func (d *Daemon) handleToolchainBuild(w http.ResponseWriter, r *http.Request) {
	var body buildToolchainRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	p, err := d.toolchains.Build(r.PathValue("id"), body.Tools)
	if err != nil {
		writeProjectError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, d.projectView(p, nil))
}

// projectView renders a project WITH the host facts a caller needs to interpret
// it — today, whether this machine can build a toolchain at all.
//
// A method rather than the bare projectResp because the field was set in exactly
// one handler and absent from the two that list and show, so the cockpit could
// not tell "no toolchain yet" from "this host cannot make one".
func (d *Daemon) projectView(p project.Project, envs []project.Environment) projectResponse {
	resp := projectResp(p, envs)
	resp.ToolchainAvailable = d.toolchains != nil && d.toolchains.Available()
	return resp
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
