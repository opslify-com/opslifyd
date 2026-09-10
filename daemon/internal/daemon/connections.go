package daemon

import (
	"errors"
	"net/http"

	"github.com/opslify-com/opslifyd/internal/broker"
)

// ConnectionService is the narrow view the daemon needs of the F8.2 service. An
// interface rather than the concrete type so the HTTP layer is testable without a
// store, and so the daemon cannot reach operations it has no route for.
type ConnectionService interface {
	Add(spec broker.ConnectionSpec) error
	// Validate checks a spec WITHOUT storing it, backing `connection test`.
	Validate(spec broker.ConnectionSpec) error
	List() ([]broker.ConnectionSpec, error)
	Remove(projectID, environmentID, name string) error
}

// registerConnectionRoutes adds the F8.2 endpoints when the service is wired.
func (d *Daemon) registerConnectionRoutes(mux *http.ServeMux) {
	if d.connections == nil {
		return
	}
	mux.HandleFunc("POST /"+APIVersion+"/connections", d.handleConnectionAdd)
	mux.HandleFunc("POST /"+APIVersion+"/connections/test", d.handleConnectionTest)
	mux.HandleFunc("GET /"+APIVersion+"/connections", d.handleConnectionList)
	mux.HandleFunc("DELETE /"+APIVersion+"/connections/{name}", d.handleConnectionDelete)
}

// addConnectionRequest is the POST body. There is deliberately NO field that
// could carry a secret value: a connection references a credential by ref, and a
// request shape that allowed a value would invite putting one in a script.
type addConnectionRequest struct {
	Name          string            `json:"name"`
	Kind          string            `json:"kind"`
	SecretRef     string            `json:"secret_ref"`
	Hosts         []string          `json:"hosts,omitempty"`
	ProjectID     string            `json:"project_id,omitempty"`
	EnvironmentID string            `json:"environment_id,omitempty"`
	Config        map[string]string `json:"config,omitempty"`
}

// connectionResponse reports a connection by reference and metadata only.
type connectionResponse struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	SecretRef string   `json:"secret_ref"`
	Hosts     []string `json:"hosts,omitempty"`
	Scope     string   `json:"scope,omitempty"`
}

func connectionResp(spec broker.ConnectionSpec) connectionResponse {
	scope := spec.EnvironmentID
	if scope == "" {
		scope = spec.ProjectID
	}
	return connectionResponse{
		Name: spec.Name, Kind: string(spec.Kind), SecretRef: spec.SecretRef,
		Hosts: spec.Hosts, Scope: scope,
	}
}

func (r addConnectionRequest) spec() broker.ConnectionSpec {
	return broker.ConnectionSpec{
		Name: r.Name, Kind: broker.Kind(r.Kind), SecretRef: r.SecretRef,
		Hosts: r.Hosts, ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		Config: r.Config,
	}
}

func (d *Daemon) handleConnectionAdd(w http.ResponseWriter, r *http.Request) {
	var body addConnectionRequest
	// The tight bound: a connection spec is names and refs, kilobytes at most.
	if err := decodeJSONLimit(r, &body, maxSecretBody); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	spec := body.spec()
	if err := d.connections.Add(spec); err != nil {
		writeConnectionError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, connectionResp(spec))
}

// handleConnectionTest validates WITHOUT storing, so an operator can get
// kind-specific config right before a session depends on it.
func (d *Daemon) handleConnectionTest(w http.ResponseWriter, r *http.Request) {
	var body addConnectionRequest
	if err := decodeJSONLimit(r, &body, maxSecretBody); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	spec := body.spec()
	if err := d.connections.Validate(spec); err != nil {
		writeConnectionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectionResp(spec))
}

func (d *Daemon) handleConnectionList(w http.ResponseWriter, r *http.Request) {
	specs, err := d.connections.List()
	if err != nil {
		writeConnectionError(w, err)
		return
	}
	out := make([]connectionResponse, 0, len(specs))
	for _, s := range specs {
		out = append(out, connectionResp(s))
	}
	writeJSON(w, http.StatusOK, out)
}

func (d *Daemon) handleConnectionDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	project := r.URL.Query().Get("project")
	env := r.URL.Query().Get("env")
	if err := d.connections.Remove(project, env, name); err != nil {
		writeConnectionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeConnectionError maps a broker error to a layer-tagged status. Every
// connection failure names layer "cred", since a connection is a credential
// route — that keeps failure legibility consistent with the secret routes.
func writeConnectionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, broker.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "cred", err.Error())
	case errors.Is(err, broker.ErrExists):
		writeAPIError(w, http.StatusConflict, "cred", err.Error())
	case errors.Is(err, broker.ErrConflict):
		writeAPIError(w, http.StatusConflict, "cred", err.Error())
	case errors.Is(err, broker.ErrInvalidInput):
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
	case errors.Is(err, broker.ErrDenied):
		writeAPIError(w, http.StatusForbidden, "cred", err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "cred", err.Error())
	}
}
