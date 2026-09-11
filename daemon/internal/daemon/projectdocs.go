package daemon

import (
	"errors"
	"net/http"

	"github.com/opslify-com/opslifyd/internal/projectdoc"
)

// The document surface: the markdown a project is made of, editable from the
// cockpit.
//
// This is a deliberate, narrow loosening of F3.6. That control refuses RAW
// workspace bytes to a browser so a local page can never read what the agent
// wrote — and the large surface it protects is whatever was cloned into the
// workspace, which stays unreachable here. What these routes reach is three known
// directories of operator-authored markdown under .opslify/, which the operator
// typed and which memory search already returns excerpts of.
//
// The difference between that and a file browser is the whole argument for
// building it.

func (d *Daemon) registerProjectDocRoutes(mux *http.ServeMux) {
	if d.workspaces == nil {
		return
	}
	mux.HandleFunc("GET /"+APIVersion+"/docs", d.handleDocList)
	mux.HandleFunc("GET /"+APIVersion+"/docs/read", d.handleDocRead)
	mux.HandleFunc("PUT /"+APIVersion+"/docs", d.handleDocWrite)
	mux.HandleFunc("DELETE /"+APIVersion+"/docs", d.handleDocDelete)
}

// docWorkspace resolves the project's workspace, which is where all three
// document kinds live.
func (d *Daemon) docWorkspace(projectID string) string {
	if l, ok := d.workspaces.(interface {
		Tree(string, int) (WorkspaceTree, error)
	}); ok {
		if t, err := l.Tree(projectID, 1); err == nil && t.Path != "" {
			return t.Path
		}
	}
	return ""
}

type docListResponse struct {
	Project string           `json:"project"`
	Kind    string           `json:"kind"`
	Docs    []projectdoc.Doc `json:"docs"`
}

func (d *Daemon) handleDocList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind := projectdoc.Kind(q.Get("kind"))
	docs, err := projectdoc.List(d.docWorkspace(q.Get("project")), kind)
	if err != nil {
		writeDocError(w, err)
		return
	}
	if docs == nil {
		docs = []projectdoc.Doc{}
	}
	writeJSON(w, http.StatusOK, docListResponse{Project: q.Get("project"), Kind: string(kind), Docs: docs})
}

func (d *Daemon) handleDocRead(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	doc, err := projectdoc.Read(d.docWorkspace(q.Get("project")),
		projectdoc.Kind(q.Get("kind")), q.Get("path"))
	if err != nil {
		writeDocError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

type docWriteRequest struct {
	Project string `json:"project,omitempty"`
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

func (d *Daemon) handleDocWrite(w http.ResponseWriter, r *http.Request) {
	var body docWriteRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	ws := d.docWorkspace(body.Project)
	if ws == "" {
		writeAPIError(w, http.StatusBadRequest, "workspace",
			"this project has no workspace yet, so there is nowhere to put the document")
		return
	}
	doc, err := projectdoc.Write(ws, projectdoc.Kind(body.Kind), body.Path, body.Content)
	if err != nil {
		writeDocError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (d *Daemon) handleDocDelete(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	err := projectdoc.Delete(d.docWorkspace(q.Get("project")),
		projectdoc.Kind(q.Get("kind")), q.Get("path"))
	if err != nil {
		writeDocError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeDocError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, projectdoc.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "document", err.Error())
	case errors.Is(err, projectdoc.ErrUnsafe):
		// A refused PATH is a security answer, not a formatting one, and the
		// message says which so an operator does not go looking for a typo.
		writeAPIError(w, http.StatusForbidden, "document", err.Error())
	case errors.Is(err, projectdoc.ErrInvalidInput):
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "document", err.Error())
	}
}
