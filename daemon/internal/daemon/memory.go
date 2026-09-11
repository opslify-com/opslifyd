package daemon

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/opslify-com/opslifyd/internal/memory"
)

// MemoryService is the F8.10 seam: a project's document corpus and the search
// over it. nil => the routes are absent, and the cockpit's Memory section says
// so rather than rendering an empty list that looks like "no documents".
type MemoryService interface {
	// Documents lists a project's corpus.
	Documents(projectID string) ([]memory.Document, error)
	// Search returns cited excerpts. It is READ-ONLY by construction: there is no
	// write method on this interface, because an agent that could write memory
	// could author its own future justifications, and a poisoned document would
	// persist across sessions looking authoritative.
	Search(projectID, query string, k int) ([]memory.Excerpt, error)
	// SetEnabled switches one document off or on. An OPERATOR action.
	SetEnabled(projectID, rel string, enabled bool) error
}

func (d *Daemon) registerMemoryRoutes(mux *http.ServeMux) {
	if d.memory == nil {
		return
	}
	mux.HandleFunc("GET /"+APIVersion+"/memory", d.handleMemoryList)
	mux.HandleFunc("GET /"+APIVersion+"/memory/search", d.handleMemorySearch)
	mux.HandleFunc("POST /"+APIVersion+"/memory/enable", d.handleMemoryEnable)
}

type memoryListResponse struct {
	Project   string            `json:"project"`
	Documents []memory.Document `json:"documents"`
}

func (d *Daemon) handleMemoryList(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	docs, err := d.memory.Documents(project)
	if err != nil {
		writeMemoryError(w, err)
		return
	}
	if docs == nil {
		docs = []memory.Document{}
	}
	writeJSON(w, http.StatusOK, memoryListResponse{Project: project, Documents: docs})
}

type memorySearchResponse struct {
	Query    string           `json:"query"`
	Excerpts []memory.Excerpt `json:"excerpts"`
}

func (d *Daemon) handleMemorySearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := q.Get("q")
	if query == "" {
		writeAPIError(w, http.StatusBadRequest, "input", "a query is required")
		return
	}
	k := memory.DefaultK
	if v := q.Get("k"); v != "" {
		if n, err := atoiBounded(v, 1, 25); err == nil {
			k = n
		}
	}
	ex, err := d.memory.Search(q.Get("project"), query, k)
	if err != nil {
		writeMemoryError(w, err)
		return
	}
	if ex == nil {
		ex = []memory.Excerpt{}
	}
	writeJSON(w, http.StatusOK, memorySearchResponse{Query: query, Excerpts: ex})
}

type memoryEnableRequest struct {
	Project string `json:"project,omitempty"`
	Doc     string `json:"doc"`
	Enabled bool   `json:"enabled"`
}

func (d *Daemon) handleMemoryEnable(w http.ResponseWriter, r *http.Request) {
	var body memoryEnableRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	if err := d.memory.SetEnabled(body.Project, body.Doc, body.Enabled); err != nil {
		writeMemoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// atoiBounded parses a small positive integer inside a range, so a query
// parameter cannot ask for a hundred thousand excerpts.
func atoiBounded(s string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if n < lo {
		n = lo
	}
	if n > hi {
		n = hi
	}
	return n, nil
}

func writeMemoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, memory.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "memory", err.Error())
	case errors.Is(err, memory.ErrUnsafeSource):
		// A refused document is an operator problem with a specific fix (remove the
		// symlink, split the file), so it must not read as a daemon fault.
		writeAPIError(w, http.StatusBadRequest, "memory", err.Error())
	case errors.Is(err, memory.ErrInvalidInput):
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "memory", err.Error())
	}
}
