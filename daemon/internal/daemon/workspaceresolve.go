package daemon

import (
	"path/filepath"
	"strings"

	"github.com/opslify-com/opslifyd/internal/project"
)

// ProjectLookup is the minimum needed to find where a project's workspace lives.
// Narrower than ProjectService because the two consumers — the memory store and
// the workspace listing — have no business creating or removing anything.
type ProjectLookup interface {
	Project(id string) (project.Project, []project.Environment, error)
}

// WorkspaceDirFor resolves a project's workspace directory.
//
// One function because there are two answers and three callers, and they were
// diverging: a project that names its own directory gets it for sessions and for
// the F8.4 skill assembly, and — until this existed — did NOT get it for memory
// or for the workspace listing. Both kept reading <root>/ws-<project>, so an
// operator who pointed a project at ~/opslify-workspace/thing and put a runbook
// in it saw an empty Memory panel and a tree of the wrong directory.
//
// A workspace has exactly one location and everything that reads it has to agree
// on which.
func WorkspaceDirFor(lookup ProjectLookup, root, projectID string) string {
	if projectID == "" {
		projectID = project.DefaultProjectID
	}
	// One path segment, resolved here. An id containing a separator would
	// otherwise walk out of the workspace root.
	if projectID != filepath.Base(projectID) || strings.Contains(projectID, "..") {
		return ""
	}
	if lookup != nil {
		if p, _, err := lookup.Project(projectID); err == nil && p.WorkspacePath != "" {
			return p.WorkspacePath
		}
	}
	if root == "" {
		return ""
	}
	return filepath.Join(root, "ws-"+projectID)
}
