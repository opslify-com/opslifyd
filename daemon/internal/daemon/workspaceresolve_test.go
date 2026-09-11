package daemon

import (
	"path/filepath"
	"testing"

	"github.com/opslify-com/opslifyd/internal/project"
)

type fakeLookup struct{ p project.Project }

func (f *fakeLookup) Project(id string) (project.Project, []project.Environment, error) {
	return f.p, nil, nil
}

// TestWorkspaceDirForFollowsACustomPath.
//
// A workspace has exactly one location and everything that reads it has to agree
// on which. Sessions and the F8.4 skill assembly followed a project's own
// directory; memory and the workspace listing kept reading <root>/ws-<project>.
// So an operator who pointed a project at ~/opslify-workspace/thing and put a
// runbook in it saw an empty Memory panel and a tree of the wrong directory.
func TestWorkspaceDirForFollowsACustomPath(t *testing.T) {
	custom := "/home/op/opslify-workspace/thing"
	got := WorkspaceDirFor(&fakeLookup{p: project.Project{ID: "thing", WorkspacePath: custom}},
		"/var/lib/opslify/workspaces", "thing")
	if got != custom {
		t.Fatalf("got %q, want the project's own directory %q", got, custom)
	}
}

func TestWorkspaceDirForFallsBackToTheManagedOne(t *testing.T) {
	got := WorkspaceDirFor(&fakeLookup{p: project.Project{ID: "thing"}},
		"/var/lib/opslify/workspaces", "thing")
	want := filepath.Join("/var/lib/opslify/workspaces", "ws-thing")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestWorkspaceDirForRefusesATraversingID: an id with a separator would walk out
// of the workspace root.
func TestWorkspaceDirForRefusesATraversingID(t *testing.T) {
	for _, id := range []string{"../etc", "a/b", "..", "x/../../y"} {
		if got := WorkspaceDirFor(nil, "/var/lib/opslify/workspaces", id); got != "" {
			t.Errorf("id %q resolved to %q", id, got)
		}
	}
}

func TestWorkspaceDirForWithNoLookupStillWorks(t *testing.T) {
	got := WorkspaceDirFor(nil, "/ws", "thing")
	if got != filepath.Join("/ws", "ws-thing") {
		t.Fatalf("got %q", got)
	}
}
