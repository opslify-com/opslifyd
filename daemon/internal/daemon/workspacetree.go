package daemon

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/opslify-com/opslifyd/internal/wssync"
)

// WorkspaceLister reports what is in a project's workspace, for the cockpit's
// Workspace section.
//
// This is a LISTING, never a reader: names, sizes and types only. F3.6's refusal
// to serve raw workspace bytes to a browser stays closed — an operator wants to
// see that the repo is there and that memory is beside it, not to read files
// through a web page.
type WorkspaceLister interface {
	Tree(projectID string, depth int) (WorkspaceTree, error)
}

// WorkspaceTree is one project's workspace, shallowly.
type WorkspaceTree struct {
	Project string           `json:"project"`
	Path    string           `json:"path"`
	Exists  bool             `json:"exists"`
	Entries []WorkspaceEntry `json:"entries"`
}

// WorkspaceEntry is one file or directory.
type WorkspaceEntry struct {
	Rel   string `json:"rel"`
	Dir   bool   `json:"dir"`
	Bytes int64  `json:"bytes,omitempty"`
	// Excluded marks an entry withheld by the secret deny-list. Shown as a count
	// rather than silently dropped: an operator who cannot find the file they just
	// put there should learn that it was excluded, and why.
	Excluded bool `json:"excluded,omitempty"`
}

func (d *Daemon) registerWorkspaceTreeRoutes(mux *http.ServeMux) {
	if d.workspaces == nil {
		return
	}
	mux.HandleFunc("GET /"+APIVersion+"/workspace", d.handleWorkspaceTree)
}

func (d *Daemon) handleWorkspaceTree(w http.ResponseWriter, r *http.Request) {
	depth := 2
	if v := r.URL.Query().Get("depth"); v != "" {
		if n, err := atoiBounded(v, 1, 4); err == nil {
			depth = n
		}
	}
	tree, err := d.workspaces.Tree(r.URL.Query().Get("project"), depth)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "workspace", err.Error())
		return
	}
	if tree.Entries == nil {
		tree.Entries = []WorkspaceEntry{}
	}
	writeJSON(w, http.StatusOK, tree)
}

// workspaceTreeFS is the filesystem implementation, kept here rather than in the
// composition root because the exclusion and symlink rules are the interesting
// part and they belong next to the type that promises them.
type workspaceTreeFS struct{ root string }

// NewWorkspaceLister returns a lister over <root>/ws-<project>.
func NewWorkspaceLister(root string) WorkspaceLister {
	if root == "" {
		return nil
	}
	return &workspaceTreeFS{root: root}
}

func (t *workspaceTreeFS) Tree(projectID string, depth int) (WorkspaceTree, error) {
	if projectID == "" {
		projectID = "default"
	}
	// One path segment, resolved by the daemon. A project id containing a
	// separator would otherwise walk out of the workspace root.
	if projectID != filepath.Base(projectID) || strings.Contains(projectID, "..") {
		return WorkspaceTree{}, nil
	}
	dir := filepath.Join(t.root, "ws-"+projectID)
	out := WorkspaceTree{Project: projectID, Path: dir}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return out, nil
	}
	out.Exists = true

	err = filepath.WalkDir(dir, func(p string, de fs.DirEntry, werr error) error {
		if werr != nil {
			// A directory the daemon cannot read is skipped, not fatal: podman
			// idmaps a running sandbox's scratch dir to a subuid, and one live
			// session must not make the whole listing fail.
			if de != nil && de.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if strings.Count(rel, "/") >= depth {
			if de.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		// Symlinks are listed as nothing at all: following one would report a tree
		// that is not this workspace, and naming the target leaks host layout.
		if de.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		e := WorkspaceEntry{Rel: rel, Dir: de.IsDir()}
		if wssync.Excluded(rel) {
			// Named but never sized or read — the operator learns it is there and
			// that it was withheld.
			e.Excluded = true
			out.Entries = append(out.Entries, e)
			if de.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !de.IsDir() {
			if info, ierr := de.Info(); ierr == nil {
				e.Bytes = info.Size()
			}
		}
		out.Entries = append(out.Entries, e)
		return nil
	})
	if err != nil {
		return out, err
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		if out.Entries[i].Dir != out.Entries[j].Dir {
			return out.Entries[i].Dir
		}
		return out.Entries[i].Rel < out.Entries[j].Rel
	})
	// Bounded: a workspace with a node_modules in it must not produce a response
	// that takes a second to render.
	if len(out.Entries) > 400 {
		out.Entries = out.Entries[:400]
	}
	return out, nil
}
