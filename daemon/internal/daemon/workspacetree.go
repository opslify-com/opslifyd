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
	// Scaffold creates a project's workspace and the directories that make it
	// useful, if it does not exist. Called when a project is created so the
	// Memory and Workspace panels have somewhere real to point at from the first
	// minute, rather than both reading empty until somebody discovers they were
	// meant to mkdir it by hand.
	Scaffold(projectID string) (string, error)
}

// WorkspaceTree is one project's workspace, shallowly.
type WorkspaceTree struct {
	Project string           `json:"project"`
	Path    string           `json:"path"`
	Exists  bool             `json:"exists"`
	Entries []WorkspaceEntry `json:"entries"`
	// Truncated marks a listing cut at the entry cap. Reported rather than silent:
	// a cloned monorepo will blow past it, and a listing that just stopped would
	// have an operator hunting for a file that is present.
	Truncated bool `json:"truncated,omitempty"`
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
	// Four, not two. At two the walk stopped exactly at .opslify/memory and
	// .opslify/skills — so the panel showed the folders and never a single file in
	// them, which reads as "the tree is broken" rather than "you asked for two
	// levels". The entry cap below is what actually bounds the response.
	depth := 4
	if v := r.URL.Query().Get("depth"); v != "" {
		if n, err := atoiBounded(v, 1, 8); err == nil {
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

// Scaffold creates <root>/ws-<project> with the layout the rest of the product
// expects, and a README that says what goes where.
//
// Nothing here is a secret and nothing is executable: the workspace is a host
// directory visible to whoever can read it and mounted read-write into every
// sandbox for this project. That is exactly why credentials never go in it — they
// live in the vault and are injected at the egress proxy.
func (t *workspaceTreeFS) Scaffold(projectID string) (string, error) {
	if projectID == "" || projectID != filepath.Base(projectID) || strings.Contains(projectID, "..") {
		return "", nil
	}
	dir := filepath.Join(t.root, "ws-"+projectID)
	for _, sub := range []string{
		filepath.Join(".opslify", "memory"),
		filepath.Join(".opslify", "skills"),
		"repos",
	} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return "", err
		}
	}
	readme := filepath.Join(dir, ".opslify", "README.md")
	if _, err := os.Stat(readme); os.IsNotExist(err) {
		if err := os.WriteFile(readme, []byte(workspaceReadme(projectID)), 0o644); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func workspaceReadme(projectID string) string {
	return "# " + projectID + " workspace\n\n" +
		"This directory is mounted read-write at `/workspace` in every sandbox for\n" +
		"this project. You can edit it here on the host; the agent sees the same files.\n\n" +
		"## Layout\n\n" +
		"- `.opslify/skills/*.md` — rules the agent must ALWAYS follow. Injected into\n" +
		"  every session, so keep them short.\n" +
		"- `.opslify/memory/**` — documents it might need to CONSULT: runbooks,\n" +
		"  architecture notes, postmortems. Retrieved on demand and cited, never\n" +
		"  injected wholesale.\n" +
		"- `.opslify/instructions.md` — project-wide behaviour, reviewed in a commit.\n" +
		"- `repos/` — clone what the work needs here.\n\n" +
		"The rule of thumb: a rule the agent must always follow is a skill; a document\n" +
		"it might need to look up is memory.\n\n" +
		"## What does NOT go here\n\n" +
		"Credentials. This directory is readable by anyone who can read the host path\n" +
		"and by every sandbox for this project. Secrets live in the daemon's vault\n" +
		"(`opslify secrets add`) and are injected at the egress proxy, so the sandbox\n" +
		"authenticates without ever holding one. Files that look like credentials\n" +
		"(`.env`, `*.pem`, `id_rsa*`, `credentials*`) are refused on the way into a\n" +
		"sandbox and withheld from the workspace listing.\n"
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
	// Plain path order, so a client can render a tree by indenting on "/" depth.
	// Sorting directories first would separate a directory from its own contents.
	sort.Slice(out.Entries, func(i, j int) bool {
		return out.Entries[i].Rel < out.Entries[j].Rel
	})
	// Bounded, and the truncation is REPORTED. A cloned monorepo will blow past
	// this, and a listing that silently stopped would have an operator hunting for
	// a file that is present.
	const cap = 2000
	if len(out.Entries) > cap {
		out.Entries = out.Entries[:cap]
		out.Truncated = true
	}
	return out, nil
}
