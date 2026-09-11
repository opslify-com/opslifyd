package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/opslify-com/opslifyd/internal/memory"
	"github.com/opslify-com/opslifyd/internal/project"
)

// memoryService is F8.10's composition-root adapter.
//
// A project's memory lives in its workspace — <workspace-root>/ws-<project>/
// followed by one of the configured memory roots. Keeping it in the workspace is
// what makes "clone the repo and the runbooks come with it" work, and it is why
// documents version and review like code.
//
// The index is rebuilt on read rather than cached across requests. A memory
// folder is tens of documents and the corpus is bounded at 64 MiB; rebuilding is
// milliseconds, and a cache would be a way for the agent to search a corpus that
// no longer matches what an operator just edited.
type memoryService struct {
	workspaceRoot string
	roots         []string
	projects      *project.Service

	mu        sync.Mutex
	disabled  map[string]map[string]bool // project -> rel -> disabled
	statePath string
}

// defaultMemoryRoots are searched inside a project's workspace, in order.
//
// More than one because teams already have a convention and will not move their
// documents to adopt a tool. `.opslify/memory` is ours; the rest are what people
// already write.
var defaultMemoryRoots = []string{
	".opslify/memory",
	".claude/memory",
	"docs/memory",
	"memory",
}

func newMemoryService(workspaceRoot string, projects *project.Service, stateDir string) (*memoryService, error) {
	if workspaceRoot == "" {
		return nil, nil
	}
	s := &memoryService{
		workspaceRoot: workspaceRoot,
		roots:         defaultMemoryRoots,
		projects:      projects,
		disabled:      map[string]map[string]bool{},
		statePath:     filepath.Join(stateDir, "memory-disabled.txt"),
	}
	s.loadDisabled()
	return s, nil
}

// rootFor returns the memory directory for a project, or "" when none exists.
//
// The FIRST matching root wins rather than merging them, so two copies of a
// runbook in two conventions cannot both be retrieved and disagree.
func (s *memoryService) rootFor(projectID string) string {
	if projectID == "" {
		projectID = project.DefaultProjectID
	}
	ws := filepath.Join(s.workspaceRoot, "ws-"+projectID)
	for _, r := range s.roots {
		p := filepath.Join(ws, filepath.FromSlash(r))
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p
		}
	}
	// Nothing there yet: name the preferred location so the error and the UI can
	// tell an operator where to put the first document.
	return filepath.Join(ws, filepath.FromSlash(s.roots[0]))
}

func (s *memoryService) open(projectID string) (*memory.Store, error) {
	s.mu.Lock()
	var off []string
	for rel := range s.disabled[projectID] {
		off = append(off, rel)
	}
	s.mu.Unlock()
	sort.Strings(off)
	return memory.Open(memory.Options{Root: s.rootFor(projectID), Disabled: off})
}

func (s *memoryService) Documents(projectID string) ([]memory.Document, error) {
	st, err := s.open(projectID)
	if err != nil {
		return nil, err
	}
	return st.Documents(), nil
}

func (s *memoryService) Search(projectID, query string, k int) ([]memory.Excerpt, error) {
	st, err := s.open(projectID)
	if err != nil {
		return nil, err
	}
	return st.Search(query, k), nil
}

func (s *memoryService) SetEnabled(projectID, rel string, enabled bool) error {
	if rel == "" {
		return fmt.Errorf("%w: a document is required", memory.ErrInvalidInput)
	}
	s.mu.Lock()
	if s.disabled[projectID] == nil {
		s.disabled[projectID] = map[string]bool{}
	}
	if enabled {
		delete(s.disabled[projectID], rel)
	} else {
		s.disabled[projectID][rel] = true
	}
	s.mu.Unlock()
	return s.saveDisabled()
}

// The disabled set is daemon state, not workspace state. It lives beside the
// project records rather than in /workspace, because an operator switching a
// document off is a decision about this installation, and a repo sync must not
// silently re-enable it.
func (s *memoryService) loadDisabled() {
	b, err := os.ReadFile(s.statePath)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		p, rel, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || p == "" || rel == "" {
			continue
		}
		if s.disabled[p] == nil {
			s.disabled[p] = map[string]bool{}
		}
		s.disabled[p][rel] = true
	}
}

func (s *memoryService) saveDisabled() error {
	s.mu.Lock()
	var lines []string
	for p, set := range s.disabled {
		for rel := range set {
			lines = append(lines, p+"\t"+rel)
		}
	}
	s.mu.Unlock()
	sort.Strings(lines)
	tmp := s.statePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath)
}
