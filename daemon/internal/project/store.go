package project

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Store persists project and environment records durably enough to survive a
// daemon restart and reconcile with the sandboxes still running under them. It
// is an interface so the Service is unit-testable with an in-memory fake and
// production uses a directory of 0600 JSON files. Records carry NO secrets — a
// credential is always a ref, resolved through the F5.6 broker.
type Store interface {
	// SaveProject writes (or overwrites) a project record.
	SaveProject(p Project) error
	// LoadProject returns a project and true, or a zero project and false when
	// the id is unknown.
	LoadProject(id string) (Project, bool, error)
	// LoadProjects returns every persisted project (for `project ls`).
	LoadProjects() ([]Project, error)
	// DeleteProject removes a project record; absence is not an error.
	DeleteProject(id string) error

	// SaveEnvironment writes (or overwrites) an environment record.
	SaveEnvironment(e Environment) error
	// LoadEnvironment returns an environment and true, or a zero environment and
	// false when the id is unknown.
	LoadEnvironment(id string) (Environment, bool, error)
	// LoadEnvironments returns every persisted environment (the Service filters
	// by project).
	LoadEnvironments() ([]Environment, error)
	// DeleteEnvironment removes an environment record; absence is not an error.
	DeleteEnvironment(id string) error
}

// fileStore persists one JSON file per project under dir/projects and one per
// environment under dir/environments. Both directories are created 0700
// (owner-only): project and environment metadata is daemon-private. They are
// SEPARATE subdirectories so a load of one kind can never pick up a record of the
// other — the same reason session.fileStore keeps workspaces below the session
// records.
type fileStore struct {
	// log surfaces unreadable records. A store that silently skips a corrupt file
	// makes a scope disappear from every listing with no signal anywhere.
	log     *slog.Logger
	projDir string
	envDir  string
}

// NewFileStore returns a Store rooted at dir, creating it (and its projects /
// environments subdirs) 0700.
func NewFileStore(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("project: create state dir %s: %w", dir, err)
	}
	projDir := filepath.Join(dir, "projects")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		return nil, fmt.Errorf("project: create project state dir %s: %w", projDir, err)
	}
	envDir := filepath.Join(dir, "environments")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		return nil, fmt.Errorf("project: create environment state dir %s: %w", envDir, err)
	}
	return &fileStore{projDir: projDir, envDir: envDir, log: slog.Default()}, nil
}

// safeRecordID refuses any id that could address a file outside its record
// directory. Callers validate at the trust boundary (ValidateName); this is the
// LAST line of defence, so that a caller which forgets is a refused request
// rather than an arbitrary-file read/delete primitive running as the daemon
// user. Defence in depth is warranted here because the id reaches filepath.Join.
func safeRecordID(kind, id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty %s id", ErrInvalidInput, kind)
	}
	if id != filepath.Base(id) || id == "." || id == ".." ||
		strings.ContainsAny(id, `/\`+"\x00") {
		return fmt.Errorf("%w: unsafe %s id %q", ErrInvalidInput, kind, id)
	}
	return nil
}

// corrupt reports a record that could not be decoded. It is a WARN, not an
// error return: one bad file must not make every other scope unreachable.
func (s *fileStore) corrupt(name string, err error) {
	log := s.log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("project: skipping unreadable record — it will not appear in listings",
		"file", name, "err", err)
}

func (s *fileStore) projPath(id string) string { return filepath.Join(s.projDir, id+".json") }

func (s *fileStore) envPath(id string) string { return filepath.Join(s.envDir, id+".json") }

// writeAtomic marshals v and writes it to path via temp + rename, so a crash
// mid-write never leaves a half-written record the loader would choke on. The
// file is 0600 (daemon-private) like every other daemon state file.
func writeAtomic(path, what string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("project: marshal %s: %w", what, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("project: write %s: %w", what, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("project: commit %s: %w", what, err)
	}
	return nil
}

func (s *fileStore) SaveProject(p Project) error {
	if err := safeRecordID("project", p.ID); err != nil {
		return err
	}
	return writeAtomic(s.projPath(p.ID), "project "+p.ID, p)
}

func (s *fileStore) LoadProject(id string) (Project, bool, error) {
	if err := safeRecordID("project", id); err != nil {
		return Project{}, false, err
	}
	b, err := os.ReadFile(s.projPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return Project{}, false, nil
		}
		return Project{}, false, fmt.Errorf("project: read project %s: %w", id, err)
	}
	var p Project
	if err := json.Unmarshal(b, &p); err != nil {
		return Project{}, false, fmt.Errorf("project: parse project %s: %w", id, err)
	}
	return p, true, nil
}

func (s *fileStore) LoadProjects() ([]Project, error) {
	entries, err := os.ReadDir(s.projDir)
	if err != nil {
		return nil, fmt.Errorf("project: read project state dir %s: %w", s.projDir, err)
	}
	var out []Project
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.projDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("project: read project %s: %w", e.Name(), err)
		}
		var p Project
		if err := json.Unmarshal(b, &p); err != nil {
			// A corrupt record must not wedge `project ls` or startup — but it must
			// not vanish silently either, or an operator simply stops seeing a scope
			// they still have on disk. Surface it and keep going.
			s.corrupt(e.Name(), err)
			continue
		}
		out = append(out, p)
	}
	return sortProjects(out), nil
}

func (s *fileStore) DeleteProject(id string) error {
	if err := safeRecordID("project", id); err != nil {
		return err
	}
	if err := os.Remove(s.projPath(id)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("project: delete project %s: %w", id, err)
	}
	return nil
}

func (s *fileStore) SaveEnvironment(e Environment) error {
	if err := safeRecordID("environment", e.ID); err != nil {
		return err
	}
	return writeAtomic(s.envPath(e.ID), "environment "+e.ID, e)
}

func (s *fileStore) LoadEnvironment(id string) (Environment, bool, error) {
	if err := safeRecordID("environment", id); err != nil {
		return Environment{}, false, err
	}
	b, err := os.ReadFile(s.envPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return Environment{}, false, nil
		}
		return Environment{}, false, fmt.Errorf("project: read environment %s: %w", id, err)
	}
	var e Environment
	if err := json.Unmarshal(b, &e); err != nil {
		return Environment{}, false, fmt.Errorf("project: parse environment %s: %w", id, err)
	}
	return e, true, nil
}

func (s *fileStore) LoadEnvironments() ([]Environment, error) {
	entries, err := os.ReadDir(s.envDir)
	if err != nil {
		return nil, fmt.Errorf("project: read environment state dir %s: %w", s.envDir, err)
	}
	var out []Environment
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.envDir, ent.Name()))
		if err != nil {
			return nil, fmt.Errorf("project: read environment %s: %w", ent.Name(), err)
		}
		var e Environment
		if err := json.Unmarshal(b, &e); err != nil {
			// Same reasoning as LoadProjects — but this one also feeds the >=1
			// invariant and default-environment pick, so a silent drop makes a
			// later refusal ("is the last environment") undiagnosable.
			s.corrupt(ent.Name(), err)
			continue // a corrupt record must not wedge `env ls` or startup
		}
		out = append(out, e)
	}
	return sortEnvironments(out), nil
}

func (s *fileStore) DeleteEnvironment(id string) error {
	if err := safeRecordID("environment", id); err != nil {
		return err
	}
	if err := os.Remove(s.envPath(id)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("project: delete environment %s: %w", id, err)
	}
	return nil
}
