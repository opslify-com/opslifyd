package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// record is the persisted, restart-surviving projection of a session. It is the
// minimum needed to reap the underlying container after a daemon crash/restart
// (orphan reconciliation): the container handle, the tier that produced it, and
// the scratch workspace to clean. It contains NO secrets.
type record struct {
	ID           string                  `json:"id"`
	Mode         Mode                    `json:"mode"`
	Name         string                  `json:"name,omitempty"` // workspace name (workspace mode only)
	Tier         runtime.Tier            `json:"tier"`
	Location     runtime.Location        `json:"location"`
	Handle       runtime.ContainerHandle `json:"handle"`
	WorkspaceDir string                  `json:"workspace_dir"`
	Created      time.Time               `json:"created"`
	TTL          time.Duration           `json:"ttl"`
	// ProjectID / EnvironmentID are the F8.1 scope the session was created in.
	// They are persisted so a restart's reconcile knows WHICH environment each
	// orphan belonged to (an environment removal must be able to find its
	// sandboxes even across a daemon lifetime). omitempty keeps a pre-F8.1 record
	// loadable: it simply decodes with empty ids.
	ProjectID     string `json:"project_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
}

// snapshotMeta records one committed workspace snapshot image. The tag is the
// monotonically increasing suffix in opslify/ws-<name>:<tag>; Created orders the
// retention window (oldest pruned first).
type snapshotMeta struct {
	Image   string    `json:"image"`   // opslify/ws-<name>:<tag>
	Tag     int       `json:"tag"`     // the :<tag> suffix
	Created time.Time `json:"created"` // when the commit happened
}

// workspaceRecord is the persisted, restart-surviving mapping of a workspace
// name to its snapshot history (oldest→newest). It is what makes a workspace
// session resume with installed deps intact ACROSS a daemon restart: the latest
// snapshot's image is used as the resume base on the next workspace create. It
// carries NO secrets.
type workspaceRecord struct {
	Name      string         `json:"name"`
	Snapshots []snapshotMeta `json:"snapshots"`
}

// latest returns the newest snapshot image and true, or "" and false when the
// workspace has no snapshots yet (a first-ever create resumes from the base
// image).
func (w workspaceRecord) latest() (string, bool) {
	if len(w.Snapshots) == 0 {
		return "", false
	}
	return w.Snapshots[len(w.Snapshots)-1].Image, true
}

// nextTag returns the tag to use for the next snapshot: one past the highest
// existing tag, so tags are monotonic and never reused even after prune.
func (w workspaceRecord) nextTag() int {
	max := 0
	for _, s := range w.Snapshots {
		if s.Tag > max {
			max = s.Tag
		}
	}
	return max + 1
}

// Store persists session records durably enough to reconcile after a restart.
// It is an interface so the Manager is unit-testable with an in-memory fake and
// production uses a directory of 0600 JSON files. Records carry no secrets.
type Store interface {
	// Save writes (or overwrites) a record.
	Save(r record) error
	// Delete removes a record; absence is not an error.
	Delete(id string) error
	// LoadAll returns every persisted record (used at startup to reap orphans).
	LoadAll() ([]record, error)

	// SaveWorkspace writes (or overwrites) a workspace's snapshot history. This is
	// the durable name→latest-snapshot mapping that survives daemon restart.
	SaveWorkspace(w workspaceRecord) error
	// LoadWorkspace returns a workspace record and true, or a zero record and
	// false when the name is unknown.
	LoadWorkspace(name string) (workspaceRecord, bool, error)
	// LoadWorkspaces returns every persisted workspace record (for `ws ls`).
	LoadWorkspaces() ([]workspaceRecord, error)
	// DeleteWorkspace removes a workspace record; absence is not an error.
	DeleteWorkspace(name string) error
}

// fileStore persists one JSON file per session under dir, and one file per
// workspace under dir/workspaces. The directories are created 0700 (owner-only):
// session and workspace metadata are daemon-private. Workspaces live in a
// SUBDIRECTORY so LoadAll (which skips subdirs) never mistakes a workspace file
// for a session record.
type fileStore struct {
	dir   string
	wsDir string
}

// NewFileStore returns a Store rooted at dir, creating it (and its workspaces
// subdir) 0700.
func NewFileStore(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("session: create state dir %s: %w", dir, err)
	}
	wsDir := filepath.Join(dir, "workspaces")
	if err := os.MkdirAll(wsDir, 0o700); err != nil {
		return nil, fmt.Errorf("session: create workspace state dir %s: %w", wsDir, err)
	}
	return &fileStore{dir: dir, wsDir: wsDir}, nil
}

func (s *fileStore) path(id string) string { return filepath.Join(s.dir, id+".json") }

func (s *fileStore) wsPath(name string) string { return filepath.Join(s.wsDir, name+".json") }

func (s *fileStore) Save(r record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("session: marshal record %s: %w", r.ID, err)
	}
	// Write atomically: temp + rename, so a crash mid-write never leaves a
	// half-written record the reconciler would choke on.
	tmp := s.path(r.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("session: write record %s: %w", r.ID, err)
	}
	if err := os.Rename(tmp, s.path(r.ID)); err != nil {
		return fmt.Errorf("session: commit record %s: %w", r.ID, err)
	}
	return nil
}

func (s *fileStore) Delete(id string) error {
	if err := os.Remove(s.path(id)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("session: delete record %s: %w", id, err)
	}
	return nil
}

func (s *fileStore) LoadAll() ([]record, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("session: read state dir %s: %w", s.dir, err)
	}
	var out []record
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("session: read record %s: %w", e.Name(), err)
		}
		var r record
		if err := json.Unmarshal(b, &r); err != nil {
			// A corrupt record must not wedge startup; skip it legibly (the
			// reaper will still not leak because the container name is prefixed
			// and a future podman-ps sweep catches it — noted as gated).
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// SaveWorkspace atomically writes a workspace record (temp + rename) under the
// workspaces subdir. name is validated by the Manager (no traversal) before it
// reaches here.
func (s *fileStore) SaveWorkspace(w workspaceRecord) error {
	b, err := json.Marshal(w)
	if err != nil {
		return fmt.Errorf("session: marshal workspace %s: %w", w.Name, err)
	}
	tmp := s.wsPath(w.Name) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("session: write workspace %s: %w", w.Name, err)
	}
	if err := os.Rename(tmp, s.wsPath(w.Name)); err != nil {
		return fmt.Errorf("session: commit workspace %s: %w", w.Name, err)
	}
	return nil
}

func (s *fileStore) LoadWorkspace(name string) (workspaceRecord, bool, error) {
	b, err := os.ReadFile(s.wsPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return workspaceRecord{}, false, nil
		}
		return workspaceRecord{}, false, fmt.Errorf("session: read workspace %s: %w", name, err)
	}
	var w workspaceRecord
	if err := json.Unmarshal(b, &w); err != nil {
		return workspaceRecord{}, false, fmt.Errorf("session: parse workspace %s: %w", name, err)
	}
	return w, true, nil
}

func (s *fileStore) LoadWorkspaces() ([]workspaceRecord, error) {
	entries, err := os.ReadDir(s.wsDir)
	if err != nil {
		return nil, fmt.Errorf("session: read workspace state dir %s: %w", s.wsDir, err)
	}
	var out []workspaceRecord
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.wsDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("session: read workspace %s: %w", e.Name(), err)
		}
		var w workspaceRecord
		if err := json.Unmarshal(b, &w); err != nil {
			continue // a corrupt workspace file must not wedge `ws ls`
		}
		out = append(out, w)
	}
	return out, nil
}

func (s *fileStore) DeleteWorkspace(name string) error {
	if err := os.Remove(s.wsPath(name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("session: delete workspace %s: %w", name, err)
	}
	return nil
}
