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
	Tier         runtime.Tier            `json:"tier"`
	Location     runtime.Location        `json:"location"`
	Handle       runtime.ContainerHandle `json:"handle"`
	WorkspaceDir string                  `json:"workspace_dir"`
	Created      time.Time               `json:"created"`
	TTL          time.Duration           `json:"ttl"`
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
}

// fileStore persists one JSON file per session under Dir. The directory is
// created 0700 (owner-only): session metadata is daemon-private.
type fileStore struct{ dir string }

// NewFileStore returns a Store rooted at dir, creating it 0700.
func NewFileStore(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("session: create state dir %s: %w", dir, err)
	}
	return &fileStore{dir: dir}, nil
}

func (s *fileStore) path(id string) string { return filepath.Join(s.dir, id+".json") }

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
