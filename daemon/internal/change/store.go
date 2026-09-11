package change

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileStore keeps one 0600 JSON file per Change.
type fileStore struct {
	dir string
	log *slog.Logger
}

// NewFileStore returns a Store rooted at dir, created 0700.
//
// A Change record is daemon-private even though it holds no credential: it names
// hosts, resource counts and the exact commands an estate runs, which together
// describe far more than any single one of them does.
func NewFileStore(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("change: create state dir %s: %w", dir, err)
	}
	// MkdirAll does NOT tighten a directory that already exists, so a state dir
	// left at 0755 by an earlier release (or created by hand) would stay
	// world-readable and nothing would say so. Chmod unconditionally: this
	// directory is daemon-private, and tightening it is always the right answer.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("change: secure state dir %s: %w", dir, err)
	}
	return &fileStore{dir: dir, log: slog.Default()}, nil
}

// safeRecordID is the last line of defence before filepath.Join. Callers validate
// at the trust boundary; this refuses anything that could still address a file
// outside the record directory.
func safeRecordID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty change id", ErrInvalidInput)
	}
	if id != filepath.Base(id) || id == "." || id == ".." ||
		strings.ContainsAny(id, `/\`+"\x00") {
		return fmt.Errorf("%w: unsafe change id %q", ErrInvalidInput, id)
	}
	return nil
}

func (s *fileStore) path(id string) (string, error) {
	if err := safeRecordID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, id+".json"), nil
}

func (s *fileStore) Save(c Change) error {
	p, err := s.path(c.ID)
	if err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("change: marshal %s: %w", c.ID, err)
	}
	// Temp + rename. A half-written Change is worse than most half-written
	// records: it is the thing an operator consults to find out what was approved.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("change: write %s: %w", c.ID, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("change: commit %s: %w", c.ID, err)
	}
	return nil
}

func (s *fileStore) Load(id string) (Change, bool, error) {
	p, err := s.path(id)
	if err != nil {
		return Change{}, false, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Change{}, false, nil
		}
		return Change{}, false, fmt.Errorf("change: read %s: %w", id, err)
	}
	var c Change
	if err := json.Unmarshal(b, &c); err != nil {
		return Change{}, false, fmt.Errorf("change: parse %s: %w", id, err)
	}
	return c, true, nil
}

// List returns every Change, NEWEST FIRST — the order an operator wants, since
// the thing they are looking for is almost always the one that just happened.
//
// A corrupt record is surfaced and skipped: one bad file must not make every
// other Change unreachable, but it must not vanish silently either, or an
// operator stops seeing a Change they still have on disk.
func (s *fileStore) List() ([]Change, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("change: read state dir %s: %w", s.dir, err)
	}
	var out []Change
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if rerr != nil {
			s.logger().Warn("change: skipping unreadable record", "file", e.Name(), "err", rerr)
			continue
		}
		var c Change
		if jerr := json.Unmarshal(b, &c); jerr != nil {
			s.logger().Warn("change: skipping unparseable record — it will not appear in listings",
				"file", e.Name(), "err", jerr)
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *fileStore) logger() *slog.Logger {
	if s.log == nil {
		return slog.Default()
	}
	return s.log
}
