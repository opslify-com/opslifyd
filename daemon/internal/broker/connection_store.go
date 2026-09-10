package broker

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ConnectionStore persists connection SPECS — never values. A spec references a
// secret by ref, so the store holds nothing worth stealing even if read.
type ConnectionStore interface {
	Save(spec ConnectionSpec) error
	Load(scopeKey, name string) (ConnectionSpec, bool, error)
	List() ([]ConnectionSpec, error)
	Delete(scopeKey, name string) error
}

// connectionFileStore keeps one 0600 JSON file per connection.
type connectionFileStore struct {
	dir string
	log *slog.Logger
}

// NewConnectionStore returns a store rooted at dir, created 0700 (owner-only):
// connection metadata is daemon-private. It names hosts and secret refs, which
// together describe an estate's shape — worth withholding even though no value
// is present.
func NewConnectionStore(dir string) (ConnectionStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("broker: create connection state dir %s: %w", dir, err)
	}
	return &connectionFileStore{dir: dir, log: slog.Default()}, nil
}

// ScopeKey is the project/environment a connection belongs to, rendered as one
// safe filename segment.
//
// An empty scope is the DAEMON-WIDE scope, spelled explicitly rather than left
// as an empty string in a filename — a record whose name begins with a separator
// is the kind of thing that turns into a path bug later.
func ScopeKey(projectID, environmentID string) string {
	switch {
	case environmentID != "":
		return environmentID
	case projectID != "":
		return projectID
	default:
		return "_daemon"
	}
}

// recordName is the on-disk identity of one connection.
func recordName(scopeKey, name string) string { return scopeKey + "__" + name }

// safeConnectionID refuses any id that could address a file outside the store.
//
// Callers validate at the trust boundary (ValidateSpec); this is the LAST line of
// defence, so a caller that forgets is a refused write rather than an
// arbitrary-file primitive running as the daemon user. Same reasoning as
// project.safeRecordID — the id reaches filepath.Join.
func safeConnectionID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty connection id", ErrInvalidInput)
	}
	if id != filepath.Base(id) || id == "." || id == ".." ||
		strings.ContainsAny(id, `/\`+"\x00") {
		return fmt.Errorf("%w: unsafe connection id %q", ErrInvalidInput, id)
	}
	return nil
}

func (s *connectionFileStore) path(scopeKey, name string) (string, error) {
	id := recordName(scopeKey, name)
	if err := safeConnectionID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, id+".json"), nil
}

func (s *connectionFileStore) Save(spec ConnectionSpec) error {
	if err := spec.ValidateSpec(); err != nil {
		return err
	}
	key := ScopeKey(spec.ProjectID, spec.EnvironmentID)
	if err := safeConnectionID(key); err != nil {
		return err
	}
	p, err := s.path(key, spec.Name)
	if err != nil {
		return err
	}
	b, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("broker: marshal connection %s: %w", spec.Name, err)
	}
	// Temp + rename, so a crash mid-write never leaves a half-written record the
	// loader would choke on — and never leaves a connection an operator believes
	// exists in an unparseable state.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("broker: write connection %s: %w", spec.Name, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("broker: commit connection %s: %w", spec.Name, err)
	}
	return nil
}

func (s *connectionFileStore) Load(scopeKey, name string) (ConnectionSpec, bool, error) {
	p, err := s.path(scopeKey, name)
	if err != nil {
		return ConnectionSpec{}, false, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return ConnectionSpec{}, false, nil
		}
		return ConnectionSpec{}, false, fmt.Errorf("broker: read connection %s: %w", name, err)
	}
	var spec ConnectionSpec
	if err := json.Unmarshal(b, &spec); err != nil {
		return ConnectionSpec{}, false, fmt.Errorf("broker: parse connection %s: %w", name, err)
	}
	return spec, true, nil
}

// List returns every persisted spec, name-sorted.
//
// A corrupt record is SURFACED and skipped rather than failing the whole listing:
// one bad file must not make every other connection unreachable, but it must not
// vanish silently either — an operator would simply stop seeing a connection they
// still have on disk.
func (s *connectionFileStore) List() ([]ConnectionSpec, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("broker: read connection state dir %s: %w", s.dir, err)
	}
	var out []ConnectionSpec
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if rerr != nil {
			s.logger().Warn("broker: skipping unreadable connection record", "file", e.Name(), "err", rerr)
			continue
		}
		var spec ConnectionSpec
		if jerr := json.Unmarshal(b, &spec); jerr != nil {
			s.logger().Warn("broker: skipping unparseable connection record — it will not appear in listings",
				"file", e.Name(), "err", jerr)
			continue
		}
		out = append(out, spec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProjectID != out[j].ProjectID {
			return out[i].ProjectID < out[j].ProjectID
		}
		if out[i].EnvironmentID != out[j].EnvironmentID {
			return out[i].EnvironmentID < out[j].EnvironmentID
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (s *connectionFileStore) Delete(scopeKey, name string) error {
	p, err := s.path(scopeKey, name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("broker: delete connection %s: %w", name, err)
	}
	return nil
}

func (s *connectionFileStore) logger() *slog.Logger {
	if s.log == nil {
		return slog.Default()
	}
	return s.log
}

// --- service ------------------------------------------------------------------

// ConnectionService is the operator-facing surface: add, list, remove, and
// resolving the set in force for a session's scope.
type ConnectionService struct {
	store    ConnectionStore
	registry *Registry
	secrets  SecretResolver
}

// NewConnectionService wires the service.
func NewConnectionService(store ConnectionStore, registry *Registry, secrets SecretResolver) (*ConnectionService, error) {
	if store == nil || registry == nil {
		return nil, fmt.Errorf("broker: a connection store and registry are required")
	}
	return &ConnectionService{store: store, registry: registry, secrets: secrets}, nil
}

// Add validates a spec by BUILDING it and then stores it.
//
// Building first is the point: a spec that cannot produce a working connection is
// rejected at create time, where the operator is watching, rather than at session
// start where it surfaces as an agent mysteriously lacking access.
func (s *ConnectionService) Add(spec ConnectionSpec) error {
	if _, err := s.registry.Build(spec, s.secrets); err != nil {
		return err
	}
	existing, found, err := s.store.Load(ScopeKey(spec.ProjectID, spec.EnvironmentID), spec.Name)
	if err != nil {
		return err
	}
	if found {
		return fmt.Errorf("%w: connection %q already exists in this scope (kind %s)", ErrExists, existing.Name, existing.Kind)
	}
	return s.store.Save(spec)
}

// Validate checks a spec by building it, WITHOUT storing anything.
//
// Building rather than merely checking fields is the point: it exercises the same
// path a session will, so `connection test` cannot pass on something that fails
// at session start.
func (s *ConnectionService) Validate(spec ConnectionSpec) error {
	_, err := s.registry.Build(spec, s.secrets)
	return err
}

// Replace overwrites an existing connection, validating the new spec first.
func (s *ConnectionService) Replace(spec ConnectionSpec) error {
	if _, err := s.registry.Build(spec, s.secrets); err != nil {
		return err
	}
	return s.store.Save(spec)
}

// List returns every stored spec.
func (s *ConnectionService) List() ([]ConnectionSpec, error) { return s.store.List() }

// Remove deletes a connection by scope and name.
func (s *ConnectionService) Remove(projectID, environmentID, name string) error {
	key := ScopeKey(projectID, environmentID)
	_, found, err := s.store.Load(key, name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: connection %q in scope %q", ErrNotFound, name, key)
	}
	return s.store.Delete(key, name)
}

// ForScope returns the built connections in force for a session.
//
// A connection applies when its scope matches the session's environment, its
// project, or is daemon-wide. Broader scopes are included so a daemon-wide
// connection does not have to be repeated per project — the scoping model is
// "applies to everything at or below me", the same shape as the policy layers.
//
// It FAILS CLOSED on a spec that cannot build. A session running without a
// connection an operator configured would fail later, inside the agent's work, as
// a confusing authorization error.
func (s *ConnectionService) ForScope(projectID, environmentID string) ([]Connection, error) {
	specs, err := s.store.List()
	if err != nil {
		return nil, err
	}
	var out []Connection
	for _, spec := range specs {
		if !specApplies(spec, projectID, environmentID) {
			continue
		}
		c, err := s.registry.Build(spec, s.secrets)
		if err != nil {
			return nil, fmt.Errorf("broker: connection %q (kind %s) is stored but unusable: %w", spec.Name, spec.Kind, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// specApplies reports whether a stored spec is in force for a scope.
func specApplies(spec ConnectionSpec, projectID, environmentID string) bool {
	switch {
	case spec.EnvironmentID != "":
		return spec.EnvironmentID == environmentID
	case spec.ProjectID != "":
		return spec.ProjectID == projectID
	default:
		return true // daemon-wide
	}
}

// Consumers exposes the stored specs as an F8.3 consumer source, so a secret a
// connection depends on cannot be deleted out from under it.
func (s *ConnectionService) Consumers() (map[string][]Consumer, error) {
	specs, err := s.store.List()
	if err != nil {
		// FAIL CLOSED: an index that cannot read the connections would under-report
		// consumers, and under-reporting is exactly what lets a delete break a live
		// grant.
		return nil, err
	}
	return ConnectionConsumers(specs).Consumers()
}
