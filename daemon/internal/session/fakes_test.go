package session

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// fakeClock is a manually-advanced Clock so TTL/age accounting is deterministic
// (no sleeping on the wall clock).
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeRuntime is an in-memory Runtime double implementing the F0.3 interface. It
// records the SessionSpec of the last Create (so tests can assert what the
// manager asked the runtime to build) and counts Destroy calls (so tests can
// prove no sandbox leaks). available controls the capability gate.
type fakeRuntime struct {
	mu           sync.Mutex
	available    error
	createErr    error
	execErr      error
	lastSpec     runtime.SessionSpec
	specs        []runtime.SessionSpec // every Create spec, in order (resume-base checks)
	created      int
	destroyed    int
	destroyedIDs []string
	snapshots    []string // images committed via Snapshot, in order
	removed      []string // images deleted via RemoveImage (ImageRemover)
	nextExec     runtime.ExecStream
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		nextExec: runtime.ExecStream{
			Stdout:   strings.NewReader(""),
			Stderr:   strings.NewReader(""),
			ExitCode: 0,
		},
	}
}

func (f *fakeRuntime) Create(_ context.Context, spec runtime.SessionSpec) (runtime.ContainerHandle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return runtime.ContainerHandle{}, f.createErr
	}
	f.lastSpec = spec
	f.specs = append(f.specs, spec)
	f.created++
	return runtime.ContainerHandle{
		ID:      fmt.Sprintf("ctr-%d", f.created),
		Tier:    spec.Tier,
		Runtime: "runsc",
	}, nil
}

func (f *fakeRuntime) Exec(_ context.Context, _ runtime.ContainerHandle, _ runtime.ExecRequest) (runtime.ExecStream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.execErr != nil {
		return runtime.ExecStream{}, f.execErr
	}
	return f.nextExec, nil
}

func (f *fakeRuntime) Destroy(_ context.Context, h runtime.ContainerHandle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyed++
	f.destroyedIDs = append(f.destroyedIDs, h.ID)
	return nil
}

func (f *fakeRuntime) Snapshot(_ context.Context, _ runtime.ContainerHandle, name string) (runtime.ImageRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshots = append(f.snapshots, name)
	return runtime.ImageRef{Name: name}, nil
}

// RemoveImage makes fakeRuntime satisfy runtime.ImageRemover so retention prune
// and `ws rm` are exercised in unit tests.
func (f *fakeRuntime) RemoveImage(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, ref)
	return nil
}

func (f *fakeRuntime) Available() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.available
}

func (f *fakeRuntime) createdCount() int   { f.mu.Lock(); defer f.mu.Unlock(); return f.created }
func (f *fakeRuntime) destroyedCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.destroyed }
func (f *fakeRuntime) spec() runtime.SessionSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastSpec
}

// memStore is an in-memory Store double.
type memStore struct {
	mu         sync.Mutex
	records    map[string]record
	workspaces map[string]workspaceRecord
}

func newMemStore() *memStore {
	return &memStore{records: map[string]record{}, workspaces: map[string]workspaceRecord{}}
}

func (s *memStore) Save(r record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[r.ID] = r
	return nil
}

func (s *memStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, id)
	return nil
}

func (s *memStore) LoadAll() ([]record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	return out, nil
}

func (s *memStore) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.records) }

func (s *memStore) SaveWorkspace(w workspaceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workspaces[w.Name] = w
	return nil
}

func (s *memStore) LoadWorkspace(name string) (workspaceRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.workspaces[name]
	return w, ok, nil
}

func (s *memStore) LoadWorkspaces() ([]workspaceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]workspaceRecord, 0, len(s.workspaces))
	for _, w := range s.workspaces {
		out = append(out, w)
	}
	return out, nil
}

func (s *memStore) DeleteWorkspace(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.workspaces, name)
	return nil
}

// captureSink is an in-memory ExecSink recording frames for assertions.
type captureSink struct {
	mu        sync.Mutex
	stdout    []byte
	stderr    []byte
	truncated map[string]bool
	exit      *int
	err       error
}

func newCaptureSink() *captureSink {
	return &captureSink{truncated: map[string]bool{}}
}

func (c *captureSink) Chunk(stream string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Copy: the pump reuses its buffer between reads.
	cp := append([]byte(nil), data...)
	if stream == StreamStdout {
		c.stdout = append(c.stdout, cp...)
	} else {
		c.stderr = append(c.stderr, cp...)
	}
	return nil
}

func (c *captureSink) Truncated(stream string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.truncated[stream] = true
	return nil
}

func (c *captureSink) Exit(code int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.exit = &code
	return nil
}

var _ io.Reader = strings.NewReader("")
