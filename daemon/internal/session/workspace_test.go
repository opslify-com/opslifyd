package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// newWSManager builds a Manager over an explicit workspace root + store so a
// "restart" can be modeled by constructing a second manager over the same two.
func newWSManager(t *testing.T, rt runtime.Runtime, clk Clock, st Store, root string) *Manager {
	t.Helper()
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:             "base@sha256:deadbeef",
			ToolchainDigest:   "tool@sha256:cafe",
			WorkspaceRoot:     root,
			DefaultTier:       runtime.TierLocalHardened,
			DefaultTTL:        30 * time.Minute,
			Limits:            runtime.ResourceLimits{MemoryBytes: 2 << 30, CPUs: 2, PidsLimit: 256},
			SnapshotRetention: 3,
		},
		Resolve: func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:   clk,
		Store:   st,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// AC: a workspace persists installed state across sessions (host dir), resumes
// from its latest rootfs snapshot, and survives a daemon restart.
func TestWorkspaceMode_PersistResumeRestart(t *testing.T) {
	rt := newFakeRuntime()
	st := newMemStore()
	root := t.TempDir()
	clk := newFakeClock(time.Unix(0, 0))
	m := newWSManager(t, rt, clk, st, root)
	ctx := context.Background()
	wsDir := filepath.Join(root, "ws-proj")

	// First create: no prior snapshot → boots the signed base image.
	s1, err := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: "proj"})
	if err != nil {
		t.Fatalf("create1: %v", err)
	}
	if s1.WorkspaceDir != wsDir {
		t.Fatalf("workspace dir = %q, want %q", s1.WorkspaceDir, wsDir)
	}
	if got := rt.specs[0].Image; got != "base@sha256:deadbeef" {
		t.Fatalf("first create base image = %q, want signed base", got)
	}
	// Agent writes state into /workspace (the only writable path).
	if err := os.WriteFile(filepath.Join(wsDir, "deps.txt"), []byte("installed"), 0o600); err != nil {
		t.Fatal(err)
	}

	// End → rootfs snapshot committed, record saved, host dir KEPT.
	if err := m.Destroy(ctx, s1.ID); err != nil {
		t.Fatalf("destroy1: %v", err)
	}
	if len(rt.snapshots) != 1 || rt.snapshots[0] != "opslify/ws-proj:1" {
		t.Fatalf("snapshots = %v, want [opslify/ws-proj:1]", rt.snapshots)
	}
	if _, err := os.Stat(filepath.Join(wsDir, "deps.txt")); err != nil {
		t.Fatalf("workspace dir must persist after end: %v", err)
	}

	// Resume: base image = latest snapshot; same host dir → deps still present.
	s2, err := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: "proj"})
	if err != nil {
		t.Fatalf("create2: %v", err)
	}
	if s2.WorkspaceDir != wsDir {
		t.Fatalf("resume dir = %q, want %q", s2.WorkspaceDir, wsDir)
	}
	if got := rt.specs[len(rt.specs)-1].Image; got != "opslify/ws-proj:1" {
		t.Fatalf("resume base = %q, want latest snapshot opslify/ws-proj:1", got)
	}
	if b, _ := os.ReadFile(filepath.Join(wsDir, "deps.txt")); string(b) != "installed" {
		t.Fatalf("deps lost on resume: %q", b)
	}
	if err := m.Destroy(ctx, s2.ID); err != nil { // snapshot :2
		t.Fatalf("destroy2: %v", err)
	}

	// Restart: a NEW manager over the SAME store + root resumes from :2 with deps.
	m2 := newWSManager(t, rt, clk, st, root)
	s3, err := m2.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: "proj"})
	if err != nil {
		t.Fatalf("create after restart: %v", err)
	}
	if got := rt.specs[len(rt.specs)-1].Image; got != "opslify/ws-proj:2" {
		t.Fatalf("post-restart resume base = %q, want opslify/ws-proj:2", got)
	}
	if b, _ := os.ReadFile(filepath.Join(wsDir, "deps.txt")); string(b) != "installed" {
		t.Fatalf("deps lost after restart: %q", b)
	}
	_ = m2.Destroy(ctx, s3.ID)
}

// AC: retention caps snapshots per name; older images are pruned + removed.
func TestWorkspaceMode_RetentionPrunes(t *testing.T) {
	rt := newFakeRuntime()
	st := newMemStore()
	m := newWSManager(t, rt, newFakeClock(time.Unix(0, 0)), st, t.TempDir())
	ctx := context.Background()
	for i := 0; i < 4; i++ { // retention 3 → the 4th commit prunes the oldest
		s, err := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: "w"})
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		if err := m.Destroy(ctx, s.ID); err != nil {
			t.Fatalf("destroy %d: %v", i, err)
		}
	}
	if len(rt.snapshots) != 4 {
		t.Fatalf("committed %d snapshots, want 4", len(rt.snapshots))
	}
	if len(rt.removed) != 1 || rt.removed[0] != "opslify/ws-w:1" {
		t.Fatalf("removed = %v, want [opslify/ws-w:1]", rt.removed)
	}
	rec, ok, _ := st.LoadWorkspace("w")
	if !ok || len(rec.Snapshots) != 3 {
		t.Fatalf("kept %d snapshots, want 3", len(rec.Snapshots))
	}
}

// Security AC: a RESUMED workspace session still carries the full hard-spec —
// only the base-image FS carries over, never a hardening bypass.
func TestWorkspaceMode_ResumePreservesHardening(t *testing.T) {
	rt := newFakeRuntime()
	st := newMemStore()
	m := newWSManager(t, rt, newFakeClock(time.Unix(0, 0)), st, t.TempDir())
	ctx := context.Background()

	s, _ := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: "h"})
	_ = m.Destroy(ctx, s.ID) // snapshot :1
	if _, err := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: "h"}); err != nil {
		t.Fatalf("resume create: %v", err)
	}
	args, err := runtime.RenderCreateArgs(runtime.TierLocalHardened, rt.spec())
	if err != nil {
		t.Fatalf("RenderCreateArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, w := range []string{"--cap-drop=ALL", "--security-opt=no-new-privileges", "--userns=auto", "--read-only", "--pid=private"} {
		if !strings.Contains(joined, w) {
			t.Errorf("resumed workspace spec missing hardening flag %q: %v", w, args)
		}
	}
	if rt.spec().Image != "opslify/ws-h:1" {
		t.Errorf("resume base = %q, want the snapshot", rt.spec().Image)
	}
}

// AC: ws ls lists workspaces; ws rm removes record + image + dir; rm of an
// in-use workspace is refused.
func TestWorkspaceListAndRemove(t *testing.T) {
	rt := newFakeRuntime()
	st := newMemStore()
	root := t.TempDir()
	m := newWSManager(t, rt, newFakeClock(time.Unix(0, 0)), st, root)
	ctx := context.Background()

	for _, n := range []string{"a", "b"} {
		s, _ := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: n})
		_ = m.Destroy(ctx, s.ID)
	}
	ws, err := m.ListWorkspaces()
	if err != nil {
		t.Fatalf("ListWorkspaces: %v", err)
	}
	if len(ws) != 2 || ws[0].Name != "a" || ws[1].Name != "b" || ws[0].Snapshots != 1 {
		t.Fatalf("ws = %+v", ws)
	}

	if err := m.RemoveWorkspace(ctx, "a"); err != nil {
		t.Fatalf("rm a: %v", err)
	}
	if _, ok, _ := st.LoadWorkspace("a"); ok {
		t.Fatal("record a not deleted")
	}
	if _, err := os.Stat(filepath.Join(root, "ws-a")); !os.IsNotExist(err) {
		t.Fatalf("ws-a dir not removed: %v", err)
	}
	var found bool
	for _, r := range rt.removed {
		if r == "opslify/ws-a:1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("snapshot image not removed: %v", rt.removed)
	}

	// rm of an in-use workspace is refused.
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: "b"})
	if err := m.RemoveWorkspace(ctx, "b"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("rm in-use err = %v, want ErrInvalidInput", err)
	}
	_ = m.Destroy(ctx, s.ID)
}

// Boundary: workspace mode requires a valid, traversal-free name.
func TestWorkspaceBadNameRejected(t *testing.T) {
	m := newTestManager(t, newFakeRuntime(), newFakeClock(time.Unix(0, 0)), newMemStore())
	for _, bad := range []string{"", "../x", "a/b", "UPPER", "a:b", "a b"} {
		if _, err := m.Create(context.Background(), CreateRequest{Mode: ModeWorkspace, Name: bad}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("name %q: err = %v, want ErrInvalidInput", bad, err)
		}
	}
}

// scratch mode is unchanged: its per-session dir is discarded on end, no snapshot.
func TestScratchModeNoSnapshotEphemeralDir(t *testing.T) {
	rt := newFakeRuntime()
	root := t.TempDir()
	m := newWSManager(t, rt, newFakeClock(time.Unix(0, 0)), newMemStore(), root)
	ctx := context.Background()
	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	dir := s.WorkspaceDir
	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if len(rt.snapshots) != 0 {
		t.Fatalf("scratch must not snapshot: %v", rt.snapshots)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("scratch dir must be discarded: %v", err)
	}
}
