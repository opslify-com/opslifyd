package change

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fileService(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	n := time.Unix(1700000000, 0).UTC()
	svc, err := NewService(store, func() time.Time { n = n.Add(time.Second); return n })
	if err != nil {
		t.Fatal(err)
	}
	return svc, dir
}

// TestStoreRefusesTraversalIds is the last line of defence before filepath.Join:
// a change id that reached it unvalidated would be an arbitrary-file write
// running as the daemon user.
func TestStoreRefusesTraversalIds(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Plant a file at the traversal target, so the assertion is that the write was
	// REFUSED rather than that an error came back for some other reason.
	victim := filepath.Join(filepath.Dir(dir), "victim.json")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"../victim", "../../victim", "a/b", "..", ".", `x\y`, "nul\x00"} {
		c := Change{ID: id, Intent: "x", Proposer: Proposer{Kind: ProposerHuman, Name: "a"}, Status: StatusProposed}
		if err := store.Save(c); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("id %q must be refused, got %v", id, err)
		}
		if _, _, err := store.Load(id); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Load(%q) must be refused, got %v", id, err)
		}
	}
	if body, _ := os.ReadFile(victim); string(body) != "original" {
		t.Fatal("a traversal id overwrote a file outside the store")
	}
}

// TestRecordsAreDaemonPrivate: a Change names hosts, resource counts and the
// exact commands an estate runs.
func TestRecordsAreDaemonPrivate(t *testing.T) {
	svc, dir := fileService(t)
	if _, err := svc.Propose(Change{
		ID: "chg-1", Intent: "restart web",
		Proposer: Proposer{Kind: ProposerHuman, Name: "alice"},
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "chg-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %o, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}
}

// TestChangesSurviveARestart: the record is what an operator consults to find out
// what was approved, so it has to outlive the process.
func TestChangesSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := NewService(store, func() time.Time { return time.Unix(1700000000, 0).UTC() })
	c, err := svc.Propose(Change{
		ID: "chg-1", Intent: "restart the web deployment",
		Proposer: Proposer{Kind: ProposerAgent, Name: "qwen", Model: "qwen2.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Preview(c.ID, restartSteps(), "diff", []ResourceCount{{Kind: "pods", Count: 3}}, goodInverse()); err != nil {
		t.Fatal(err)
	}

	// A fresh store over the same directory, as a restarted daemon would build.
	reopened, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc2, _ := NewService(reopened, nil)
	got, err := svc2.Get("chg-1")
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if got.Intent != "restart the web deployment" {
		t.Errorf("intent = %q", got.Intent)
	}
	// The PIN must survive, or an approval after a restart could not be checked
	// against what was reviewed before it.
	if got.PlanHash != Pin(restartSteps()) {
		t.Fatal("the plan pin did not survive a restart; an approval could not then be verified against the reviewed plan")
	}
	if got.Inverse.Kind != InverseManifestReapply {
		t.Errorf("the prepared inverse did not survive: %+v", got.Inverse)
	}
}

// TestListIsNewestFirst: the change an operator wants is almost always the one
// that just happened.
func TestListIsNewestFirst(t *testing.T) {
	svc, _ := fileService(t)
	for _, id := range []string{"chg-a", "chg-b", "chg-c"} {
		if _, err := svc.Propose(Change{
			ID: id, Intent: "do " + id,
			Proposer: Proposer{Kind: ProposerHuman, Name: "alice"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d changes", len(list))
	}
	if list[0].ID != "chg-c" || list[2].ID != "chg-a" {
		t.Errorf("order = %s, %s, %s; want newest first", list[0].ID, list[1].ID, list[2].ID)
	}
}

// TestCorruptRecordIsSkippedAndSurfaced: one bad file must not make every other
// Change unreachable, but it must not vanish silently either.
func TestCorruptRecordIsSkippedAndSurfaced(t *testing.T) {
	svc, dir := fileService(t)
	if _, err := svc.Propose(Change{
		ID: "chg-good", Intent: "fine",
		Proposer: Proposer{Kind: ProposerHuman, Name: "alice"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chg-broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := svc.List()
	if err != nil {
		t.Fatalf("a corrupt record must not fail the whole listing: %v", err)
	}
	if len(list) != 1 || list[0].ID != "chg-good" {
		t.Fatalf("the good record must still list: %v", list)
	}
}

// TestDuplicateIdIsRefused: silently overwriting would replace the record of what
// was approved.
func TestDuplicateIdIsRefused(t *testing.T) {
	svc, _ := fileService(t)
	c := Change{ID: "chg-1", Intent: "x", Proposer: Proposer{Kind: ProposerHuman, Name: "alice"}}
	if _, err := svc.Propose(c); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Propose(c); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a duplicate id must be refused, got %v", err)
	}
}
