package session

import (
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// The file store round-trips records and survives a "restart" (fresh store over
// the same dir sees the prior records) — the property orphan reconciliation
// depends on.
func TestFileStoreRoundTripAndRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	r := record{
		ID:      "sess1",
		Mode:    ModeScratch,
		Tier:    runtime.TierLocalHardened,
		Handle:  runtime.ContainerHandle{ID: "ctr1", Runtime: "runsc"},
		Created: time.Unix(1000, 0).UTC(),
		TTL:     30 * time.Minute,
	}
	if err := st.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Simulate a daemon restart: a brand-new store over the same directory.
	st2, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := st2.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(got) != 1 || got[0].ID != "sess1" || got[0].Handle.ID != "ctr1" {
		t.Fatalf("records not durable across restart: %+v", got)
	}

	if err := st2.Delete("sess1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got, _ := st2.LoadAll(); len(got) != 0 {
		t.Fatalf("record not deleted: %+v", got)
	}
	// Deleting a missing record is not an error.
	if err := st2.Delete("ghost"); err != nil {
		t.Fatalf("Delete missing: %v", err)
	}
}
