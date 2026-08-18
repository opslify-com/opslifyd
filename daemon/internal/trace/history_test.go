package trace

import (
	"context"
	"testing"
)

// AC (F3.6): History lists PERSISTED sessions from the durable store with cheap
// metadata (tier, event count, sealed, start/end), newest first — independent of
// any live in-memory state.
func TestFileSinkHistoryListsPersisted(t *testing.T) {
	dir := t.TempDir()
	sink := newFileSink(t, dir, newTestSigner(t))

	// Two fully-recorded + sealed sessions.
	emitSession(t, sink, "sess-A")
	emitSession(t, sink, "sess-B")

	// A third, still-live (unsealed) session: session.start only, no session.end.
	rec := NewRecorder(sink, "sess-live", NoopRedactor{}, fixedClock())
	if err := rec.Emit(context.Background(), TypeSessionStart, startPayload()); err != nil {
		t.Fatalf("emit start: %v", err)
	}

	hist, err := sink.History()
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 3 {
		t.Fatalf("History returned %d sessions, want 3: %+v", len(hist), hist)
	}

	byID := map[string]SessionMeta{}
	for _, m := range hist {
		byID[m.SessionID] = m
	}
	a, ok := byID["sess-A"]
	if !ok {
		t.Fatal("sess-A missing from history")
	}
	if a.Tier != "local-hardened" {
		t.Errorf("sess-A tier = %q, want local-hardened", a.Tier)
	}
	if a.EventCount != 6 {
		t.Errorf("sess-A event_count = %d, want 6", a.EventCount)
	}
	if !a.Sealed {
		t.Error("sess-A should be sealed")
	}
	if a.EndedAt == nil {
		t.Error("sess-A should have an ended_at (session.end recorded)")
	}
	if live := byID["sess-live"]; live.Sealed || live.EndedAt != nil {
		t.Errorf("sess-live should be unsealed + open-ended, got %+v", live)
	}

	// Newest first: start timestamps strictly non-increasing.
	for i := 1; i < len(hist); i++ {
		if hist[i].StartedAt.After(hist[i-1].StartedAt) {
			t.Errorf("history not newest-first at %d: %v after %v", i, hist[i].StartedAt, hist[i-1].StartedAt)
		}
	}
}

// QA (F3.6): an ended session survives a daemon restart (a NEW FileSink over the
// SAME trace dir) and still lists — history reads the durable store, not memory.
func TestFileSinkHistorySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	signer := newTestSigner(t)

	first := newFileSink(t, dir, signer)
	emitSession(t, first, "sess-restart")
	_ = first.Close()

	// Fresh sink over the same dir = a daemon restart with no in-memory sessions.
	second := newFileSink(t, dir, signer)
	hist, err := second.History()
	if err != nil {
		t.Fatalf("History after restart: %v", err)
	}
	if len(hist) != 1 || hist[0].SessionID != "sess-restart" {
		t.Fatalf("post-restart history = %+v, want [sess-restart]", hist)
	}
	if hist[0].EventCount != 6 || !hist[0].Sealed {
		t.Errorf("post-restart meta = %+v, want 6 events + sealed", hist[0])
	}
}
