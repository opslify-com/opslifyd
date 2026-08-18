package trace

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SessionMeta is a cheap, read-only summary of one PERSISTED session in the
// durable trace store, used by the F3.6 past-session browser. It is derived
// purely from the on-disk log — independent of whether the session is still
// live in memory — so an ended session (even one that survived a daemon
// restart) is listable, replayable, and verifiable. It carries NO event
// payloads, only counts + lifecycle timestamps, so it adds no data path.
type SessionMeta struct {
	SessionID  string     `json:"session_id"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	Tier       string     `json:"tier,omitempty"`
	EventCount int        `json:"event_count"`
	Sealed     bool       `json:"sealed"`
}

// Historian is the read-only seam the F3.6 past-session browser drives: it
// enumerates the persisted sessions in the durable store (newest first). Only
// FileSink implements it — MemSink has no durable directory to enumerate, so a
// daemon without persistence has no history (a legible ErrNotFound upstream).
type Historian interface {
	History() ([]SessionMeta, error)
}

// History enumerates <dir>/*.log and returns a cheap metadata summary per
// persisted session, newest first. It reads each log through the same
// crash-safe/tamper-legible loader Export uses (a torn last line is skipped; a
// mid-file tamper still counts its surviving events), so history agrees with
// verify. A log with no parseable events is skipped. It never returns event
// payloads — only counts and lifecycle timestamps.
func (s *FileSink) History() ([]SessionMeta, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("trace: read trace dir %s: %w", s.dir, err)
	}
	out := make([]SessionMeta, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".log") {
			continue
		}
		id := strings.TrimSuffix(name, ".log")
		events, seal, err := loadSessionLog(filepath.Join(s.dir, name))
		if err != nil || len(events) == 0 {
			continue
		}
		meta := SessionMeta{
			SessionID:  id,
			StartedAt:  events[0].TS,
			Tier:       payloadString(events[0].Payload, "tier"),
			EventCount: len(events),
			Sealed:     seal != nil,
		}
		// EndedAt is the terminal event's time once the session has closed
		// (session.end recorded, or sealed). A still-live session has no end.
		last := events[len(events)-1]
		if seal != nil || last.Type == TypeSessionEnd {
			t := last.TS
			meta.EndedAt = &t
		}
		out = append(out, meta)
	}
	// Newest first by start time; stable so equal timestamps keep dir order.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out, nil
}

var _ Historian = (*FileSink)(nil)
