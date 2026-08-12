package trace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FsyncPolicy controls how aggressively FileSink flushes the append-only log to
// stable storage. The append itself is always ordered (O_APPEND, one write per
// record); the policy only trades durability-on-power-loss against throughput.
type FsyncPolicy string

const (
	// FsyncBatch (default) fsyncs on the durability-significant boundaries
	// exec.end / session.end (and on Seal), letting output chunks batch. A torn
	// last line from a crash is detected and skipped on reload (crash-safe).
	FsyncBatch FsyncPolicy = "batch"
	// FsyncAlways fsyncs after every record — maximum durability, lower throughput.
	FsyncAlways FsyncPolicy = "always"
)

// DefaultRingBufferSize is the default per-session in-memory tail retained for
// instant SSE catch-up. It bounds memory; SSE backfill reads the on-disk log when
// a consumer asks for a from_seq older than the retained tail.
const DefaultRingBufferSize = 1024

// FileSinkConfig configures the durable sink. Zero values take safe defaults.
type FileSinkConfig struct {
	// Dir is the append-only trace directory (one <session>.log per session). It
	// is created 0700 if absent; files are 0600, owned by the daemon user, and are
	// NOT under the workspace mount (the sandbox has no path to them).
	Dir string
	// Fsync selects the flush policy; empty => FsyncBatch.
	Fsync FsyncPolicy
	// RingBufferSize bounds the per-session in-memory tail; <= 0 => default.
	RingBufferSize int
	// Now is an injectable clock for the seal timestamp (tests). nil => time.Now.
	Now func() time.Time
}

// logRecord is one line of the append-only log: exactly one of Event/Seal is set.
// A self-describing wrapper keeps events and the seal distinguishable on reload
// while the embedded Event marshals to the same shape verify already consumes.
type logRecord struct {
	Event *Event     `json:"event,omitempty"`
	Seal  *Signature `json:"seal,omitempty"`
}

// FileSink is the F3.2 durable TraceSink: it assembles the SAME hash chain as
// MemSink (via the shared chainState) while writing one line-delimited JSON record
// per event to an append-only <dir>/<session>.log, and serves live SSE via a
// bounded ring buffer + subscriber fan-out. The on-disk log is the source of
// truth: Export/verify read it, so they survive a daemon restart.
type FileSink struct {
	dir       string
	fsync     FsyncPolicy
	ringSize  int
	signer    Signer
	now       func() time.Time
	subBuffer int

	mu        sync.Mutex // guards sessions + onSession
	sessions  map[string]*fileSession
	onSession func(string) // fired once per newly-opened session (uploader hook)
}

// fileSession is one live session's durable state. Its mutex serializes chain
// assignment + the file append + ring/subscriber updates, so concurrent Appends
// (stdout/stderr pumps) can never interleave a single session's log, and distinct
// sessions never share a file (each has its own fileSession + <session>.log).
type fileSession struct {
	mu    sync.Mutex
	id    string
	f     *os.File
	state chainState
	seal  *Signature

	ring      []Event // bounded tail; ring[0] has seq ringBase
	ringBase  uint64
	notify    chan struct{} // closed+replaced on each append (uploader wakeup)
	subs      map[int]*subscriber
	nextSubID int
}

// subscriber is one live SSE/uploader tail. ch is buffered; on overflow the
// subscription is dropped (closed) rather than blocking Append — the consumer
// reconnects and backfills from the on-disk log, so no on-disk event is lost.
type subscriber struct {
	ch      chan Event
	dropped bool
}

// NewFileSink builds a durable sink rooted at cfg.Dir, sealing with signer (may be
// nil: events still persist, Seal fails legibly). It creates the trace dir 0700.
func NewFileSink(cfg FileSinkConfig, signer Signer) (*FileSink, error) {
	if cfg.Dir == "" {
		return nil, errors.New("trace: file sink requires a trace dir")
	}
	if cfg.Fsync == "" {
		cfg.Fsync = FsyncBatch
	}
	if cfg.RingBufferSize <= 0 {
		cfg.RingBufferSize = DefaultRingBufferSize
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// 0700: the trace dir holds integrity evidence; only the daemon user may read.
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("trace: create trace dir %s: %w", cfg.Dir, err)
	}
	return &FileSink{
		dir:       cfg.Dir,
		fsync:     cfg.Fsync,
		ringSize:  cfg.RingBufferSize,
		signer:    signer,
		now:       cfg.Now,
		subBuffer: cfg.RingBufferSize, // live channel depth mirrors the ring
		sessions:  map[string]*fileSession{},
	}, nil
}

func (s *FileSink) logPath(id string) string { return filepath.Join(s.dir, id+".log") }

// sessionFor returns the live fileSession for id, opening (creating) its log in
// O_APPEND and rehydrating the chain position from any existing on-disk records
// (so a same-process reopen — or a restart — continues the chain, never restarts
// seq at 0).
func (s *FileSink) sessionFor(id string) (*fileSession, error) {
	s.mu.Lock()
	if fs, ok := s.sessions[id]; ok {
		s.mu.Unlock()
		return fs, nil
	}
	defer s.mu.Unlock()
	// Rehydrate chain position + seal from disk (empty for a fresh session).
	events, seal, err := loadSessionLog(s.logPath(id))
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.logPath(id), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("trace: open log %s: %w", s.logPath(id), err)
	}
	fs := &fileSession{
		id:     id,
		f:      f,
		notify: make(chan struct{}),
		subs:   map[int]*subscriber{},
	}
	if n := len(events); n > 0 {
		fs.state.seq = events[n-1].Seq + 1
		fs.state.last = events[n-1].Hash
		// Seed the ring with the tail so an immediate SSE subscribe is instant.
		base := 0
		if n > s.ringSize {
			base = n - s.ringSize
		}
		fs.ring = append(fs.ring, events[base:]...)
		fs.ringBase = events[base].Seq
	}
	fs.seal = seal
	s.sessions[id] = fs
	if s.onSession != nil {
		// Fire in a goroutine so the hook (uploader) cannot deadlock against s.mu,
		// which we still hold here.
		go s.onSession(id)
	}
	return fs, nil
}

// setOnSession registers the per-new-session hook (the uploader's tail launcher).
func (s *FileSink) setOnSession(fn func(string)) {
	s.mu.Lock()
	s.onSession = fn
	s.mu.Unlock()
}

// sessionIDs snapshots the currently-open session ids (uploader adoption on start).
func (s *FileSink) sessionIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	return ids
}

// Append assigns seq/prev_hash/hash under the per-session lock, writes the record
// to the append-only log, updates the ring, and wakes tailers.
func (s *FileSink) Append(_ context.Context, ev Event) error {
	fs, err := s.sessionFor(ev.SessionID)
	if err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.seal != nil {
		return fmt.Errorf("trace: session %s already sealed; refusing append", ev.SessionID)
	}
	if err := fs.state.assign(&ev); err != nil {
		return err
	}
	if err := fs.writeRecord(logRecord{Event: &ev}); err != nil {
		return err
	}
	if s.fsync == FsyncAlways || ev.Type == TypeExecEnd || ev.Type == TypeSessionEnd {
		if err := fs.f.Sync(); err != nil {
			return fmt.Errorf("trace: fsync log %s: %w", fs.id, err)
		}
	}
	fs.pushRing(ev, s.ringSize)
	fs.fanout(ev)
	fs.wake()
	return nil
}

// Seal signs the session's final chain hash and appends the seal record (fsynced).
// Idempotent: a second Seal returns the recorded signature.
func (s *FileSink) Seal(_ context.Context, sessionID string) (Signature, error) {
	fs, err := s.sessionFor(sessionID)
	if err != nil {
		return Signature{}, err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.seal != nil {
		return *fs.seal, nil
	}
	if fs.state.seq == 0 {
		return Signature{}, fmt.Errorf("trace: no events for session %s", sessionID)
	}
	sg, err := sealHash(s.signer, s.now, fs.state.last)
	if err != nil {
		return Signature{}, err
	}
	if err := fs.writeRecord(logRecord{Seal: &sg}); err != nil {
		return Signature{}, err
	}
	if err := fs.f.Sync(); err != nil {
		return Signature{}, fmt.Errorf("trace: fsync seal %s: %w", sessionID, err)
	}
	fs.seal = &sg
	fs.wake() // let a tailing uploader observe the seal / session end
	return sg, nil
}

// Export reads a session's events (chain order) + seal. It ALWAYS reads the
// on-disk log (the durable source of truth), so `opslify verify` works across a
// daemon restart. A live session is read under its lock to avoid a torn read; an
// unknown (post-restart, not-yet-reopened) session is read straight from the file.
func (s *FileSink) Export(sessionID string) ([]Event, *Signature, bool) {
	s.mu.Lock()
	fs := s.sessions[sessionID]
	s.mu.Unlock()
	if fs != nil {
		fs.mu.Lock()
		defer fs.mu.Unlock()
	}
	events, seal, err := loadSessionLog(s.logPath(sessionID))
	if err != nil || len(events) == 0 {
		return nil, nil, false
	}
	return events, seal, true
}

// Subscribe backfills events with seq >= fromSeq from the ring (or the on-disk log
// when the tail is too short) and returns a channel of subsequently-appended
// events plus a cancel func. Snapshot + registration are atomic under the session
// lock: the live channel begins exactly at the next seq after the backfill, so a
// consumer sees every event once with no gap.
func (s *FileSink) Subscribe(sessionID string, fromSeq uint64) ([]Event, <-chan Event, func(), error) {
	fs, err := s.sessionFor(sessionID)
	if err != nil {
		return nil, nil, nil, err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	var backfill []Event
	if fromSeq < fs.state.seq { // there is history to replay
		if len(fs.ring) > 0 && fromSeq >= fs.ringBase {
			backfill = append(backfill, fs.ring[fromSeq-fs.ringBase:]...)
		} else {
			// Tail too short (or dropped): read the durable log for full coverage.
			all, _, lerr := loadSessionLog(s.logPath(sessionID))
			if lerr != nil {
				return nil, nil, nil, lerr
			}
			for _, ev := range all {
				if ev.Seq >= fromSeq {
					backfill = append(backfill, ev)
				}
			}
		}
	}

	sub := &subscriber{ch: make(chan Event, s.subBuffer)}
	id := fs.nextSubID
	fs.nextSubID++
	fs.subs[id] = sub
	cancel := func() {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		if _, ok := fs.subs[id]; ok {
			delete(fs.subs, id)
			close(sub.ch)
		}
	}
	return backfill, sub.ch, cancel, nil
}

// Close closes all open log files. Records already written are durable; Close only
// releases descriptors (the daemon calls it on shutdown).
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	for _, fs := range s.sessions {
		fs.mu.Lock()
		if err := fs.f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		fs.mu.Unlock()
	}
	return firstErr
}

// --- fileSession helpers (all called under fs.mu) ---

// writeRecord marshals rec and appends it as one line. A single Write of the
// full line keeps a crash's torn record confined to the LAST line (detected and
// skipped on reload), never corrupting a prior record.
func (fs *fileSession) writeRecord(rec logRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("trace: marshal record: %w", err)
	}
	b = append(b, '\n')
	if _, err := fs.f.Write(b); err != nil {
		return fmt.Errorf("trace: append log %s: %w", fs.id, err)
	}
	return nil
}

// pushRing appends ev to the bounded tail, dropping the oldest BUFFERED view once
// full (never an on-disk record — the log keeps everything).
func (fs *fileSession) pushRing(ev Event, size int) {
	fs.ring = append(fs.ring, ev)
	if len(fs.ring) > size {
		fs.ring = fs.ring[len(fs.ring)-size:]
	}
	fs.ringBase = fs.ring[0].Seq
}

// fanout delivers ev to every live subscriber without blocking Append. A full
// channel means the consumer fell behind: it is dropped (closed) so it reconnects
// and backfills from disk — the on-disk log is never at risk.
func (fs *fileSession) fanout(ev Event) {
	for id, sub := range fs.subs {
		select {
		case sub.ch <- ev:
		default:
			sub.dropped = true
			delete(fs.subs, id)
			close(sub.ch)
		}
	}
}

// wake signals tailers (the uploader) that new records exist, by closing and
// replacing the notify channel — a broadcast without per-waiter bookkeeping.
func (fs *fileSession) wake() {
	close(fs.notify)
	fs.notify = make(chan struct{})
}

// notifyCh returns the current wakeup channel (called under fs.mu by tailers).
func (fs *fileSession) notifyCh() chan struct{} { return fs.notify }

// waitCh exposes the session's current notify channel for a tailer to block on.
func (s *FileSink) waitCh(sessionID string) (<-chan struct{}, bool) {
	s.mu.Lock()
	fs := s.sessions[sessionID]
	s.mu.Unlock()
	if fs == nil {
		return nil, false
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.notifyCh(), true
}

// loadSessionLog reads <path> and returns its events (chain order) + seal. It is
// crash-safe AND tamper-legible:
//   - a torn/partial LAST line (a crash mid-append) is detected and skipped,
//     leaving all prior records intact and the chain unbroken;
//   - a corrupt/unparseable NON-LAST line is tampering, not a torn write. It is
//     dropped from the returned events, which leaves a seq GAP that trace.Verify
//     reports as a tamper failure at that record — so `opslify verify` prints
//     TAMPER at the right seq rather than a misleading "not found".
//
// A missing file => empty, no error.
func loadSessionLog(path string) ([]Event, *Signature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("trace: read log %s: %w", path, err)
	}
	lines := bytes.Split(data, []byte{'\n'})
	// A clean file ends in '\n', so the final split element is empty; a torn write
	// leaves a non-empty final element with no trailing newline. Find the index of
	// the last non-empty line so we can treat only IT as possibly-torn.
	lastNonEmpty := -1
	for i, ln := range lines {
		if len(bytes.TrimSpace(ln)) > 0 {
			lastNonEmpty = i
		}
	}
	var (
		events []Event
		seal   *Signature
	)
	for i, ln := range lines {
		if len(bytes.TrimSpace(ln)) == 0 {
			continue
		}
		var rec logRecord
		if err := json.Unmarshal(ln, &rec); err != nil {
			if i == lastNonEmpty {
				break // torn last line from a crash: skip it, prior records stand
			}
			// Corrupt NON-last record = tampering. Drop it and keep parsing: the
			// resulting seq gap makes trace.Verify fail at this record (TAMPER),
			// which is the correct audit signal — never a silent pass.
			continue
		}
		switch {
		case rec.Seal != nil:
			seal = rec.Seal
		case rec.Event != nil:
			events = append(events, *rec.Event)
		}
	}
	return events, seal, nil
}

var _ TraceSink = (*FileSink)(nil)
var _ Exporter = (*FileSink)(nil)
var _ Streamer = (*FileSink)(nil)
