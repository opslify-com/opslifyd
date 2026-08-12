package trace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UploaderConfig configures the optional cloud push. With BackendURL empty the
// uploader is a clean no-op: local persistence and the local SSE stream are
// entirely unaffected (this is the default posture).
type UploaderConfig struct {
	// BackendURL receives POSTed events (one JSON event per request). Empty => the
	// uploader does nothing. The real receiver is F3.4; tests use a fake server.
	BackendURL string
	// Dir is the trace dir; the per-session acked-seq is persisted here as
	// <session>.ack so resume survives a daemon restart (not just a reconnect).
	Dir string
	// BackoffBase / BackoffMax bound the exponential, jittered retry on a down
	// backend. Zero => sane defaults. A down backend never blocks a session (the
	// uploader runs off the on-disk log in its own goroutine) nor grows memory
	// unboundedly (it re-reads bounded slices from disk, never buffers the world).
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// HTTPClient / Now are injectable for tests. nil => defaults.
	HTTPClient *http.Client
	Now        func() time.Time
	Logger     *slog.Logger
}

// Uploader tails each session's durable log and pushes events to the cloud backend
// with resume-from-acked-seq. It is exactly-once PAST THE ACK: everything at or
// below the persisted acked seq is never re-sent, and the backend keys events by
// seq so an at-least-once in-flight retry across a crash dedupes to one.
type Uploader struct {
	url    string
	dir    string
	client *http.Client
	now    func() time.Time
	log    *slog.Logger
	base   time.Duration
	max    time.Duration
	sink   *FileSink
	rnd    *rand.Rand
	rndMu  sync.Mutex

	wg     sync.WaitGroup
	mu     sync.Mutex
	seen   map[string]bool
	cancel context.CancelFunc
	ctx    context.Context
}

// NewUploader builds an uploader over sink. If cfg.BackendURL is empty it returns
// nil — callers treat a nil *Uploader as the no-op it is (Start/Stop are no-ops).
func NewUploader(sink *FileSink, cfg UploaderConfig) *Uploader {
	if cfg.BackendURL == "" {
		return nil
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 200 * time.Millisecond
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 30 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Uploader{
		url:    cfg.BackendURL,
		dir:    cfg.Dir,
		client: cfg.HTTPClient,
		now:    cfg.Now,
		log:    cfg.Logger,
		base:   cfg.BackoffBase,
		max:    cfg.BackoffMax,
		sink:   sink,
		rnd:    rand.New(rand.NewSource(cfg.Now().UnixNano())),
		seen:   map[string]bool{},
	}
}

// Start wires the uploader to fire a per-session tail goroutine whenever a session
// first appears in the sink. A nil *Uploader is a no-op.
func (u *Uploader) Start(ctx context.Context) {
	if u == nil {
		return
	}
	u.mu.Lock()
	u.ctx, u.cancel = context.WithCancel(ctx)
	u.mu.Unlock()
	// Adopt every future session via the hook, plus any already open in the sink.
	u.sink.setOnSession(func(id string) { u.track(id) })
	for _, id := range u.sink.sessionIDs() {
		u.track(id)
	}
	// Startup sweep (restart resume): the sink's in-memory map is empty at boot, so
	// a session whose un-acked tail is stranded on disk (e.g. the backend was down
	// when the daemon last exited) would never be adopted by the hook. Scan the
	// durable logs and adopt any whose persisted ack is behind the last on-disk seq
	// — this is what makes resume-from-acked-seq survive a daemon RESTART, not just
	// a reconnect. track() is idempotent, so a session also opened live is not
	// double-tracked, and a fully-acked one is skipped.
	u.sweep()
}

// sweep scans <dir>/*.log and adopts any session with un-delivered events past its
// persisted ack, so a stranded tail drains on the next daemon lifetime.
func (u *Uploader) sweep() {
	logs, err := filepath.Glob(filepath.Join(u.dir, "*.log"))
	if err != nil {
		u.log.Warn("trace uploader: startup sweep glob failed", "err", err)
		return
	}
	for _, p := range logs {
		id := strings.TrimSuffix(filepath.Base(p), ".log")
		events, _, lerr := loadSessionLog(p)
		if lerr != nil || len(events) == 0 {
			continue
		}
		last := int64(events[len(events)-1].Seq)
		ack, _ := u.loadAck(id)
		if ack < last {
			u.track(id) // stranded un-acked tail: drain it from the durable log
		}
	}
}

// Stop cancels all tail goroutines and waits for them. A nil *Uploader is a no-op.
func (u *Uploader) Stop() {
	if u == nil {
		return
	}
	u.mu.Lock()
	if u.cancel != nil {
		u.cancel()
	}
	u.mu.Unlock()
	u.wg.Wait()
}

// track starts one tail goroutine per session (idempotent).
func (u *Uploader) track(id string) {
	u.mu.Lock()
	if u.seen[id] || u.ctx == nil {
		u.mu.Unlock()
		return
	}
	u.seen[id] = true
	ctx := u.ctx
	u.mu.Unlock()

	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		u.tail(ctx, id)
	}()
}

// tail pushes a single session's events to the backend, resuming from the
// persisted acked seq. It reads the on-disk log for events past the ack (bounded
// memory — never the whole world in RAM), posts each with backoff, and persists
// the ack after each success. When the session is sealed and fully acked it exits.
func (u *Uploader) tail(ctx context.Context, id string) {
	acked, _ := u.loadAck(id)
	for {
		// Grab the wakeup channel BEFORE reading, so an append that lands while we
		// process still closes the channel we are about to wait on (no lost wakeup).
		wait, haveWait := u.sink.waitCh(id)
		events, seal, ok := u.sink.Export(id)
		if ok {
			for _, ev := range events {
				if int64(ev.Seq) <= acked {
					continue // at/below the ack: never re-sent (exactly-once past ack)
				}
				if err := u.postWithBackoff(ctx, ev); err != nil {
					return // ctx cancelled: resume from persisted ack next lifetime
				}
				acked = int64(ev.Seq)
				if err := u.saveAck(id, acked); err != nil {
					u.log.Warn("trace uploader: persist ack failed", "session", id, "err", err)
				}
			}
			if seal != nil && len(events) > 0 && acked >= int64(events[len(events)-1].Seq) {
				return // sealed + fully delivered
			}
		}
		// Wait for the next append/seal (or context cancel). If the session is not
		// yet open (no wait channel), poll after a short delay.
		if !haveWait {
			select {
			case <-ctx.Done():
				return
			case <-time.After(u.base):
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-wait:
		}
	}
}

// postWithBackoff POSTs one event, retrying on failure with exponential,
// jittered, capped backoff until success or ctx cancellation. It never blocks the
// session (this runs in the uploader goroutine) and holds no growing buffer.
func (u *Uploader) postWithBackoff(ctx context.Context, ev Event) error {
	delay := u.base
	for {
		err := u.postOnce(ctx, ev)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		sleep := u.jitter(delay)
		u.log.Debug("trace uploader: backend push failed; backing off", "session", ev.SessionID, "seq", ev.Seq, "retry_in", sleep, "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
		delay *= 2
		if delay > u.max {
			delay = u.max
		}
	}
}

// postOnce sends one event to the backend, keyed by session_id+seq so the receiver
// dedupes an at-least-once retry. A 2xx is an ACK.
func (u *Uploader) postOnce(ctx context.Context, ev Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("backend rejected seq %d: status %d", ev.Seq, resp.StatusCode)
	}
	return nil
}

// jitter returns d with full jitter in [d/2, d], capped at max.
func (u *Uploader) jitter(d time.Duration) time.Duration {
	if d > u.max {
		d = u.max
	}
	u.rndMu.Lock()
	f := 0.5 + 0.5*u.rnd.Float64()
	u.rndMu.Unlock()
	return time.Duration(float64(d) * f)
}

func (u *Uploader) ackPath(id string) string { return filepath.Join(u.dir, id+".ack") }

// loadAck reads the persisted acked seq (-1 if none), so resume survives a daemon
// restart, not just a reconnect.
func (u *Uploader) loadAck(id string) (int64, error) {
	b, err := os.ReadFile(u.ackPath(id))
	if err != nil {
		return -1, nil
	}
	n, err := strconv.ParseInt(string(bytes.TrimSpace(b)), 10, 64)
	if err != nil {
		return -1, err
	}
	return n, nil
}

// saveAck persists the acked seq atomically (write temp + rename) so a crash can
// never leave a half-written ack that would resend or skip.
func (u *Uploader) saveAck(id string, seq int64) error {
	tmp := u.ackPath(id) + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(seq, 10)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, u.ackPath(id))
}
