package trace

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeBackend is a stand-in cloud receiver (the real one is F3.4). It records
// every posted event keyed by session_id+seq so duplicates are visible, and can be
// toggled "down" to simulate a network cut.
type fakeBackend struct {
	mu     sync.Mutex
	counts map[string]int
	down   bool
}

func newFakeBackend() *fakeBackend { return &fakeBackend{counts: map[string]int{}} }

func (b *fakeBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	down := b.down
	b.mu.Unlock()
	if down {
		http.Error(w, "backend down", http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "bad event", http.StatusBadRequest)
		return
	}
	b.mu.Lock()
	b.counts[fmt.Sprintf("%s#%d", ev.SessionID, ev.Seq)]++
	b.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (b *fakeBackend) setDown(v bool) { b.mu.Lock(); b.down = v; b.mu.Unlock() }

func (b *fakeBackend) received() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]int{}
	for k, v := range b.counts {
		out[k] = v
	}
	return out
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func newTestUploader(sink *FileSink, dir, url string) *Uploader {
	return NewUploader(sink, UploaderConfig{
		BackendURL:  url,
		Dir:         dir,
		BackoffBase: 2 * time.Millisecond,
		BackoffMax:  20 * time.Millisecond,
		Now:         time.Now,
	})
}

// AC: with no backend URL configured the uploader is a clean no-op and local
// persistence is unaffected.
func TestUploaderNoBackendIsNoop(t *testing.T) {
	dir := t.TempDir()
	sink := newFileSink(t, dir, newTestSigner(t))
	up := NewUploader(sink, UploaderConfig{BackendURL: "", Dir: dir})
	if up != nil {
		t.Fatal("NewUploader with empty URL should return nil (no-op)")
	}
	up.Start(context.Background()) // nil-safe no-op
	up.Stop()                      // nil-safe no-op

	// Local persistence still works fully.
	emitSession(t, sink, "sess-1")
	if _, _, ok := sink.Export("sess-1"); !ok {
		t.Fatal("local persistence broken with no uploader")
	}
	// No .ack files were written.
	if _, err := os.Stat(filepath.Join(dir, "sess-1.ack")); !os.IsNotExist(err) {
		t.Fatal("ack file written despite no backend")
	}
}

// AC: a session pushes every event to the backend exactly once, and the acked seq
// is persisted; a second uploader lifetime (restart) resumes past the ack with no
// resend.
func TestUploaderDeliversExactlyOnceAndPersistsAck(t *testing.T) {
	dir := t.TempDir()
	backend := newFakeBackend()
	srv := httptest.NewServer(backend)
	defer srv.Close()

	sink := newFileSink(t, dir, newTestSigner(t))
	up := newTestUploader(sink, dir, srv.URL)
	up.Start(context.Background())

	emitSession(t, sink, "sess-1") // 6 events, seq 0..5

	waitFor(t, func() bool { return len(backend.received()) == 6 })
	up.Stop()

	got := backend.received()
	for seq := 0; seq < 6; seq++ {
		key := fmt.Sprintf("sess-1#%d", seq)
		if got[key] != 1 {
			t.Fatalf("seq %d delivered %d times, want exactly 1", seq, got[key])
		}
	}
	// Ack persisted at the final event seq (5).
	if ack := readAck(t, dir, "sess-1"); ack != 5 {
		t.Fatalf("persisted ack = %d, want 5", ack)
	}

	// "Restart": a fresh uploader over the same dir must resume past the ack and
	// NOT resend anything (counts stay exactly 1).
	up2 := newTestUploader(sink, dir, srv.URL)
	up2.Start(context.Background())
	time.Sleep(50 * time.Millisecond)
	up2.Stop()
	for seq := 0; seq < 6; seq++ {
		if got := backend.received()[fmt.Sprintf("sess-1#%d", seq)]; got != 1 {
			t.Fatalf("after restart seq %d delivered %d times, want 1 (no resend past ack)", seq, got)
		}
	}
}

// AC: a network cut mid-session → after reconnect the backend has every event
// exactly once (resume-from-acked-seq; no gaps, no dupes past the ack).
func TestUploaderResumesAfterNetworkCut(t *testing.T) {
	dir := t.TempDir()
	backend := newFakeBackend()
	backend.setDown(true) // cut from the start
	srv := httptest.NewServer(backend)
	defer srv.Close()

	sink := newFileSink(t, dir, newTestSigner(t))
	up := newTestUploader(sink, dir, srv.URL)
	up.Start(context.Background())

	// Emit the whole session while the backend is DOWN. The uploader retries with
	// backoff; nothing is acked, the session is never blocked (this returns).
	emitSession(t, sink, "sess-1")
	time.Sleep(30 * time.Millisecond)
	if len(backend.received()) != 0 {
		t.Fatalf("backend received %d events while down, want 0", len(backend.received()))
	}

	// Reconnect: the uploader must drain everything exactly once.
	backend.setDown(false)
	waitFor(t, func() bool { return len(backend.received()) == 6 })
	up.Stop()

	for seq := 0; seq < 6; seq++ {
		if got := backend.received()[fmt.Sprintf("sess-1#%d", seq)]; got != 1 {
			t.Fatalf("after reconnect seq %d delivered %d times, want exactly 1", seq, got)
		}
	}
}

// Finding 1 / AC: resume-from-acked-seq survives a daemon RESTART. A durable log
// with a stranded un-acked tail (persisted ack K < last seq N) is adopted by the
// startup sweep with NO Subscribe/Append — the uploader drains seq K+1..N exactly
// once; a fully-acked session triggers no resend.
func TestUploaderStartupSweepResumesStrandedTail(t *testing.T) {
	dir := t.TempDir()
	backend := newFakeBackend()
	srv := httptest.NewServer(backend)
	defer srv.Close()

	// Produce a durable 6-event sealed log on disk via one sink, then drop it.
	signer := newTestSigner(t)
	writer := newFileSink(t, dir, signer)
	emitSession(t, writer, "sess-1") // seq 0..5 + seal
	_ = writer.Close()

	// Persist an ack at K=2, as if the backend was down for seq 3..5 at last exit.
	if err := os.WriteFile(filepath.Join(dir, "sess-1.ack"), []byte("2"), 0o600); err != nil {
		t.Fatal(err)
	}

	// "Restart": a brand-new sink (empty in-memory map) + uploader. NO Subscribe or
	// Append is ever called — only the startup sweep can adopt the stranded tail.
	sink := newFileSink(t, dir, signer)
	up := newTestUploader(sink, dir, srv.URL)
	up.Start(context.Background())
	waitFor(t, func() bool { return len(backend.received()) == 3 })
	up.Stop()

	got := backend.received()
	for seq := 3; seq <= 5; seq++ {
		if got[fmt.Sprintf("sess-1#%d", seq)] != 1 {
			t.Fatalf("swept tail seq %d delivered %d times, want exactly 1", seq, got[fmt.Sprintf("sess-1#%d", seq)])
		}
	}
	for seq := 0; seq <= 2; seq++ {
		if _, sent := got[fmt.Sprintf("sess-1#%d", seq)]; sent {
			t.Fatalf("acked seq %d was re-sent; sweep must not resend past the ack", seq)
		}
	}
	if ack := readAck(t, dir, "sess-1"); ack != 5 {
		t.Fatalf("ack after sweep = %d, want 5", ack)
	}

	// A fully-acked session (ack == last seq) must not be adopted → no resend.
	dir2 := t.TempDir()
	backend2 := newFakeBackend()
	srv2 := httptest.NewServer(backend2)
	defer srv2.Close()
	w2 := newFileSink(t, dir2, signer)
	emitSession(t, w2, "sess-2")
	_ = w2.Close()
	if err := os.WriteFile(filepath.Join(dir2, "sess-2.ack"), []byte("5"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink2 := newFileSink(t, dir2, signer)
	up2 := newTestUploader(sink2, dir2, srv2.URL)
	up2.Start(context.Background())
	time.Sleep(50 * time.Millisecond)
	up2.Stop()
	if n := len(backend2.received()); n != 0 {
		t.Fatalf("fully-acked session resent %d events, want 0", n)
	}
}

func readAck(t *testing.T, dir, id string) int64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, id+".ack"))
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		t.Fatalf("parse ack %q: %v", b, err)
	}
	return n
}
