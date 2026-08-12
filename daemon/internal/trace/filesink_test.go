package trace

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// emitSession drives the representative session sequence through any TraceSink via
// a Recorder, then seals — mirroring buildSession but sink-agnostic so FileSink and
// MemSink can be exercised (and compared) with the identical event stream.
func emitSession(t *testing.T, sink TraceSink, id string) Signature {
	t.Helper()
	ctx := context.Background()
	rec := NewRecorder(sink, id, NoopRedactor{}, fixedClock())
	must(t, rec.Emit(ctx, TypeSessionStart, startPayload()))
	must(t, rec.Emit(ctx, TypeExecStart, map[string]any{"argv": []string{"echo", "hi"}, "cwd": "/workspace"}))
	must(t, rec.Emit(ctx, TypeExecOutput, map[string]any{"stream": "stdout", "offset": 0, "chunk": "hi\n"}))
	must(t, rec.Emit(ctx, TypeExecEnd, map[string]any{"exit_code": 0, "duration_ms": 5}))
	must(t, rec.Emit(ctx, TypeFileWrite, map[string]any{"path": "out.txt", "size": 3}))
	must(t, rec.Emit(ctx, TypeSessionEnd, map[string]any{"reason": "destroyed"}))
	seal, err := rec.Seal(ctx)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return seal
}

func newFileSink(t *testing.T, dir string, signer Signer) *FileSink {
	t.Helper()
	s, err := NewFileSink(FileSinkConfig{Dir: dir, Now: fixedClock(), RingBufferSize: 8}, signer)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// AC: every emitted event lands in <session>.log in seq order, one JSON per line;
// files are 0600.
func TestFileSinkAppendsOnePerLine(t *testing.T) {
	dir := t.TempDir()
	sink := newFileSink(t, dir, newTestSigner(t))
	emitSession(t, sink, "sess-1")

	path := filepath.Join(dir, "sess-1.log")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("log perms = %o, want 0600", perm)
	}
	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	var seq uint64
	var sawSeal bool
	for sc.Scan() {
		var rec logRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("line not valid JSON: %v", err)
		}
		switch {
		case rec.Event != nil:
			if rec.Event.Seq != seq {
				t.Fatalf("out-of-order line: got seq %d, want %d", rec.Event.Seq, seq)
			}
			seq++
		case rec.Seal != nil:
			sawSeal = true
		}
	}
	if seq != 6 {
		t.Fatalf("event lines = %d, want 6", seq)
	}
	if !sawSeal {
		t.Fatal("no seal record on disk")
	}
}

// AC: reload-from-disk replays in order and Verify passes — including across a
// simulated daemon restart (a NEW sink over the same dir).
func TestFileSinkReloadAndVerifyAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	signer := newTestSigner(t)
	sink := newFileSink(t, dir, signer)
	emitSession(t, sink, "sess-1")
	_ = sink.Close()

	// "Restart": brand-new sink, same dir, nothing in memory.
	sink2 := newFileSink(t, dir, signer)
	events, seal, ok := sink2.Export("sess-1")
	if !ok {
		t.Fatal("Export after restart: not found")
	}
	if len(events) != 6 || seal == nil {
		t.Fatalf("reloaded %d events seal=%v, want 6 + seal", len(events), seal)
	}
	for i, ev := range events {
		if ev.Seq != uint64(i) {
			t.Fatalf("reloaded seq[%d] = %d", i, ev.Seq)
		}
	}
	if res := Verify(events, seal, signer.Public()); !res.OK {
		t.Fatalf("reloaded chain failed verify at seq %d: %s", res.BrokenSeq, res.Reason)
	}
}

// AC (parity): the same event sequence through FileSink and MemSink yields
// IDENTICAL hashes and an identically-verifiable seal — the shared chain core is
// not forked.
func TestFileSinkMemSinkParity(t *testing.T) {
	signer := newTestSigner(t)
	dir := t.TempDir()

	fsink := newFileSink(t, dir, signer)
	fSeal := emitSession(t, fsink, "sess-1")
	fEvents, _, _ := fsink.Export("sess-1")

	msink := NewMemSink(signer)
	msink.now = fixedClock()
	mSeal := emitSession(t, msink, "sess-1")
	mEvents, _, _ := msink.Export("sess-1")

	if len(fEvents) != len(mEvents) {
		t.Fatalf("event counts differ: file=%d mem=%d", len(fEvents), len(mEvents))
	}
	for i := range fEvents {
		if fEvents[i].Hash != mEvents[i].Hash {
			t.Fatalf("seq %d hash differs: file=%s mem=%s", i, fEvents[i].Hash, mEvents[i].Hash)
		}
		if fEvents[i].PrevHash != mEvents[i].PrevHash {
			t.Fatalf("seq %d prev_hash differs", i)
		}
	}
	if fSeal.FinalHash != mSeal.FinalHash {
		t.Fatalf("seal final_hash differs: file=%s mem=%s", fSeal.FinalHash, mSeal.FinalHash)
	}
	// Both seals verify against the same trusted identity.
	if res := Verify(fEvents, &fSeal, signer.Public()); !res.OK {
		t.Fatalf("file seal verify failed: %s", res.Reason)
	}
	if res := Verify(mEvents, &mSeal, signer.Public()); !res.OK {
		t.Fatalf("mem seal verify failed: %s", res.Reason)
	}
}

// AC / security: flipping a byte inside a .log record breaks Verify at that seq —
// on-disk tamper is the F3.1 chain signal, and it survives a reload.
func TestFileSinkTamperDetected(t *testing.T) {
	dir := t.TempDir()
	signer := newTestSigner(t)
	sink := newFileSink(t, dir, signer)
	emitSession(t, sink, "sess-1")
	_ = sink.Close()

	path := filepath.Join(dir, "sess-1.log")
	data, _ := os.ReadFile(path)
	// Flip the chunk payload of the exec.output record (seq 2): "hi\n" -> "hX\n".
	tampered := []byte(string(data))
	idx := indexOf(tampered, []byte(`hi\n`))
	if idx < 0 {
		t.Fatal("could not locate chunk to tamper")
	}
	tampered[idx+1] = 'X'
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	sink2 := newFileSink(t, dir, signer)
	events, seal, ok := sink2.Export("sess-1")
	if !ok {
		t.Fatal("Export tampered log: not found")
	}
	res := Verify(events, seal, signer.Public())
	if res.OK || res.BrokenSeq != 2 {
		t.Fatalf("tampered log: got OK=%v seq=%d, want fail at seq 2", res.OK, res.BrokenSeq)
	}
}

// QA: a truncated (torn) LAST line — as a crash mid-append would leave — is skipped
// on reload and the prior events stay intact and verifiable (unsealed chain).
func TestFileSinkCrashSafeTornLastLine(t *testing.T) {
	dir := t.TempDir()
	signer := newTestSigner(t)
	sink := newFileSink(t, dir, signer)
	ctx := context.Background()
	rec := NewRecorder(sink, "sess-1", NoopRedactor{}, fixedClock())
	must(t, rec.Emit(ctx, TypeSessionStart, startPayload()))
	must(t, rec.Emit(ctx, TypeExecStart, map[string]any{"argv": []string{"ls"}, "cwd": ""}))
	_ = sink.Close()

	path := filepath.Join(dir, "sess-1.log")
	data, _ := os.ReadFile(path)
	// Append a partial JSON record with NO trailing newline (a torn write).
	torn := append([]byte(string(data)), []byte(`{"event":{"session_id":"sess-1","seq":2,"typ`)...)
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}

	events, _, err := loadSessionLog(path)
	if err != nil {
		t.Fatalf("loadSessionLog on torn file errored: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("torn reload: got %d events, want 2 (partial line skipped)", len(events))
	}
	if res := Verify(events, nil, nil); !res.OK {
		t.Fatalf("prior events not intact after torn line: seq %d %s", res.BrokenSeq, res.Reason)
	}
}

// AC: a local SSE consumer with no cloud gets live events AND can backfill from an
// arbitrary from_seq via Subscribe.
func TestFileSinkSubscribeBackfillAndLive(t *testing.T) {
	dir := t.TempDir()
	sink := newFileSink(t, dir, newTestSigner(t))
	ctx := context.Background()
	rec := NewRecorder(sink, "sess-1", NoopRedactor{}, fixedClock())
	// Emit 3 events first (history).
	must(t, rec.Emit(ctx, TypeSessionStart, startPayload()))
	must(t, rec.Emit(ctx, TypeExecStart, map[string]any{"argv": []string{"a"}, "cwd": ""}))
	must(t, rec.Emit(ctx, TypeExecOutput, map[string]any{"stream": "stdout", "offset": 0, "chunk": "x"}))

	// Subscribe from seq 1: backfill covers 1,2; live picks up 3+.
	backfill, live, cancel, err := sink.Subscribe("sess-1", 1)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer cancel()
	if len(backfill) != 2 || backfill[0].Seq != 1 || backfill[1].Seq != 2 {
		t.Fatalf("backfill = %d events starting seq %d, want 2 from seq 1", len(backfill), backfill[0].Seq)
	}

	// Append two more; they must arrive live in order with no gap after backfill.
	must(t, rec.Emit(ctx, TypeExecOutput, map[string]any{"stream": "stdout", "offset": 1, "chunk": "y"}))
	must(t, rec.Emit(ctx, TypeSessionEnd, map[string]any{"reason": "done"}))
	for want := uint64(3); want <= 4; want++ {
		ev := <-live
		if ev.Seq != want {
			t.Fatalf("live event seq = %d, want %d", ev.Seq, want)
		}
	}
}

// QA: concurrent sessions never interleave into each other's log files — each
// <session>.log holds only its own session's events, all verifiable.
func TestFileSinkConcurrentSessionsIsolated(t *testing.T) {
	dir := t.TempDir()
	signer := newTestSigner(t)
	sink := newFileSink(t, dir, signer)

	const nSessions = 6
	var wg sync.WaitGroup
	wg.Add(nSessions)
	for i := 0; i < nSessions; i++ {
		go func(i int) {
			defer wg.Done()
			id := "sess-" + string(rune('a'+i))
			emitSession(t, sink, id)
		}(i)
	}
	wg.Wait()

	for i := 0; i < nSessions; i++ {
		id := "sess-" + string(rune('a'+i))
		events, seal, ok := sink.Export(id)
		if !ok {
			t.Fatalf("%s: not exported", id)
		}
		for _, ev := range events {
			if ev.SessionID != id {
				t.Fatalf("%s.log contains foreign session %s (cross-contamination)", id, ev.SessionID)
			}
		}
		if res := Verify(events, seal, signer.Public()); !res.OK {
			t.Fatalf("%s chain failed: %s", id, res.Reason)
		}
	}
}

// Finding 3 / QA: a corrupt NON-LAST record is tampering (not a torn write). It
// must surface as a Verify TAMPER failure at that seq — never a silent pass or a
// misleading "not found". (A torn LAST line is the crash-safety case, tested
// separately above and skipped cleanly.)
func TestFileSinkCorruptMiddleLineReportsTamper(t *testing.T) {
	dir := t.TempDir()
	signer := newTestSigner(t)
	sink := newFileSink(t, dir, signer)
	emitSession(t, sink, "sess-1") // 6 events + seal, so line 2 is NOT the last
	_ = sink.Close()

	path := filepath.Join(dir, "sess-1.log")
	data, _ := os.ReadFile(path)
	lines := splitLines(data)
	// Corrupt the seq-2 record into unparseable JSON (a structural break).
	lines[2] = []byte(`{"event":{"seq":2,,,BROKEN`)
	if err := os.WriteFile(path, joinLines(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	sink2 := newFileSink(t, dir, signer)
	events, seal, ok := sink2.Export("sess-1")
	if !ok {
		t.Fatal("Export corrupt log returned not-found; want tamper-legible events")
	}
	res := Verify(events, seal, signer.Public())
	if res.OK || res.BrokenSeq != 2 {
		t.Fatalf("corrupt middle line: got OK=%v seq=%d, want tamper fail at seq 2", res.OK, res.BrokenSeq)
	}
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			out = append(out, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}

func joinLines(lines [][]byte) []byte {
	var out []byte
	for _, ln := range lines {
		out = append(out, ln...)
		out = append(out, '\n')
	}
	return out
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
