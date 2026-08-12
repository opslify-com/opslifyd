package session

import (
	"context"
	"fmt"
	"sync"

	"github.com/opslify-com/opslifyd/internal/trace"
)

// traceExecSink wraps the caller's ExecSink to emit F3.1 exec.output events for
// every streamed chunk (and the truncation marker) while forwarding every frame
// to the real sink unchanged — so tracing never alters what the caller receives.
// It records the exit code so Manager.Exec can emit exec.end with it.
//
// streamExec drives stdout and stderr through two concurrent goroutines, so Chunk
// may be called concurrently for the two streams. Per-stream byte offsets are
// tracked under mu; the trace Append itself is serialized by the sink's
// per-session chain lock, so concurrent chunks can never interleave the chain.
type traceExecSink struct {
	ctx   context.Context
	rec   *trace.Recorder
	inner ExecSink

	mu      sync.Mutex
	offsets map[string]int
	code    int
	codeSet bool
}

func newTraceExecSink(ctx context.Context, rec *trace.Recorder, inner ExecSink) *traceExecSink {
	return &traceExecSink{ctx: ctx, rec: rec, inner: inner, offsets: map[string]int{}, code: -1}
}

func (t *traceExecSink) Chunk(stream string, data []byte) error {
	t.mu.Lock()
	off := t.offsets[stream]
	t.offsets[stream] += len(data)
	t.mu.Unlock()
	// Record the chunk (redaction — F3.3 — will scrub it before hashing). The
	// chunk is committed to the chain BEFORE it is forwarded, so the trace can
	// never lag behind what the caller saw.
	_ = t.rec.Emit(t.ctx, trace.TypeExecOutput, map[string]any{
		"stream": stream,
		"offset": off,
		"chunk":  string(data),
	})
	return t.inner.Chunk(stream, data)
}

func (t *traceExecSink) Truncated(stream string) error {
	_ = t.rec.Emit(t.ctx, trace.TypeExecOutput, map[string]any{
		"stream":    stream,
		"truncated": true,
	})
	return t.inner.Truncated(stream)
}

func (t *traceExecSink) Exit(code int) error {
	t.mu.Lock()
	t.code = code
	t.codeSet = true
	t.mu.Unlock()
	return t.inner.Exit(code)
}

// exitCode returns the captured exit code (-1 if Exit was never reached, e.g. a
// mid-stream failure), for the exec.end event.
func (t *traceExecSink) exitCode() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.code
}

// TraceExport returns a session's trace events (in chain order) and its seal for
// `opslify verify`. Since durable persistence is F3.2, this reads the in-memory
// sink: it works for any session the running daemon still holds (live or sealed
// but not yet evicted by a restart). A session with no trace is ErrNotFound.
func (m *Manager) TraceExport(_ context.Context, id string) ([]trace.Event, *trace.Signature, error) {
	if m.trace == nil {
		return nil, nil, fmt.Errorf("%w: tracing is not enabled on this daemon", ErrNotFound)
	}
	ex, ok := m.trace.(trace.Exporter)
	if !ok {
		return nil, nil, fmt.Errorf("%w: trace sink does not support export", ErrNotFound)
	}
	events, seal, ok := ex.Export(id)
	if !ok {
		return nil, nil, fmt.Errorf("%w: no trace for session %s", ErrNotFound, id)
	}
	return events, seal, nil
}

// TraceStream opens a live tail of a session's trace for the F3.2 local SSE
// endpoint: it returns the backfill (events with seq >= fromSeq) plus a channel of
// subsequently-appended events and a cancel func the caller MUST invoke. It
// requires a durable sink that implements trace.Streamer (the in-memory F3.1 sink
// does not); an unstreamable sink is a legible ErrNotFound.
func (m *Manager) TraceStream(id string, fromSeq uint64) ([]trace.Event, <-chan trace.Event, func(), error) {
	if m.trace == nil {
		return nil, nil, nil, fmt.Errorf("%w: tracing is not enabled on this daemon", ErrNotFound)
	}
	st, ok := m.trace.(trace.Streamer)
	if !ok {
		return nil, nil, nil, fmt.Errorf("%w: trace sink does not support live streaming", ErrNotFound)
	}
	backfill, live, cancel, err := st.Subscribe(id, fromSeq)
	if err != nil {
		return nil, nil, nil, err
	}
	return backfill, live, cancel, nil
}
