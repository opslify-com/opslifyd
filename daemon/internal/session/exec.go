package session

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// Stream names for exec output frames.
const (
	StreamStdout = "stdout"
	StreamStderr = "stderr"
)

// Default output bounds. The sandbox occupant is hostile: a command can emit
// unbounded output to exhaust daemon memory, so every exec is copied in fixed
// chunks and capped per stream, with a truncation marker when the cap is hit.
const (
	// DefaultChunkSize is the fixed read/flush granularity. Output is never
	// buffered beyond one chunk before being handed to the sink.
	DefaultChunkSize = 32 * 1024
	// DefaultOutputCap bounds bytes forwarded per stream (stdout, stderr each).
	DefaultOutputCap = 1 << 20 // 1 MiB
)

// ExecSink receives bounded exec output frames. The HTTP handler adapts it to a
// flushing chunked response; tests use an in-memory sink to assert bounding,
// interleaving, truncation, and exit-code delivery without a socket.
//
// Contract: Chunk may be called concurrently for different stream names, so
// implementations must be safe for one concurrent stdout + one concurrent
// stderr writer. Truncated is emitted at most once per stream. Exit is emitted
// exactly once, last.
type ExecSink interface {
	Chunk(stream string, data []byte) error
	Truncated(stream string) error
	Exit(code int) error
}

// pump copies one reader to the sink in bounded chunks, stopping at cap and
// emitting a single truncation marker. It never accumulates more than one chunk
// in memory. A nil reader is treated as empty.
func pump(ctx context.Context, sink ExecSink, stream string, r io.Reader, chunk, cap int) error {
	if r == nil {
		return nil
	}
	buf := make([]byte, chunk)
	var sent int
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := r.Read(buf)
		if n > 0 {
			// Trim to the remaining cap; emit a truncation marker once we hit it.
			remaining := cap - sent
			if remaining <= 0 {
				return sink.Truncated(stream)
			}
			out := buf[:n]
			truncated := false
			if n > remaining {
				out = buf[:remaining]
				truncated = true
			}
			if cerr := sink.Chunk(stream, out); cerr != nil {
				return cerr
			}
			sent += len(out)
			if truncated {
				return sink.Truncated(stream)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("session: read %s: %w", stream, err)
		}
	}
}

// streamExec pumps stdout and stderr concurrently under their caps, then emits
// the exit code. Concurrency keeps a chatty stderr from blocking stdout (and
// vice versa) while both stay individually bounded.
func streamExec(ctx context.Context, sink ExecSink, es runtime.ExecStream, chunk, cap int) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	setErr := func(e error) {
		if e == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = e
		}
		mu.Unlock()
	}

	wg.Add(2)
	go func() { defer wg.Done(); setErr(pump(ctx, sink, StreamStdout, es.Stdout, chunk, cap)) }()
	go func() { defer wg.Done(); setErr(pump(ctx, sink, StreamStderr, es.Stderr, chunk, cap)) }()
	wg.Wait()

	if firstErr != nil {
		return firstErr
	}
	return sink.Exit(es.ExitCode)
}
