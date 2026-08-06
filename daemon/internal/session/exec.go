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
// in memory. A nil reader is treated as empty. It returns truncated=true when it
// stopped at the cap WITHOUT reaching EOF — the signal streamExec uses to kill
// and reap the still-writing process instead of blocking on it.
func pump(ctx context.Context, sink ExecSink, stream string, r io.Reader, chunk, cap int) (truncated bool, err error) {
	if r == nil {
		return false, nil
	}
	buf := make([]byte, chunk)
	var sent int
	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		default:
		}
		n, rerr := r.Read(buf)
		if n > 0 {
			// Trim to the remaining cap; emit a truncation marker once we hit it.
			remaining := cap - sent
			if remaining <= 0 {
				return true, sink.Truncated(stream)
			}
			out := buf[:n]
			hit := false
			if n > remaining {
				out = buf[:remaining]
				hit = true
			}
			if cerr := sink.Chunk(stream, out); cerr != nil {
				return true, cerr
			}
			sent += len(out)
			if hit {
				return true, sink.Truncated(stream)
			}
		}
		if rerr == io.EOF {
			return false, nil
		}
		if rerr != nil {
			return true, fmt.Errorf("session: read %s: %w", stream, rerr)
		}
	}
}

// streamExec pumps stdout and stderr concurrently under their caps, then emits
// the exit code. Concurrency keeps a chatty stderr from blocking stdout (and
// vice versa) while both stay individually bounded.
func streamExec(ctx context.Context, sink ExecSink, es runtime.ExecStream, chunk, cap int) error {
	// Always release the exec context on return (idempotent with the early cancel
	// below). On the clean path this fires only AFTER Wait, so it never turns a
	// clean exit into a kill.
	if es.Cancel != nil {
		defer es.Cancel()
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	// earlyStop KILLS the process the INSTANT either pump early-stops (cap hit or
	// read error), from inside that pump's own goroutine — NOT after wg.Wait().
	// This is essential: if stdout truncates while the process floods it, the
	// process blocks in write() and never exits, so it never closes stderr; the
	// stderr pump would then Read-block forever and wg.Wait() would hang before any
	// post-join cancel could run. Killing immediately closes ALL the process's
	// pipes, unblocking the sibling pump so wg.Wait() completes. Idempotent, so
	// both pumps racing to call it is fine; the clean under-cap path never calls it,
	// preserving the real exit code.
	earlyStop := func() {
		if es.Cancel != nil {
			es.Cancel()
		}
	}
	setResult := func(tr bool, e error) {
		if tr {
			earlyStop()
		}
		if e != nil {
			mu.Lock()
			if firstErr == nil {
				firstErr = e
			}
			mu.Unlock()
		}
	}

	wg.Add(2)
	go func() { defer wg.Done(); setResult(pump(ctx, sink, StreamStdout, es.Stdout, chunk, cap)) }()
	go func() { defer wg.Done(); setResult(pump(ctx, sink, StreamStderr, es.Stderr, chunk, cap)) }()
	wg.Wait()

	// Both pumps have returned (any early-stop already killed the process above, so
	// no pump could be blocked). Drain any unread bytes so cmd.Wait() sees both
	// pipes at EOF (os/exec pipe contract) and returns without leaking the
	// process/goroutine/fds. On the clean path both readers are already at EOF, so
	// this is a no-op.
	drain(es.Stdout)
	drain(es.Stderr)

	// Reap the process on EVERY path (even on error) so nothing is left running.
	code := es.ExitCode
	if es.Wait != nil {
		c, werr := es.Wait()
		if firstErr == nil {
			firstErr = werr
		}
		code = c
	}
	if firstErr != nil {
		return firstErr
	}
	// The exit code is delivered LAST, after both streams are drained. A truncation-
	// killed exec surfaces the kill via code (exit -1), never a misleading 0.
	return sink.Exit(code)
}

// drain discards any remaining bytes from r to EOF. After the process is killed
// its pipes reach EOF promptly, so this unblocks and returns; on the clean path r
// is already at EOF. A nil reader is a no-op.
func drain(r io.Reader) {
	if r == nil {
		return
	}
	_, _ = io.Copy(io.Discard, r)
}
