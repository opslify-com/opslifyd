package session

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// AC: exec output is bounded; a truncation marker is emitted at the cap and no
// bytes beyond the cap are forwarded (hostile occupant cannot OOM the daemon).
func TestStreamBoundedTruncation(t *testing.T) {
	// 10 KiB of output, cap at 4 KiB, 1 KiB chunks.
	big := strings.Repeat("A", 10*1024)
	es := runtime.ExecStream{
		Stdout:   strings.NewReader(big),
		Stderr:   strings.NewReader(""),
		ExitCode: 7,
	}
	sink := newCaptureSink()
	if err := streamExec(context.Background(), sink, es, 1024, 4*1024); err != nil {
		t.Fatalf("streamExec: %v", err)
	}
	if len(sink.stdout) != 4*1024 {
		t.Errorf("forwarded %d bytes, want cap 4096", len(sink.stdout))
	}
	if !sink.truncated[StreamStdout] {
		t.Error("expected a truncation marker on stdout")
	}
	if sink.exit == nil || *sink.exit != 7 {
		t.Errorf("exit = %v, want 7", sink.exit)
	}
}

// Output under the cap is passed through whole with no truncation marker.
func TestStreamUnderCap(t *testing.T) {
	es := runtime.ExecStream{
		Stdout:   strings.NewReader("small"),
		Stderr:   strings.NewReader("err"),
		ExitCode: 0,
	}
	sink := newCaptureSink()
	if err := streamExec(context.Background(), sink, es, 1024, 1<<20); err != nil {
		t.Fatalf("streamExec: %v", err)
	}
	if string(sink.stdout) != "small" || string(sink.stderr) != "err" {
		t.Errorf("stdout=%q stderr=%q", sink.stdout, sink.stderr)
	}
	if sink.truncated[StreamStdout] || sink.truncated[StreamStderr] {
		t.Error("no truncation marker expected under cap")
	}
}

// A cap that exactly matches the size emits everything with no false truncation.
func TestStreamExactCap(t *testing.T) {
	es := runtime.ExecStream{
		Stdout: strings.NewReader("1234"),
		Stderr: strings.NewReader(""),
	}
	sink := newCaptureSink()
	if err := streamExec(context.Background(), sink, es, 2, 4); err != nil {
		t.Fatalf("streamExec: %v", err)
	}
	if string(sink.stdout) != "1234" {
		t.Errorf("stdout = %q, want 1234", sink.stdout)
	}
	if sink.truncated[StreamStdout] {
		t.Error("exact-fit output must not be marked truncated")
	}
}

// BLOCKING-D1 regression: enforcing the output cap must not deadlock or leak the
// process. A hostile occupant keeps writing PAST the cap; pump stops reading at
// the cap, so the process would block in write() and cmd.Wait() would hang
// forever unless streamExec kills-then-drains. This models real pipe backpressure
// deterministically via io.Pipe (synchronous: Write blocks until read) plus a
// Wait closure that — like cmd.Wait() — only returns once the process has stopped.
//
// Against the pre-fix streamExec (no cancel, no drain) this HANGS and trips the
// timeout; the fixed version returns promptly, emits the truncation marker, reaps
// the process (Wait/Cancel fired), and surfaces the kill exit code (not a false 0).
func TestStreamExec_TruncationKillsAndReapsNoDeadlock(t *testing.T) {
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		buf := bytes.Repeat([]byte("A"), 1024)
		for {
			select {
			case <-ctx.Done():
				// Killed: EOF the reader so the drain completes (mirrors the process
				// dying and its pipes closing).
				_ = pw.Close()
				return
			default:
			}
			if _, err := pw.Write(buf); err != nil {
				return // reader gone
			}
		}
	}()

	waitCalled := make(chan struct{})
	es := runtime.ExecStream{
		Stdout: pr,
		Stderr: strings.NewReader(""),
		Cancel: cancel,
		// Mirrors cmd.Wait(): blocks until the process has actually stopped, then
		// yields the kill code. If streamExec fails to kill+drain, this never
		// returns — exactly the production deadlock.
		Wait: func() (int, error) {
			close(waitCalled)
			<-writerDone
			return -1, nil
		},
	}

	sink := newCaptureSink()
	done := make(chan error, 1)
	go func() { done <- streamExec(context.Background(), sink, es, 1024, 4*1024) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("streamExec returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK: streamExec did not return — pump stopped at cap but the process was never killed/reaped")
	}

	if !sink.truncated[StreamStdout] {
		t.Error("expected a truncation marker on stdout")
	}
	select {
	case <-waitCalled:
	default:
		t.Error("process was never reaped (Wait not called)")
	}
	// The writer goroutine must have exited (no leaked process/goroutine).
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Error("writer/process goroutine leaked (not stopped after truncation)")
	}
	if sink.exit == nil || *sink.exit != -1 {
		t.Errorf("exit = %v, want -1 (killed by truncation, not a misleading 0)", sink.exit)
	}
}

// BLOCKING-D2 regression: the kill must fire the INSTANT EITHER stream early-
// stops — not after both pumps finish. Models TWO concurrently-live streams:
// stdout floods PAST the cap (synchronous io.Pipe), while stderr stays OPEN and
// SILENT (no bytes, no EOF) until the process is "killed". A child process holds
// its stderr fd open until it exits, so the stderr pump Read-blocks; if the kill
// waited on wg.Wait() it would never come (the stdout flooder never exits, so the
// process never closes stderr). The fix cancels from inside the stdout pump the
// moment it truncates, which "kills" the process and EOFs stderr.
//
// Against code that cancels only AFTER wg.Wait() this HANGS (the stderr pump
// blocks forever); the fixed version returns promptly.
func TestStreamExec_CrossStreamNoDeadlock(t *testing.T) {
	// stdout: synchronous flooder past the cap.
	outR, outW := io.Pipe()
	// stderr: open + silent; only EOFs when the process is "killed" (Cancel).
	errR, errW := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	killed := make(chan struct{})
	var killOnce int32
	kill := func() {
		if atomic.CompareAndSwapInt32(&killOnce, 0, 1) {
			cancel()
			// Killing the process closes ALL its pipes: stdout flooder unblocks and
			// stderr reaches EOF.
			_ = outW.Close()
			_ = errW.Close()
			close(killed)
		}
	}

	stdoutDone := make(chan struct{})
	go func() { // stdout flooder
		defer close(stdoutDone)
		buf := bytes.Repeat([]byte("A"), 1024)
		for {
			if _, err := outW.Write(buf); err != nil {
				return // pipe closed (killed)
			}
		}
	}()

	waitCalled := make(chan struct{})
	es := runtime.ExecStream{
		Stdout: outR,
		Stderr: errR, // stays blocked in Read until kill closes errW
		// The Cancel the consumer holds triggers the process kill (mirrors
		// CommandContext SIGKILL closing every pipe).
		Cancel: kill,
		Wait: func() (int, error) {
			close(waitCalled)
			<-killed // cmd.Wait() only returns once the process has stopped
			return -1, nil
		},
	}

	sink := newCaptureSink()
	done := make(chan error, 1)
	go func() { done <- streamExec(context.Background(), sink, es, 1024, 4*1024) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("streamExec returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CROSS-STREAM DEADLOCK: kill did not fire until both pumps finished; the silent-stderr pump blocked forever")
	}

	if !sink.truncated[StreamStdout] {
		t.Error("expected a truncation marker on stdout")
	}
	select {
	case <-waitCalled:
	default:
		t.Error("process was never reaped (Wait not called)")
	}
	// Both output goroutines must have unwound (no leak).
	select {
	case <-stdoutDone:
	case <-time.After(time.Second):
		t.Error("stdout flooder goroutine leaked")
	}
	select {
	case <-killed:
	default:
		t.Error("process kill (Cancel) never fired")
	}
	if sink.exit == nil || *sink.exit != -1 {
		t.Errorf("exit = %v, want -1 (killed by truncation)", sink.exit)
	}
	_ = ctx
}
