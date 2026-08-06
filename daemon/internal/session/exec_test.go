package session

import (
	"context"
	"strings"
	"testing"

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
