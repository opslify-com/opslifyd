package main

import (
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/trace"
)

// TestTopModelRenderFrame proves `opslify top` constructs and renders one frame
// against injected data, without a real daemon: the session table, the selection
// marker, and the folded exec output all appear.
func TestTopModelRenderFrame(t *testing.T) {
	m := &topModel{selected: "a1", maxStream: 50}
	m.setSessions([]sessionView{
		{SessionID: "a1", Mode: "workspace", Tier: "local-hardened", State: "ready", AgeSeconds: 90, TTLRemaining: 1800},
		{SessionID: "b2", Mode: "scratch", Tier: "local-docker", State: "paused", AgeSeconds: 5},
	})
	m.addEvent(trace.Event{Type: trace.TypeExecStart, Payload: map[string]any{"argv": []any{"echo", "hi"}}})
	m.addEvent(trace.Event{Type: trace.TypeExecOutput, Payload: map[string]any{"stream": "stdout", "chunk": "hello world\n"}})
	m.addEvent(trace.Event{Type: trace.TypeExecEnd, Payload: map[string]any{"exit_code": float64(0)}})

	frame := m.render("") // empty prefix = capturable single frame

	for _, want := range []string{"a1", "b2", "ready", "1m30s", "30m", "▶", "hello world", "stream: a1"} {
		if !strings.Contains(frame, want) {
			t.Errorf("frame missing %q:\n%s", want, frame)
		}
	}
	// b2 has no TTL -> "-"; a1 is the selected row (marker present above).
	if !strings.Contains(frame, "$ [echo hi]") {
		t.Errorf("exec.start not folded into stream:\n%s", frame)
	}
}

func TestTopModelEmptyAndError(t *testing.T) {
	m := &topModel{maxStream: 10}
	if !strings.Contains(m.render(""), "no active sessions") {
		t.Error("empty session list should render a placeholder")
	}
	m.setErr(errFake("boom"))
	if !strings.Contains(m.render(""), "daemon unreachable") {
		t.Error("error state should be legible")
	}
}

// TestTopStreamCap bounds the retained output tail.
func TestTopStreamCap(t *testing.T) {
	m := &topModel{selected: "s", maxStream: 3}
	for i := 0; i < 10; i++ {
		m.addEvent(trace.Event{Type: trace.TypeExecOutput, Payload: map[string]any{"chunk": "line\n"}})
	}
	if len(m.stream) != 3 {
		t.Errorf("stream not capped to maxStream: got %d", len(m.stream))
	}
}

func TestStripAnsiGo(t *testing.T) {
	in := "\x1b[31mred\x1b[0m plain \x1b[1;32mbold\x1b[0m"
	if got := stripAnsiGo(in); got != "red plain bold" {
		t.Errorf("stripAnsiGo = %q", got)
	}
}

type errFake string

func (e errFake) Error() string { return string(e) }
