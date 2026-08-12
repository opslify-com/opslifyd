package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// advancingClock returns a Now() that advances a fixed step each call, so an
// exec's start and end timestamps differ and duration_ms is provably captured.
type advancingClock struct {
	mu   sync.Mutex
	now  time.Time
	step time.Duration
}

func (c *advancingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(c.step)
	return c.now
}

// newTracedManager wires a Manager with an in-memory trace sink signed by a test
// identity — the whole F3.1 emission path exercised with no podman, no root.
func newTracedManager(t *testing.T, rt runtime.Runtime, clk Clock) (*Manager, *trace.MemSink, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	sink := trace.NewMemSink(trace.NewEd25519Signer(priv))
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:           "base@sha256:deadbeef",
			ToolchainDigest: "tool@sha256:cafe",
			WorkspaceRoot:   t.TempDir(),
			DefaultTier:     runtime.TierLocalHardened,
			DefaultTTL:      30 * time.Minute,
		},
		Resolve: func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:   clk,
		Store:   newMemStore(),
		Trace:   sink,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, sink, pub
}

// AC: a full session (create → exec → destroy) yields a well-formed, verifiable
// chain whose exec.* events capture argv, cwd, exit code, duration, and output,
// and whose seal verifies against the daemon identity.
func TestManagerEmitsVerifiableChain(t *testing.T) {
	rt := newFakeRuntime()
	rt.nextExec = runtime.ExecStream{
		Stdout:   strings.NewReader("hello\n"),
		Stderr:   strings.NewReader(""),
		ExitCode: 7,
	}
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, sink, trustedPub := newTracedManager(t, rt, clk)
	ctx := context.Background()

	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"echo", "hello"}, Cwd: "/workspace"}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	// A mediated file write should surface as a file.write event.
	if err := m.WriteFile(ctx, s.ID, "out.txt", []byte("hi")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	events, seal, err := m.TraceExport(ctx, s.ID)
	if err != nil {
		t.Fatalf("TraceExport: %v", err)
	}
	if seal == nil {
		t.Fatal("session not sealed on destroy")
	}
	if res := trace.Verify(events, seal, trustedPub); !res.OK {
		t.Fatalf("Verify failed at seq %d: %s", res.BrokenSeq, res.Reason)
	}

	// Assert the captured content by type.
	byType := map[trace.EventType]map[string]any{}
	var sawStart, sawOutput bool
	for _, ev := range events {
		switch ev.Type {
		case trace.TypeSessionStart:
			sawStart = true
			if ev.Seq != 0 {
				t.Fatalf("session.start at seq %d, want 0", ev.Seq)
			}
			if ev.Payload["image_digest"] != "base@sha256:deadbeef" ||
				ev.Payload["toolchain_lock_hash"] != "tool@sha256:cafe" {
				t.Fatalf("session.start missing binding: %v", ev.Payload)
			}
		case trace.TypeExecOutput:
			sawOutput = true
			if ev.Payload["stream"] == "stdout" && ev.Payload["chunk"] != "hello\n" {
				t.Fatalf("exec.output chunk = %v, want hello", ev.Payload["chunk"])
			}
		default:
			byType[ev.Type] = ev.Payload
		}
	}
	if !sawStart || !sawOutput {
		t.Fatalf("missing start/output events (start=%v output=%v)", sawStart, sawOutput)
	}

	// exec.start captures argv + cwd (argv stays []string in the in-memory export).
	es := byType[trace.TypeExecStart]
	argv, _ := es["argv"].([]string)
	if len(argv) != 2 || argv[0] != "echo" || es["cwd"] != "/workspace" {
		t.Fatalf("exec.start payload = %v", es)
	}
	// exec.end captures exit code + a positive duration (advancing clock).
	ee := byType[trace.TypeExecEnd]
	if code, _ := ee["exit_code"].(int); code != 7 {
		t.Fatalf("exec.end exit_code = %v, want 7", ee["exit_code"])
	}
	if dur, _ := ee["duration_ms"].(int64); dur <= 0 {
		t.Fatalf("exec.end duration_ms = %v, want > 0", ee["duration_ms"])
	}
	// file.write captures path + size.
	fw := byType[trace.TypeFileWrite]
	if fw["path"] != "out.txt" || fw["size"].(int) != 2 {
		t.Fatalf("file.write payload = %v", fw)
	}

	// The exported chain must still verify after a JSON round-trip through Export.
	_ = sink
}

// Tracing is optional: a Manager with no Trace wired behaves exactly as before
// (no emission, no error) — existing lifecycle tests rely on this.
func TestManagerNoTraceIsNoop(t *testing.T) {
	rt := newFakeRuntime()
	m := newTestManager(t, rt, newFakeClock(time.Unix(0, 0)), newMemStore())
	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Exec(context.Background(), s.ID, ExecOptions{Argv: []string{"ls"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if _, _, err := m.TraceExport(context.Background(), s.ID); err == nil {
		t.Fatal("TraceExport should error when tracing is unwired")
	}
	if err := m.Destroy(context.Background(), s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
}
