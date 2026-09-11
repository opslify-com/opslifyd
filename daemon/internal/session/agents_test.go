package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/agents"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

func agentManager(t *testing.T, rt runtime.Runtime, src AgentSource) *Manager {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTier:   runtime.TierLocalHardened,
			DefaultTTL:    30 * time.Minute,
		},
		Resolve: func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:   &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second},
		Store:   newMemStore(),
		Trace:   trace.NewMemSink(trace.NewEd25519Signer(priv)),
		Agents:  src,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func boundAgent() agents.Agent {
	return agents.Agent{
		Name: "qwen-local", Command: "/usr/bin/ollama", ModelHint: "qwen2.5-coder:32b",
		Locality: agents.LocalityLocal,
	}
}

// AC (F8.5): the bound agent's identity AND model hint are recorded in
// session.start, so a decision is attributable to a model rather than to "an
// agent".
func TestSessionStartRecordsTheBoundAgent(t *testing.T) {
	rt := newFakeRuntime()
	m := agentManager(t, rt, func(string, string) (agents.Agent, error) { return boundAgent(), nil })
	ctx := context.Background()

	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	events, _, err := m.TraceExport(ctx, s.ID)
	if err != nil {
		t.Fatalf("TraceExport: %v", err)
	}
	start := events[0]
	if start.Type != trace.TypeSessionStart {
		t.Fatalf("seq 0 = %s, want session.start", start.Type)
	}
	for field, want := range map[string]any{
		"agent":          "qwen-local",
		"agent_model":    "qwen2.5-coder:32b",
		"agent_locality": "local",
	} {
		if got := start.Payload[field]; got != want {
			t.Errorf("session.start %s = %v, want %v", field, got, want)
		}
	}
	// The command line must NOT be recorded: an argument list can carry local
	// paths and account identifiers, and identity is what attributes a decision.
	for _, forbidden := range []string{"command", "args", "argv"} {
		if _, present := start.Payload[forbidden]; present {
			t.Errorf("session.start carries %q; identity attributes a decision, not the command line", forbidden)
		}
	}
}

// TestAgentIdentityIsBoundAtSeqZero: it belongs in the chain ROOT, not in a later
// event that could be absent from a truncated trace.
func TestAgentIdentityIsBoundAtSeqZero(t *testing.T) {
	rt := newFakeRuntime()
	m := agentManager(t, rt, func(string, string) (agents.Agent, error) { return boundAgent(), nil })
	ctx := context.Background()
	s, _ := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	_ = m.Destroy(ctx, s.ID)
	events, _, _ := m.TraceExport(ctx, s.ID)
	if events[0].Seq != 0 {
		t.Fatalf("first event seq = %d", events[0].Seq)
	}
	if events[0].Payload["agent"] != "qwen-local" {
		t.Error("the agent identity must be in the seq-0 event")
	}
}

// TestNoAgentBoundIsNotFatal: opslify ships no model, so a daemon with no agent
// registered is a valid state for someone driving the CLI directly. Refusing to
// start a session would break every CLI-only workflow.
func TestNoAgentBoundIsNotFatal(t *testing.T) {
	rt := newFakeRuntime()
	m := agentManager(t, rt, func(string, string) (agents.Agent, error) {
		return agents.Agent{}, errors.New("no agent bound")
	})
	ctx := context.Background()
	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("a session must start with no agent bound: %v", err)
	}
	_ = m.Destroy(ctx, s.ID)
	events, _, _ := m.TraceExport(ctx, s.ID)
	if got := events[0].Payload["agent"]; got != "" {
		t.Errorf("with nothing bound the agent field must be empty, got %v", got)
	}
}

// TestNoAgentSourceIsNotFatal keeps the seam optional for every pre-P8 path.
func TestNoAgentSourceIsNotFatal(t *testing.T) {
	rt := newFakeRuntime()
	m := agentManager(t, rt, nil)
	ctx := context.Background()
	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = m.Destroy(ctx, s.ID)
}

// TestTheAgentBindingDoesNotChangeWhatASessionCanDo is the feature's central
// constraint, asserted where it actually matters: the SAME session shape under
// two very different agents. The sandbox binding, the policy hash and the scope
// must be identical — only the attribution differs.
func TestTheAgentBindingDoesNotChangeWhatASessionCanDo(t *testing.T) {
	run := func(a agents.Agent) map[string]any {
		rt := newFakeRuntime()
		m := agentManager(t, rt, func(string, string) (agents.Agent, error) { return a, nil })
		ctx := context.Background()
		s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		_ = m.Destroy(ctx, s.ID)
		events, _, _ := m.TraceExport(ctx, s.ID)
		return events[0].Payload
	}
	hosted := run(agents.Agent{Name: "claude", Command: "/usr/local/bin/claude",
		ModelHint: "claude-opus-5", Locality: agents.LocalityHosted})
	local := run(boundAgent())

	if len(hosted) != len(local) {
		t.Fatalf("the two agents produced different field SETS:\n%v\n%v", hosted, local)
	}
	for k, hv := range hosted {
		switch k {
		case "agent", "agent_model", "agent_locality":
			// Expected to differ — that is the whole point of the binding.
			if hv == local[k] {
				t.Errorf("%s did not differ between two different agents", k)
			}
		default:
			// Everything that governs what the session MAY DO must be identical.
			if hv != local[k] {
				t.Errorf("session.start %s differs between agents (%v vs %v): a binding must not change capability",
					k, hv, local[k])
			}
		}
	}
}
