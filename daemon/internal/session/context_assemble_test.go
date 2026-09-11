package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/agentcontext"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// ctxManager builds a traced Manager with an F8.4 assembler wired in.
func ctxManager(t *testing.T, rt runtime.Runtime, assembler ContextAssembler) (*Manager, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTier:   runtime.TierLocalHardened,
			DefaultTTL:    30 * time.Minute,
		},
		Resolve:         func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:           &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second},
		Store:           newMemStore(),
		Trace:           trace.NewMemSink(trace.NewEd25519Signer(priv)),
		AssembleContext: assembler,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, pub
}

// houseRulesAssembler returns an assembler reading a real house-rules file that
// lives OUTSIDE the workspace, which is the only arrangement layer 1 accepts.
func houseRulesAssembler(t *testing.T, rules string) ContextAssembler {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "house-rules.md")
	if err := os.WriteFile(path, []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	return func(projectID, envID, wsDir string) (*agentcontext.Assembly, error) {
		return agentcontext.Assemble(agentcontext.Sources{
			HouseRulesPath: path,
			WorkspaceRoot:  wsDir,
			Env:            "",
		})
	}
}

// AC (F8.4): context.assemble is emitted at session start with the layer hashes
// and lands in the verifiable chain, so a Change resolves to the exact
// instruction set it ran under.
func TestSessionEmitsContextAssemble(t *testing.T) {
	rt := newFakeRuntime()
	m, _ := ctxManager(t, rt, houseRulesAssembler(t, "Never restart db-01."))
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
	if events[0].Type != trace.TypeSessionStart {
		t.Fatalf("seq 0 = %s, want session.start", events[0].Type)
	}
	// Seq 1: bound to the chain root alongside the policy hash, before any exec
	// could interleave.
	if len(events) < 2 || events[1].Type != trace.TypeContextAssemble {
		t.Fatalf("seq 1 = %v, want context.assemble", eventTypes(events))
	}
	// Assert against the MARSHALLED payload: that is the form a verifier and the
	// UI actually read, and it is what the on-disk chain holds. Asserting on the
	// in-memory Go types would pass even if the payload could not be serialized.
	raw, err := json.Marshal(events[1].Payload)
	if err != nil {
		t.Fatalf("the context.assemble payload must be serializable: %v", err)
	}
	var p struct {
		Hash   string `json:"hash"`
		Tokens int    `json:"tokens"`
		Layers []struct {
			Kind    string          `json:"kind"`
			Name    string          `json:"name"`
			Hash    string          `json:"hash"`
			Bytes   int             `json:"bytes"`
			Content json.RawMessage `json:"content"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if p.Hash == "" {
		t.Error("context.assemble must carry the assembly hash, or a Change cannot bind to it")
	}
	if len(p.Layers) == 0 {
		t.Fatalf("no layers in the payload: %s", raw)
	}
	if p.Layers[0].Kind != string(agentcontext.LayerHouseRules) {
		t.Errorf("first layer kind = %q, want house_rules", p.Layers[0].Kind)
	}
	if p.Layers[0].Hash == "" || p.Layers[0].Bytes == 0 {
		t.Errorf("a layer entry must carry its hash and size: %+v", p.Layers[0])
	}
	if p.Layers[0].Content != nil {
		t.Error("a layer entry must never carry content")
	}
}

// TestContextAssembleCarriesNoInstructionContent: the trace is permanent and
// verifiable, so a leak here cannot be retracted. Instruction text can hold
// estate detail — which box is the primary, who to page — that an operator never
// agreed to persist in an audit log.
func TestContextAssembleCarriesNoInstructionContent(t *testing.T) {
	const canary = "CANARY-house-rule-text-must-not-be-traced"
	rt := newFakeRuntime()
	m, _ := ctxManager(t, rt, houseRulesAssembler(t, canary))
	ctx := context.Background()

	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = m.Destroy(ctx, s.ID)
	events, _, err := m.TraceExport(ctx, s.ID)
	if err != nil {
		t.Fatalf("TraceExport: %v", err)
	}
	for _, e := range events {
		if strings.Contains(sprintPayload(e.Payload), canary) {
			t.Fatalf("%s carried the instruction CONTENT: %v", e.Type, e.Payload)
		}
	}
}

// TestSessionRefusesToStartOnAssemblyFailure is the fail-closed property. A
// session running with its house rules quietly missing is exactly what layer 1
// exists to prevent, and it would be invisible from the outside — the agent would
// simply behave as though the rule had never been written. So an unreadable or
// unsafe source aborts the create.
func TestSessionRefusesToStartOnAssemblyFailure(t *testing.T) {
	rt := newFakeRuntime()
	boom := errors.New("house rules unreadable")
	m, _ := ctxManager(t, rt, func(string, string, string) (*agentcontext.Assembly, error) {
		return nil, boom
	})
	ctx := context.Background()

	if _, err := m.Create(ctx, CreateRequest{Mode: ModeScratch}); !errors.Is(err, boom) {
		t.Fatalf("Create must fail closed on an assembly error, got %v", err)
	}
	// And it must not leak a sandbox: the container is rolled back. Comparing
	// created against destroyed is the honest check — a create that spawned and did
	// not tear down is exactly the orphan this rollback exists to prevent.
	rt.mu.Lock()
	created, destroyed := rt.created, rt.destroyed
	rt.mu.Unlock()
	if created != destroyed {
		t.Errorf("%d container(s) created but only %d destroyed: the refused create leaked a sandbox", created, destroyed)
	}
	if sessions := m.List(); len(sessions) != 0 {
		t.Errorf("a refused create left %d session(s) registered", len(sessions))
	}
}

// TestUnsafeWorkspaceContextAbortsTheSession ties the fail-closed path to a REAL
// attack rather than a synthetic error: a skill file symlinked at a host secret.
// Without the refusal it would be read by the daemon and placed into the model's
// context.
func TestUnsafeWorkspaceContextAbortsTheSession(t *testing.T) {
	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "vault.key")
	if err := os.WriteFile(secret, []byte("MASTER-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	rulesDir := t.TempDir()
	rules := filepath.Join(rulesDir, "house-rules.md")
	if err := os.WriteFile(rules, []byte("Never restart db-01."), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := newFakeRuntime()
	m, _ := ctxManager(t, rt, func(_, _, wsDir string) (*agentcontext.Assembly, error) {
		// Plant the symlink in the session's own workspace, as an agent could.
		skills := filepath.Join(wsDir, ".opslify", "skills")
		if err := os.MkdirAll(skills, 0o755); err != nil {
			return nil, err
		}
		if err := os.Symlink(secret, filepath.Join(skills, "kubernetes.md")); err != nil {
			return nil, err
		}
		return agentcontext.Assemble(agentcontext.Sources{HouseRulesPath: rules, WorkspaceRoot: wsDir})
	})

	_, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err == nil {
		t.Fatal("a symlinked skill file must abort the session, not be read into the context")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("the refusal must name the reason: %v", err)
	}
}

// TestNoAssemblerMeansNoEvent keeps the seam optional: every pre-P8 path runs
// without an assembler and must be unaffected.
func TestNoAssemblerMeansNoEvent(t *testing.T) {
	rt := newFakeRuntime()
	m, _ := ctxManager(t, rt, nil)
	ctx := context.Background()

	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create without an assembler must work: %v", err)
	}
	_ = m.Destroy(ctx, s.ID)
	events, _, _ := m.TraceExport(ctx, s.ID)
	for _, e := range events {
		if e.Type == trace.TypeContextAssemble {
			t.Fatal("no assembler configured, yet a context.assemble event was emitted")
		}
	}
}

func eventTypes(events []trace.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, string(e.Type))
	}
	return out
}

func sprintPayload(p map[string]any) string {
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, vv := range t {
				b.WriteString(k)
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		default:
			fmt.Fprintf(&b, "%v", v)
		}
	}
	walk(p)
	return b.String()
}

// --- ordering: the assembly must precede the container ------------------------

// orderingRuntime records when Create is called relative to the assembler.
type orderingRuntime struct {
	runtime.Runtime
	events *[]string
}

func (r *orderingRuntime) Create(ctx context.Context, spec runtime.SessionSpec) (runtime.ContainerHandle, error) {
	*r.events = append(*r.events, "container.create")
	return r.Runtime.Create(ctx, spec)
}

// TestContextIsAssembledBeforeTheContainerExists.
//
// This ordering is not a preference. The workspace is bind mounted into the
// sandbox, and podman's --userns=auto idmaps that mount: once the container
// exists, the directory belongs to a subuid range and the daemon's own lstat
// inside it returns EPERM. Assembling afterwards failed EVERY create that had a
// workspace root configured, with "unsafe source: .opslify/instructions.md:
// permission denied" — for a file that was simply not there.
//
// Nothing caught it because every test here uses a fake runtime that does not
// idmap anything, so the order was invisible. This asserts the order directly.
func TestContextIsAssembledBeforeTheContainerExists(t *testing.T) {
	var events []string
	rt := &orderingRuntime{Runtime: newFakeRuntime(), events: &events}

	assembler := func(projectID, envID, wsDir string) (*agentcontext.Assembly, error) {
		events = append(events, "context.assemble")
		// The root must be readable at this point when it exists — that is the
		// claim. A project that has never had a workspace created is a normal
		// starting state and assembling from a missing directory is not an error,
		// so absence is allowed and only an unreadable one is a failure.
		if wsDir != "" {
			if _, err := os.Stat(wsDir); err != nil && !os.IsNotExist(err) {
				t.Errorf("workspace %s is not readable when the context is assembled: %v", wsDir, err)
			}
		}
		return &agentcontext.Assembly{}, nil
	}

	m, _ := ctxManager(t, rt, assembler)
	if _, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	ai, ci := -1, -1
	for i, e := range events {
		if e == "context.assemble" && ai < 0 {
			ai = i
		}
		if e == "container.create" && ci < 0 {
			ci = i
		}
	}
	if ai < 0 {
		t.Fatal("the assembler was never called")
	}
	if ci < 0 {
		t.Fatal("the container was never created")
	}
	if ai > ci {
		t.Fatalf("context was assembled AFTER the container (%v) — once podman idmaps "+
			"the bind-mounted workspace the daemon cannot read it, and every create "+
			"with a workspace root fails", events)
	}
}

// TestAFailedAssemblyCostsNoContainer: assembling first means a bad source is
// refused before anything is spent.
func TestAFailedAssemblyCostsNoContainer(t *testing.T) {
	var events []string
	rt := &orderingRuntime{Runtime: newFakeRuntime(), events: &events}
	assembler := func(projectID, envID, wsDir string) (*agentcontext.Assembly, error) {
		return nil, errors.New("a symlinked skill file")
	}
	m, _ := ctxManager(t, rt, assembler)
	if _, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch}); err == nil {
		t.Fatal("Create succeeded with a failing assembler; it must fail closed")
	}
	for _, e := range events {
		if e == "container.create" {
			t.Error("a container was created even though the context could not be assembled")
		}
	}
}

// --- delivery: the rules have to reach somebody ---------------------------------

// TestInstructionsAreDeliverableFromASession.
//
// The assembly was computed, hashed into the trace and bound into every Change —
// and handed to nobody. The house-rules layer is the one that makes the whole
// scheme worth having ("stop before touching db-01"), and no agent had ever read
// it. A rule the model never sees is not a guardrail, it is a note in a filing
// cabinet.
func TestInstructionsAreDeliverableFromASession(t *testing.T) {
	const rule = "Never restart db-01. Fail over first, then ask."
	m, _ := ctxManager(t, newFakeRuntime(), houseRulesAssembler(t, rule))

	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	text, hash := s.Instructions()
	if text == "" {
		t.Fatal("a session assembled instructions and cannot hand them over")
	}
	if hash == "" {
		t.Error("the instruction set has no hash, so a client cannot tell two apart")
	}
	if !strings.Contains(text, rule) {
		t.Errorf("the house rule is missing from the delivered text:\n%s", text)
	}
	// Provenance travels with it: a model that cannot tell a house rule from a
	// repo note an agent wrote moments ago cannot weigh them when they disagree.
	if !strings.Contains(text, "repo cannot change") {
		t.Error("the delivered text does not label the house-rules layer's authority")
	}
}

// TestInstructionsAreEmptyWithoutAnAssembler keeps the accessor honest rather
// than inventing a plausible-looking empty ruleset.
func TestInstructionsAreEmptyWithoutAnAssembler(t *testing.T) {
	m := newTestManager(t, newFakeRuntime(), &advancingClock{
		now: time.Unix(1700000000, 0).UTC(), step: time.Second,
	}, newMemStore())
	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatal(err)
	}
	text, hash := s.Instructions()
	if text != "" || hash != "" {
		t.Errorf("no assembler was wired but instructions came back: %q / %q", text, hash)
	}
}

// TestContextComesFromTheProjectWorkspaceNotTheSessionOne.
//
// A scratch session's workspace is a fresh empty <root>/<session-id>. A project's
// skills and instructions.md live in ITS workspace. Assembling from the session's
// directory meant the rules loaded for workspace-mode sessions and silently
// vanished for scratch ones — the agent ran without them on exactly the short
// tasks people run most, and nothing reported it.
func TestContextComesFromTheProjectWorkspaceNotTheSessionOne(t *testing.T) {
	var sawRoot string
	assembler := func(projectID, envID, root string) (*agentcontext.Assembly, error) {
		sawRoot = root
		return &agentcontext.Assembly{}, nil
	}
	m, _ := ctxManager(t, newFakeRuntime(), assembler)

	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sawRoot == "" {
		t.Fatal("the assembler was never called")
	}
	// The session id must not appear: that would be the ephemeral scratch dir.
	if strings.Contains(sawRoot, s.ID) {
		t.Fatalf("context assembled from the session's own scratch directory (%s); a "+
			"project's skills do not live there", sawRoot)
	}
	if !strings.Contains(sawRoot, "ws-") {
		t.Errorf("context root %q is not a project workspace", sawRoot)
	}
}
