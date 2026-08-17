package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// AC (F4.1): the resolved policy_hash is written into the session.start trace
// binding. With no policy file and an empty daemon default, that hash is the
// stable, well-known policy.DefaultHash — and the sealed chain still verifies.
func TestSessionStartBindsDefaultPolicyHash(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, _, trustedPub := newTracedManager(t, rt, clk)
	ctx := context.Background()

	s, err := m.Create(ctx, CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	events, seal, err := m.TraceExport(ctx, s.ID)
	if err != nil {
		t.Fatalf("TraceExport: %v", err)
	}
	start := events[0]
	if start.Type != trace.TypeSessionStart {
		t.Fatalf("seq0 is %s, want session.start", start.Type)
	}
	if got := start.Payload["policy_hash"]; got != policy.DefaultHash {
		t.Fatalf("policy_hash = %v, want DefaultHash %s", got, policy.DefaultHash)
	}
	// The binding is committed: the sealed chain verifies against the daemon key,
	// and the seq-0 root is derived from the binding (image+toolchain+policy_hash).
	if res := trace.Verify(events, seal, trustedPub); !res.OK {
		t.Fatalf("verify failed at seq %d: %s", res.BrokenSeq, res.Reason)
	}
}

// AC (F4.1): a workspace-mode session reads its /workspace policy file, resolves
// it (narrowed over the daemon default), and binds THAT resolved hash — proving
// the policy_hash flows from the workspace file into the trace, and that a
// widening workspace grant is clamped before it is ever bound.
func TestWorkspacePolicyResolvesIntoBinding(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}

	// Daemon default allows one namespace; the workspace tries to add another.
	daemonPol := policy.Policy{
		Allow: policy.Allow{Kubectl: policy.Kubectl{Namespaces: []string{"team-a"}}},
	}
	m, _, _ := newTracedManager(t, rt, clk)
	m.cfg.DefaultPolicy = daemonPol
	ctx := context.Background()

	// Pre-create the workspace host dir and drop a policy file at its root (the
	// mounted /workspace). It over-reaches (extra namespace) and adds a gate.
	wsName := "proj"
	wsDir := m.workspaceDir(wsName)
	if err := os.MkdirAll(wsDir, 0o700); err != nil {
		t.Fatalf("mkdir ws: %v", err)
	}
	wsPolicy := "allow:\n  kubectl:\n    namespaces: [team-a, kube-system]\napproval_required:\n  - \"^kubectl delete\"\n"
	if err := os.WriteFile(filepath.Join(wsDir, policy.DefaultFileName), []byte(wsPolicy), 0o600); err != nil {
		t.Fatalf("write ws policy: %v", err)
	}

	s, err := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: wsName})
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
	gotHash, _ := events[0].Payload["policy_hash"].(string)

	// Independently resolve the same inputs; the bound hash must equal the
	// narrowed resolution (kube-system dropped, gate added) — NOT the widened one.
	wsParsed, perr := policy.Parse([]byte(wsPolicy), "opslify.policy.yaml")
	if perr != nil {
		t.Fatalf("parse ws policy: %v", perr)
	}
	want := policy.Resolve(daemonPol, wsParsed)
	if gotHash != want.Hash {
		t.Fatalf("bound policy_hash %s != resolved %s", gotHash, want.Hash)
	}
	// Sanity: the resolution actually clamped the widening.
	for _, ns := range want.Allow.Kubectl.Namespaces {
		if ns == "kube-system" {
			t.Fatalf("resolution failed to clamp widening namespace")
		}
	}
	if len(want.Notes) == 0 {
		t.Fatalf("expected a clamp note for the widening workspace policy")
	}
	// And it must DIFFER from the default-only hash (workspace policy took effect).
	if gotHash == policy.DefaultHash {
		t.Fatalf("workspace policy did not affect the bound hash")
	}
}

// Fail-closed: a present-but-INVALID workspace policy makes Create refuse to
// serve rather than silently falling back to the permissive default.
func TestInvalidWorkspacePolicyRefusesToServe(t *testing.T) {
	rt := newFakeRuntime()
	clk := &advancingClock{now: time.Unix(1700000000, 0).UTC(), step: time.Second}
	m, _, _ := newTracedManager(t, rt, clk)
	ctx := context.Background()

	wsName := "broken"
	wsDir := m.workspaceDir(wsName)
	if err := os.MkdirAll(wsDir, 0o700); err != nil {
		t.Fatalf("mkdir ws: %v", err)
	}
	bad := "session:\n  tier: wide-open\n" // unknown tier → semantic error
	if err := os.WriteFile(filepath.Join(wsDir, policy.DefaultFileName), []byte(bad), 0o600); err != nil {
		t.Fatalf("write ws policy: %v", err)
	}

	_, err := m.Create(ctx, CreateRequest{Mode: ModeWorkspace, Name: wsName})
	if err == nil {
		t.Fatalf("expected Create to refuse an invalid workspace policy")
	}
	var verr *policy.ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("error not a policy ValidationError: %v", err)
	}
}
