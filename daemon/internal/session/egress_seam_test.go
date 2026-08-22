package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/egress"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// fakeEgress records SetupSession/TeardownSession calls so the Manager integration
// (program on create, remove on destroy, no leak) is asserted with no nft/root.
type fakeEgress struct {
	mu         sync.Mutex
	setup      []string
	teardown   []string
	lastNet    egress.SessionNet
	setupErr   error
	setupCalls int
}

func (f *fakeEgress) SetupSession(_ context.Context, n egress.SessionNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setupCalls++
	if f.setupErr != nil {
		return f.setupErr
	}
	f.setup = append(f.setup, n.SessionID)
	f.lastNet = n
	return nil
}

func (f *fakeEgress) TeardownSession(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.teardown = append(f.teardown, id)
	return nil
}

func (f *fakeEgress) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.setup), len(f.teardown)
}

func newEgressManager(t *testing.T, rt runtime.Runtime, eg egress.Controller, ipFn func(runtime.ContainerHandle) string) *Manager {
	t.Helper()
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTier:   runtime.TierLocalHardened,
			DefaultTTL:    30 * time.Minute,
		},
		Resolve:   func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:     newFakeClock(time.Unix(0, 0)),
		Store:     newMemStore(),
		Egress:    eg,
		SandboxIP: ipFn,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// F5.8: once the credential-blind listeners bind, allowBlindPathPorts re-programs
// egress with the gateway IP + the bound ports, so the host_input chain opens ONLY
// those ports (the sandbox can then reach the proxy). Asserts the reprogram carries
// the gateway + collected ports from every bound listener.
func TestAllowBlindPathPorts_OpensBoundListenerPorts(t *testing.T) {
	eg := &fakeEgress{}
	m := newEgressManager(t, newFakeRuntime(), eg, nil)

	s := &Session{ID: "sess1"}
	s.credEndpoint = &sessionCredEndpoint{addr: "http://10.89.0.1:45307"}
	s.egress = &sessionEgress{addr: "10.89.0.1:37011"}
	s.registry = &sessionRegistry{addr: "10.89.0.1:34087"}

	before := eg.setupCalls
	m.allowBlindPathPorts(context.Background(), s, sessionNet{known: true, ok: true, containerIP: "10.89.0.6", gatewayIP: "10.89.0.1"})

	if eg.setupCalls != before+1 {
		t.Fatalf("want one reprogram, got %d extra", eg.setupCalls-before)
	}
	if eg.lastNet.GatewayIP != "10.89.0.1" || eg.lastNet.SandboxIP != "10.89.0.6" {
		t.Fatalf("reprogram net missing gateway/sandbox scope: %+v", eg.lastNet)
	}
	for _, want := range []int{45307, 37011, 34087} {
		found := false
		for _, p := range eg.lastNet.LocalTCPPorts {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("port %d not opened; got %v", want, eg.lastNet.LocalTCPPorts)
		}
	}
}

// Fail-closed: no reachable gateway (sn.ok=false) => NO reprogram, so the host_input
// chain is never widened. A blind path that could not bind must not open a hole.
func TestAllowBlindPathPorts_NoGatewayNoReprogram(t *testing.T) {
	eg := &fakeEgress{}
	m := newEgressManager(t, newFakeRuntime(), eg, nil)
	s := &Session{ID: "s"}
	s.credEndpoint = &sessionCredEndpoint{addr: "http://10.89.0.1:45307"}

	before := eg.setupCalls
	m.allowBlindPathPorts(context.Background(), s, sessionNet{known: true, ok: false})
	if eg.setupCalls != before {
		t.Fatalf("no-gateway must NOT reprogram egress (fail-closed), got %d extra", eg.setupCalls-before)
	}
}

// No listeners bound (no applicable rule) => no ports => no reprogram, even with a
// live gateway. The hole only opens for actually-bound credential-blind listeners.
func TestAllowBlindPathPorts_NoListenersNoReprogram(t *testing.T) {
	eg := &fakeEgress{}
	m := newEgressManager(t, newFakeRuntime(), eg, nil)
	s := &Session{ID: "s"}

	before := eg.setupCalls
	m.allowBlindPathPorts(context.Background(), s, sessionNet{known: true, ok: true, containerIP: "10.89.0.6", gatewayIP: "10.89.0.1"})
	if eg.setupCalls != before {
		t.Fatalf("no bound listeners must NOT reprogram egress, got %d extra", eg.setupCalls-before)
	}
}

// AC: egress rules are programmed on session create and torn down on destroy, with
// no leak (setup count == teardown count after destroy).
func TestEgress_ProgrammedOnCreateTornDownOnDestroy(t *testing.T) {
	rt := newFakeRuntime()
	eg := &fakeEgress{}
	m := newEgressManager(t, rt, eg, func(runtime.ContainerHandle) string { return "10.88.0.7" })

	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n, _ := eg.counts(); n != 1 {
		t.Fatalf("want 1 egress setup, got %d", n)
	}
	if eg.lastNet.SessionID != s.ID || eg.lastNet.SandboxIP != "10.88.0.7" {
		t.Fatalf("egress setup got wrong net: %+v", eg.lastNet)
	}

	if err := m.Destroy(context.Background(), s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	setups, teardowns := eg.counts()
	if setups != teardowns {
		t.Fatalf("rule leak: %d setups but %d teardowns", setups, teardowns)
	}
}

// AC: if egress cannot be programmed, create FAILS CLOSED (no session served) with
// an ErrEgress-tagged error, and the underlying sandbox is destroyed (no leak).
func TestEgress_SetupFailureFailsClosed(t *testing.T) {
	rt := newFakeRuntime()
	eg := &fakeEgress{setupErr: errors.New("nft program failed")}
	m := newEgressManager(t, rt, eg, nil)

	_, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err == nil || !errors.Is(err, ErrEgress) {
		t.Fatalf("want ErrEgress on egress setup failure, got %v", err)
	}
	// The sandbox must have been rolled back so we never leak an unconstrained one.
	if got := rt.destroyedCount(); got != 1 {
		t.Fatalf("want the sandbox destroyed on egress failure, got %d destroys", got)
	}
	if len(m.List()) != 0 {
		t.Fatal("no session must be registered when egress setup fails")
	}
}

// Egress teardown runs on the reaper/reconcile paths too (idempotent, no leak).
func TestEgress_TornDownOnReap(t *testing.T) {
	rt := newFakeRuntime()
	eg := &fakeEgress{}
	m := newEgressManager(t, rt, eg, nil)

	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch, TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	reaped := m.ReapExpired(context.Background(), s.Created.Add(2*time.Minute))
	if len(reaped) != 1 {
		t.Fatalf("want 1 reaped, got %d", len(reaped))
	}
	if _, teardowns := eg.counts(); teardowns != 1 {
		t.Fatalf("want egress torn down on reap, got %d teardowns", teardowns)
	}
}

// The default (no Egress wired) is the Noop controller: existing F1.1–F1.3 tests
// and callers keep working with no egress wiring.
func TestEgress_DefaultsToNoop(t *testing.T) {
	m := newEgressManager(t, newFakeRuntime(), nil, nil)
	if _, ok := m.egress.(egress.Noop); !ok {
		t.Fatalf("want egress.Noop default, got %T", m.egress)
	}
}
