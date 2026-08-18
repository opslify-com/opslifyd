package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// managerWithBroker builds a Manager wired with a Broker over a seeded vault, a
// trace MemSink (so cred.resolve is emitted + inspectable), and a daemon default
// policy granting the given creds.
func managerWithBroker(t *testing.T, grants []policy.Cred) (*Manager, *broker.Vault, *trace.MemSink) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	v, err := broker.OpenVault(path, broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	sink := trace.NewMemSink(nil)
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTier:   runtime.TierLocalHardened,
			DefaultTTL:    30 * time.Minute,
			Limits:        runtime.ResourceLimits{MemoryBytes: 2 << 30, CPUs: 2, PidsLimit: 256},
			DefaultPolicy: policy.Policy{Creds: grants},
		},
		Resolve: func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return newFakeRuntime(), nil },
		Clock:   newFakeClock(time.Unix(0, 0)),
		Store:   newMemStore(),
		Trace:   sink,
		Broker:  broker.NewBroker(v),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, v, sink
}

func TestResolveSecretGranted(t *testing.T) {
	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	m, v, sink := managerWithBroker(t, grants)
	secret := []byte("FAKE-session-token")
	if err := v.Put(context.Background(), "aws/deploy", secret, broker.PutMeta{Provider: "aws"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, meta, err := m.ResolveSecret(context.Background(), s.ID, "aws/deploy")
	if err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("value mismatch: %q", got)
	}
	if meta.Provider != "aws" {
		t.Fatalf("meta: %+v", meta)
	}
	assertCredResolveEmitted(t, sink, s.ID, secret, true)
}

func TestResolveSecretUngrantedDenied(t *testing.T) {
	// Daemon default grants nothing → session resolves nothing.
	m, v, sink := managerWithBroker(t, nil)
	secret := []byte("FAKE-forbidden")
	_ = v.Put(context.Background(), "aws/deploy", secret, broker.PutMeta{Provider: "aws"}, false)
	s, err := m.Create(context.Background(), CreateRequest{Mode: ModeScratch})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, _, err := m.ResolveSecret(context.Background(), s.ID, "aws/deploy")
	if !errors.Is(err, broker.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if got != nil {
		t.Fatal("SECURITY: ungranted ResolveSecret returned a value")
	}
	assertCredResolveEmitted(t, sink, s.ID, secret, false)
}

func TestResolveSecretUnknownSession(t *testing.T) {
	m, _, _ := managerWithBroker(t, nil)
	if _, _, err := m.ResolveSecret(context.Background(), "no-such", "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func assertCredResolveEmitted(t *testing.T, sink *trace.MemSink, id string, secret []byte, success bool) {
	t.Helper()
	events, _, ok := sink.Export(id)
	if !ok {
		t.Fatal("no events for session")
	}
	var found bool
	for _, e := range events {
		if e.Type != trace.TypeCredResolve {
			continue
		}
		found = true
		if e.Payload["success"] != success {
			t.Fatalf("cred.resolve success = %v, want %v", e.Payload["success"], success)
		}
	}
	if !found {
		t.Fatal("no cred.resolve event emitted")
	}
	// The value must never appear in ANY event of the session's chain.
	for _, e := range events {
		raw, _ := json.Marshal(e)
		if bytes.Contains(raw, secret) {
			t.Fatalf("SECURITY: secret value present in a %s event", e.Type)
		}
	}
}
