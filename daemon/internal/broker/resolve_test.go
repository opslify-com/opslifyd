package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// recorderCapture wires a Recorder over a MemSink so a test can inspect emitted
// cred.resolve events. session.start is emitted first so the chain has a root.
func recorderCapture(t *testing.T) (*trace.Recorder, *trace.MemSink) {
	t.Helper()
	sink := trace.NewMemSink(nil)
	rec := trace.NewRecorder(sink, "sess-1", nil, nil)
	if err := rec.Emit(context.Background(), trace.TypeSessionStart, map[string]any{
		"image_digest": "sha256:test", "policy_hash": "h",
	}); err != nil {
		t.Fatalf("seed session.start: %v", err)
	}
	return rec, sink
}

func credEvents(t *testing.T, sink *trace.MemSink) []trace.Event {
	t.Helper()
	events, _, ok := sink.Export("sess-1")
	if !ok {
		t.Fatal("no events exported")
	}
	var out []trace.Event
	for _, e := range events {
		if e.Type == trace.TypeCredResolve {
			out = append(out, e)
		}
	}
	return out
}

func TestResolveGranted(t *testing.T) {
	v, _ := newTestVault(t)
	secret := []byte("FAKE-granted-token")
	if err := v.Put(context.Background(), "aws/deploy", secret, PutMeta{Provider: "aws", Scope: "s3", TTL: "15m"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	b := NewBroker(v)
	rec, sink := recorderCapture(t)

	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	got, meta, err := b.Resolve(context.Background(), rec, grants, "aws/deploy")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("value mismatch: %q", got)
	}
	if meta.Provider != "aws" {
		t.Fatalf("meta: %+v", meta)
	}
	evs := credEvents(t, sink)
	if len(evs) != 1 {
		t.Fatalf("want 1 cred.resolve, got %d", len(evs))
	}
	assertAuditNoValue(t, evs[0], secret, true, "aws/deploy")
	if evs[0].Payload["policy_rule"] != "creds:aws/deploy/aws" {
		t.Fatalf("policy_rule = %v", evs[0].Payload["policy_rule"])
	}
}

func TestResolveDeniedByDefault(t *testing.T) {
	v, _ := newTestVault(t)
	secret := []byte("FAKE-ungranted-token")
	_ = v.Put(context.Background(), "aws/deploy", secret, PutMeta{Provider: "aws"}, false)
	b := NewBroker(v)
	rec, sink := recorderCapture(t)

	// No grants at all => deny-by-default; NO value returned.
	got, _, err := b.Resolve(context.Background(), rec, nil, "aws/deploy")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if got != nil {
		t.Fatal("SECURITY: denied resolve returned a value")
	}
	evs := credEvents(t, sink)
	if len(evs) != 1 {
		t.Fatalf("want 1 cred.resolve, got %d", len(evs))
	}
	assertAuditNoValue(t, evs[0], secret, false, "aws/deploy")
	if evs[0].Payload["success"] != false {
		t.Fatalf("success = %v, want false", evs[0].Payload["success"])
	}
}

func TestResolveGrantedButMissingFailsClosed(t *testing.T) {
	v, _ := newTestVault(t) // no secret stored
	b := NewBroker(v)
	rec, sink := recorderCapture(t)
	grants := []policy.Cred{{Name: "ghost", Provider: "aws"}}
	got, _, err := b.Resolve(context.Background(), rec, grants, "ghost")
	if err == nil {
		t.Fatal("want error for granted-but-missing")
	}
	if got != nil {
		t.Fatal("SECURITY: returned a value for a missing secret")
	}
	evs := credEvents(t, sink)
	if len(evs) != 1 || evs[0].Payload["success"] != false {
		t.Fatalf("expected one failed cred.resolve, got %+v", evs)
	}
}

func TestResolveProviderMismatchDenied(t *testing.T) {
	v, _ := newTestVault(t)
	secret := []byte("FAKE-mismatch")
	_ = v.Put(context.Background(), "k", secret, PutMeta{Provider: "aws"}, false)
	b := NewBroker(v)
	rec, _ := recorderCapture(t)
	// Grant pins a DIFFERENT provider than the stored secret.
	grants := []policy.Cred{{Name: "k", Provider: "github"}}
	got, _, err := b.Resolve(context.Background(), rec, grants, "k")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied on provider mismatch, got %v", err)
	}
	if got != nil {
		t.Fatal("SECURITY: provider-mismatch returned a value")
	}
}

func TestResolveNilBackendFailsClosed(t *testing.T) {
	b := NewBroker(nil)
	rec, _ := recorderCapture(t)
	grants := []policy.Cred{{Name: "k"}}
	if _, _, err := b.Resolve(context.Background(), rec, grants, "k"); err == nil {
		t.Fatal("nil backend should deny")
	}
}

// TestPolicyNarrowsNotWidens reuses the F4.1 resolver to prove a WORKSPACE policy
// cannot self-grant a cred the daemon did not allow — the grant a session resolves
// under is the NARROWED set, so honouring it can never over-grant.
func TestPolicyNarrowsNotWidens(t *testing.T) {
	daemon := policy.Policy{} // daemon grants NO creds
	workspace := policy.Policy{Creds: []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}}
	resolved := policy.Resolve(daemon, workspace)
	if len(resolved.Creds) != 0 {
		t.Fatalf("workspace self-granted a cred: %+v", resolved.Creds)
	}
	// A resolve under this narrowed policy is therefore denied.
	v, _ := newTestVault(t)
	_ = v.Put(context.Background(), "aws/deploy", []byte("FAKE"), PutMeta{Provider: "aws"}, false)
	b := NewBroker(v)
	rec, _ := recorderCapture(t)
	if _, _, err := b.Resolve(context.Background(), rec, resolved.Creds, "aws/deploy"); !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied under narrowed policy, got %v", err)
	}
}

// assertAuditNoValue checks a cred.resolve event carries the expected shape and
// NEVER the secret value (nor its length) anywhere in the marshalled payload.
func assertAuditNoValue(t *testing.T, e trace.Event, secret []byte, success bool, ref string) {
	t.Helper()
	if e.Payload["ref"] != ref {
		t.Fatalf("ref = %v, want %s", e.Payload["ref"], ref)
	}
	if e.Payload["success"] != success {
		t.Fatalf("success = %v, want %v", e.Payload["success"], success)
	}
	// The value must not appear anywhere in the serialized event.
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("SECURITY: secret value present in cred.resolve event")
	}
	// No key literally named "value" (a length/value leak guard).
	if _, ok := e.Payload["value"]; ok {
		t.Fatal("SECURITY: cred.resolve payload has a value field")
	}
}
