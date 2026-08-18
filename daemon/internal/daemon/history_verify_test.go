package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/trace"
)

// sealedFixture builds a real sealed trace chain (via MemSink) signed by a fresh
// identity, returning its events, seal, and the trusted public key — so the
// server-side verify endpoint can be exercised end-to-end.
func sealedFixture(t *testing.T) ([]trace.Event, *trace.Signature, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	sink := trace.NewMemSink(trace.NewEd25519Signer(priv))
	rec := trace.NewRecorder(sink, "sess-v", trace.NoopRedactor{}, func() time.Time { return time.Unix(1700000000, 0).UTC() })
	ctx := context.Background()
	if err := rec.Emit(ctx, trace.TypeSessionStart, map[string]any{
		"schema_version": trace.SchemaVersion, "tier": "local-hardened", "mode": "scratch",
	}); err != nil {
		t.Fatalf("emit start: %v", err)
	}
	if err := rec.Emit(ctx, trace.TypeExecStart, map[string]any{"argv": []string{"echo", "hi"}, "cwd": "/workspace"}); err != nil {
		t.Fatalf("emit exec: %v", err)
	}
	if err := rec.Emit(ctx, trace.TypeSessionEnd, map[string]any{"reason": "destroyed"}); err != nil {
		t.Fatalf("emit end: %v", err)
	}
	seal, err := rec.Seal(ctx)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	events, sealOut, ok := sink.Export("sess-v")
	if !ok {
		t.Fatal("export failed")
	}
	_ = seal
	return events, sealOut, pub
}

// AC (F3.6): GET /v1/sessions/history lists persisted sessions (newest first).
func TestHTTPSessionHistory(t *testing.T) {
	started := time.Unix(1700000000, 0).UTC()
	ended := started.Add(30 * time.Second)
	mgr := &fakeManager{history: []trace.SessionMeta{
		{SessionID: "sess-new", StartedAt: started.Add(time.Minute), Tier: "local-hardened", EventCount: 4, Sealed: true, EndedAt: &ended},
		{SessionID: "sess-old", StartedAt: started, Tier: "gvisor", EventCount: 2, Sealed: false},
	}}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp := mustGet(t, srv.URL+"/v1/sessions/history")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var items []historyItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(items) != 2 || items[0].SessionID != "sess-new" || items[1].SessionID != "sess-old" {
		t.Fatalf("history order/content wrong: %+v", items)
	}
	if items[0].EventCount != 4 || !items[0].Sealed || items[0].EndedAt == nil {
		t.Errorf("sess-new metadata wrong: %+v", items[0])
	}
}

// AC (F3.6): GET /v1/sessions/{id}/verify returns verified=true for an
// untampered sealed trace, checked SERVER-SIDE against the trusted identity.
func TestHTTPVerifyUntampered(t *testing.T) {
	events, seal, pub := sealedFixture(t)
	mgr := &fakeManager{traceEvents: events, traceSeal: seal}
	d := newTestDaemon(t, mgr)
	d.trustedPub = pub // the daemon's trust anchor (set by Startup in production)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp := mustGet(t, srv.URL+"/v1/sessions/sess-v/verify")
	defer resp.Body.Close()
	var v verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !v.Verified {
		t.Fatalf("want verified=true, got %+v", v)
	}
	if v.Events != len(events) {
		t.Errorf("events = %d, want %d", v.Events, len(events))
	}
}

// AC (F3.6): a tampered (byte-flipped) on-disk trace yields verified=false with
// the broken seq — the browser cannot spoof a ✓ because the verdict is daemon-side.
func TestHTTPVerifyTampered(t *testing.T) {
	events, seal, pub := sealedFixture(t)
	// Tamper: edit a payload field of seq 1 (its recomputed hash will diverge).
	events[1].Payload["cwd"] = "/etc"
	mgr := &fakeManager{traceEvents: events, traceSeal: seal}
	d := newTestDaemon(t, mgr)
	d.trustedPub = pub
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp := mustGet(t, srv.URL+"/v1/sessions/sess-v/verify")
	defer resp.Body.Close()
	var v verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.Verified {
		t.Fatal("tampered trace wrongly verified")
	}
	if v.BrokenSeq == nil || *v.BrokenSeq != 1 {
		t.Errorf("broken_seq = %v, want 1", v.BrokenSeq)
	}
	if v.Events != len(events) {
		t.Errorf("events = %d, want %d", v.Events, len(events))
	}
}

// Security (F3.6): with no trusted anchor (daemon couldn't load its pubkey), a
// SEALED session fails closed — verify never self-trusts the seal's own key.
func TestHTTPVerifyFailsClosedWithoutAnchor(t *testing.T) {
	events, seal, _ := sealedFixture(t)
	mgr := &fakeManager{traceEvents: events, traceSeal: seal}
	d := newTestDaemon(t, mgr) // d.trustedPub left nil
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp := mustGet(t, srv.URL+"/v1/sessions/sess-v/verify")
	defer resp.Body.Close()
	var v verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.Verified {
		t.Fatal("sealed session verified without a trusted anchor — must fail closed")
	}
}
