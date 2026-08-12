package trace

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// testSigner is a deterministic Ed25519 signer over a freshly generated key, so
// the seal path is exercised against a real signature with no daemon identity
// file, no root.
func newTestSigner(t *testing.T) *Ed25519Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return NewEd25519Signer(priv)
}

// startPayload is a well-formed session.start payload carrying the binding.
func startPayload() map[string]any {
	return map[string]any{
		"schema_version":      SchemaVersion,
		"tier":                "local-hardened",
		"mode":                "scratch",
		"agent":               "",
		"image_digest":        "base@sha256:deadbeef",
		"toolchain_lock_hash": "tool@sha256:cafe",
		"policy_hash":         "",
	}
}

// buildSession emits a representative session into a fresh sink and seals it:
// start → exec.start → two output chunks → exec.end → file.write → end + seal.
func buildSession(t *testing.T, sink *MemSink, id string) Signature {
	t.Helper()
	ctx := context.Background()
	rec := NewRecorder(sink, id, NoopRedactor{}, fixedClock())
	must(t, rec.Emit(ctx, TypeSessionStart, startPayload()))
	must(t, rec.Emit(ctx, TypeExecStart, map[string]any{"argv": []string{"echo", "hi"}, "cwd": "/workspace"}))
	must(t, rec.Emit(ctx, TypeExecOutput, map[string]any{"stream": "stdout", "offset": 0, "chunk": "hi\n"}))
	must(t, rec.Emit(ctx, TypeExecEnd, map[string]any{"exit_code": 0, "duration_ms": 5}))
	must(t, rec.Emit(ctx, TypeFileWrite, map[string]any{"path": "out.txt", "size": 3}))
	must(t, rec.Emit(ctx, TypeSessionEnd, map[string]any{"reason": "destroyed"}))
	seal, err := rec.Seal(ctx)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return seal
}

func fixedClock() func() time.Time {
	base := time.Unix(1700000000, 0).UTC()
	var mu sync.Mutex
	var n int64
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		n++
		return base.Add(time.Duration(n) * time.Second)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
}

// AC: a session produces a well-formed chain (seq contiguous from 0, every hash
// recomputes, prev_hash links hold) and seal+verify passes on an untampered run.
func TestChainWellFormedAndVerifies(t *testing.T) {
	sink := NewMemSink(newTestSigner(t))
	seal := buildSession(t, sink, "sess-1")

	events, gotSeal, ok := sink.Export("sess-1")
	if !ok {
		t.Fatal("Export: no events")
	}
	if gotSeal == nil || gotSeal.FinalHash != seal.FinalHash {
		t.Fatal("Export seal mismatch")
	}
	for i, ev := range events {
		if ev.Seq != uint64(i) {
			t.Fatalf("seq[%d] = %d, want %d", i, ev.Seq, i)
		}
	}
	if events[0].Type != TypeSessionStart {
		t.Fatalf("seq 0 = %s, want session.start", events[0].Type)
	}
	res := Verify(events, gotSeal, sink.signer.Public())
	if !res.OK {
		t.Fatalf("Verify clean chain failed at seq %d: %s", res.BrokenSeq, res.Reason)
	}
	if res.Events != len(events) {
		t.Fatalf("Verify Events = %d, want %d", res.Events, len(events))
	}
}

// AC: chain root binds image_digest + toolchain_lock_hash (+ policy_hash slot).
// Editing a binding field in the seq-0 payload breaks verification at seq 0.
func TestChainRootBindsEnvironment(t *testing.T) {
	sink := NewMemSink(newTestSigner(t))
	seal := buildSession(t, sink, "sess-1")
	events, _, _ := sink.Export("sess-1")

	// seq-0 prev_hash must equal the binding root derived from its payload.
	wantRoot := bindingFromPayload(startPayload()).Root()
	if events[0].PrevHash != wantRoot {
		t.Fatalf("seq0 prev_hash = %s, want binding root %s", events[0].PrevHash, wantRoot)
	}

	// Tamper the image_digest in the seq-0 payload: the recorded hash no longer
	// recomputes (payload edit) → first broken seq is 0.
	tampered := cloneEvents(events)
	tampered[0].Payload["image_digest"] = "base@sha256:evil"
	res := Verify(tampered, &seal, sink.signer.Public())
	if res.OK || res.BrokenSeq != 0 {
		t.Fatalf("tampered binding: got OK=%v seq=%d, want fail at 0", res.OK, res.BrokenSeq)
	}
}

// AC: editing any event (payload) makes Verify fail, naming the first broken seq.
func TestTamperPayloadEdit(t *testing.T) {
	sink := NewMemSink(newTestSigner(t))
	seal := buildSession(t, sink, "sess-1")
	events, _, _ := sink.Export("sess-1")

	tampered := cloneEvents(events)
	// Edit the exec.output chunk at seq 2.
	tampered[2].Payload["chunk"] = "HACKED\n"
	res := Verify(tampered, &seal, sink.signer.Public())
	if res.OK || res.BrokenSeq != 2 {
		t.Fatalf("payload edit: got OK=%v seq=%d, want fail at 2", res.OK, res.BrokenSeq)
	}
}

// AC: reordering events makes Verify fail at the first out-of-place seq.
func TestTamperReorder(t *testing.T) {
	sink := NewMemSink(newTestSigner(t))
	seal := buildSession(t, sink, "sess-1")
	events, _, _ := sink.Export("sess-1")

	tampered := cloneEvents(events)
	tampered[2], tampered[3] = tampered[3], tampered[2] // swap two adjacent events
	res := Verify(tampered, &seal, sink.signer.Public())
	if res.OK || res.BrokenSeq != 2 {
		t.Fatalf("reorder: got OK=%v seq=%d, want fail at 2", res.OK, res.BrokenSeq)
	}
}

// AC: dropping an event makes Verify fail (contiguity gap) at the drop point.
func TestTamperDrop(t *testing.T) {
	sink := NewMemSink(newTestSigner(t))
	seal := buildSession(t, sink, "sess-1")
	events, _, _ := sink.Export("sess-1")

	tampered := cloneEvents(events)
	// Drop seq 3; positions 0,1,2 fine, position 3 now holds the event with seq 4.
	tampered = append(tampered[:3], tampered[4:]...)
	res := Verify(tampered, &seal, sink.signer.Public())
	if res.OK || res.BrokenSeq != 3 {
		t.Fatalf("drop: got OK=%v seq=%d, want fail at 3", res.OK, res.BrokenSeq)
	}
}

// AC: a corrupted signature (same identity) makes Verify fail at the chain head.
func TestTamperBadSignature(t *testing.T) {
	signer := newTestSigner(t)
	sink := NewMemSink(signer)
	seal := buildSession(t, sink, "sess-1")
	events, _, _ := sink.Export("sess-1")

	// Corrupt the signature bytes, keeping the (correct) trusted identity.
	bad := seal
	if bad.Signature[0] == 'a' {
		bad.Signature = "b" + bad.Signature[1:]
	} else {
		bad.Signature = "a" + bad.Signature[1:]
	}
	res := Verify(events, &bad, signer.Public())
	head := int64(len(events) - 1)
	if res.OK || res.BrokenSeq != head {
		t.Fatalf("bad sig: got OK=%v seq=%d, want fail at head %d", res.OK, res.BrokenSeq, head)
	}
}

// B1 REGRESSION — the forge attack the trust anchor must defeat. An attacker who
// can edit stored events edits a payload, RE-CHAINS every hash (no secret
// needed), generates their OWN keypair, re-signs the new final hash, and
// overwrites seal.{PublicKey,Signature,PubKeyFingerprint}. The seal is internally
// consistent — but it is NOT the trusted daemon identity, so Verify against the
// trusted anchor MUST fail. (Without the anchor this would return OK: the defect.)
func TestForgeResignedWithAttackerKeyFails(t *testing.T) {
	signer := newTestSigner(t)      // the legitimate daemon identity
	sink := NewMemSink(signer)      // (used only to produce a well-formed original)
	buildSession(t, sink, "sess-1") // original, honest chain
	events, _, _ := sink.Export("sess-1")

	// 1. Tamper a payload: rewrite the recorded exec.start argv.
	forged := cloneEvents(events)
	forged[1].Payload["argv"] = []string{"echo", "innocent"} // was e.g. curl evil.com

	// 2. Re-chain every hash from seq 0 (attacker needs no secret for this).
	var prev string
	for i := range forged {
		if i == 0 {
			forged[i].PrevHash = bindingFromPayload(forged[i].Payload).Root()
		} else {
			forged[i].PrevHash = prev
		}
		h, err := computeHash(forged[i])
		if err != nil {
			t.Fatal(err)
		}
		forged[i].Hash = h
		prev = h
	}

	// 3. Attacker generates their OWN key and re-signs the new final hash, then
	//    overwrites the seal's key + fingerprint to match — a self-consistent seal.
	attacker := newTestSigner(t)
	forgedSeal := &Signature{
		FinalHash:         prev,
		Signature:         hex.EncodeToString(attacker.Sign([]byte(prev))),
		PublicKey:         hex.EncodeToString(attacker.Public()),
		PubKeyFingerprint: attacker.Fingerprint(),
	}

	// Sanity: the forged seal is internally consistent (self-verifies) — this is
	// exactly why self-trusting the embedded key is fatal.
	if !ed25519.Verify(attacker.Public(), []byte(forgedSeal.FinalHash), mustHex(t, forgedSeal.Signature)) {
		t.Fatal("test setup: forged seal should self-verify")
	}

	// Against the TRUSTED daemon identity the forgery is rejected at the head.
	res := Verify(forged, forgedSeal, signer.Public())
	head := int64(len(forged) - 1)
	if res.OK || res.BrokenSeq != head {
		t.Fatalf("forge: got OK=%v seq=%d reason=%q, want fail at head %d", res.OK, res.BrokenSeq, res.Reason, head)
	}
}

// B1 — a sealed session with NO trusted anchor supplied must FAIL CLOSED: Verify
// must never self-trust the seal's embedded key.
func TestSealedWithoutAnchorFailsClosed(t *testing.T) {
	signer := newTestSigner(t)
	sink := NewMemSink(signer)
	seal := buildSession(t, sink, "sess-1")
	events, _, _ := sink.Export("sess-1")

	res := Verify(events, &seal, nil) // no trusted pub
	if res.OK {
		t.Fatal("sealed session verified with no trusted anchor — self-trust defect")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// QA: canonical serialization is stable — the same logical event hashes to the
// same value regardless of map construction order, and survives a JSON round-trip
// (so the CLI recomputing over transported events matches the daemon's hash).
func TestCanonicalSerializationStable(t *testing.T) {
	ev := Event{
		TS:        time.Unix(1700000001, 0).UTC(),
		SessionID: "sess-1",
		Seq:       2,
		Type:      TypeExecOutput,
		PrevHash:  "abcd",
	}
	// Two payloads with keys inserted in different orders must hash identically.
	ev.Payload = map[string]any{}
	ev.Payload["stream"] = "stdout"
	ev.Payload["offset"] = 0
	ev.Payload["chunk"] = "hi\n"
	h1, err := computeHash(ev)
	if err != nil {
		t.Fatal(err)
	}
	ev.Payload = map[string]any{}
	ev.Payload["chunk"] = "hi\n"
	ev.Payload["offset"] = 0
	ev.Payload["stream"] = "stdout"
	h2, err := computeHash(ev)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hash depends on map insertion order: %s != %s", h1, h2)
	}

	// JSON round-trip (as the CLI receives events) must preserve the hash: numbers
	// become float64 but re-marshal identically for our integer-valued payloads.
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var back Event
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	h3, err := computeHash(back)
	if err != nil {
		t.Fatal(err)
	}
	if h3 != h1 {
		t.Fatalf("hash changed across JSON round-trip: %s != %s", h3, h1)
	}
}

// QA: seq/prev_hash assignment is under a per-session lock — concurrent Appends
// (as stdout + stderr chunk pumps do) must still yield a contiguous, verifiable
// chain with no interleaving or lost links.
func TestConcurrentAppendChainIntegrity(t *testing.T) {
	sink := NewMemSink(newTestSigner(t))
	ctx := context.Background()
	rec := NewRecorder(sink, "sess-c", NoopRedactor{}, fixedClock())
	// seq 0 must be session.start (single-threaded), then fan out concurrent output.
	must(t, rec.Emit(ctx, TypeSessionStart, startPayload()))

	const n = 200
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			stream := "stdout"
			if i%2 == 1 {
				stream = "stderr"
			}
			_ = rec.Emit(ctx, TypeExecOutput, map[string]any{"stream": stream, "offset": i, "chunk": "x"})
		}(i)
	}
	wg.Wait()
	seal, err := rec.Seal(ctx)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	events, _, _ := sink.Export("sess-c")
	if len(events) != n+1 {
		t.Fatalf("events = %d, want %d", len(events), n+1)
	}
	res := Verify(events, &seal, sink.signer.Public())
	if !res.OK {
		t.Fatalf("concurrent chain failed verification at seq %d: %s", res.BrokenSeq, res.Reason)
	}
}

// QA: reserved types (policy.decision, cred.resolve) are known to v1 — appending
// and verifying them does not break the chain (future P4/P5 emission is safe).
func TestReservedTypesDoNotBreakV1(t *testing.T) {
	sink := NewMemSink(newTestSigner(t))
	ctx := context.Background()
	rec := NewRecorder(sink, "sess-r", NoopRedactor{}, fixedClock())
	must(t, rec.Emit(ctx, TypeSessionStart, startPayload()))
	must(t, rec.Emit(ctx, TypePolicyDecision, map[string]any{"decision": "allow"}))
	must(t, rec.Emit(ctx, TypeCredResolve, map[string]any{"ref": "aws-role"}))
	must(t, rec.Emit(ctx, TypeSessionEnd, map[string]any{"reason": "destroyed"}))
	seal, err := rec.Seal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	events, _, _ := sink.Export("sess-r")
	if res := Verify(events, &seal, sink.signer.Public()); !res.OK {
		t.Fatalf("reserved-type chain failed at seq %d: %s", res.BrokenSeq, res.Reason)
	}
}

// QA: an unsealed (still-live) session's chain verifies without a seal.
func TestVerifyUnsealed(t *testing.T) {
	sink := NewMemSink(newTestSigner(t))
	ctx := context.Background()
	rec := NewRecorder(sink, "sess-u", NoopRedactor{}, fixedClock())
	must(t, rec.Emit(ctx, TypeSessionStart, startPayload()))
	must(t, rec.Emit(ctx, TypeExecStart, map[string]any{"argv": []string{"ls"}, "cwd": ""}))
	events, seal, _ := sink.Export("sess-u")
	if seal != nil {
		t.Fatal("expected nil seal before Seal()")
	}
	if res := Verify(events, nil, nil); !res.OK {
		t.Fatalf("unsealed chain failed at seq %d: %s", res.BrokenSeq, res.Reason)
	}
}

// Seal without a signer fails legibly (the daemon wires the identity signer).
func TestSealRequiresSigner(t *testing.T) {
	sink := NewMemSink(nil)
	ctx := context.Background()
	rec := NewRecorder(sink, "sess-n", NoopRedactor{}, fixedClock())
	must(t, rec.Emit(ctx, TypeSessionStart, startPayload()))
	if _, err := rec.Seal(ctx); err == nil {
		t.Fatal("Seal with nil signer should error")
	}
}

func cloneEvents(in []Event) []Event {
	out := make([]Event, len(in))
	for i, ev := range in {
		ev.Payload = cloneMap(ev.Payload)
		out[i] = ev
	}
	return out
}

func cloneMap(m map[string]any) map[string]any {
	c := make(map[string]any, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
