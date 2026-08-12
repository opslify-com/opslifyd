package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/trace"
)

// buildSealedTrace produces a small sealed chain via a real MemSink and returns
// its events + seal (what the daemon's /trace endpoint serves) plus the signing
// identity's public key (the out-of-band anchor the CLI must be given).
func buildSealedTrace(t *testing.T) ([]trace.Event, *trace.Signature, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sink := trace.NewMemSink(trace.NewEd25519Signer(priv))
	rec := trace.NewRecorder(sink, "sess-1", trace.NoopRedactor{}, nil)
	ctx := context.Background()
	_ = rec.Emit(ctx, trace.TypeSessionStart, map[string]any{
		"image_digest": "base@sha256:deadbeef", "toolchain_lock_hash": "tool@sha256:cafe", "policy_hash": "",
	})
	_ = rec.Emit(ctx, trace.TypeExecStart, map[string]any{"argv": []string{"echo"}, "cwd": ""})
	_ = rec.Emit(ctx, trace.TypeSessionEnd, map[string]any{"reason": "destroyed"})
	if _, err := rec.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	events, s, _ := sink.Export("sess-1")
	return events, s, pub
}

// writePubFile writes an Ed25519 public key as PKIX/PEM (the format
// install.LoadPublicKey reads) and returns its path.
func writePubFile(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.key.pub")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// traceMux serves a fixed trace body at GET /v1/sessions/{id}/trace.
func traceMux(events []trace.Event, seal *trace.Signature) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions/{id}/trace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Events []trace.Event    `json:"events"`
			Seal   *trace.Signature `json:"seal"`
		}{events, seal})
	})
	return mux
}

// AC: `opslify verify` passes (exit 0) on an untampered, sealed session when the
// trusted daemon public key is supplied out-of-band.
func TestVerifyCLIClean(t *testing.T) {
	events, seal, pub := buildSealedTrace(t)
	fd := newFakeDaemon(t, traceMux(events, seal))
	pubPath := writePubFile(t, pub)

	out, _, err := execRoot(t, "verify", "sess-1", "--socket", fd.socketPath, "--pubkey", pubPath)
	if err != nil {
		t.Fatalf("verify clean: unexpected error %v", err)
	}
	if !strings.Contains(out, "OK:") || !strings.Contains(out, "signature valid against trusted identity") {
		t.Fatalf("verify clean stdout = %q", out)
	}
}

// AC: editing an event makes `opslify verify` fail — non-zero exit, first broken
// seq named on stderr.
func TestVerifyCLITamperExitsNonZero(t *testing.T) {
	events, seal, pub := buildSealedTrace(t)
	events[1].Payload["argv"] = []string{"rm", "-rf", "/"} // tamper seq 1
	fd := newFakeDaemon(t, traceMux(events, seal))
	pubPath := writePubFile(t, pub)

	_, errOut, err := execRoot(t, "verify", "sess-1", "--socket", fd.socketPath, "--pubkey", pubPath)
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code == 0 {
		t.Fatalf("tamper: want non-zero exitCodeError, got %v", err)
	}
	if !strings.Contains(errOut, "TAMPER") || !strings.Contains(errOut, "seq 1") {
		t.Fatalf("tamper stderr = %q, want first broken seq 1", errOut)
	}
}

// B1 REGRESSION (CLI): the forge attack. An attacker rewrites a payload, re-chains
// every hash, generates their OWN key, re-signs, and overwrites the seal's
// key+signature+fingerprint. Against the trusted daemon pubkey, `opslify verify`
// must exit non-zero — the seal self-verifies but is NOT the trusted identity.
func TestVerifyCLIForgedSealFails(t *testing.T) {
	events, _, pub := buildSealedTrace(t)

	// Tamper a payload, then present a fully self-consistent forgery: re-chain every
	// hash over the tampered payloads and re-seal with an ATTACKER key (no daemon
	// secret needed). The forged seal verifies against its own embedded key — the
	// exact case the trusted anchor must reject.
	events[1].Payload["argv"] = []string{"echo", "innocent"}
	attacker := trace.NewEd25519Signer(mustGenKey(t))
	forgedEvents, forgedSeal := rechainAndResign(t, events, attacker)

	fd := newFakeDaemon(t, traceMux(forgedEvents, forgedSeal))
	pubPath := writePubFile(t, pub) // the TRUSTED daemon identity

	_, errOut, err := execRoot(t, "verify", "sess-1", "--socket", fd.socketPath, "--pubkey", pubPath)
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code == 0 {
		t.Fatalf("forge: want non-zero exit, got %v (stderr=%q)", err, errOut)
	}
	if !strings.Contains(errOut, "TAMPER") || !strings.Contains(errOut, "trusted daemon identity") {
		t.Fatalf("forge stderr = %q, want a trusted-identity mismatch", errOut)
	}
}

// B1 (CLI): a sealed session with NO resolvable trusted key must fail closed —
// verify must NOT self-trust the seal's embedded key.
func TestVerifyCLINoAnchorFailsClosed(t *testing.T) {
	events, seal, _ := buildSealedTrace(t)
	fd := newFakeDaemon(t, traceMux(events, seal))

	// Point --pubkey at a nonexistent file so no trusted key resolves.
	missing := filepath.Join(t.TempDir(), "nope.pub")
	_, errOut, err := execRoot(t, "verify", "sess-1", "--socket", fd.socketPath, "--pubkey", missing)
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code == 0 {
		t.Fatalf("no-anchor: want non-zero exit, got %v", err)
	}
	if !strings.Contains(errOut, "cannot verify") {
		t.Fatalf("no-anchor stderr = %q, want a fail-closed message", errOut)
	}
}

// AC: --fingerprint pins the trusted identity without a key file; a clean session
// whose seal fingerprint matches verifies.
func TestVerifyCLIFingerprintPin(t *testing.T) {
	events, seal, pub := buildSealedTrace(t)
	fd := newFakeDaemon(t, traceMux(events, seal))
	fp := hex.EncodeToString(pub)[:16]

	out, _, err := execRoot(t, "verify", "sess-1", "--socket", fd.socketPath, "--fingerprint", fp)
	if err != nil {
		t.Fatalf("fingerprint pin clean: unexpected error %v", err)
	}
	if !strings.Contains(out, "OK:") {
		t.Fatalf("fingerprint pin stdout = %q", out)
	}

	// A WRONG fingerprint must fail closed even though the seal self-verifies.
	_, errOut, err := execRoot(t, "verify", "sess-1", "--socket", fd.socketPath, "--fingerprint", "00000000deadbeef")
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code == 0 {
		t.Fatalf("wrong fingerprint: want non-zero exit, got %v (stderr=%q)", err, errOut)
	}
}

func mustGenKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// rechainAndResign rebuilds a valid hash chain over the (tampered) payloads via a
// MemSink, then seals it with signer — producing a self-consistent forgery whose
// only flaw is that signer is not the trusted daemon identity.
func rechainAndResign(t *testing.T, tampered []trace.Event, signer trace.Signer) ([]trace.Event, *trace.Signature) {
	t.Helper()
	sink := trace.NewMemSink(signer)
	rec := trace.NewRecorder(sink, "sess-1", trace.NoopRedactor{}, nil)
	ctx := context.Background()
	for _, ev := range tampered {
		if err := rec.Emit(ctx, ev.Type, ev.Payload); err != nil {
			t.Fatal(err)
		}
	}
	seal, err := rec.Seal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	events, s, _ := sink.Export("sess-1")
	_ = seal
	return events, s
}
