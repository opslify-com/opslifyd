package trace

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// TraceSink is the seam every event is emitted to. F3.1 ships MemSink (in-memory
// chain + seal, no I/O); F3.2 implements the same interface for real (ring buffer
// + append-only file). The sink OWNS seq/prev_hash/hash assignment under a
// per-session lock, so concurrent emits (e.g. stdout + stderr chunks) can never
// interleave the chain.
//
// Redaction (F3.3) sits BEFORE the sink, in the emit path (see Recorder), so the
// payload the sink hashes is already redacted — the chain commits to the redacted
// bytes and there is no direct-to-sink bypass of redaction.
type TraceSink interface {
	// Append assigns seq/prev_hash/hash to ev (using ev.TS, ev.SessionID,
	// ev.Type, ev.Payload as the content) and records it. Seq 0's prev_hash is
	// derived from the session-binding fields in the (session.start) payload.
	Append(ctx context.Context, ev Event) error
	// Seal signs the session's final chain hash with the daemon identity and
	// records {final_hash, signature, pubkey_fingerprint, public_key}. Idempotent:
	// a second Seal returns the recorded signature.
	Seal(ctx context.Context, sessionID string) (Signature, error)
}

// Exporter is the read side used by `opslify verify`: it returns a session's
// events (in chain order) and its seal (nil if not yet sealed). MemSink retains
// sealed sessions in memory until daemon restart; F3.2 will serve them from the
// append-only log so verify survives a restart.
type Exporter interface {
	Export(sessionID string) (events []Event, seal *Signature, ok bool)
}

// Streamer is the live-tail seam the local SSE endpoint (F3.2) drives. Subscribe
// returns the on-disk backfill (events with seq >= fromSeq known at call time), a
// channel delivering every subsequently-appended event, and a cancel func the
// consumer MUST call to release the subscription. Registration and snapshot happen
// under the per-session lock, so no event between the backfill and the first live
// delivery is lost or duplicated. MemSink does not implement this (no durable log);
// FileSink does.
type Streamer interface {
	Subscribe(sessionID string, fromSeq uint64) (backfill []Event, live <-chan Event, cancel func(), err error)
}

// Signature is the recorded seal of a session's chain: the final hash, the
// Ed25519 signature over it, and the signer's public key + fingerprint. The
// public key is recorded so verification is fully offline. It contains NO private
// key material.
type Signature struct {
	FinalHash         string    `json:"final_hash"`
	Signature         string    `json:"signature"`          // hex Ed25519 signature over FinalHash
	PubKeyFingerprint string    `json:"pubkey_fingerprint"` // short id of the daemon identity
	PublicKey         string    `json:"public_key"`         // hex Ed25519 public key
	SealedAt          time.Time `json:"sealed_at"`
}

// Signer signs a session's final hash with the daemon identity (F1.1). The
// private key never leaves the process and never enters an event; only the
// signature, public key, and fingerprint are recorded.
type Signer interface {
	Sign(msg []byte) []byte
	Public() ed25519.PublicKey
	Fingerprint() string
}

// Ed25519Signer adapts a daemon Ed25519 private key to Signer.
type Ed25519Signer struct {
	priv ed25519.PrivateKey
	fp   string
}

// NewEd25519Signer builds a Signer from a daemon private key. The fingerprint is
// the first 16 hex chars of the public key — the same derivation as
// install.Identity.Fingerprint, so a seal is attributable to the daemon identity.
func NewEd25519Signer(priv ed25519.PrivateKey) *Ed25519Signer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Ed25519Signer{priv: priv, fp: hex.EncodeToString(pub)[:16]}
}

func (s *Ed25519Signer) Sign(msg []byte) []byte    { return ed25519.Sign(s.priv, msg) }
func (s *Ed25519Signer) Public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }
func (s *Ed25519Signer) Fingerprint() string       { return s.fp }

// chainState is the SHARED chain core: the running position (next seq + last
// hash) of a single session's SHA-256 hash chain. Both MemSink (F3.1) and FileSink
// (F3.2) drive their chain through assign/sealHash so the two sinks compute
// IDENTICAL seq/prev_hash/hash/seal for the same event sequence — there is exactly
// one implementation of the chain rule, never a fork. chainState is NOT
// goroutine-safe on its own; the owning sink serializes it under a per-session lock.
type chainState struct {
	seq  uint64
	last string // hash of the most recent event
}

// assign stamps seq/prev_hash/hash onto ev and advances the chain. Seq 0's
// prev_hash is the binding root derived from the (session.start) payload; every
// later event chains to its predecessor's hash. This is the ONE place the chain
// rule lives.
func (c *chainState) assign(ev *Event) error {
	ev.Seq = c.seq
	if c.seq == 0 {
		ev.PrevHash = bindingFromPayload(ev.Payload).Root()
	} else {
		ev.PrevHash = c.last
	}
	h, err := computeHash(*ev)
	if err != nil {
		return err
	}
	ev.Hash = h
	c.last = h
	c.seq++
	return nil
}

// sealHash signs finalHash with signer, producing the recorded Signature. It is
// shared so MemSink and FileSink seal identically. signer must be non-nil.
func sealHash(signer Signer, now func() time.Time, finalHash string) (Signature, error) {
	if signer == nil {
		return Signature{}, errors.New("trace: no signer configured; cannot seal")
	}
	sig := signer.Sign([]byte(finalHash))
	return Signature{
		FinalHash:         finalHash,
		Signature:         hex.EncodeToString(sig),
		PubKeyFingerprint: signer.Fingerprint(),
		PublicKey:         hex.EncodeToString(signer.Public()),
		SealedAt:          now(),
	}, nil
}

// MemSink is the in-memory TraceSink: it assembles each session's hash chain
// under a per-session lock and seals with the injected Signer. It retains events
// (and the seal) for the daemon's lifetime so `opslify verify` can read them
// before F3.2's durable transport exists.
type MemSink struct {
	signer Signer
	now    func() time.Time

	mu     sync.Mutex // guards the chains map
	chains map[string]*chain
}

// chain is one session's chain state. Its own mutex serializes seq/prev_hash/hash
// assignment so concurrent Appends (stdout + stderr chunks, or an exec racing a
// file.write) can never interleave the chain. It embeds the shared chainState so
// the assignment rule is not duplicated.
type chain struct {
	mu     sync.Mutex
	state  chainState
	events []Event
	seal   *Signature
}

// NewMemSink builds an in-memory sink. signer may be nil (events are still
// recorded, but Seal fails legibly) — the daemon wires the F1.1 identity signer.
func NewMemSink(signer Signer) *MemSink {
	return &MemSink{signer: signer, now: time.Now, chains: map[string]*chain{}}
}

func (s *MemSink) chainFor(id string) *chain {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.chains[id]
	if c == nil {
		c = &chain{}
		s.chains[id] = c
	}
	return c
}

// Append assigns seq/prev_hash/hash under the per-session lock and records the
// event. Seq 0's prev_hash is the binding root derived from the payload, so the
// chain root commits to the environment.
func (s *MemSink) Append(_ context.Context, ev Event) error {
	c := s.chainFor(ev.SessionID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seal != nil {
		return fmt.Errorf("trace: session %s already sealed; refusing append", ev.SessionID)
	}
	if err := c.state.assign(&ev); err != nil {
		return err
	}
	c.events = append(c.events, ev)
	return nil
}

// Seal signs the session's final hash with the daemon identity. Idempotent.
func (s *MemSink) Seal(_ context.Context, sessionID string) (Signature, error) {
	c := s.chainFor(sessionID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seal != nil {
		return *c.seal, nil
	}
	if len(c.events) == 0 {
		return Signature{}, fmt.Errorf("trace: no events for session %s", sessionID)
	}
	sg, err := sealHash(s.signer, s.now, c.state.last)
	if err != nil {
		return Signature{}, err
	}
	c.seal = &sg
	return sg, nil
}

// Export returns a copy of the session's events (in chain order) and its seal.
func (s *MemSink) Export(sessionID string) ([]Event, *Signature, bool) {
	c := s.chainFor(sessionID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return nil, nil, false
	}
	out := make([]Event, len(c.events))
	copy(out, c.events)
	var seal *Signature
	if c.seal != nil {
		cp := *c.seal
		seal = &cp
	}
	return out, seal, true
}

var _ TraceSink = (*MemSink)(nil)
var _ Exporter = (*MemSink)(nil)
