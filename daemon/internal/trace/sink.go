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
// file.write) can never interleave the chain.
type chain struct {
	mu     sync.Mutex
	seq    uint64
	last   string // hash of the most recent event
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
	ev.Seq = c.seq
	if c.seq == 0 {
		ev.PrevHash = bindingFromPayload(ev.Payload).Root()
	} else {
		ev.PrevHash = c.last
	}
	h, err := computeHash(ev)
	if err != nil {
		return err
	}
	ev.Hash = h
	c.events = append(c.events, ev)
	c.last = h
	c.seq++
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
	if s.signer == nil {
		return Signature{}, errors.New("trace: no signer configured; cannot seal")
	}
	final := c.last
	sig := s.signer.Sign([]byte(final))
	sg := Signature{
		FinalHash:         final,
		Signature:         hex.EncodeToString(sig),
		PubKeyFingerprint: s.signer.Fingerprint(),
		PublicKey:         hex.EncodeToString(s.signer.Public()),
		SealedAt:          s.now(),
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
