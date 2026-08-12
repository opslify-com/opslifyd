package trace

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// VerifyResult is the outcome of recomputing a session's chain + checking its
// seal. On failure BrokenSeq names the first offending event (or the chain head
// for a seal failure) and Reason is a legible, layer-specific explanation.
type VerifyResult struct {
	OK        bool   `json:"ok"`
	BrokenSeq int64  `json:"broken_seq"` // -1 when OK
	Reason    string `json:"reason,omitempty"`
	Events    int    `json:"events"`
}

func broken(seq int64, format string, args ...any) VerifyResult {
	return VerifyResult{OK: false, BrokenSeq: seq, Reason: fmt.Sprintf(format, args...)}
}

// Verify recomputes a session's hash chain and verifies its seal AGAINST A
// TRUSTED daemon identity supplied out-of-band. It catches:
//   - a reordered event (seq no longer matches position),
//   - a dropped event (a gap in the contiguous seq run),
//   - an edited payload/field (recomputed hash no longer matches),
//   - a broken prev_hash link,
//   - a seal whose final_hash ≠ the chain head, or a bad signature,
//   - a seal signed by a key that is NOT the trusted daemon identity.
//
// CRITICAL trust model: the seal carries its own public key for offline
// convenience, but that embedded key is NEVER self-trusted. An attacker who can
// edit stored events can recompute the whole chain and re-sign it with a key they
// generated; the ONLY thing that defeats that is pinning the signature to a
// public key obtained out-of-band. trustedPub is that anchor: when seal is
// non-nil, trustedPub MUST be a valid Ed25519 public key equal to the seal's
// embedded key, or verification FAILS. A caller that cannot resolve a trusted key
// must pass nil AND treat a sealed session as unverifiable (it will fail here) —
// never fall back to the seal's own key.
//
// events must be in chain order (as Export returns them). seal may be nil (an
// unsealed, still-live session): the chain is still checked structurally, only
// the signature step is skipped.
func Verify(events []Event, seal *Signature, trustedPub ed25519.PublicKey) VerifyResult {
	if len(events) == 0 {
		return broken(0, "no events: nothing to verify")
	}
	var prev string
	for i, ev := range events {
		seq := int64(i)
		// Ordering + completeness: seq must be contiguous from 0. A reorder or a
		// dropped event surfaces here as a seq that no longer matches its position.
		if ev.Seq != uint64(i) {
			return broken(seq, "seq out of order or event dropped: event at position %d has seq %d", i, ev.Seq)
		}
		// prev_hash link: seq 0 must equal the binding root derived from its own
		// (session.start) payload; every later event must chain to its predecessor.
		var expectedPrev string
		if i == 0 {
			expectedPrev = bindingFromPayload(ev.Payload).Root()
		} else {
			expectedPrev = prev
		}
		if ev.PrevHash != expectedPrev {
			return broken(seq, "prev_hash link broken at seq %d (event reordered, dropped, or root binding tampered)", ev.Seq)
		}
		// Integrity: the recorded hash must recompute from the event's own fields.
		got, err := computeHash(ev)
		if err != nil {
			return broken(seq, "cannot recompute hash at seq %d: %v", ev.Seq, err)
		}
		if got != ev.Hash {
			return broken(seq, "hash mismatch at seq %d (payload or a field was edited)", ev.Seq)
		}
		prev = ev.Hash
	}

	head := int64(len(events) - 1)
	if seal != nil {
		if seal.FinalHash != prev {
			return broken(head, "seal final_hash does not match the chain head (events added, removed, or reordered)")
		}
		pub, err := hex.DecodeString(seal.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return broken(head, "seal public key is malformed")
		}
		// Trust anchor: the seal's key must equal the trusted daemon identity
		// obtained out-of-band. Refusing a missing anchor is what makes the log
		// tamper-EVIDENT: without it, a re-signed forgery would verify against its
		// own attacker key.
		if len(trustedPub) != ed25519.PublicKeySize {
			return broken(head, "no trusted daemon identity provided; refusing to self-trust the seal's embedded key (supply the daemon public key out-of-band)")
		}
		if !bytes.Equal(pub, trustedPub) {
			return broken(head, "seal not signed by the trusted daemon identity (embedded key does not match the trusted anchor)")
		}
		// Fingerprint must also match the anchor (defence in depth; the fingerprint
		// is display-facing and must never disagree with the pinned key).
		if seal.PubKeyFingerprint != hex.EncodeToString(trustedPub)[:16] {
			return broken(head, "seal fingerprint does not match the trusted daemon identity")
		}
		sig, err := hex.DecodeString(seal.Signature)
		if err != nil {
			return broken(head, "seal signature is malformed")
		}
		if !ed25519.Verify(trustedPub, []byte(seal.FinalHash), sig) {
			return broken(head, "signature verification failed (final hash not signed by the trusted daemon identity)")
		}
	}

	return VerifyResult{OK: true, BrokenSeq: -1, Events: len(events)}
}
