package change

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// pinVersion tags the plan-hash preimage, mirroring policy.hashVersion and the
// trace SchemaVersion discipline: a change to the canonical form is a deliberate,
// detectable version bump rather than a silent drift that would make every
// existing Change fail its pin for the wrong reason.
const pinVersion = "opslify.change.plan.v1"

// Pin computes the plan hash: the exact commands, in order, with the gate marked.
//
// WHAT IS PINNED, and why each part:
//
//   - The ARGV of every step, in order. This is the plan itself; if it can change
//     between review and apply, approval means nothing.
//   - WHICH step is gated. Moving the gate past a destructive step would let an
//     approved plan run something the human never saw behind a gate.
//
// What is NOT pinned: the intent, the preview text, the blast radius, the
// description. Those are how the plan is DESCRIBED, and re-wording a description
// must not invalidate an approval an operator already gave — while changing what
// actually runs must.
//
// Fields are length-prefixed so two different plans cannot render the same
// preimage: without it, argv ["a","bc"] and ["ab","c"] would concatenate
// identically.
func Pin(steps []Step) string {
	var buf bytes.Buffer
	buf.WriteString(pinVersion)
	buf.WriteByte('\n')
	for i, s := range steps {
		fmt.Fprintf(&buf, "%d|%d|", i, len(s.Argv))
		for _, a := range s.Argv {
			fmt.Fprintf(&buf, "%d:%s|", len(a), a)
		}
		if s.Gated {
			buf.WriteString("gated")
		}
		buf.WriteByte('\n')
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

// VerifyPin re-computes the pin over the steps about to run and compares it with
// what was approved.
//
// This is called AT APPLY, not only at preview. The window between approval and
// execution is a TOCTOU window, and the whole value of a pinned preview is that
// it is checked on the far side of it. A mismatch is refused, never repaired.
func VerifyPin(approved string, steps []Step) error {
	// Redundant with the comparison below — a real hash is never the empty string,
	// so an unpinned plan would mismatch anyway. Kept because the message is the
	// difference between "your plan changed" (alarming, and wrong here) and "this
	// was never pinned" (a configuration bug). Mutation testing confirms removing
	// BOTH is caught.
	if approved == "" {
		return fmt.Errorf("%w: this change carries no plan pin, so nothing can be verified against it", ErrPinMismatch)
	}
	actual := Pin(steps)
	if actual != approved {
		return fmt.Errorf("%w: approved %s but the plan now hashes to %s — refusing to run a plan nobody reviewed",
			ErrPinMismatch, short(approved), short(actual))
	}
	return nil
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
