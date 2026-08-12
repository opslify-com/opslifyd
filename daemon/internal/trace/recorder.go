package trace

import (
	"context"
	"time"
)

// Redactor scrubs an event payload BEFORE it is hashed and stored. It is the
// F3.3 seam: F3.1 wires the identity NoopRedactor, and F3.3 replaces it with the
// real pattern scrubber. Because Redact runs in the emit path before the sink
// computes the hash, the chain commits to the REDACTED payload — there is no
// path that hashes raw payload and redacts afterwards.
type Redactor interface {
	// Redact returns the payload to hash+store for an event of evType. It may
	// mutate and return the same map or return a new one. It must be deterministic.
	Redact(evType EventType, payload map[string]any) map[string]any
}

// NoopRedactor performs no redaction (F3.1). It is NOT permission to be sloppy
// upstream — shared-engineering §4: no secret is ever put into a payload in the
// first place; F3.3 redaction is defence-in-depth.
type NoopRedactor struct{}

func (NoopRedactor) Redact(_ EventType, payload map[string]any) map[string]any { return payload }

// Recorder is a per-session emit helper: it stamps ts + session_id, runs the
// Redactor, and Appends to the sink. The sink assigns seq/prev_hash/hash under
// its per-session lock. A nil *Recorder is a valid no-op, so tracing can be left
// unwired (Emit/Seal simply do nothing) without sprinkling nil checks at call
// sites.
type Recorder struct {
	sink      TraceSink
	redactor  Redactor
	now       func() time.Time
	sessionID string
}

// NewRecorder builds a per-session recorder. redactor nil => NoopRedactor;
// now nil => time.Now.
func NewRecorder(sink TraceSink, sessionID string, redactor Redactor, now func() time.Time) *Recorder {
	if redactor == nil {
		redactor = NoopRedactor{}
	}
	if now == nil {
		now = time.Now
	}
	return &Recorder{sink: sink, redactor: redactor, now: now, sessionID: sessionID}
}

// Emit redacts payload then appends an event of evType. On a nil recorder it is a
// no-op.
func (r *Recorder) Emit(ctx context.Context, evType EventType, payload map[string]any) error {
	if r == nil {
		return nil
	}
	redacted := r.redactor.Redact(evType, payload)
	return r.sink.Append(ctx, Event{
		TS:        r.now(),
		SessionID: r.sessionID,
		Type:      evType,
		Payload:   redacted,
	})
}

// Seal seals the session's chain. On a nil recorder it is a no-op returning a
// zero Signature.
func (r *Recorder) Seal(ctx context.Context) (Signature, error) {
	if r == nil {
		return Signature{}, nil
	}
	return r.sink.Seal(ctx, r.sessionID)
}
