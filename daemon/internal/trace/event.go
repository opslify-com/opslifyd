// Package trace implements F3.1 — the per-session, tamper-evident event stream.
//
// Every session action (lifecycle, exec, file write) is recorded as an Event in
// a per-session SHA-256 hash chain, sealed with the daemon's Ed25519 identity at
// session close. The chain proves INTEGRITY + ORDERING (not confidentiality): it
// is the evidence that a session's recorded history was not altered after the
// fact. `opslify verify <session>` recomputes the chain and checks the seal.
//
// This package is pure logic — no I/O, no podman, no socket — so the whole
// chain/sign/verify core is unit-testable against a test identity. Persistence
// (F3.2) implements TraceSink for real; redaction (F3.3) sits in the emit path
// via the Redactor seam BEFORE hashing, so the chain commits to the redacted
// payload.
package trace

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// SchemaVersion is the trace event schema version (shared-engineering §9: the
// trace schema carries a version). It is recorded in the session.start payload,
// so the chain root commits to the schema the events were produced under.
const SchemaVersion = 1

// EventType is the discriminator for an event's payload shape.
type EventType string

const (
	// TypeSessionStart is the first event of every session (seq 0). Its payload
	// carries the session-binding fields (image_digest, toolchain_lock_hash,
	// policy_hash) the chain root commits to, plus tier/mode/agent/schema_version.
	TypeSessionStart EventType = "session.start"
	// TypeSessionEnd is the terminal event before sealing. Payload: {reason}.
	TypeSessionEnd EventType = "session.end"
	// TypeExecStart records a mediated exec beginning. Payload: {argv, cwd}.
	TypeExecStart EventType = "exec.start"
	// TypeExecOutput records one bounded output chunk. Payload:
	// {stream, offset, chunk} or {stream, truncated:true} at the cap marker.
	TypeExecOutput EventType = "exec.output"
	// TypeExecEnd records a mediated exec finishing. Payload:
	// {exit_code, duration_ms}.
	TypeExecEnd EventType = "exec.end"
	// TypeFileWrite records a mediated file write into /workspace. Payload:
	// {path, size}.
	TypeFileWrite EventType = "file.write"

	// TypePolicyDecision is RESERVED for P4 (F-policy). Known to v1 consumers but
	// never emitted in P3, so a future daemon can add it without a schema bump.
	// F4.2 emits it at classify time (allow/deny/needs_approval); F4.3 emits it
	// again on an approval resolution (approved/denied, with the approver comment).
	TypePolicyDecision EventType = "policy.decision"
	// TypeApprovalRequested marks a command paused on a human approval gate (F4.3).
	// Payload: {exec_id, argv_summary, rule, reason}. It is pushed over the F3.2 SSE
	// stream so the local UI (F3.5) renders a live approval prompt. Like
	// policy.decision it was a reserved, known-to-v1 type so adding it needs no
	// schema bump.
	TypeApprovalRequested EventType = "approval.requested"
	// TypeCredResolve is RESERVED for P5 (broker). Known-but-unemitted in P3.
	TypeCredResolve EventType = "cred.resolve"
	// TypeEgressAnomaly is RESERVED for P5 (F5.2 L7 egress proxy). The proxy emits
	// it when an outbound sandbox body trips a bound — an upload byte cap or a
	// high-entropy score (an exfil signal). Payload:
	// {host, method, path, reason, bytes, entropy, capped} — DELIBERATELY carries
	// NO body content and NO injected credential, only the non-secret signal.
	// Like the other reserved P4/P5 types it is known-but-unemitted before P5, so a
	// future daemon adds it without a schema bump.
	TypeEgressAnomaly EventType = "egress.anomaly"
	// TypePkgInstall is RESERVED for P5 (F5.5 registry proxy). The daemon-side
	// caching registry proxy emits it once per fetched/installed package with the
	// supply-chain evidence: {ecosystem, name, version, sha256, registry, attested}
	// — the sha256 is over the REAL fetched artifact bytes (the same bytes served to
	// the client, so its own checksum/signature verification is unaffected). It
	// DELIBERATELY carries NO registry credential and NO artifact body, only the
	// non-secret supply-chain descriptors. Like the other reserved P4/P5 types it is
	// known-but-unemitted before P5, so a future daemon adds it without a schema bump.
	TypePkgInstall EventType = "pkg.install"
)

// Event is one link in a session's hash chain. The shape is fixed
// {ts, session_id, seq, type, payload, prev_hash, hash}: seq is a per-session
// monotonic counter from 0; hash = SHA256(canonical(ts,session_id,seq,type,
// payload) || prev_hash); prev_hash of seq 0 is the session-binding root digest.
type Event struct {
	TS        time.Time      `json:"ts"`
	SessionID string         `json:"session_id"`
	Seq       uint64         `json:"seq"`
	Type      EventType      `json:"type"`
	Payload   map[string]any `json:"payload"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
}

// Binding is the environment a session is bound to. Its Root digest is the
// prev_hash of seq 0, so the chain root commits to the image + toolchain (+ the
// policy_hash slot, populated in P4). The fields also live in the session.start
// payload, so a tamper of either the binding fields or the derived root breaks
// seq 0's hash — the binding is effectively committed.
type Binding struct {
	ImageDigest       string `json:"image_digest"`
	ToolchainLockHash string `json:"toolchain_lock_hash"`
	PolicyHash        string `json:"policy_hash"` // empty until P4
}

// Root is the seq-0 prev_hash: a stable SHA-256 over the binding fields.
func (b Binding) Root() string {
	// Fixed-order canonical object (never map iteration order).
	j, _ := json.Marshal(b)
	sum := sha256.Sum256(j)
	return hex.EncodeToString(sum[:])
}

// bindingFromPayload extracts the binding fields from a session.start payload so
// Verify can recompute the seq-0 root from the event alone (self-contained).
func bindingFromPayload(p map[string]any) Binding {
	return Binding{
		ImageDigest:       payloadString(p, "image_digest"),
		ToolchainLockHash: payloadString(p, "toolchain_lock_hash"),
		PolicyHash:        payloadString(p, "policy_hash"),
	}
}

func payloadString(p map[string]any, k string) string {
	if p == nil {
		return ""
	}
	if v, ok := p[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// canonicalPreimage produces the deterministic bytes hashed for an event. Field
// order is FIXED here (ts, session_id, seq, type, payload) — it never depends on
// Go map iteration order. The payload object's keys are string-only and are
// serialized by encoding/json, which sorts map keys deterministically (a
// documented, version-stable guarantee); a stability test pins this.
func canonicalPreimage(e Event) ([]byte, error) {
	payloadJSON, err := json.Marshal(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("trace: marshal payload: %w", err)
	}
	tsJSON, err := json.Marshal(e.TS.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("trace: marshal ts: %w", err)
	}
	sidJSON, err := json.Marshal(e.SessionID)
	if err != nil {
		return nil, fmt.Errorf("trace: marshal session_id: %w", err)
	}
	typeJSON, err := json.Marshal(string(e.Type))
	if err != nil {
		return nil, fmt.Errorf("trace: marshal type: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString(`{"ts":`)
	buf.Write(tsJSON)
	buf.WriteString(`,"session_id":`)
	buf.Write(sidJSON)
	buf.WriteString(`,"seq":`)
	buf.WriteString(strconv.FormatUint(e.Seq, 10))
	buf.WriteString(`,"type":`)
	buf.Write(typeJSON)
	buf.WriteString(`,"payload":`)
	buf.Write(payloadJSON)
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// computeHash is hash = SHA256(canonicalPreimage(e) || prev_hash). prev_hash is
// the hex string of the previous link (or the binding Root for seq 0).
func computeHash(e Event) (string, error) {
	pre, err := canonicalPreimage(e)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(pre)
	h.Write([]byte(e.PrevHash))
	return hex.EncodeToString(h.Sum(nil)), nil
}
