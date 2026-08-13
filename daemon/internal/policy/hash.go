package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// hashVersion tags the policy_hash preimage so a future change to the canonical
// serialization is a deliberate, detectable version bump rather than a silent
// hash drift (mirrors the trace SchemaVersion discipline).
const hashVersion = "opslify.policy.v1"

// hashOf canonicalises p and returns its SHA-256 as hex. p is expected to be
// already normalised (Resolve/ResolveDefault normalise before calling); it is
// normalised again defensively so a hand-built Policy still hashes canonically.
func hashOf(p Policy) string {
	pre := canonicalPreimage(p)
	sum := sha256.Sum256(pre)
	return hex.EncodeToString(sum[:])
}

// canonicalPreimage builds the exact bytes hashed for a policy_hash: the version
// tag, a separator, then the canonical JSON of the normalised policy. encoding/
// json emits struct fields in declaration order and (were there any) map keys
// sorted, so the output is deterministic; a stability test pins it.
func canonicalPreimage(p Policy) []byte {
	n := p.normalize()
	body, err := json.Marshal(n)
	if err != nil {
		// A Policy is plain data (strings/bools/slices) — Marshal cannot fail.
		// Panic loudly rather than silently return a wrong hash.
		panic(fmt.Sprintf("policy: canonical marshal: %v", err))
	}
	var buf bytes.Buffer
	buf.WriteString(hashVersion)
	buf.WriteByte('\n')
	buf.Write(body)
	return buf.Bytes()
}

// Hash returns the deterministic policy_hash for a bare Policy — the convenience
// used by `opslify policy check` and by callers that have a model but no
// Resolved wrapper. It equals ResolveDefault(p).Hash.
func Hash(p Policy) string { return hashOf(p) }

// DefaultHash is the stable, well-known policy_hash of the empty/default policy
// (no file present). Computed once at init from Default(); a test pins its value
// so a change to the canonical form is caught.
var DefaultHash = hashOf(Default())
