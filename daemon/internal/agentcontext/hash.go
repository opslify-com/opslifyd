package agentcontext

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// hashVersion tags the assembly-hash preimage, mirroring policy.hashVersion and
// the trace SchemaVersion discipline: a future change to the canonical form is a
// deliberate, detectable version bump rather than a silent hash drift that would
// make old Changes un-replayable without anyone noticing.
const hashVersion = "opslify.context.v1"

// newLayer builds a Layer with its content hash and accounting filled in.
func newLayer(kind LayerKind, name, content string) *Layer {
	return &Layer{
		Kind:    kind,
		Name:    name,
		Content: content,
		Hash:    hashContent(content),
		Bytes:   len(content),
		Tokens:  EstimateTokens(content),
	}
}

// hashContent is the SHA-256 of one layer's bytes, hex.
func hashContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// assemblyHash is the deterministic identity of an ordered layer set.
//
// The preimage is built from each layer's KIND, logical NAME and content hash —
// never an absolute host path, and never a byte offset. That is what lets the
// daemon host and a reviewer's laptop derive the same hash for the same
// instructions, which is the property a Change replay depends on.
//
// Length-prefixing every field keeps the preimage unambiguous: without it, a
// layer named "a" with content hash "bc" and one named "ab" with hash "c" could
// concatenate to the same bytes, and two different instruction sets would share
// a hash.
func assemblyHash(layers []Layer) string {
	var buf bytes.Buffer
	buf.WriteString(hashVersion)
	buf.WriteByte('\n')
	for _, l := range layers {
		fmt.Fprintf(&buf, "%d:%s|%d:%s|%d:%s\n",
			len(l.Kind), l.Kind, len(l.Name), l.Name, len(l.Hash), l.Hash)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}
