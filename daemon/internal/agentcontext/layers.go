// Package agentcontext assembles the layered instruction set an agent runs
// under: house rules held by the daemon, project and environment instructions
// from the repo, per-tool skill packs, and generated tool contracts.
//
// The package is named agentcontext rather than context (as the F8.4 spec wrote
// it) so that callers can keep using the standard library's context.Context
// without an import alias at every site. The daemon threads context.Context
// through nearly every function, and a package that shadowed it would make each
// of those files import one of the two under an alias — a naming trap with no
// upside.
//
// It is PURE: no model calls, no network, no mutation of anything it reads. That
// is what makes the assembly hash reproducible, which is the whole point — a
// Change records the hash of the instructions it ran under, so "why did it do
// that?" is answerable against the rules the agent actually had.
package agentcontext

import (
	"errors"
	"fmt"
)

// ErrInvalidInput is a caller/config error: a bad environment name, a path that
// escapes the workspace, an unsafe house-rules file. Callers map it to a 400 and
// must NOT fall back to a partial assembly — a session that runs with the house
// rules silently missing is worse than a session that refuses to start.
var ErrInvalidInput = errors.New("agentcontext: invalid input")

// ErrUnsafeSource marks a source that was refused for a security reason rather
// than a formatting one: a world-writable house-rules file, a symlink out of the
// workspace, an oversized file. It is separate from ErrInvalidInput so the
// refusal reason survives into the operator-facing message.
var ErrUnsafeSource = errors.New("agentcontext: unsafe source")

// LayerKind identifies a layer's role. The ORDER of these constants is the
// documented precedence order: earlier layers are authoritative, later ones may
// add detail but have no mechanism to remove or rewrite what came before.
type LayerKind string

const (
	// LayerHouseRules is the operator's non-negotiable behaviour, held by the
	// DAEMON and never sourced from the repo. This is the layer that makes the
	// whole scheme worth having: an agent with commit access can rewrite layers
	// 2-4, but it cannot edit the rule that says stop before touching db-01.
	LayerHouseRules LayerKind = "house_rules"
	// LayerProjectInstructions is repo-wide behaviour, reviewed in an MR.
	LayerProjectInstructions LayerKind = "project_instructions"
	// LayerEnvOverlay narrows behaviour for one environment (prod narrows staging).
	LayerEnvOverlay LayerKind = "env_overlay"
	// LayerSkill is knowledge about this estate for one tool.
	LayerSkill LayerKind = "skill"
	// LayerToolContract is generated from the tools and the resolved policy. It is
	// not hand-edited, so it always describes what the session can ACTUALLY do.
	LayerToolContract LayerKind = "tool_contract"
)

// precedence gives each kind its rank in the assembly order.
var precedence = map[LayerKind]int{
	LayerHouseRules:          1,
	LayerProjectInstructions: 2,
	LayerEnvOverlay:          3,
	LayerSkill:               4,
	LayerToolContract:        5,
}

// Rank returns a kind's precedence, and false for an unknown kind. An unknown
// kind is never given a default rank: silently sorting it somewhere plausible is
// how a new layer ends up able to precede the house rules.
func (k LayerKind) Rank() (int, bool) {
	r, ok := precedence[k]
	return r, ok
}

// Layer is one assembled layer with its provenance.
//
// Name is a LOGICAL, machine-independent identity ("house-rules",
// "instructions", "env/prod", "skills/kubernetes") — never an absolute host
// path. Absolute paths differ between the daemon host and a reviewer's machine,
// and putting one in the hash would make the same instructions hash differently
// in two places, defeating replay.
type Layer struct {
	Kind LayerKind `json:"kind"`
	Name string    `json:"name"`
	// Content is the layer's text. It is deliberately NOT serialized into the
	// trace: only names, hashes and sizes are (F8.4 AC). Instruction content can
	// carry estate detail an operator did not agree to persist in an audit log.
	Content string `json:"-"`
	// Hash is the SHA-256 of Content, hex. Present in the trace; the content is not.
	Hash   string `json:"hash"`
	Bytes  int    `json:"bytes"`
	Tokens int    `json:"tokens"`
}

// maxLayerBytes bounds one source file. A file beyond this is refused, not
// truncated: silently cutting an instruction file mid-sentence can invert its
// meaning ("never restart db-01 unless" …).
const maxLayerBytes = 1 << 20 // 1 MiB

// maxTotalBytes bounds the whole assembly for the same reason, one level up.
const maxTotalBytes = 4 << 20 // 4 MiB

// tooBig renders the refusal for an oversized source.
func tooBig(name string, n, limit int) error {
	return fmt.Errorf("%w: %s is %d bytes, over the %d-byte limit; split it rather than letting it be cut mid-sentence",
		ErrUnsafeSource, name, n, limit)
}
