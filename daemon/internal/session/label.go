package session

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// A session's ID is 32 hex characters, which is correct for a chain and useless
// in a sentence. "did 882607998d1d1e02 finish?" is not a question anybody asks
// out loud, and an operator watching three sandboxes has no way to tell which is
// which from a truncated hash.
//
// So every session also gets a LABEL: project-environment-word. The label is
// cosmetic and the ID stays authoritative — the trace, the API paths and every
// verification are keyed on the ID, and nothing looks a session up by label.
// Collisions are therefore harmless rather than something to defend against.

// labelWords are short, unambiguous, and read aloud cleanly over a call. No
// words that could describe a state (failed, broken, live), because
// "tripon-prod-broken" is a sentence somebody will misread at the wrong moment.
var labelWords = []string{
	"amber", "anchor", "arrow", "aspen", "atlas", "basil", "beacon", "birch",
	"cedar", "cobalt", "comet", "coral", "cove", "delta", "dune", "ember",
	"fable", "fern", "flint", "forge", "garnet", "glacier", "harbor", "hazel",
	"indigo", "ivory", "jade", "juniper", "kestrel", "lagoon", "lantern", "larch",
	"maple", "meadow", "mesa", "nimbus", "oak", "onyx", "opal", "orchid",
	"pebble", "pine", "quartz", "quill", "raven", "reef", "ridge", "river",
	"saffron", "sage", "slate", "solstice", "spruce", "summit", "thistle", "tide",
	"topaz", "tundra", "umber", "vale", "verdant", "willow", "zephyr", "zinc",
}

// MakeLabel builds "project-environment-word".
//
// The environment id is usually "project.env", so the project prefix is dropped
// to avoid "tripon-tripon.staging-maple". What comes out is short enough to say.
func MakeLabel(projectID, environmentID string) string {
	env := environmentID
	if i := strings.LastIndex(env, "."); i >= 0 {
		env = env[i+1:]
	}
	parts := make([]string, 0, 3)
	if projectID != "" {
		parts = append(parts, projectID)
	}
	if env != "" && env != projectID {
		parts = append(parts, env)
	}
	parts = append(parts, randomWord())
	return strings.Join(parts, "-")
}

// randomWord picks from labelWords with crypto/rand.
//
// Not because a label needs to be unguessable — it is cosmetic — but because
// math/rand without an explicit seed makes every daemon on every machine produce
// the same sequence, and "amber" being the first sandbox everywhere would look
// like a bug the first time two people compared notes.
func randomWord() string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(labelWords))))
	if err != nil {
		return labelWords[0]
	}
	return labelWords[n.Int64()]
}
