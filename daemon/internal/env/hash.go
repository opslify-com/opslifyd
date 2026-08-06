package env

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// digestSHA256 returns the canonical "sha256:<hex>" digest of b.
func digestSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// normalizeSelection returns a deterministic, canonical copy of sel: tool names
// and versions trimmed, tools sorted, exact duplicates removed. Two selections
// that differ only in ordering or whitespace normalise identically, which is
// what makes "same selection -> same digest" hold.
func normalizeSelection(sel ToolSelection) ToolSelection {
	out := ToolSelection{BaseImageDigest: strings.TrimSpace(sel.BaseImageDigest)}
	seen := make(map[Tool]struct{}, len(sel.Tools))
	for _, t := range sel.Tools {
		t = Tool{Name: strings.TrimSpace(t.Name), Version: strings.TrimSpace(t.Version)}
		if t.Name == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out.Tools = append(out.Tools, t)
	}
	sort.Slice(out.Tools, func(i, j int) bool {
		if out.Tools[i].Name != out.Tools[j].Name {
			return out.Tools[i].Name < out.Tools[j].Name
		}
		return out.Tools[i].Version < out.Tools[j].Version
	})
	return out
}

// canonicalJSON marshals v with map keys sorted (encoding/json already sorts
// struct fields in declaration order and map keys lexically), giving stable
// bytes for hashing.
func canonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// envIDFor derives a stable environment id from a normalised selection. The id
// is deterministic so the same selection is retrievable and reproducible, and
// so two different selections get different ids.
func envIDFor(sel ToolSelection) (string, error) {
	b, err := canonicalJSON(normalizeSelection(sel))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "env-" + hex.EncodeToString(sum[:])[:16], nil
}
