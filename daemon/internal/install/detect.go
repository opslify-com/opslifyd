package install

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DetectResult reports what a project scan found: the tool ids suggested by
// markers, and the marker files that triggered them (for a legible summary).
type DetectResult struct {
	// Suggested is the sorted set of catalog tool ids suggested for this project,
	// including the always-on base utilities.
	Suggested []string
	// Evidence maps each suggested (non-base) tool id to the marker that matched,
	// so `init` can explain *why* it suggested a tool.
	Evidence map[string]string
}

// Detect scans dir (non-recursively at the top level; markers are conventionally
// at the project root) for project markers and returns the suggested toolset.
// It never errors on a missing/empty dir — an unreadable dir yields just the
// base utilities, so detection degrades legibly rather than failing the flow.
func Detect(dir string) DetectResult {
	res := DetectResult{Evidence: map[string]string{}}
	suggested := map[string]struct{}{}

	// Base utilities are always suggested.
	for _, id := range baseToolIDs() {
		suggested[id] = struct{}{}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		res.Suggested = keysSorted(suggested)
		return res
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}

	for _, e := range catalog {
		if e.Base {
			continue
		}
		for _, marker := range e.Markers {
			if hit, ok := matchMarker(names, marker); ok {
				suggested[e.ID] = struct{}{}
				if _, already := res.Evidence[e.ID]; !already {
					res.Evidence[e.ID] = hit
				}
				break
			}
		}
	}

	// A Kubernetes project (helm chart or kustomize) implies kubectl.
	if _, ok := res.Evidence["helm"]; ok {
		if _, has := suggested["kubectl"]; !has {
			suggested["kubectl"] = struct{}{}
			res.Evidence["kubectl"] = res.Evidence["helm"]
		}
	}

	res.Suggested = keysSorted(suggested)
	return res
}

// matchMarker reports whether any filename matches marker. A marker containing a
// glob metacharacter is matched with filepath.Match; otherwise it is an exact
// filename match. Returns the matched filename for evidence.
func matchMarker(names []string, marker string) (string, bool) {
	glob := strings.ContainsAny(marker, "*?[")
	for _, n := range names {
		if glob {
			if ok, _ := filepath.Match(marker, n); ok {
				return n, true
			}
		} else if n == marker {
			return n, true
		}
	}
	return "", false
}

func keysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
