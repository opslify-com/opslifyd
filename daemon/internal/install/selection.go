package install

import (
	"fmt"
	"sort"
	"strings"

	"github.com/opslify-com/opslifyd/internal/env"
)

// CustomTool is an operator-supplied Nix package added on top of the curated
// catalog (e.g. a niche tool we don't curate). Version is optional.
type CustomTool struct {
	NixPackage string
	Version    string
}

// Selection is the resolved outcome of the prompt: the chosen catalog tool ids
// plus any custom Nix packages. It is pure data so the merge from
// detection-defaults + user edits is unit-testable headlessly.
type Selection struct {
	// ToolIDs are chosen catalog ids (e.g. "terraform").
	ToolIDs []string
	// Custom are extra raw Nix packages the operator added.
	Custom []CustomTool
	// Versions optionally pins a catalog tool id to a version (empty = let the
	// composer's pinned nixpkgs decide; flake.lock still records the exact hash).
	Versions map[string]string
}

// ToToolSelection converts the resolved Selection into F0.2's env.ToolSelection,
// mapping each catalog id to its Nix package and folding in the base image
// digest. Unknown ids are skipped legibly (they cannot be resolved by the
// composer). The result is what drives EnvBuilder.Compose.
func (s Selection) ToToolSelection(baseImageDigest string) (env.ToolSelection, error) {
	sel := env.ToolSelection{BaseImageDigest: strings.TrimSpace(baseImageDigest)}
	seen := map[string]struct{}{}

	for _, id := range s.ToolIDs {
		e, ok := entryByID(id)
		if !ok {
			return env.ToolSelection{}, fmt.Errorf("install: unknown tool id %q (not in catalog)", id)
		}
		if _, dup := seen[e.NixPackage]; dup {
			continue
		}
		seen[e.NixPackage] = struct{}{}
		sel.Tools = append(sel.Tools, env.Tool{Name: e.NixPackage, Version: s.Versions[id]})
	}
	for _, c := range s.Custom {
		name := strings.TrimSpace(c.NixPackage)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		sel.Tools = append(sel.Tools, env.Tool{Name: name, Version: strings.TrimSpace(c.Version)})
	}
	if len(sel.Tools) == 0 {
		return env.ToolSelection{}, fmt.Errorf("install: %w", env.ErrEmptySelection)
	}
	sort.Slice(sel.Tools, func(i, j int) bool { return sel.Tools[i].Name < sel.Tools[j].Name })
	return sel, nil
}
