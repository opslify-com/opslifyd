package install

import (
	"errors"
	"testing"

	"github.com/opslify-com/opslifyd/internal/env"
)

func TestSelectionToToolSelection(t *testing.T) {
	sel := Selection{
		ToolIDs:  []string{"terraform", "kubectl", "git"},
		Versions: map[string]string{"terraform": "1.7.0"},
	}
	out, err := sel.ToToolSelection("repo@sha256:abc")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out.BaseImageDigest != "repo@sha256:abc" {
		t.Errorf("base digest not carried: %q", out.BaseImageDigest)
	}
	// Catalog ids map to Nix package names.
	byName := map[string]string{}
	for _, tl := range out.Tools {
		byName[tl.Name] = tl.Version
	}
	if _, ok := byName["terraform"]; !ok {
		t.Errorf("terraform nix package missing: %v", out.Tools)
	}
	if byName["terraform"] != "1.7.0" {
		t.Errorf("version pin lost: %q", byName["terraform"])
	}
	// kubectl id -> "kubectl", git -> "git".
	if _, ok := byName["kubectl"]; !ok {
		t.Errorf("kubectl missing")
	}
}

func TestSelectionMapsHelmToNixPackage(t *testing.T) {
	out, err := Selection{ToolIDs: []string{"helm"}}.ToToolSelection("")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Tools) != 1 || out.Tools[0].Name != "kubernetes-helm" {
		t.Fatalf("helm should map to nixpkgs kubernetes-helm, got %v", out.Tools)
	}
}

func TestSelectionCustomPackages(t *testing.T) {
	out, err := Selection{
		ToolIDs: []string{"git"},
		Custom:  []CustomTool{{NixPackage: "cowsay", Version: "3.7"}, {NixPackage: ""}},
	}.ToToolSelection("")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, tl := range out.Tools {
		if tl.Name == "cowsay" && tl.Version == "3.7" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom package cowsay@3.7 missing: %v", out.Tools)
	}
}

func TestSelectionUnknownID(t *testing.T) {
	_, err := Selection{ToolIDs: []string{"not-a-real-tool"}}.ToToolSelection("")
	if err == nil {
		t.Fatal("expected error for unknown tool id")
	}
}

func TestSelectionEmpty(t *testing.T) {
	_, err := Selection{}.ToToolSelection("")
	if !errors.Is(err, env.ErrEmptySelection) {
		t.Fatalf("expected ErrEmptySelection, got %v", err)
	}
}

func TestSelectionDedup(t *testing.T) {
	// kubectl id and a custom "kubectl" nix pkg must not double up.
	out, err := Selection{
		ToolIDs: []string{"kubectl"},
		Custom:  []CustomTool{{NixPackage: "kubectl"}},
	}.ToToolSelection("")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, tl := range out.Tools {
		if tl.Name == "kubectl" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected kubectl once, got %d (%v)", n, out.Tools)
	}
}
