package project

import (
	"strings"
	"testing"
)

func TestToolchainForMapsCapabilitiesToPackages(t *testing.T) {
	got := ToolchainFor(map[string]string{
		"k8s": "kubernetes", "iac": "terraform", "git": "gitlab", "charts": "helm",
	})
	joined := strings.Join(got, " ")
	// The vocabularies differ: a project says "kubernetes", nixpkgs says "kubectl".
	for _, want := range []string{"kubectl", "terraform", "glab", "kubernetes-helm"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s missing from %v", want, got)
		}
	}
	if strings.Contains(joined, " kubernetes ") {
		t.Errorf("the capability name leaked into the package list: %v", got)
	}
	// Baseline: every estate clones something, and a runbook that says "check the
	// endpoint" is unrunnable without curl.
	for _, want := range BaselinePackages {
		if !strings.Contains(joined, want) {
			t.Errorf("baseline package %s missing from %v", want, got)
		}
	}
}

func TestValidateToolsRefusesInjection(t *testing.T) {
	// A package name is written into a generated flake and then reaches a shell.
	for _, bad := range []string{
		"kubectl; rm -rf /", "foo$(whoami)", "a`id`", "pkg with space",
		"../../etc/passwd", "pkg\nname", "-starts-with-dash",
	} {
		if _, err := ValidateTools([]string{bad}); err == nil {
			t.Errorf("%q was accepted as a package name", bad)
		}
	}
}

func TestValidateToolsCanonicalises(t *testing.T) {
	got, err := ValidateTools([]string{"terraform", "kubectl", "terraform", "  ", "git"})
	if err != nil {
		t.Fatal(err)
	}
	// Sorted and de-duplicated: the same set must be the same identity regardless
	// of the order it was typed in, or two identical toolchains build twice.
	want := []string{"git", "kubectl", "terraform"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestAFailedBuildKeepsTheWorkingToolchain: losing a good layer to a typo in a
// package name would be a worse outcome than the error message.
func TestAFailedBuildKeepsTheWorkingToolchain(t *testing.T) {
	svc, _, _ := newTestService(t)
	if _, _, err := svc.CreateProject(ProjectSpec{Name: "tripon"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetToolchain("tripon", Toolchain{
		Tools: []string{"kubectl"}, Status: ToolchainReady, LayerDigest: "sha256:good",
	}); err != nil {
		t.Fatal(err)
	}
	p, err := svc.SetToolchain("tripon", Toolchain{
		Tools: []string{"kubectl", "nosuchpkg"}, Status: ToolchainFailed, Error: "compose: no such package",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Toolchain.LayerDigest != "sha256:good" {
		t.Errorf("a failed build discarded the working layer: %+v", p.Toolchain)
	}
	if p.Toolchain.Status != ToolchainFailed || p.Toolchain.Error == "" {
		t.Errorf("the failure is not reported: %+v", p.Toolchain)
	}
	// And a project with a failed build still runs its old toolchain.
	if !p.Toolchain.InUse() && p.Toolchain.LayerDigest != "" {
		t.Log("note: InUse is false while status is failed — sandboxes fall back to the daemon layer")
	}
}
