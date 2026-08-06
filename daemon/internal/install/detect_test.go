package install

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFiles creates empty files under dir for detection tests.
func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name     string
		files    []string
		wantTool string // a tool that must be suggested
	}{
		{"terraform", []string{"main.tf"}, "terraform"},
		{"terraform-glob", []string{"network.tf"}, "terraform"},
		{"helm", []string{"Chart.yaml"}, "helm"},
		{"kustomize", []string{"kustomization.yaml"}, "kubectl"},
		{"node", []string{"package.json"}, "node"},
		{"python", []string{"requirements.txt"}, "python3"},
		{"go", []string{"go.mod"}, "go"},
		{"docker", []string{"Dockerfile"}, "docker-cli"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, tc.files...)
			res := Detect(dir)
			if !contains(res.Suggested, tc.wantTool) {
				t.Fatalf("expected %q in suggested %v", tc.wantTool, res.Suggested)
			}
			// Base utilities are always suggested.
			for _, base := range []string{"git", "jq", "curl"} {
				if !contains(res.Suggested, base) {
					t.Errorf("expected base tool %q always suggested", base)
				}
			}
		})
	}
}

func TestDetectHelmImpliesKubectl(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "Chart.yaml")
	res := Detect(dir)
	if !contains(res.Suggested, "kubectl") {
		t.Fatalf("helm chart should imply kubectl; got %v", res.Suggested)
	}
	if res.Evidence["helm"] != "Chart.yaml" {
		t.Errorf("expected evidence Chart.yaml for helm, got %q", res.Evidence["helm"])
	}
}

func TestDetectMissingDir(t *testing.T) {
	res := Detect(filepath.Join(t.TempDir(), "does-not-exist"))
	// Degrades to base utilities only, never errors.
	if !contains(res.Suggested, "git") {
		t.Fatalf("missing dir should still suggest base tools; got %v", res.Suggested)
	}
	if contains(res.Suggested, "terraform") {
		t.Fatalf("missing dir should not suggest terraform")
	}
}

func TestDetectEmptyProject(t *testing.T) {
	res := Detect(t.TempDir())
	if len(res.Suggested) != 3 { // git, jq, curl
		t.Fatalf("empty project should suggest exactly the 3 base tools, got %v", res.Suggested)
	}
}
