package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/env"
	"gopkg.in/yaml.v3"
)

func sampleSelection() env.ToolSelection {
	return env.ToolSelection{
		BaseImageDigest: "repo@sha256:abc",
		Tools: []env.Tool{
			{Name: "terraform", Version: "1.7.0"},
			{Name: "git"},
		},
	}
}

func TestWriteArtifacts(t *testing.T) {
	dir := t.TempDir()
	if err := WriteArtifacts(dir, sampleSelection()); err != nil {
		t.Fatal(err)
	}

	// opslify.env.yaml
	mb, err := os.ReadFile(filepath.Join(dir, EnvManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m EnvManifest
	if err := yaml.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != EnvManifestSchemaVersion || m.BaseImageDigest != "repo@sha256:abc" {
		t.Fatalf("manifest header wrong: %+v", m)
	}
	if len(m.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(m.Tools))
	}

	// devbox.json — packages carry version pins.
	db, err := os.ReadFile(filepath.Join(dir, DevboxName))
	if err != nil {
		t.Fatal(err)
	}
	var devbox struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(db, &devbox); err != nil {
		t.Fatal(err)
	}
	if !contains(devbox.Packages, "terraform@1.7.0") {
		t.Fatalf("devbox missing pinned terraform: %v", devbox.Packages)
	}
	if !contains(devbox.Packages, "git@latest") {
		t.Fatalf("devbox missing git@latest: %v", devbox.Packages)
	}

	// flake.nix references the packages.
	fb, err := os.ReadFile(filepath.Join(dir, FlakeName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fb), "terraform") || !strings.Contains(string(fb), "buildEnv") {
		t.Fatalf("flake.nix malformed:\n%s", fb)
	}

	// No secret material in any artifact.
	for _, b := range [][]byte{mb, db, fb} {
		if strings.Contains(string(b), "PRIVATE KEY") {
			t.Fatal("artifact leaked key material")
		}
	}
}
