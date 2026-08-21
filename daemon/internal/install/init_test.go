package install

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/opslify-com/opslifyd/internal/env"
	"gopkg.in/yaml.v3"
)

// fakeBuilder is a headless env.EnvBuilder that records the driven selection and
// returns deterministic locked/signed outputs — no nix, no cosign, no network.
type fakeBuilder struct {
	gotSelection env.ToolSelection
	composeErr   error
	bakeErr      error
}

func (f *fakeBuilder) Compose(_ context.Context, sel env.ToolSelection) (env.LockedEnv, error) {
	f.gotSelection = sel
	if f.composeErr != nil {
		return env.LockedEnv{}, f.composeErr
	}
	return env.LockedEnv{
		EnvID:         "env-test",
		FlakeLockHash: "sha256:lockhash",
		Selection:     sel,
	}, nil
}

func (f *fakeBuilder) Bake(_ context.Context, locked env.LockedEnv) (env.SignedLayer, error) {
	if f.bakeErr != nil {
		return env.SignedLayer{}, f.bakeErr
	}
	return env.SignedLayer{
		EnvID:       locked.EnvID,
		LayerDigest: "sha256:layerdigest",
		Signature:   []byte("sig"),
	}, nil
}

func (f *fakeBuilder) Verify(context.Context, env.SignedLayer) error { return nil }

// newTestOpts builds InitOptions rooted entirely in temp dirs (no root, no /etc).
func newTestOpts(t *testing.T, projectDir string, p Prompter, b env.EnvBuilder) (InitOptions, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	buf := &bytes.Buffer{}
	return InitOptions{
		TargetDir:        projectDir,
		ConfigPath:       filepath.Join(root, "etc", "config.yaml"),
		IdentityKeyPath:  filepath.Join(root, "etc", "identity.key"),
		VaultKeyFilePath: filepath.Join(root, "etc", "vault.key"),
		SystemdUnitPath:  filepath.Join(root, "etc", "opslifyd.service"),
		BaseImageDigest:  "repo@sha256:base",
		Prompter:         p,
		Builder:          b,
		Probe:            func() Capabilities { return Capabilities{Podman: true, Runsc: true, Runc: true} },
		Out:              buf,
	}, buf
}

func TestRunEndToEndTerraform(t *testing.T) {
	project := t.TempDir()
	writeFiles(t, project, "main.tf")

	fb := &fakeBuilder{}
	// Accept detected suggestion set (ScriptedPrompter default), no custom.
	opts, buf := newTestOpts(t, project, ScriptedPrompter{}, fb)

	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, buf.String())
	}

	// Detection suggested terraform → it drove the builder with terraform.
	var hasTerraform bool
	for _, tl := range fb.gotSelection.Tools {
		if tl.Name == "terraform" {
			hasTerraform = true
		}
	}
	if !hasTerraform {
		t.Fatalf("builder not driven with terraform: %v", fb.gotSelection.Tools)
	}
	if fb.gotSelection.BaseImageDigest != "repo@sha256:base" {
		t.Errorf("base image digest not threaded to builder: %q", fb.gotSelection.BaseImageDigest)
	}

	// Signed layer digest + flake.lock hash printed and recorded.
	if !res.Baked || res.LayerDigest != "sha256:layerdigest" || res.FlakeLockHash != "sha256:lockhash" {
		t.Fatalf("bake result not surfaced: %+v", res)
	}
	if !bytesContains(buf, "sha256:layerdigest") {
		t.Error("layer digest not printed to operator")
	}

	// Artifacts written.
	for _, f := range []string{EnvManifestName, DevboxName, FlakeName} {
		if _, err := os.Stat(filepath.Join(project, f)); err != nil {
			t.Errorf("artifact %s not written", f)
		}
	}

	// Config written with digests folded in and defaults intact.
	cb, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(cb, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SessionTTL != "30m" || cfg.WarmPoolSize != 1 || cfg.Tier != "local-hardened" {
		t.Errorf("config defaults wrong: %+v", cfg)
	}
	if cfg.ToolchainDigest != "sha256:layerdigest" || cfg.FlakeLockHash != "sha256:lockhash" {
		t.Errorf("config missing baked digests: %+v", cfg)
	}

	// Identity key exists with 0600.
	info, err := os.Stat(opts.IdentityKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("identity key perms: %o", info.Mode().Perm())
	}
}

func TestRunAddRemoveTools(t *testing.T) {
	project := t.TempDir()
	writeFiles(t, project, "main.tf")

	fb := &fakeBuilder{}
	// Operator drops terraform, adds go + a custom package.
	p := ScriptedPrompter{
		Tools:  []string{"go", "git"},
		Custom: []CustomTool{{NixPackage: "ripgrep"}},
	}
	opts, buf := newTestOpts(t, project, p, fb)
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v\n%s", err, buf.String())
	}

	names := map[string]bool{}
	for _, tl := range fb.gotSelection.Tools {
		names[tl.Name] = true
	}
	if names["terraform"] {
		t.Error("terraform should have been removed")
	}
	if !names["go"] || !names["ripgrep"] {
		t.Fatalf("expected go + custom ripgrep, got %v", fb.gotSelection.Tools)
	}
}

func TestRunRuncFallbackNoCrash(t *testing.T) {
	project := t.TempDir()
	fb := &fakeBuilder{}
	opts, buf := newTestOpts(t, project, ScriptedPrompter{}, fb)
	// runsc absent → must warn + offer fallback, not crash.
	opts.Probe = func() Capabilities { return Capabilities{Podman: true, Runsc: false, Runc: true} }

	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("missing runsc must not fail init: %v", err)
	}
	if res.RecommendTier != "local-docker" {
		t.Errorf("expected runc fallback tier, got %q", res.RecommendTier)
	}
	if !bytesContains(buf, "runsc") {
		t.Error("expected a legible runsc warning")
	}
}

func TestRunIdempotentPromptBeforeOverwrite(t *testing.T) {
	project := t.TempDir()
	fb := &fakeBuilder{}

	// First run creates everything.
	opts, _ := newTestOpts(t, project, ScriptedPrompter{}, fb)
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	keyInfo1, _ := os.Stat(opts.IdentityKeyPath)

	// Second run: decline all overwrites → files preserved, no error.
	declined := ScriptedPrompter{ConfirmFunc: func(string, bool) bool { return false }}
	opts2 := opts
	opts2.Prompter = declined
	keyBefore, _ := os.ReadFile(opts.IdentityKeyPath)
	if _, err := Run(context.Background(), opts2); err != nil {
		t.Fatal(err)
	}
	keyAfter, _ := os.ReadFile(opts.IdentityKeyPath)
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("declined overwrite still rewrote identity key")
	}
	keyInfo2, _ := os.Stat(opts.IdentityKeyPath)
	if !keyInfo1.ModTime().Equal(keyInfo2.ModTime()) {
		t.Error("identity key modified despite declined overwrite")
	}
}

func TestRunForceOverwrites(t *testing.T) {
	project := t.TempDir()
	fb := &fakeBuilder{}
	opts, _ := newTestOpts(t, project, ScriptedPrompter{}, fb)
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	keyBefore, _ := os.ReadFile(opts.IdentityKeyPath)

	opts.Force = true
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	keyAfter, _ := os.ReadFile(opts.IdentityKeyPath)
	if bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("force should regenerate the identity key")
	}
}

func TestRunNoBuilderStillWritesArtifacts(t *testing.T) {
	project := t.TempDir()
	writeFiles(t, project, "go.mod")
	// Builder nil AND no cosign on PATH → gated skip, artifacts still written.
	withLookPath(t, map[string]bool{}) // ensures env.NewDefault fails (no cosign)
	opts, buf := newTestOpts(t, project, ScriptedPrompter{}, nil)
	opts.Builder = nil

	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run without builder must not fail: %v\n%s", err, buf.String())
	}
	if res.Baked {
		t.Error("no builder → should not report a baked layer")
	}
	if _, err := os.Stat(filepath.Join(project, EnvManifestName)); err != nil {
		t.Error("artifacts must still be written without a builder")
	}
}

func bytesContains(buf *bytes.Buffer, sub string) bool {
	return bytes.Contains(buf.Bytes(), []byte(sub))
}
