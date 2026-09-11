package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/opslify-com/opslifyd/internal/env"
	"github.com/opslify-com/opslifyd/internal/project"
)

// toolchainBuilder composes and bakes a per-project toolchain.
//
// Asynchronous, because a nix build is minutes and an HTTP request is not. The
// state lives on the project record rather than in this struct: an operator who
// restarts the daemon mid-build should see "failed" and be able to retry, not a
// project stuck in "building" forever with nothing running.
type toolchainBuilder struct {
	projects *project.Service
	builder  env.EnvBuilder
	image    string
	// why records WHY the builder is nil, so the operator is told the actual
	// reason rather than a guess. The first version said "nix/devbox is not
	// installed" on a host that had both and was missing cosign.
	why string
	log *slog.Logger

	// mu guards inflight, which stops two builds of the same project racing to
	// write the record. The second caller is refused rather than queued: a rebuild
	// is cheap to ask for again and expensive to do twice.
	mu       sync.Mutex
	inflight map[string]bool
}

func newToolchainBuilder(projects *project.Service, builder env.EnvBuilder, why, image string, log *slog.Logger) *toolchainBuilder {
	return &toolchainBuilder{
		projects: projects, builder: builder, image: image, why: why, log: log,
		inflight: map[string]bool{},
	}
}

// reason states why building is impossible here, in the builder's own words.
func (b *toolchainBuilder) reason() string {
	if b == nil || b.why == "" {
		return "the environment builder is not configured"
	}
	return b.why
}

// Available reports whether this host can build a toolchain at all.
func (b *toolchainBuilder) Available() bool { return b != nil && b.builder != nil }

// Build starts a build and returns the project as it stands immediately after —
// with status "building", so a caller sees the transition without waiting.
func (b *toolchainBuilder) Build(projectID string, tools []string) (project.Project, error) {
	if !b.Available() {
		// Not an error the operator can fix by retrying, so it is recorded as its
		// own status rather than a failure. The sandboxes keep the daemon toolchain.
		return b.projects.SetToolchain(projectID, project.Toolchain{
			Tools:  tools,
			Status: project.ToolchainUnavailable,
			Error: "this host cannot build a per-project toolchain: " + b.reason() + ". " +
				"Sandboxes for this project use the daemon-wide toolchain instead.",
		})
	}
	clean, err := project.ValidateTools(tools)
	if err != nil {
		return project.Project{}, err
	}

	b.mu.Lock()
	if b.inflight[projectID] {
		b.mu.Unlock()
		return project.Project{}, fmt.Errorf("%w: a toolchain build for %q is already running",
			project.ErrInUse, projectID)
	}
	b.inflight[projectID] = true
	b.mu.Unlock()

	p, err := b.projects.SetToolchain(projectID, project.Toolchain{
		Tools: clean, Status: project.ToolchainBuilding,
	})
	if err != nil {
		b.mu.Lock()
		delete(b.inflight, projectID)
		b.mu.Unlock()
		return project.Project{}, err
	}

	go b.run(projectID, clean)
	return p, nil
}

// run does the compose+bake. Its own context, not the request's: the caller has
// already been answered and a build must not be cancelled because a browser tab
// closed.
func (b *toolchainBuilder) run(projectID string, tools []string) {
	defer func() {
		b.mu.Lock()
		delete(b.inflight, projectID)
		b.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	sel := env.ToolSelection{BaseImageDigest: b.image}
	for _, t := range tools {
		sel.Tools = append(sel.Tools, env.Tool{Name: t})
	}

	fail := func(stage string, err error) {
		b.log.Error("toolchain build failed", "project", projectID, "stage", stage, "error", err)
		if _, serr := b.projects.SetToolchain(projectID, project.Toolchain{
			Tools: tools, Status: project.ToolchainFailed,
			Error: stage + ": " + err.Error(),
		}); serr != nil {
			b.log.Error("recording the failure also failed", "project", projectID, "error", serr)
		}
	}

	locked, err := b.builder.Compose(ctx, sel)
	if err != nil {
		fail("compose", err)
		return
	}
	layer, err := b.builder.Bake(ctx, locked)
	if err != nil {
		fail("bake", err)
		return
	}

	if _, err := b.projects.SetToolchain(projectID, project.Toolchain{
		Tools:         tools,
		Status:        project.ToolchainReady,
		LayerDigest:   layer.LayerDigest,
		FlakeLockHash: locked.FlakeLockHash,
		BuiltAt:       time.Now().UTC(),
	}); err != nil {
		b.log.Error("recording a successful build failed", "project", projectID, "error", err)
		return
	}
	b.log.Info("toolchain built",
		"project", projectID, "tools", len(tools), "digest", layer.LayerDigest)
}

// tryEnvBuilder returns the production F0.2 builder, or nil when this host
// cannot run one.
//
// nil is a normal outcome, not a failure: a daemon on a machine without nix
// still runs sandboxes, using the toolchain baked at install time. What it cannot
// do is compose a different one per project, and saying so plainly beats a
// startup error nobody can act on.
func tryEnvBuilder(log *slog.Logger) (env.EnvBuilder, string) {
	b, err := env.NewDefault("", "", "")
	if err != nil {
		log.Info("per-project toolchains unavailable on this host",
			"reason", err, "effect", "projects use the daemon-wide toolchain")
		return nil, err.Error()
	}
	return b, ""
}
