package project

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// A project's toolchain is the set of CLIs its sandboxes get.
//
// F0.2 composes one at `opslify init` for the whole daemon, which is the right
// default and the wrong granularity for an estate: tripon needs kubectl and helm,
// yuusr needs terraform, and neither should carry the other's binaries. A tool
// present in a sandbox is a tool an agent can run, so the smallest set that does
// the job is also the smallest blast radius.
//
// Building one takes minutes, so it is asynchronous and its state is part of the
// project record rather than a hidden background fact.

// ToolchainStatus is where a project's build has got to.
type ToolchainStatus string

const (
	// ToolchainNone means the project has never asked for one; its sandboxes use
	// the daemon-wide toolchain.
	ToolchainNone ToolchainStatus = ""
	// ToolchainBuilding means a compose/bake is running.
	ToolchainBuilding ToolchainStatus = "building"
	// ToolchainReady means LayerDigest is pinned and in use.
	ToolchainReady ToolchainStatus = "ready"
	// ToolchainFailed means the last build failed; Error says why and the project
	// keeps whatever it had before.
	ToolchainFailed ToolchainStatus = "failed"
	// ToolchainUnavailable means this host cannot build one — no nix, no devbox.
	// Distinct from failed: nothing is wrong with the request, the machine simply
	// cannot serve it, and telling an operator to "retry" would be a lie.
	ToolchainUnavailable ToolchainStatus = "unavailable"
)

// Toolchain is the project's declared tools and the layer built from them.
type Toolchain struct {
	// Tools are nix package names, as declared. Sorted and de-duplicated so the
	// same set always produces the same identity.
	Tools  []string        `json:"tools,omitempty"`
	Status ToolchainStatus `json:"status,omitempty"`
	// LayerDigest is the signed layer mounted at /opt/toolchain. Empty until a
	// build succeeds; a failed rebuild leaves the previous one in place, because
	// losing a working toolchain to a typo would be a worse outcome than an error
	// message.
	LayerDigest string `json:"layer_digest,omitempty"`
	// FlakeLockHash identifies the resolved versions. Two projects with the same
	// tools and the same lock get the same binaries, which is what makes a Change
	// replayable.
	FlakeLockHash string    `json:"flake_lock_hash,omitempty"`
	BuiltAt       time.Time `json:"built_at,omitempty"`
	// Error is the last failure, operator-facing. Cleared on success.
	Error string `json:"error,omitempty"`
}

// InUse reports whether this project's sandboxes should mount its own layer.
func (t Toolchain) InUse() bool { return t.Status == ToolchainReady && t.LayerDigest != "" }

// nixPkgRe is deliberately narrow. A package name reaches a generated flake and
// then a shell, so anything outside this charset is refused at the boundary
// rather than escaped later.
var nixPkgRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$`)

// ValidateTools checks and canonicalises a tool list.
func ValidateTools(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > 64 {
		return nil, fmt.Errorf("%w: %d tools is more than a project needs; a toolchain is "+
			"what its sandboxes can run, so keep it to what the work uses", ErrInvalidInput, len(in))
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !nixPkgRe.MatchString(t) {
			return nil, fmt.Errorf("%w: %q is not a valid package name; it is written into a "+
				"generated flake and must match %s", ErrInvalidInput, t, nixPkgRe.String())
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	// Sorted so the same set is the same identity regardless of the order it was
	// typed in.
	sort.Strings(out)
	return out, nil
}

// SetToolchain replaces a project's toolchain record.
//
// The whole record, for the same reason SetCapabilities replaces rather than
// merges: a build has a status, a digest and an error that only make sense
// together, and a partial update can express a state the builder never produced.
func (s *Service) SetToolchain(projectID string, tc Toolchain) (Project, error) {
	if projectID == "" {
		projectID = DefaultProjectID
	}
	clean, err := ValidateTools(tc.Tools)
	if err != nil {
		return Project{}, err
	}
	tc.Tools = clean
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok, err := s.store.LoadProject(projectID)
	if err != nil {
		return Project{}, err
	}
	if !ok {
		return Project{}, fmt.Errorf("%w: project %q", ErrNotFound, projectID)
	}
	// A failed build keeps whatever was working. Losing a good toolchain to a
	// typo in a package name would be a worse outcome than the error.
	if tc.Status == ToolchainFailed && tc.LayerDigest == "" {
		tc.LayerDigest = p.Toolchain.LayerDigest
		tc.FlakeLockHash = p.Toolchain.FlakeLockHash
		tc.BuiltAt = p.Toolchain.BuiltAt
	}
	p.Toolchain = tc
	if err := s.store.SaveProject(p); err != nil {
		return Project{}, err
	}
	s.log.Info("project toolchain updated",
		"project", p.ID, "status", tc.Status, "tools", len(tc.Tools), "digest", tc.LayerDigest)
	return p, nil
}

// NixPackageFor maps a capability tool name to the nixpkgs attribute that
// provides it.
//
// A separate mapping because the two vocabularies are not the same: a project
// declares "kubernetes" as a role's tool, and nixpkgs calls the binary "kubectl".
// Guessing between them would silently produce a toolchain missing the thing the
// operator asked for.
//
// An unmapped name is passed through unchanged rather than refused — nixpkgs has
// far more packages than this table, and an operator naming one directly is doing
// something reasonable.
func NixPackageFor(tool string) string {
	switch tool {
	case "kubernetes":
		return "kubectl"
	case "helm":
		return "kubernetes-helm"
	case "gitlab":
		return "glab"
	case "github":
		return "gh"
	case "aws":
		return "awscli2"
	case "azure":
		return "azure-cli"
	case "gcp", "gcloud":
		return "google-cloud-sdk"
	case "docker":
		return "docker-client"
	case "argocd":
		return "argocd"
	case "terraform":
		return "terraform"
	}
	return tool
}

// BaselinePackages are added to every project toolchain.
//
// git because every estate clones something, and curl/jq/openssh because a
// runbook that says "check the endpoint" is unrunnable without them. Small, and
// the alternative is every operator discovering the same four omissions.
var BaselinePackages = []string{"git", "curl", "jq", "openssh"}

// ToolchainFor turns a project's capability map into a package list.
func ToolchainFor(caps map[string]string) []string {
	set := map[string]bool{}
	for _, p := range BaselinePackages {
		set[p] = true
	}
	for _, tool := range caps {
		if pkg := NixPackageFor(tool); pkg != "" {
			set[pkg] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
