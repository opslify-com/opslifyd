// Package project implements F8.1 — the Project → Environment spine of Phase 8.
//
// A Project gathers what one body of work needs: a name, the repo it lives in,
// and a CAPABILITY MAP (role → tool, e.g. git=gitlab, ci=gitlab-ci,
// deploy=argocd, iac=terraform) that later features route skills and tool
// contracts off. An Environment is a layer WITHIN a project that carries the risk
// gradient — staging auto-approves what prod gates — and it is a separate record,
// not a heading inside one file, so "which rules applied in prod?" is a lookup
// rather than a reading exercise.
//
// The security teeth are in policy.go: an environment overlay may only NARROW its
// project's policy, which may only narrow the daemon's. The narrowing itself is
// NOT reimplemented here — every layer goes through the existing F4.1
// policy.Resolve, so a widening attempt is structurally impossible and each clamp
// is recorded, layer-tagged, exactly as F4.1 does for a workspace policy.
//
// This package is pure records + validation + resolution. It owns no sandbox: the
// live-sandbox seam (Sandboxes) is an interface the session Manager satisfies, so
// removals can be ordered and fail closed without this package importing session.
package project

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Well-known ids for the implicit default scope. A create that names no project
// or environment lands here, so every pre-F8.1 caller keeps working unchanged and
// every session still records a concrete (project, environment) pair — there is
// no "unscoped" session and therefore no un-filterable trace.
const (
	// DefaultProjectID is the id (and name) of the implicit default project.
	DefaultProjectID = "default"
	// DefaultEnvironmentName is the name of every project's first environment
	// when the operator does not name one.
	DefaultEnvironmentName = "default"
	// DefaultEnvironmentID is the id of the default project's default environment.
	DefaultEnvironmentID = DefaultProjectID + envIDSeparator + DefaultEnvironmentName
)

// envIDSeparator joins a project id and an environment name into the environment
// id. It is deliberately OUTSIDE the name charset (see nameRe), so an environment
// id parses back to exactly one (project, name) pair and can never collide with a
// differently-scoped environment.
const envIDSeparator = "."

// Roles the capability map is expected to carry. They are documentation + the
// vocabulary F8.4 skill routing keys off; the map is NOT restricted to them (a
// project may declare its own role), only to the safe slug charset below.
const (
	RoleGit      = "git"
	RoleCI       = "ci"
	RoleDeploy   = "deploy"
	RoleIaC      = "iac"
	RoleRegistry = "registry"
	RoleObserve  = "observability"
)

// Sentinel errors. Each names its failure LAYER so the HTTP surface and the CLI
// can distinguish a bad request from a missing record from a refusal-while-live,
// rather than collapsing them into one opaque 500 (failure legibility).
var (
	// ErrInvalidInput is returned when a boundary check rejects caller input (a
	// malformed name, an unknown tier, a duplicate environment).
	ErrInvalidInput = errors.New("project: invalid input")
	// ErrNotFound is returned for an unknown project or environment id.
	ErrNotFound = errors.New("project: not found")
	// ErrExists is returned when a create would overwrite an existing record.
	ErrExists = errors.New("project: already exists")
	// ErrInUse is returned when a removal is refused because something is still
	// live under the record. Deleting a project must never orphan a live sandbox
	// holding connections, so this fails CLOSED.
	ErrInUse = errors.New("project: in use")
)

// nameRe bounds a project/environment name to a safe, traversal-free token: a
// lowercase alnum start followed by alnum / '-' / '_', up to 64 chars. This keeps
// the derived id inside its on-disk namespace (<state>/projects/<id>.json) — no
// '/', '..', ':', '.', or whitespace can appear — and keeps ids legible in a
// trace filter. It mirrors session.wsNameRe deliberately: one naming rule for
// every operator-facing name in the daemon.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// slugRe bounds a capability role and its tool. Same charset as a name, so a
// capability map is always safe to render into a trace, a path, or a prompt.
var slugRe = nameRe

// ValidateName rejects any name that could traverse out of the record directory
// or produce an ambiguous id.
func ValidateName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("%w: %s name is required", ErrInvalidInput, kind)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%w: %s name %q must match %s", ErrInvalidInput, kind, name, nameRe.String())
	}
	return nil
}

// EnvironmentID derives an environment's id from its project id and name. The id
// is stable and human-readable so `opslify env ls`, a trace filter, and the
// on-disk record all name the same thing.
func EnvironmentID(projectID, name string) string {
	return projectID + envIDSeparator + name
}

// Project is one body of work: the platforms it runs on and the environments it
// is delivered through. It carries NO secret — a credential is always a ref
// resolved through the F5.6 broker, never a value stored here.
type Project struct {
	// ID is the stable, path-safe identifier. It is derived from the validated
	// name at creation and never changes (there is no rename in v1: a rename
	// would orphan the trace history that references the id).
	ID string `json:"id"`
	// Name is the operator-facing name. It equals ID for a project created
	// through this package; the field is kept distinct so a future rename can
	// move the display name without moving the id.
	Name string `json:"name"`
	// Created is when the project record was written.
	Created time.Time `json:"created"`
	// RepoURL is the optional source repository the work lives in. It is
	// descriptive metadata only — nothing clones it in F8.1.
	RepoURL string `json:"repo_url,omitempty"`
	// Capabilities is the role → tool map (git=gitlab, ci=gitlab-ci,
	// deploy=argocd, iac=terraform). F8.4 routes skill packs off it and F8.2 binds
	// connections to it; F8.1 records and validates it.
	Capabilities map[string]string `json:"capabilities,omitempty"`
	// PolicyFile is an optional path to the project's policy layer. It may only
	// NARROW the daemon baseline (F4.1 resolution, see policy.go). Empty means the
	// project adds no restriction of its own.
	PolicyFile string `json:"policy_file,omitempty"`
	// WorkspacePath is a HOST directory the operator chose for this project's
	// workspace, mounted read-write at /workspace in its sandboxes. Empty means the
	// daemon manages one under its workspace root.
	//
	// Choosing one is what makes "clone the repo, then open it in your editor"
	// work: the agent and the operator are looking at the same files. It also
	// changes the sandbox's user namespace — see the session runtime — so it is a
	// per-project decision rather than a global setting.
	WorkspacePath string `json:"workspace_path,omitempty"`
	// Toolchain is the project's own set of CLIs, built by F0.2 and mounted at
	// /opt/toolchain instead of the daemon-wide layer. Zero means "use the
	// daemon's".
	Toolchain Toolchain `json:"toolchain,omitempty"`
}

// Environment is one risk rung inside a project: staging, prod, whatever the
// operator names. It is a SEPARATE record from the project — prod must be able to
// narrow staging, and the narrowing must be enforced by the daemon rather than by
// convention.
type Environment struct {
	// ID is the stable, path-safe identifier: "<project id>.<name>".
	ID string `json:"id"`
	// ProjectID is the owning project.
	ProjectID string `json:"project_id"`
	// Name is the operator-facing name, unique WITHIN the project.
	Name string `json:"name"`
	// Created is when the environment record was written.
	Created time.Time `json:"created"`
	// PolicyOverlay is an optional path to this environment's policy overlay. It
	// may only NARROW the project's policy (which may only narrow the daemon's);
	// a widening attempt is clamped daemon-side and the clamp recorded.
	PolicyOverlay string `json:"policy_overlay,omitempty"`
	// DefaultTier is the isolation rung a session in this environment gets when
	// the create names none. It is a DEFAULT, not a floor: a floor is expressed in
	// the policy overlay (session.tier), which the daemon enforces.
	DefaultTier string `json:"default_tier,omitempty"`
	// DefaultTTL is the idle lifetime a session in this environment gets when the
	// create names none (a Go duration string, e.g. "30m"). Like DefaultTier it is
	// a default; the enforceable bound lives in the policy overlay (session.ttl).
	DefaultTTL string `json:"default_ttl,omitempty"`
	// Production marks the environment as the one where mistakes are expensive.
	// F8.1 records and surfaces it; the gating itself is expressed in the overlay
	// (approval_required), so the flag is a label, never the enforcement.
	Production bool `json:"production,omitempty"`
}

// ProjectSpec is the validated input to CreateProject.
type ProjectSpec struct {
	Name         string
	RepoURL      string
	Capabilities map[string]string
	PolicyFile   string
	// WorkspacePath is the operator-chosen host directory, or empty for a
	// daemon-managed one.
	WorkspacePath string
	// Environments are the environments created with the project. A project owns
	// at least one environment, so an empty list creates the default one rather
	// than an environment-less project.
	Environments []EnvironmentSpec
}

// EnvironmentSpec is the validated input to AddEnvironment.
type EnvironmentSpec struct {
	Name          string
	PolicyOverlay string
	DefaultTier   string
	DefaultTTL    string
	Production    bool
}

// validate checks a project spec at the trust boundary and returns the record it
// describes (minus Created, which the service stamps).
func (s ProjectSpec) validate() (Project, error) {
	if err := ValidateName("project", s.Name); err != nil {
		return Project{}, err
	}
	caps, err := validateCapabilities(s.Capabilities)
	if err != nil {
		return Project{}, err
	}
	if err := ValidateWorkspacePath(s.WorkspacePath); err != nil {
		return Project{}, err
	}
	if err := validatePolicyPath("policy_file", s.PolicyFile); err != nil {
		return Project{}, err
	}
	if err := validateRepoURL(s.RepoURL); err != nil {
		return Project{}, err
	}
	return Project{
		ID:            s.Name,
		Name:          s.Name,
		RepoURL:       s.RepoURL,
		Capabilities:  caps,
		PolicyFile:    s.PolicyFile,
		WorkspacePath: s.WorkspacePath,
	}, nil
}

// validate checks an environment spec at the trust boundary and returns the
// record it describes for projectID (minus Created).
func (s EnvironmentSpec) validate(projectID string) (Environment, error) {
	if err := ValidateName("environment", s.Name); err != nil {
		return Environment{}, err
	}
	if err := validatePolicyPath("policy_overlay", s.PolicyOverlay); err != nil {
		return Environment{}, err
	}
	if s.DefaultTier != "" && !knownTier(s.DefaultTier) {
		return Environment{}, fmt.Errorf("%w: unknown default_tier %q", ErrInvalidInput, s.DefaultTier)
	}
	if s.DefaultTTL != "" {
		d, err := time.ParseDuration(s.DefaultTTL)
		if err != nil {
			return Environment{}, fmt.Errorf("%w: invalid default_ttl %q: %v", ErrInvalidInput, s.DefaultTTL, err)
		}
		if d <= 0 {
			return Environment{}, fmt.Errorf("%w: default_ttl %q must be positive", ErrInvalidInput, s.DefaultTTL)
		}
	}
	return Environment{
		ID:            EnvironmentID(projectID, s.Name),
		ProjectID:     projectID,
		Name:          s.Name,
		PolicyOverlay: s.PolicyOverlay,
		DefaultTier:   s.DefaultTier,
		DefaultTTL:    s.DefaultTTL,
		Production:    s.Production,
	}, nil
}

// validateCapabilities returns a copy of the role → tool map with every key and
// value checked against the slug charset. A capability map is rendered into
// traces and (later) into agent context, so an unvalidated value would be an
// injection surface; rejecting at the boundary keeps it inert data.
func validateCapabilities(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for role, tool := range in {
		if !slugRe.MatchString(role) {
			return nil, fmt.Errorf("%w: capability role %q must match %s", ErrInvalidInput, role, slugRe.String())
		}
		if !slugRe.MatchString(tool) {
			return nil, fmt.Errorf("%w: capability %q tool %q must match %s", ErrInvalidInput, role, tool, slugRe.String())
		}
		out[role] = tool
	}
	return out, nil
}

// validatePolicyPath bounds a configured policy layer path. It must be ABSOLUTE:
// a relative path would resolve against the daemon's working directory, which is
// not a stable, operator-visible location. The file's CONTENT needs no trust —
// every layer can only narrow (see policy.go) — but the path must be
// unambiguous.
func validatePolicyPath(field, p string) error {
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: %s %q must be an absolute path", ErrInvalidInput, field, p)
	}
	if strings.ContainsRune(p, '\x00') {
		return fmt.Errorf("%w: %s contains a NUL byte", ErrInvalidInput, field)
	}
	return nil
}

// validateRepoURL keeps the descriptive repo field free of control characters so
// it is safe to render in a table, an API response, or a trace payload.
func validateRepoURL(u string) error {
	if u == "" {
		return nil
	}
	if len(u) > 512 {
		return fmt.Errorf("%w: repo_url is too long (max 512)", ErrInvalidInput)
	}
	for _, r := range u {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: repo_url contains a control character", ErrInvalidInput)
		}
	}
	return nil
}

// sortProjects orders projects by id so every listing is deterministic.
func sortProjects(in []Project) []Project {
	sort.Slice(in, func(i, j int) bool { return in[i].ID < in[j].ID })
	return in
}

// sortEnvironments orders environments by id so every listing is deterministic.
func sortEnvironments(in []Environment) []Environment {
	sort.Slice(in, func(i, j int) bool { return in[i].ID < in[j].ID })
	return in
}
