package agentcontext

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Repo-relative locations of the workspace-sourced layers. These live in the
// repo on purpose: they are reviewed in an MR like any other change.
const (
	instructionsRelPath = ".opslify/instructions.md"
	envRelDir           = ".opslify/env"
	skillsRelDir        = ".opslify/skills"
)

// DefaultHouseRulesPath is the daemon-held house-rules file. It sits under
// /etc/opslify with the daemon's other authoritative files and is deliberately
// NOT under the workspace: the layer's entire value is that a repo commit — or
// an agent with commit access — cannot change it.
const DefaultHouseRulesPath = "/etc/opslify/house-rules.md"

// envNameRe bounds an environment name to what can safely become one path
// segment. The environment name arrives from a caller and is joined into a
// path, so this is the trust boundary: without it, env "../../../../etc/shadow"
// would make the daemon read an arbitrary file and hand it to a model.
var envNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// validateEnvName refuses anything that is not a single safe path segment.
func validateEnvName(env string) error {
	if env == "" {
		return nil // no environment overlay requested
	}
	if !envNameRe.MatchString(env) {
		return fmt.Errorf("%w: environment name %q must be lowercase alphanumeric with dashes (1-40 chars)", ErrInvalidInput, env)
	}
	return nil
}

// loadHouseRules reads layer 1 from the DAEMON path.
//
// It refuses rather than degrades. A house-rules file that exists but cannot be
// read, or whose permissions let a non-owner rewrite it, means the constraint
// layer is not trustworthy — and a session that runs without its constraints,
// silently, is the exact failure this layer exists to prevent. A file that is
// simply absent is fine: no house rules configured.
func loadHouseRules(path, workspaceRoot string) (*Layer, error) {
	if path == "" {
		path = DefaultHouseRulesPath
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no house rules configured
		}
		return nil, fmt.Errorf("%w: house rules %s: %v", ErrUnsafeSource, path, err)
	}
	// A symlink here could point INTO the workspace, which would quietly turn the
	// one repo-unreachable layer into a repo-controlled one.
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: house rules %s is a symlink; layer 1 must be a real file on the daemon host, or the repo could redirect it", ErrUnsafeSource, path)
	}
	// IsRegular is the BACKSTOP for the symlink check above (Lstat means a symlink
	// is never regular), and it also refuses a fifo/device. Mutation testing shows
	// either line alone holds the property — keep both: the explicit check names
	// the threat, this one catches everything else that is not a plain file.
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: house rules %s is not a regular file", ErrUnsafeSource, path)
	}
	// Group- or world-writable means someone other than the owner can rewrite the
	// agent's constraints. Read-only to others is fine and expected.
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return nil, fmt.Errorf("%w: house rules %s is mode %04o; it must not be group- or world-writable, or its rules can be rewritten by anyone", ErrUnsafeSource, path, perm)
	}
	if workspaceRoot != "" {
		inside, err := isInside(workspaceRoot, path)
		if err != nil {
			return nil, err
		}
		if inside {
			return nil, fmt.Errorf("%w: house rules %s resolves inside the workspace %s; layer 1 must never be workspace-sourced", ErrUnsafeSource, path, workspaceRoot)
		}
	}
	if int(info.Size()) > maxLayerBytes {
		return nil, tooBig("house rules", int(info.Size()), maxLayerBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: house rules %s: %v", ErrUnsafeSource, path, err)
	}
	return newLayer(LayerHouseRules, "house-rules", string(b)), nil
}

// isInside reports whether path, with symlinks resolved, sits within root.
func isInside(root, path string) (bool, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%w: resolve workspace %s: %v", ErrInvalidInput, root, err)
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%w: resolve %s: %v", ErrInvalidInput, path, err)
	}
	rel, err := filepath.Rel(realRoot, realPath)
	if err != nil {
		return false, nil
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

// readWorkspaceFile reads one repo-sourced file under root.
//
// The workspace is UNTRUSTED input: the agent can write to it during a session.
// So every read here refuses a symlink outright. A skill file symlinked to
// /etc/opslify/vault.key or ~/.ssh/id_rsa would otherwise be read by the daemon
// and placed straight into the model's context — a read primitive for any file
// the daemon can open, disguised as documentation.
func readWorkspaceFile(root, rel string) (string, bool, error) {
	full := filepath.Join(root, rel)
	info, err := os.Lstat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("%w: %s: %v", ErrUnsafeSource, rel, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", false, fmt.Errorf("%w: %s is a symlink; workspace context files must be real files, or a link could read any file the daemon can open", ErrUnsafeSource, rel)
	}
	if !info.Mode().IsRegular() {
		return "", false, fmt.Errorf("%w: %s is not a regular file", ErrUnsafeSource, rel)
	}
	if int(info.Size()) > maxLayerBytes {
		return "", false, tooBig(rel, int(info.Size()), maxLayerBytes)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return "", false, fmt.Errorf("%w: %s: %v", ErrUnsafeSource, rel, err)
	}
	return string(b), true, nil
}

// loadProjectInstructions reads layer 2.
func loadProjectInstructions(root string) (*Layer, error) {
	if root == "" {
		return nil, nil
	}
	content, ok, err := readWorkspaceFile(root, instructionsRelPath)
	if err != nil || !ok {
		return nil, err
	}
	return newLayer(LayerProjectInstructions, "instructions", content), nil
}

// loadEnvOverlay reads layer 3 for one environment.
func loadEnvOverlay(root, env string) (*Layer, error) {
	if root == "" || env == "" {
		return nil, nil
	}
	if err := validateEnvName(env); err != nil {
		return nil, err
	}
	rel := filepath.Join(envRelDir, env+".md")
	content, ok, err := readWorkspaceFile(root, rel)
	if err != nil || !ok {
		return nil, err
	}
	return newLayer(LayerEnvOverlay, "env/"+env, content), nil
}

// loadSkills reads layer 4: every *.md in .opslify/skills, name-sorted so the
// assembly (and therefore its hash) is stable across machines and filesystems.
// selected, when non-nil, limits the set to those skill names — the routing
// decision from the capability map.
func loadSkills(root string, selected map[string]bool) ([]Layer, error) {
	if root == "" {
		return nil, nil
	}
	dir := filepath.Join(root, skillsRelDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: read %s: %v", ErrUnsafeSource, skillsRelDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".md") || strings.HasPrefix(name, ".") {
			continue
		}
		// A directory named foo.md, or a symlinked one, is not a skill.
		if e.IsDir() {
			continue
		}
		skill := strings.TrimSuffix(name, ".md")
		if selected != nil && !selected[skill] {
			continue
		}
		names = append(names, name)
	}
	// os.ReadDir already returns entries sorted by filename, so this is redundant
	// today. It is kept because the sort is a CORRECTNESS requirement, not a
	// convenience: readdir order feeds the assembly hash, and a future switch to
	// os.Open+Readdir (which does NOT sort) would silently make the same repo hash
	// differently on two machines.
	sort.Strings(names)

	out := make([]Layer, 0, len(names))
	for _, name := range names {
		content, ok, err := readWorkspaceFile(root, filepath.Join(skillsRelDir, name))
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, *newLayer(LayerSkill, "skills/"+strings.TrimSuffix(name, ".md"), content))
	}
	return out, nil
}

// skillsOnDisk lists the skill names present in a workspace, for `skill ls` and
// for reporting which of the routed packs were missing.
func skillsOnDisk(root string) ([]string, error) {
	if root == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(filepath.Join(root, skillsRelDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: read %s: %v", ErrUnsafeSource, skillsRelDir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".md"))
	}
	sort.Strings(out)
	return out, nil
}
