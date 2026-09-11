package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A project may name its own host directory for /workspace, so an operator can
// clone a repo into it and open the same files in their editor while the agent
// works on them.
//
// That is a deliberate loosening and this file is where it is bounded. A bind
// mount has NO deny-list — unlike F7.3's copy-in path, which filters
// credential-shaped files on the way through. Everything in the chosen directory
// is visible to every sandbox for the project, which is why the checks below
// refuse the directories where a credential is most likely to be sitting, and why
// ScanForSecrets exists to refuse the specific files.

// systemRoots are never a workspace. Mounting one would hand a sandbox the host's
// configuration, not a project's code.
var systemRoots = []string{
	"/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot",
	"/proc", "/sys", "/dev", "/run", "/var", "/opt", "/srv", "/root",
}

// ValidateWorkspacePath checks a caller-chosen workspace directory.
//
// It is deliberately strict about WHICH directory rather than what is in it: a
// home directory is refused outright, because "~/ is my workspace" is the single
// most likely way to hand an agent ~/.ssh, ~/.aws and ~/.config by accident. A
// dedicated directory beneath it is the shape that works.
func ValidateWorkspacePath(p string) error {
	if p == "" {
		return nil
	}
	if strings.ContainsRune(p, '\x00') {
		return fmt.Errorf("%w: workspace_path contains a NUL byte", ErrInvalidInput)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%w: workspace_path %q must be an absolute path", ErrInvalidInput, p)
	}
	clean := filepath.Clean(p)
	if clean != p {
		return fmt.Errorf("%w: workspace_path %q is not in canonical form (did you mean %q?)",
			ErrInvalidInput, p, clean)
	}
	for _, root := range systemRoots {
		if clean == root {
			return fmt.Errorf("%w: %q is a system directory, not a workspace; "+
				"make a directory for this project (e.g. ~/opslify-workspace/%s)",
				ErrInvalidInput, clean, filepath.Base(clean))
		}
	}
	// A home directory itself is refused. Everything an operator is trying to keep
	// away from the agent lives one level inside it.
	if home, err := os.UserHomeDir(); err == nil && home != "" && clean == filepath.Clean(home) {
		return fmt.Errorf("%w: %q is a home directory. A sandbox sees everything in the "+
			"directory it mounts, including .ssh, .aws and .config — use a dedicated one "+
			"such as %s", ErrInvalidInput, clean, filepath.Join(clean, "opslify-workspace", "myproject"))
	}

	info, err := os.Lstat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			// Created on first use rather than refused: asking an operator to mkdir
			// before naming a path is a step that exists only to be forgotten.
			return nil
		}
		return fmt.Errorf("%w: workspace_path %q: %v", ErrInvalidInput, clean, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// The mount would follow it, so the path an operator reads in the UI would
		// not be the directory the agent gets.
		return fmt.Errorf("%w: workspace_path %q is a symlink; name the directory it "+
			"points at, so what you see is what is mounted", ErrInvalidInput, clean)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: workspace_path %q is not a directory", ErrInvalidInput, clean)
	}
	return nil
}

// SecretFinding is one credential-shaped file found in a proposed workspace.
type SecretFinding struct {
	Rel string `json:"rel"`
	Why string `json:"why"`
}

// ScanForSecrets walks a proposed workspace looking for the files a bind mount
// would expose.
//
// This is the check F7.3's deny-list performs on copy-in and a bind mount cannot:
// there is no filter between a mounted directory and the sandbox, so the only
// moment to catch a credential is before the mount is agreed to. Reported rather
// than silently excluded, because the operator is the only one who can decide
// whether the .env in their repo matters.
func ScanForSecrets(root string, limit int) ([]SecretFinding, error) {
	if root == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	var out []SecretFinding
	seen := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil // unreadable is not this scan's problem
		}
		seen++
		// Bounded: a scan that walks a monorepo for a minute is a scan nobody runs.
		if seen > 200000 || len(out) >= limit {
			return filepath.SkipAll
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if why, bad := secretDir(filepath.Base(rel)); bad {
				out = append(out, SecretFinding{Rel: rel + "/", Why: why})
				return filepath.SkipDir
			}
			return nil
		}
		if why, bad := secretFile(filepath.Base(rel)); bad {
			out = append(out, SecretFinding{Rel: rel, Why: why})
		}
		return nil
	})
	return out, err
}

func secretDir(base string) (string, bool) {
	switch base {
	case ".ssh":
		return "private keys", true
	case ".aws", ".azure", ".gcloud", ".kube":
		return "cloud credentials", true
	case ".gnupg":
		return "GPG keys", true
	case ".config":
		return "application credentials", true
	}
	return "", false
}

func secretFile(base string) (string, bool) {
	lower := strings.ToLower(base)
	switch {
	case lower == ".env" || strings.HasPrefix(lower, ".env."):
		return "environment file — routinely holds tokens", true
	case strings.HasSuffix(lower, ".pem"), strings.HasSuffix(lower, ".key"),
		strings.HasSuffix(lower, ".p12"), strings.HasSuffix(lower, ".pfx"):
		return "key material", true
	case strings.HasPrefix(lower, "id_rsa"), strings.HasPrefix(lower, "id_ed25519"),
		strings.HasPrefix(lower, "id_ecdsa"), strings.HasPrefix(lower, "id_dsa"):
		return "private key", true
	case lower == ".netrc", lower == ".npmrc", lower == ".pypirc", lower == ".git-credentials":
		return "stored credentials", true
	case strings.HasPrefix(lower, "credentials"):
		return "credentials file", true
	case strings.HasSuffix(lower, ".tfstate"), strings.HasSuffix(lower, ".tfstate.backup"):
		return "terraform state — frequently contains secrets in clear", true
	case lower == "kubeconfig":
		return "cluster credentials", true
	}
	return "", false
}
