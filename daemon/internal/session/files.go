package session

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// workspaceMount is the in-container path the per-session host workspace is
// bind-mounted at. It is the ONLY writable area exposed through the mediated
// file-transfer surface (F2.1 upload/download).
const workspaceMount = "/workspace"

// MaxFileBytes bounds a single mediated upload or download (decoded bytes). A
// hostile occupant must not exfiltrate an arbitrarily large blob or OOM the
// daemon/client through the file surface. On the wire the base64 body is ~4/3
// this size. The 10 MB acceptance round-trip fits comfortably.
const MaxFileBytes = 64 << 20

// WriteFile writes content to path inside the session's /workspace. path may be
// given container-absolute ("/workspace/foo") or relative to /workspace
// ("foo/bar"); anything resolving outside /workspace is rejected (hostile input,
// path traversal). Oversize content is rejected. The parent directory is created
// under /workspace as needed. The file is written 0600 (never executable, never
// group/other-readable).
func (m *Manager) WriteFile(ctx context.Context, id, path string, content []byte) error {
	if len(content) > MaxFileBytes {
		return fmt.Errorf("%w: file too large: %d bytes (max %d)", ErrInvalidInput, len(content), MaxFileBytes)
	}
	root, err := m.workspaceRoot(id)
	if err != nil {
		return err
	}
	host, err := resolveWorkspacePath(root, path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(host), 0o700); err != nil {
		return fmt.Errorf("session: upload %s: %w", id, err)
	}
	if err := os.WriteFile(host, content, 0o600); err != nil {
		return fmt.Errorf("session: upload %s: %w", id, err)
	}
	return nil
}

// ReadFile reads path from inside the session's /workspace, with the same path
// confinement and size bound as WriteFile. A path outside /workspace, a missing
// file, or an oversize file is a legible error — never a host-path read.
func (m *Manager) ReadFile(ctx context.Context, id, path string) ([]byte, error) {
	root, err := m.workspaceRoot(id)
	if err != nil {
		return nil, err
	}
	host, err := resolveWorkspacePath(root, path)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(host)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: no such file under /workspace: %s", ErrInvalidInput, path)
		}
		return nil, fmt.Errorf("session: download %s: %w", id, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("%w: path is a directory: %s", ErrInvalidInput, path)
	}
	if fi.Size() > MaxFileBytes {
		return nil, fmt.Errorf("%w: file too large: %d bytes (max %d)", ErrInvalidInput, fi.Size(), MaxFileBytes)
	}
	data, err := os.ReadFile(host)
	if err != nil {
		return nil, fmt.Errorf("session: download %s: %w", id, err)
	}
	return data, nil
}

// workspaceRoot returns the host workspace directory for a live session,
// erroring legibly if the session is unknown or has no writable workspace.
func (m *Manager) workspaceRoot(id string) (string, error) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	dir := ""
	if ok {
		dir = s.WorkspaceDir
	}
	m.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if dir == "" {
		return "", fmt.Errorf("%w: session %s has no writable workspace", ErrInvalidInput, id)
	}
	return dir, nil
}

// resolveWorkspacePath maps a caller-supplied /workspace path to a host path
// under root, rejecting anything that would escape the writable area. It is the
// trust boundary for the mediated file surface: the occupant/agent is hostile,
// so traversal ("../"), a non-/workspace absolute path, and NUL are all denied
// BEFORE any filesystem access. It is a pure function so the confinement is
// unit-testable without a real session.
func resolveWorkspacePath(root, path string) (string, error) {
	if strings.ContainsRune(path, '\x00') {
		return "", fmt.Errorf("%w: NUL byte in path", ErrInvalidInput)
	}
	rel := path
	if strings.HasPrefix(path, "/") {
		clean := filepath.Clean(path)
		if clean != workspaceMount && !strings.HasPrefix(clean, workspaceMount+"/") {
			return "", fmt.Errorf("%w: path %q must be under %s", ErrInvalidInput, path, workspaceMount)
		}
		rel = strings.TrimPrefix(clean, workspaceMount+"/")
		if clean == workspaceMount {
			rel = ""
		}
	}
	rel = filepath.Clean(rel)
	// Reject traversal explicitly (rather than silently clamping it) so a hostile
	// path is a legible error, not a surprising rewrite.
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: path %q escapes %s", ErrInvalidInput, path, workspaceMount)
	}
	if rel == "" || rel == "." {
		return "", fmt.Errorf("%w: path must name a file under %s, not the directory itself", ErrInvalidInput, workspaceMount)
	}
	host := filepath.Join(root, rel)
	// Defence in depth: after joining+cleaning, the result MUST still be within
	// root. Catches any traversal the prefix checks above did not.
	rootClean := filepath.Clean(root)
	if host != rootClean && !strings.HasPrefix(host, rootClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: path %q escapes the workspace", ErrInvalidInput, path)
	}
	return host, nil
}
