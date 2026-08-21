package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/opslify-com/opslifyd/internal/wssync"
)

// ManifestEntry describes one file in a session's /workspace: its
// workspace-relative path (forward-slashed), size, mtime (unix seconds) and
// content hash. The CLI diffs host vs sandbox off this without downloading
// every file.
type ManifestEntry struct {
	RelPath string `json:"rel_path"`
	Size    int64  `json:"size"`
	ModUnix int64  `json:"mod_unix"`
	SHA256  string `json:"sha256"`
}

// maxManifestFiles bounds how many files the manifest will enumerate. A hostile
// workspace must not exhaust the host by generating an unbounded file tree; the
// walk stops (with a legible error) rather than streaming forever.
const maxManifestFiles = 50000

// Manifest walks the session's /workspace and returns a hashed manifest of its
// files, path-guarded exactly like the mediated file surface. It NEVER follows
// a symlink out of the workspace (symlinks are skipped), never lists a path the
// secret deny-list excludes, and re-validates every path through
// resolveWorkspacePath so a crafted tree cannot escape the root. Files larger
// than MaxFileBytes are skipped (they cannot be transferred anyway).
func (m *Manager) Manifest(ctx context.Context, id string) ([]ManifestEntry, error) {
	root, err := m.workspaceRoot(id)
	if err != nil {
		return nil, err
	}
	rootClean := filepath.Clean(root)

	entries := make([]ManifestEntry, 0, 64)
	count := 0
	walkErr := filepath.WalkDir(rootClean, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A vanished/again-unreadable entry mid-walk is skipped, not fatal —
			// the workspace is live and the agent may be writing concurrently.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if p == rootClean {
			return nil
		}
		// Never follow symlinks: a link pointing outside the tree must not leak a
		// host path. Skip both symlinked dirs (don't descend) and symlinked files.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // sockets/devices/pipes are not syncable content
		}
		rel, err := filepath.Rel(rootClean, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		// Guard #1: the secret deny-list — an excluded path is never listed.
		if wssync.Excluded(rel) {
			return nil
		}
		// Guard #2: re-resolve through the same trust boundary the transfer uses,
		// so anything that would escape root is refused rather than hashed.
		host, err := resolveWorkspacePath(rootClean, rel)
		if err != nil || host != p {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > MaxFileBytes {
			return nil
		}
		sum, err := hashFile(p)
		if err != nil {
			return nil
		}
		entries = append(entries, ManifestEntry{
			RelPath: rel,
			Size:    info.Size(),
			ModUnix: info.ModTime().Unix(),
			SHA256:  sum,
		})
		count++
		if count > maxManifestFiles {
			return fmt.Errorf("%w: workspace exceeds %d files (manifest cap)", ErrInvalidInput, maxManifestFiles)
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("session: manifest %s: %w", id, walkErr)
	}
	return entries, nil
}

// hashFile returns the hex SHA-256 of a file, streaming so a large file does not
// buffer in memory.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
