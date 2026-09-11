// Package projectdoc is the safe-write path for the markdown a project is made
// of: its skills, its memory, and its instructions file.
//
// These are the documents an operator authors, and until now the only way to
// create one was to open an editor on the host. That is fine when the workspace
// is a directory you already have open and useless when it is not — so this is
// the narrow write surface that lets the cockpit do it.
//
// Narrow is the operative word. It reads and writes markdown in three known
// directories under .opslify/ and nowhere else: not the cloned repositories, not
// arbitrary workspace paths. The large untrusted surface — whatever the agent
// cloned — stays unreadable and unwritable from a browser. That is what F3.6
// protects and what a general file editor would have given away.
package projectdoc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/opslify-com/opslifyd/internal/wssync"
)

var (
	// ErrInvalidInput is a caller error: a bad name, an oversized document.
	ErrInvalidInput = errors.New("projectdoc: invalid input")
	// ErrNotFound is a document that is not there.
	ErrNotFound = errors.New("projectdoc: not found")
	// ErrUnsafe marks a path refused for a security reason rather than a
	// formatting one — a traversal, a symlink, a credential-shaped name.
	ErrUnsafe = errors.New("projectdoc: unsafe path")
)

// Kind is which of a project's document sets a path belongs to.
type Kind string

const (
	// KindSkill is a rule the agent must ALWAYS follow. Injected into every
	// session, which is why these are short by design.
	KindSkill Kind = "skill"
	// KindMemory is a document it MIGHT need to consult. Retrieved on demand and
	// cited, so a corpus costs nothing until something matches.
	KindMemory Kind = "memory"
	// KindInstructions is the single project-wide instructions file.
	KindInstructions Kind = "instructions"
)

// maxDocBytes bounds one document. A skill is a page and a runbook is a few; a
// megabyte of markdown is a mistake rather than a document.
const maxDocBytes = 512 << 10

// dirFor maps a kind to its directory under the workspace.
func dirFor(k Kind) (string, error) {
	switch k {
	case KindSkill:
		return filepath.Join(".opslify", "skills"), nil
	case KindMemory:
		return filepath.Join(".opslify", "memory"), nil
	case KindInstructions:
		return ".opslify", nil
	}
	return "", fmt.Errorf("%w: unknown document kind %q", ErrInvalidInput, k)
}

// Doc is one document, listed or fetched.
type Doc struct {
	Kind     Kind      `json:"kind"`
	Path     string    `json:"path"`
	Bytes    int       `json:"bytes"`
	Modified time.Time `json:"modified"`
	// Content is present only on a single-document fetch.
	Content string `json:"content,omitempty"`
}

// resolve turns (workspace, kind, relative path) into an absolute file path,
// refusing anything that would land outside the kind's directory.
//
// The containment check is on the CLEANED, JOINED result rather than on the input
// string. A deny-list of "../" catches the obvious spelling and misses the ones
// that matter; the only question worth asking is where the path actually points.
func resolve(workspace string, k Kind, rel string) (string, error) {
	if workspace == "" {
		return "", fmt.Errorf("%w: this project has no workspace", ErrInvalidInput)
	}
	sub, err := dirFor(k)
	if err != nil {
		return "", err
	}
	rel = strings.TrimSpace(rel)
	if k == KindInstructions {
		// Exactly one file, named by the kind. F8.4 reads this path and no other,
		// so letting a caller choose the name would produce a file nothing loads.
		rel = "instructions.md"
	}
	if rel == "" {
		return "", fmt.Errorf("%w: a document name is required", ErrInvalidInput)
	}
	if strings.ContainsRune(rel, 0) {
		return "", fmt.Errorf("%w: the name contains a NUL byte", ErrInvalidInput)
	}
	if !strings.HasSuffix(strings.ToLower(rel), ".md") {
		return "", fmt.Errorf("%w: %q must be a .md file — these are markdown documents "+
			"and anything else would never be read", ErrInvalidInput, rel)
	}
	// A credential-shaped name is refused even here. Every read path excludes it
	// anyway, so accepting the write would create a file nothing uses.
	if wssync.Excluded(filepath.ToSlash(rel)) {
		return "", fmt.Errorf("%w: %q looks like a credential file and would be excluded "+
			"from every read; documents hold knowledge, the vault holds secrets", ErrUnsafe, rel)
	}

	root := filepath.Join(workspace, sub)
	full := filepath.Clean(filepath.Join(root, rel))
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q resolves outside the %s directory", ErrUnsafe, rel, sub)
	}
	// A symlink anywhere along the way would let a write land outside the
	// workspace entirely. Checked per component, because the final path may not
	// exist yet and Lstat on it would say nothing about its parents.
	if err := noSymlinks(root, full); err != nil {
		return "", err
	}
	return full, nil
}

// noSymlinks walks from root to full, refusing any component that is a symlink.
func noSymlinks(root, full string) error {
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafe, err)
	}
	cur := root
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				// Nothing beyond here exists, so nothing beyond here can be a link.
				return nil
			}
			return fmt.Errorf("%w: %v", ErrUnsafe, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is a symlink; a write through one would land outside "+
				"the workspace", ErrUnsafe, part)
		}
	}
	return nil
}

// List returns a kind's documents.
func List(workspace string, k Kind) ([]Doc, error) {
	sub, err := dirFor(k)
	if err != nil {
		return nil, err
	}
	if workspace == "" {
		return nil, nil
	}
	root := filepath.Join(workspace, sub)
	var out []Doc
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(strings.ToLower(rel), ".md") || wssync.Excluded(rel) {
			return nil
		}
		if k == KindInstructions && rel != "instructions.md" {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		out = append(out, Doc{Kind: k, Path: rel, Bytes: int(info.Size()), Modified: info.ModTime()})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Read returns one document's content.
func Read(workspace string, k Kind, rel string) (Doc, error) {
	full, err := resolve(workspace, k, rel)
	if err != nil {
		return Doc{}, err
	}
	info, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return Doc{}, fmt.Errorf("%w: %s", ErrNotFound, rel)
		}
		return Doc{}, err
	}
	if info.Size() > maxDocBytes {
		return Doc{}, fmt.Errorf("%w: %s is %d bytes, over the %d limit",
			ErrInvalidInput, rel, info.Size(), maxDocBytes)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return Doc{}, err
	}
	return Doc{
		Kind: k, Path: filepath.ToSlash(rel), Bytes: len(b),
		Modified: info.ModTime(), Content: string(b),
	}, nil
}

// Write creates or replaces a document.
func Write(workspace string, k Kind, rel, content string) (Doc, error) {
	if len(content) > maxDocBytes {
		return Doc{}, fmt.Errorf("%w: %d bytes is over the %d limit; split it",
			ErrInvalidInput, len(content), maxDocBytes)
	}
	full, err := resolve(workspace, k, rel)
	if err != nil {
		return Doc{}, err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return Doc{}, err
	}
	// Written to a temp file and renamed, so a reader never sees half a document.
	// The memory index is rebuilt on every search and would happily index a
	// truncated one, which is a worse failure than a write that did not happen.
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return Doc{}, err
	}
	if err := os.Rename(tmp, full); err != nil {
		os.Remove(tmp)
		return Doc{}, err
	}
	info, err := os.Stat(full)
	if err != nil {
		return Doc{}, err
	}
	return Doc{Kind: k, Path: filepath.ToSlash(rel), Bytes: len(content), Modified: info.ModTime()}, nil
}

// Delete removes a document.
//
// Absence is an error rather than a silent success: an operator deleting
// something that is not there has the wrong name, and saying so is more useful
// than agreeing with them.
func Delete(workspace string, k Kind, rel string) error {
	full, err := resolve(workspace, k, rel)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrNotFound, rel)
		}
		return err
	}
	return nil
}
