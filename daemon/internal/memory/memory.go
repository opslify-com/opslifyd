// Package memory implements F8.10 — per-project project memory: a corpus of the
// operator's own documents (runbooks, architecture notes, postmortems, ADRs) that
// an agent can consult for estate-specific knowledge.
//
// Memory is RETRIEVED, never injected. That is the whole distinction from F8.4
// skills and it is not a performance detail:
//
//	skills  — small, curated, per tool     — INJECTED into every session
//	memory  — a corpus, dozens of files    — RETRIEVED on demand, only the part used
//
// Fifteen architecture documents would exhaust a session's context budget before
// the task started. So memory is a search surface, and the rule of thumb the UI
// should teach is: a rule the agent must always follow is a skill; a document it
// might need to consult is memory.
//
// Retrieval is LEXICAL — BM25 over heading-aware chunks. No model, no GPU, no
// network, and it must stay that way: a self-hosted install cannot be made to
// depend on an embedding service. An embedding backend may arrive later behind
// the Retriever interface, never in front of it.
//
// The deciding argument for lexical-first is not cost, it is provenance. F8.6
// records which documents a Change consulted, and that record is only worth
// keeping if the retrieval can be reproduced. An embedding index returns
// different documents after a model update, so the provenance would point at a
// retrieval nobody can re-run. Lexical scoring is deterministic: same corpus,
// same query, same citations, a year later.
package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/opslify-com/opslifyd/internal/wssync"
)

var (
	// ErrInvalidInput is a caller error: a bad path, an empty query.
	ErrInvalidInput = errors.New("memory: invalid input")
	// ErrUnsafeSource marks a document refused for a security reason rather than a
	// formatting one — a symlink, a credential-shaped filename, an oversized file.
	ErrUnsafeSource = errors.New("memory: unsafe source")
	// ErrNotFound is an unknown document.
	ErrNotFound = errors.New("memory: not found")
)

const (
	// maxDocBytes bounds one document. Refused rather than truncated: half a
	// runbook is worse than no runbook, because it reads as complete.
	maxDocBytes = 2 << 20 // 2 MiB
	// maxCorpusBytes bounds the whole store, so an accidental `cp -r` of a
	// monorepo into the memory folder fails loudly instead of consuming the host.
	maxCorpusBytes = 64 << 20 // 64 MiB
	// DefaultExcerptCap bounds a single search result's text.
	DefaultExcerptCap = 4000
	// DefaultK is how many excerpts a search returns when the caller does not say.
	DefaultK = 5
)

// Document is one file in the store.
type Document struct {
	// Rel is the path relative to the memory root, and the stable identity used
	// in citations and in the memory.read trace event.
	Rel string `json:"rel"`
	// Title is the first heading, or the filename when there is none.
	Title string `json:"title"`
	Bytes int    `json:"bytes"`
	// Hash is the SHA-256 of the content. It makes a citation checkable: a
	// document that changed after a Change consulted it is detectable.
	Hash string `json:"hash"`
	// Enabled is false for a document an operator has switched off. A disabled
	// document is indexed no further and never returned.
	Enabled bool `json:"enabled"`
	// Chunks is how many pieces it was split into.
	Chunks int `json:"chunks"`
}

// Chunk is one retrievable piece of a document.
type Chunk struct {
	Doc string
	// Heading is the heading path this chunk sits under ("Runbooks > Rollback"),
	// which is indexed along with the body. Operator documents are structured, and
	// matching the heading recovers most of what a semantic index would give.
	Heading   string
	StartLine int
	EndLine   int
	Text      string

	terms map[string]int
	len   int
}

// Excerpt is one search result, with everything needed to cite it.
type Excerpt struct {
	Doc       string  `json:"doc"`
	Title     string  `json:"title"`
	Heading   string  `json:"heading,omitempty"`
	StartLine int     `json:"start_line"`
	EndLine   int     `json:"end_line"`
	Text      string  `json:"text"`
	Score     float64 `json:"score"`
	// Truncated marks an excerpt cut at the cap. Marked, never silent: an agent
	// acting on half a procedure should know it has half.
	Truncated bool `json:"truncated,omitempty"`
}

// Retriever is the search seam. BM25 is the only implementation today; a local
// embedding backend can arrive behind this without changing the MCP tool, the
// CLI, or the shape of a memory.read event.
type Retriever interface {
	Search(query string, k int) []Excerpt
}

// Store is a project's memory: the documents, and the index over them.
type Store struct {
	root     string
	docs     []Document
	chunks   []Chunk
	disabled map[string]bool

	// df is the document frequency per term, over CHUNKS. avgLen is the mean
	// chunk length. Both are BM25 inputs, computed once at index time.
	df     map[string]int
	avgLen float64
}

// Options configure a store.
type Options struct {
	// Root is the memory directory, typically <workspace>/.opslify/memory.
	Root string
	// Disabled lists document Rel paths an operator has switched off.
	Disabled []string
}

// Open reads and indexes a memory root.
//
// A missing root is not an error — a project with no memory yet is the normal
// starting state, and refusing would make the first document impossible to add.
func Open(opts Options) (*Store, error) {
	if opts.Root == "" {
		return nil, fmt.Errorf("%w: a memory root is required", ErrInvalidInput)
	}
	s := &Store{root: opts.Root, disabled: map[string]bool{}, df: map[string]int{}}
	for _, d := range opts.Disabled {
		s.disabled[normalizeRel(d)] = true
	}
	if _, err := os.Stat(opts.Root); err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.index()
	return s, nil
}

// Root reports the directory this store reads.
func (s *Store) Root() string { return s.root }

// Documents returns the corpus, sorted by path. Deterministic order because it
// is rendered in a UI and compared in tests.
func (s *Store) Documents() []Document {
	out := append([]Document(nil), s.docs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

// load walks the root, applying the security filters.
func (s *Store) load() error {
	var total int
	return filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(s.root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}

		// A symlink is refused outright, directory or file.
		//
		// Inside a sandbox a symlink to /etc resolves within the container and is
		// harmless. This walk runs on the HOST, in the daemon, where a link to
		// ~/.ssh/id_rsa would be a read primitive for anything the daemon can open —
		// dressed as documentation. F8.4 already refuses symlinks for skill files
		// for exactly this reason, and memory is the larger surface: a repo somebody
		// cloned is far likelier to contain one than a hand-written skills folder.
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is a symlink; memory documents must be real files, "+
				"or a link could read any file the daemon can open", ErrUnsafeSource, rel)
		}
		if d.IsDir() {
			return nil
		}

		// The F7.3 deny-list, unconditionally. Runbooks and postmortems sit next to
		// exactly the credential-shaped files this filter exists to catch.
		if wssync.Excluded(rel) {
			return nil
		}
		if !isTextDoc(rel) {
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if info.Size() > maxDocBytes {
			return fmt.Errorf("%w: %s is %d bytes, over the %d-byte limit; split it",
				ErrUnsafeSource, rel, info.Size(), maxDocBytes)
		}
		total += int(info.Size())
		if total > maxCorpusBytes {
			return fmt.Errorf("%w: the memory corpus exceeds %d bytes; this is a knowledge "+
				"folder, not a data directory", ErrUnsafeSource, maxCorpusBytes)
		}

		b, rerr2 := os.ReadFile(p)
		if rerr2 != nil {
			return rerr2
		}
		sum := sha256.Sum256(b)
		doc := Document{
			Rel:     rel,
			Title:   titleOf(rel, string(b)),
			Bytes:   len(b),
			Hash:    hex.EncodeToString(sum[:]),
			Enabled: !s.disabled[rel],
		}
		if doc.Enabled {
			cs := chunk(rel, string(b))
			doc.Chunks = len(cs)
			s.chunks = append(s.chunks, cs...)
		}
		s.docs = append(s.docs, doc)
		return nil
	})
}

// isTextDoc keeps the corpus to what v1 can actually read. Anything else is
// skipped rather than indexed as binary noise.
func isTextDoc(rel string) bool {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".md", ".markdown", ".txt", ".rst", ".adoc":
		return true
	}
	return false
}

func normalizeRel(p string) string {
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(p)), "./")
}

// titleOf prefers the document's first heading over its filename.
func titleOf(rel, content string) string {
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			if h := strings.TrimSpace(strings.TrimLeft(t, "#")); h != "" {
				return h
			}
		}
	}
	return strings.TrimSuffix(filepath.Base(rel), filepath.Ext(rel))
}
