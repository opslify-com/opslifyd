// Package wssync holds the shared, security-critical logic for F7.3
// host-linked workspaces: the secret-exclusion filter that decides which files
// may cross into the sandbox /workspace on copy-in, and which the manifest
// route is allowed to list. It is imported by BOTH the daemon (as a manifest
// guard) and the CLI sync engine (as a copy-in guard) so the two never diverge.
//
// The filter is a SECURITY control, not a convenience: it fails safe (exclude
// on doubt) and is applied BEFORE any transmission. A file that matches the
// deny-list is never uploaded even if a `.opslifyignore` is malformed or
// absent — the deny-list is unconditional and the ignore file may only ADD
// exclusions, never remove them.
package wssync

import (
	"bufio"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// denyGlobs are the default basename globs never copied into the sandbox. These
// are the credential-shaped files a naive `cp -r` of a project dir would drag
// straight into /workspace.
var denyGlobs = []string{
	".env",
	".env.*",
	"*.pem",
	"*.key",
	"id_rsa*",
	"id_dsa*",
	"id_ecdsa*",
	"id_ed25519*",
	"credentials",
	"credentials.*",
	".netrc",
	".npmrc",
	".pypirc",
	".htpasswd",
	".opslify-ca.pem",
}

// denySegments are path components whose presence anywhere in the relative path
// excludes the file. `.git/` internals are excluded (the working tree is what
// syncs; git metadata is host-side undo state, not agent input). `.aws/` and
// friends are credential directories.
var denySegments = []string{
	".git",
	".aws",
	".gcloud",
	".azure",
	".ssh",
	".opslify-backup", // our own snapshot artifacts (prefix-matched below too)
}

// entropyFloor / entropyThreshold gate the high-entropy-filename heuristic. They
// mirror the F3.3 redaction defaults (a token clearing >4.0 bits/char and >=24
// chars is secret-shaped, not a git SHA or ordinary identifier).
const (
	entropyFloor     = 24
	entropyThreshold = 4.2
)

// normalizeRel returns a cleaned, forward-slashed, root-relative path, or ""
// if the input escapes the tree (leading "..") — which the caller treats as
// excluded (fail safe).
func normalizeRel(relPath string) string {
	rel := filepath.ToSlash(filepath.Clean(relPath))
	rel = strings.TrimPrefix(rel, "./")
	if rel == "." || rel == "" {
		return ""
	}
	if rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
		return ""
	}
	return rel
}

// Excluded reports whether a workspace-relative path matches the DEFAULT
// secret deny-list. It is the unconditional guard used by the manifest route
// and the floor beneath the CLI Filter. On any doubt (an unparseable path, a
// traversal attempt) it returns true — excluded.
func Excluded(relPath string) bool {
	rel := normalizeRel(relPath)
	if rel == "" {
		return true // traversal / empty / root — never a syncable file
	}
	segs := strings.Split(rel, "/")
	for _, seg := range segs {
		for _, deny := range denySegments {
			if seg == deny || strings.HasPrefix(seg, ".opslify-backup") {
				return true
			}
		}
		// Our own conflict siblings are never synced back in.
		if strings.HasSuffix(seg, ".opslify-conflict") {
			return true
		}
	}
	base := segs[len(segs)-1]
	for _, g := range denyGlobs {
		if ok, _ := path.Match(g, base); ok {
			return true
		}
	}
	if highEntropyName(base) {
		return true
	}
	return false
}

// highEntropyName flags a filename whose stem looks like a raw secret token
// (long, high Shannon entropy) rather than a human-meaningful name. This catches
// dumped credential files named after the token itself.
func highEntropyName(base string) bool {
	stem := base
	if i := strings.LastIndexByte(stem, '.'); i > 0 {
		stem = stem[:i]
	}
	if len(stem) < entropyFloor {
		return false
	}
	// Only score names made purely of token characters; a name with spaces or
	// many separators is human-readable, not a raw token.
	for i := 0; i < len(stem); i++ {
		if !tokenChar(stem[i]) {
			return false
		}
	}
	return shannonBits(stem) >= entropyThreshold
}

func tokenChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+' || c == '/' || c == '=' || c == '_' || c == '-':
		return true
	default:
		return false
	}
}

func shannonBits(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Filter is the CLI-side copy-in guard: the default deny-list PLUS any extra
// patterns loaded from a host-dir `.opslifyignore` (a gitignore-syntax subset).
// The extra patterns can only ADD exclusions — a malformed or absent ignore
// file never widens what may be transmitted.
type Filter struct {
	extra []ignorePattern
}

type ignorePattern struct {
	glob    string // path.Match pattern, no leading slash, no trailing slash
	dirOnly bool   // pattern ended with "/" — matches a directory subtree
	anchor  bool   // pattern contained a "/" — matched against the full rel path
}

// DefaultFilter is the deny-list-only filter (no host ignore file).
func DefaultFilter() *Filter { return &Filter{} }

// LoadFilter builds a Filter augmenting the default deny-list with the host
// dir's `.opslifyignore` if present and readable. Parse errors on individual
// lines are skipped (fail safe: a bad line simply adds nothing); a missing or
// unreadable file yields the default filter. The deny-list always applies.
func LoadFilter(hostDir string) *Filter {
	f := &Filter{}
	data, err := os.Open(filepath.Join(hostDir, ".opslifyignore"))
	if err != nil {
		return f
	}
	defer data.Close()
	sc := bufio.NewScanner(data)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue // blank, comment, or (unsupported) negation — never un-excludes
		}
		p := ignorePattern{}
		if strings.HasSuffix(line, "/") {
			p.dirOnly = true
			line = strings.TrimSuffix(line, "/")
		}
		line = strings.TrimPrefix(line, "/")
		if line == "" {
			continue
		}
		p.anchor = strings.Contains(line, "/")
		p.glob = line
		// Validate the glob once; skip an unparseable pattern (fail safe).
		if _, err := path.Match(p.glob, "x"); err != nil {
			continue
		}
		f.extra = append(f.extra, p)
	}
	return f
}

// Excluded reports whether relPath is excluded by the default deny-list or by
// the loaded `.opslifyignore` patterns.
func (f *Filter) Excluded(relPath string) bool {
	if Excluded(relPath) {
		return true
	}
	rel := normalizeRel(relPath)
	if rel == "" {
		return true
	}
	segs := strings.Split(rel, "/")
	base := segs[len(segs)-1]
	for _, p := range f.extra {
		if p.anchor {
			if ok, _ := path.Match(p.glob, rel); ok {
				return true
			}
			// A dir pattern also excludes everything beneath it.
			if p.dirOnly && strings.HasPrefix(rel, p.glob+"/") {
				return true
			}
			continue
		}
		if p.dirOnly {
			// Match the directory name anywhere in the path.
			for _, seg := range segs[:len(segs)-1] {
				if ok, _ := path.Match(p.glob, seg); ok {
					return true
				}
			}
			continue
		}
		if ok, _ := path.Match(p.glob, base); ok {
			return true
		}
	}
	return false
}
