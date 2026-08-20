package regproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Cache is the daemon-owned on-disk artifact cache. It is CONTENT-KEY-ADDRESSED:
// an entry's filename is the hex SHA-256 of its LOGICAL KEY (ecosystem + upstream
// path), never any attacker-controlled path component. That is the cache-poisoning
// / path-traversal defense: a crafted package name like "../../etc/x" hashes to a
// fixed-width hex string under CacheDir, so it can neither escape the directory nor
// collide with another entry's file. A belt-and-suspenders containment check
// re-verifies the resolved path is inside CacheDir before any read/write.
//
// A nil *Cache is a valid no-op (every op is a miss / silent skip), so the proxy
// runs cache-less when no CacheDir is configured.
type Cache struct {
	dir string
}

// NewCache roots a cache at dir. An empty dir yields a nil cache (caching off).
// The dir is created 0700 (daemon-only) if absent.
func NewCache(dir string) (*Cache, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("regproxy: resolve cache dir %q: %w", dir, err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("regproxy: create cache dir: %w", err)
	}
	return &Cache{dir: abs}, nil
}

// keyFor is the content-key: hex(SHA256(ecosystem "\x00" upstreamPath)). It is
// fixed-width, hex-only (no path metacharacters), so it is inherently traversal-
// and collision-safe. The NUL separator prevents cross-ecosystem key confusion.
func keyFor(eco Ecosystem, upstreamPath string) string {
	h := sha256.Sum256([]byte(string(eco) + "\x00" + upstreamPath))
	return hex.EncodeToString(h[:])
}

// pathFor resolves a key to its on-disk file and VERIFIES containment: the cleaned
// join must stay directly under dir. keyFor only ever produces a 64-char hex
// string, but this guard means even a future keying bug cannot write outside the
// cache dir (defense-in-depth, fail-closed).
func (c *Cache) pathFor(key string) (string, error) {
	if key == "" || strings.ContainsAny(key, "/\\.") {
		return "", fmt.Errorf("regproxy: refusing unsafe cache key %q", key)
	}
	p := filepath.Join(c.dir, key)
	if filepath.Dir(p) != c.dir {
		return "", fmt.Errorf("regproxy: cache key %q escapes cache dir", key)
	}
	return p, nil
}

// Get returns the cached bytes for (eco, upstreamPath) and whether it was a hit.
// A nil cache, a miss, or any read error is a clean miss (fetch upstream).
func (c *Cache) Get(eco Ecosystem, upstreamPath string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	p, err := c.pathFor(keyFor(eco, upstreamPath))
	if err != nil {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return b, true
}

// Put stores bytes for (eco, upstreamPath) atomically (temp file + rename), 0600.
// A nil cache is a no-op. A containment/rename failure is returned so the caller
// can log it, but it never corrupts an existing entry (rename is atomic).
func (c *Cache) Put(eco Ecosystem, upstreamPath string, data []byte) error {
	if c == nil {
		return nil
	}
	p, err := c.pathFor(keyFor(eco, upstreamPath))
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.dir, ".art-*.tmp")
	if err != nil {
		return fmt.Errorf("regproxy: create cache temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("regproxy: chmod cache temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("regproxy: write cache temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("regproxy: close cache temp: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return fmt.Errorf("regproxy: commit cache entry: %w", err)
	}
	return nil
}
