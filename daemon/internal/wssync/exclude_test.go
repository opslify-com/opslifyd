package wssync

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExcludedSecretDenyList is the load-bearing security assertion: a planted
// credential file is NEVER allowed across into the sandbox.
func TestExcludedSecretDenyList(t *testing.T) {
	deny := []string{
		".env",
		".env.local",
		".env.production",
		"server.pem",
		"tls.key",
		"id_rsa",
		"id_rsa.pub",
		"id_ed25519",
		"credentials",
		"credentials.json",
		".aws/credentials",
		"nested/dir/.env",
		"deploy/keys/prod.pem",
		".opslify-ca.pem",
		".git/config",
		".ssh/known_hosts",
		".npmrc",
		"secret.opslify-conflict",
		".opslify-backup-20260101-000000/foo",
	}
	for _, p := range deny {
		if !Excluded(p) {
			t.Errorf("Excluded(%q) = false; secret/denied path must be excluded", p)
		}
	}
}

// TestExcludedAllowsOrdinaryFiles guards against over-scrubbing ordinary source.
func TestExcludedAllowsOrdinaryFiles(t *testing.T) {
	allow := []string{
		"main.go",
		"README.md",
		"src/app/index.ts",
		"config.yaml",
		"Makefile",
		"pkg/util.go",
		"docs/design.md",
	}
	for _, p := range allow {
		if Excluded(p) {
			t.Errorf("Excluded(%q) = true; ordinary file must NOT be excluded", p)
		}
	}
}

// TestExcludedTraversalFailsSafe: a traversal or absolute path is excluded.
func TestExcludedTraversalFailsSafe(t *testing.T) {
	for _, p := range []string{"../escape", "../../etc/passwd", "/etc/passwd", "..", ".", ""} {
		if !Excluded(p) {
			t.Errorf("Excluded(%q) = false; traversal/degenerate path must be excluded", p)
		}
	}
}

// TestExcludedHighEntropyName catches a file named after a raw secret token.
func TestExcludedHighEntropyName(t *testing.T) {
	if !Excluded("aGVsbG8gd29ybGQgc2VjcmV0IHRva2Vu9zZ") {
		t.Error("high-entropy token filename must be excluded")
	}
	if Excluded("this-is-a-long-but-readable-filename.txt") {
		t.Error("long readable name must NOT be excluded")
	}
}

// TestFilterOpslifyignoreAddsExclusions: the ignore file only ADDS exclusions,
// and a deny-listed file stays excluded regardless of the ignore file.
func TestFilterOpslifyignoreAddsExclusions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".opslifyignore"),
		[]byte("# comment\n*.log\nbuild/\nsecret-notes.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := LoadFilter(dir)
	for _, p := range []string{"app.log", "logs/app.log", "build/out.bin", "secret-notes.txt"} {
		if !f.Excluded(p) {
			t.Errorf("Filter.Excluded(%q) = false; .opslifyignore pattern should exclude it", p)
		}
	}
	// Still allows ordinary files not matched.
	if f.Excluded("main.go") {
		t.Error("main.go should not be excluded")
	}
	// Deny-list still applies through the Filter.
	if !f.Excluded(".env") {
		t.Error(".env must stay excluded through Filter")
	}
}

// TestFilterMalformedIgnoreFailsSafe: a garbage ignore file never REMOVES
// deny-list exclusions.
func TestFilterMalformedIgnoreFailsSafe(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".opslifyignore"),
		[]byte("!important\n[\n***/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := LoadFilter(dir)
	if !f.Excluded(".env") || !f.Excluded("id_rsa") {
		t.Error("deny-list must hold even with a malformed .opslifyignore")
	}
}

// TestFilterMissingIgnoreIsDefault: no ignore file → default deny-list.
func TestFilterMissingIgnoreIsDefault(t *testing.T) {
	f := LoadFilter(t.TempDir())
	if !f.Excluded("server.pem") {
		t.Error("default deny-list must apply with no .opslifyignore")
	}
	if f.Excluded("main.go") {
		t.Error("ordinary file allowed with no .opslifyignore")
	}
}
