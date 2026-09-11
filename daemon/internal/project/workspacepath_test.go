package project

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A bind mount has NO deny-list — unlike F7.3's copy-in path, which filters
// credential-shaped files on the way through. Everything in the chosen directory
// is visible to every sandbox for the project, so the refusals below are the only
// place that exposure is bounded.

func TestAHomeDirectoryIsRefusedAsAWorkspace(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory")
	}
	err = ValidateWorkspacePath(home)
	if err == nil {
		t.Fatal("a home directory was accepted; a sandbox mounting it sees .ssh, .aws and .config")
	}
	// The message has to say what to do instead, or an operator just picks
	// something else equally wrong.
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestSystemDirectoriesAreRefused(t *testing.T) {
	for _, p := range []string{"/", "/etc", "/usr", "/root", "/var", "/proc"} {
		if err := ValidateWorkspacePath(p); err == nil {
			t.Errorf("%s was accepted as a workspace", p)
		}
	}
}

func TestARelativeOrNonCanonicalPathIsRefused(t *testing.T) {
	for _, p := range []string{
		"relative/path",
		"/tmp/../etc",
		"/tmp/./thing",
		"/tmp/trailing/",
	} {
		if err := ValidateWorkspacePath(p); err == nil {
			t.Errorf("%q was accepted; a non-canonical path is not the directory it appears to be", p)
		}
	}
}

func TestASymlinkedWorkspaceIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// The mount follows it, so the path an operator reads in the UI would not be
	// the directory the agent gets.
	if err := ValidateWorkspacePath(link); err == nil {
		t.Fatal("a symlinked workspace path was accepted")
	}
}

func TestAMissingDirectoryIsAllowedAndCreatedLater(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-yet")
	if err := ValidateWorkspacePath(p); err != nil {
		t.Fatalf("a path that does not exist yet should be accepted: %v", err)
	}
}

func TestAFileIsNotAWorkspace(t *testing.T) {
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWorkspacePath(f); err == nil {
		t.Fatal("a regular file was accepted as a workspace")
	}
}

func TestAnEmptyPathMeansDaemonManaged(t *testing.T) {
	if err := ValidateWorkspacePath(""); err != nil {
		t.Fatalf("empty must stay valid — it is the default: %v", err)
	}
}

// --- the scan ---------------------------------------------------------------------

func TestScanFindsTheFilesABindMountWouldExpose(t *testing.T) {
	root := t.TempDir()
	mk := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mk("src/main.go", "package main")      // fine
	mk("README.md", "# hi")                // fine
	mk(".env", "TOKEN=hunter2")            // not fine
	mk("deploy/cluster.pem", "KEY")        // not fine
	mk("infra/terraform.tfstate", "{}")    // not fine
	mk(".ssh/id_rsa", "PRIVATE")           // not fine
	mk("app/.git-credentials", "https://") // not fine

	found, err := ScanForSecrets(root, 50)
	if err != nil {
		t.Fatal(err)
	}
	byRel := map[string]bool{}
	for _, f := range found {
		byRel[f.Rel] = true
		if f.Why == "" {
			t.Errorf("%s was flagged with no reason; an operator cannot act on that", f.Rel)
		}
	}
	for _, want := range []string{
		".env", "deploy/cluster.pem", "infra/terraform.tfstate", "app/.git-credentials",
	} {
		if !byRel[want] {
			t.Errorf("%s was not flagged: %+v", want, found)
		}
	}
	if !byRel[".ssh/"] {
		t.Errorf(".ssh/ was not flagged as a directory: %+v", found)
	}
	// And it must not cry wolf over ordinary source.
	for _, no := range []string{"src/main.go", "README.md"} {
		if byRel[no] {
			t.Errorf("%s was flagged; a scan that fires on source is a scan nobody reads", no)
		}
	}
}

func TestScanOfAnEmptyOrMissingRootIsQuiet(t *testing.T) {
	if f, err := ScanForSecrets(t.TempDir(), 10); err != nil || len(f) != 0 {
		t.Fatalf("clean dir: %v %+v", err, f)
	}
	if f, _ := ScanForSecrets("", 10); len(f) != 0 {
		t.Fatalf("empty root produced findings: %+v", f)
	}
}
