package projectdoc

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is a write path reachable from a browser, so the refusals below are what
// bound it. It writes markdown in three known directories and nowhere else —
// especially not in whatever the agent cloned, which is the large untrusted
// surface F3.6 exists to keep out of a privileged page.

func ws(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, sub := range []string{".opslify/skills", ".opslify/memory"} {
		if err := os.MkdirAll(filepath.Join(d, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestWriteAndReadRoundTrip(t *testing.T) {
	w := ws(t)
	const body = "# Kubernetes\n\nAlways use --context tripon-staging.\n"
	if _, err := Write(w, KindSkill, "kubernetes.md", body); err != nil {
		t.Fatal(err)
	}
	got, err := Read(w, KindSkill, "kubernetes.md")
	if err != nil {
		t.Fatal(err)
	}
	if got.Content != body {
		t.Fatalf("content = %q", got.Content)
	}
	// It must land where F8.4 actually looks.
	if _, err := os.Stat(filepath.Join(w, ".opslify", "skills", "kubernetes.md")); err != nil {
		t.Fatalf("the file is not where the assembler reads: %v", err)
	}
}

func TestMemoryLandsWhereTheIndexerReads(t *testing.T) {
	w := ws(t)
	if _, err := Write(w, KindMemory, "incidents/2026-03.md", "# Outage\nfile descriptors\n"); err != nil {
		t.Fatal(err)
	}
	// Subdirectories are allowed: a memory corpus is organised.
	if _, err := os.Stat(filepath.Join(w, ".opslify", "memory", "incidents", "2026-03.md")); err != nil {
		t.Fatalf("nested memory document not written: %v", err)
	}
	docs, err := List(w, KindMemory)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 || docs[0].Path != "incidents/2026-03.md" {
		t.Fatalf("List = %+v", docs)
	}
}

func TestInstructionsIsAlwaysTheOneFile(t *testing.T) {
	w := ws(t)
	// Whatever name a caller supplies, F8.4 reads .opslify/instructions.md and
	// nothing else — so a chosen name would produce a file nothing loads.
	if _, err := Write(w, KindInstructions, "whatever-they-typed.md", "# Rules\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(w, ".opslify", "instructions.md")); err != nil {
		t.Fatalf("instructions did not land at the path the assembler reads: %v", err)
	}
}

// --- the refusals -----------------------------------------------------------------

func TestTraversalIsRefused(t *testing.T) {
	w := ws(t)
	// Each case names WHERE it would land if containment failed, and the check is
	// made at that exact path. The first version asserted only that nothing
	// appeared at <workspace>/out.md — which no escape would have produced anyway
	// — so it passed with the containment check deleted entirely.
	//
	// TWO independent guards cover these: wssync.Excluded refuses any path holding
	// "..", and resolve() checks the cleaned, joined result against the root.
	// Removing either alone still fails every case here; removing both lets
	// "../escaped.md" through. That redundancy is deliberate — wssync exists for a
	// different purpose and could reasonably be narrowed one day without anyone
	// realising this path was leaning on it.
	for _, tc := range []struct{ rel, escapesTo string }{
		{"../escaped.md", filepath.Join(w, ".opslify", "escaped.md")},
		{"../../escaped2.md", filepath.Join(w, "escaped2.md")},
		{"nested/../../escaped3.md", filepath.Join(w, ".opslify", "escaped3.md")},
		{"../skills/planted.md", filepath.Join(w, ".opslify", "skills", "planted.md")},
	} {
		if _, err := Write(w, KindMemory, tc.rel, "pwned"); err == nil {
			t.Errorf("%q was accepted", tc.rel)
		}
		if _, err := os.Stat(tc.escapesTo); err == nil {
			t.Errorf("%q escaped to %s", tc.rel, tc.escapesTo)
		}
	}
	// An absolute path is a separate shape: Join would discard the root entirely.
	if _, err := Write(w, KindMemory, "/etc/absolute.md", "x"); err == nil {
		t.Error("an absolute path was accepted")
	}
}

// TestPercentEncodedNamesAreContainedNotRefused.
//
// "..%2f..%2fx.md" is NOT a traversal here: a document path arrives in a JSON
// body, so the percent sequences are never decoded and it is simply an odd
// filename. It must be CONTAINED rather than refused — the containment check is
// on the resolved path, which is the only question worth asking, and a
// string-matching deny-list would refuse this while missing the spellings that
// actually escape.
func TestPercentEncodedNamesAreContainedNotRefused(t *testing.T) {
	w := ws(t)
	if _, err := Write(w, KindMemory, "..%2f..%2fx.md", "x"); err != nil {
		t.Fatalf("a literal filename was refused: %v", err)
	}
	inside := filepath.Join(w, ".opslify", "memory", "..%2f..%2fx.md")
	if _, err := os.Stat(inside); err != nil {
		t.Fatalf("it did not land inside the memory directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(w, "x.md")); err == nil {
		t.Fatal("it escaped")
	}
}

func TestOnlyMarkdownIsAccepted(t *testing.T) {
	w := ws(t)
	for _, bad := range []string{"script.sh", "config.yaml", "notes", "a.md.sh"} {
		if _, err := Write(w, KindSkill, bad, "x"); err == nil {
			t.Errorf("%q was accepted; these directories are read as markdown", bad)
		}
	}
}

func TestCredentialShapedNamesAreRefused(t *testing.T) {
	w := ws(t)
	// Every read path excludes these, so accepting the write would create a file
	// nothing ever uses.
	for _, bad := range []string{"credentials.md", ".env.md", "id_rsa.md"} {
		_, err := Write(w, KindMemory, bad, "x")
		if err == nil {
			t.Errorf("%q was accepted", bad)
			continue
		}
		if !errors.Is(err, ErrUnsafe) {
			t.Errorf("%q: err = %v, want ErrUnsafe", bad, err)
		}
	}
}

func TestAWriteThroughASymlinkIsRefused(t *testing.T) {
	w := ws(t)
	outside := t.TempDir()
	link := filepath.Join(w, ".opslify", "memory", "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Write(w, KindMemory, "escape/pwned.md", "x"); err == nil {
		t.Fatal("a write through a symlinked directory was accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.md")); err == nil {
		t.Fatal("the write landed outside the workspace")
	}
}

func TestAnOversizedDocumentIsRefused(t *testing.T) {
	w := ws(t)
	if _, err := Write(w, KindMemory, "huge.md", strings.Repeat("x", maxDocBytes+1)); err == nil {
		t.Fatal("an oversized document was accepted")
	}
}

func TestReadingSomethingThatIsNotThere(t *testing.T) {
	w := ws(t)
	if _, err := Read(w, KindSkill, "nope.md"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	// Deleting a name that does not exist is an error, not a silent success: the
	// operator has the wrong name and should be told.
	if err := Delete(w, KindSkill, "nope.md"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete err = %v, want ErrNotFound", err)
	}
}

func TestAnUnknownKindIsRefused(t *testing.T) {
	w := ws(t)
	if _, err := Write(w, Kind("repos"), "anything.md", "x"); err == nil {
		t.Fatal("an unknown kind was accepted; the writable set is exactly three directories")
	}
}

func TestAProjectWithNoWorkspaceCannotBeWrittenTo(t *testing.T) {
	if _, err := Write("", KindMemory, "a.md", "x"); err == nil {
		t.Fatal("a write with no workspace was accepted")
	}
}

func TestDeleteRemovesIt(t *testing.T) {
	w := ws(t)
	if _, err := Write(w, KindMemory, "gone.md", "x"); err != nil {
		t.Fatal(err)
	}
	if err := Delete(w, KindMemory, "gone.md"); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(w, KindMemory, "gone.md"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("still readable: %v", err)
	}
}
