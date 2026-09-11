package agentcontext

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestScaffoldSkillNeverOverwrites is the property that matters most here: the
// file is an operator's own notes and is the ONLY copy until committed. Losing
// them to a re-run of `tool add` would be unrecoverable.
func TestScaffoldSkillNeverOverwrites(t *testing.T) {
	f := newFixture(t)
	const mine = "db-01 is the primary. Never restart it."
	f.write(t, ".opslify/skills/kubernetes.md", mine)

	rel, created, err := ScaffoldSkill(f.root, "kubernetes")
	if err != nil {
		t.Fatalf("ScaffoldSkill: %v", err)
	}
	if created {
		t.Error("an existing pack must not be reported as created")
	}
	got, err := os.ReadFile(filepath.Join(f.root, rel))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != mine {
		t.Fatalf("BLOCKING: scaffolding overwrote an operator's notes:\n%s", got)
	}
}

// TestScaffoldSkillCreatesATemplate: the created file must be a set of prompts,
// not filler prose. A template full of plausible-looking defaults gets committed
// unread, and a skill that confidently describes an estate nobody described is
// worse than an absent one — the agent acts on it.
func TestScaffoldSkillCreatesATemplate(t *testing.T) {
	f := newFixture(t)
	rel, created, err := ScaffoldSkill(f.root, "argocd")
	if err != nil {
		t.Fatalf("ScaffoldSkill: %v", err)
	}
	if !created {
		t.Fatal("a missing pack must be created")
	}
	if rel != ".opslify/skills/argocd.md" {
		t.Errorf("rel = %q", rel)
	}
	body, err := os.ReadFile(filepath.Join(f.root, rel))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "argocd") {
		t.Error("the template must name the tool")
	}
	// The skill/permission distinction must be stated in the file itself, or
	// operators write security rules in the wrong place.
	if !strings.Contains(text, "not permission") {
		t.Error("the template must say a skill is data, not permission")
	}
	// It must be assembled as a real layer once written.
	f.writeHouseRules(t, houseRuleText)
	a, err := Assemble(f.sources())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Find("skills/argocd"); !ok {
		t.Error("a scaffolded pack must be picked up by the assembly")
	}
}

// TestScaffoldSkillRefusesUnsafeNames: the tool name becomes a path segment.
func TestScaffoldSkillRefusesUnsafeNames(t *testing.T) {
	f := newFixture(t)
	before := treeOf(t, f.root)
	for _, name := range []string{
		"../../etc/passwd", "..", ".", "a/b", "/abs", "UPPER", "with space",
		"trailing-", "-leading", "", strings.Repeat("x", 41), "nul\x00",
	} {
		if _, _, err := ScaffoldSkill(f.root, name); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("ScaffoldSkill(%q) must be refused, got %v", name, err)
		}
	}
	// A refused name must write NOTHING, ANYWHERE. Spot-checking a couple of paths
	// is not enough: with validation removed, "../../etc/passwd" resolves to a file
	// inside the workspace (root/etc/passwd.md), which narrower assertions missed
	// entirely. Compare the whole tree instead.
	if after := treeOf(t, f.root); !reflect.DeepEqual(after, before) {
		t.Fatalf("a refused skill name wrote files.\nbefore: %v\nafter:  %v", before, after)
	}
}

// treeOf lists every path under root, relative and sorted, so a test can assert
// that an operation touched nothing at all.
func treeOf(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(out)
	return out
}

// TestScaffoldForCapabilitiesCoversEveryToolOnce: onboarding must leave one pack
// per tool the operator actually uses, deduped (two roles can share a tool).
func TestScaffoldForCapabilitiesCoversEveryToolOnce(t *testing.T) {
	f := newFixture(t)
	caps := CapabilityMap{
		RoleGit:           "gitlab",
		RoleCI:            "gitlab", // same tool as git — must not scaffold twice
		RoleOrchestration: "kubernetes",
		RoleIaC:           "terraform",
		RoleCloud:         "", // unfilled role: nothing to scaffold
	}
	created, err := ScaffoldForCapabilities(f.root, caps)
	if err != nil {
		t.Fatalf("ScaffoldForCapabilities: %v", err)
	}
	want := []string{
		filepath.Join(skillsRelDir, "gitlab.md"),
		filepath.Join(skillsRelDir, "kubernetes.md"),
		filepath.Join(skillsRelDir, "terraform.md"),
	}
	if !reflect.DeepEqual(created, want) {
		t.Errorf("created = %v, want %v", created, want)
	}
	// One file per TOOL, not per role: gitlab fills two roles and must appear once.
	entries, err := os.ReadDir(filepath.Join(f.root, skillsRelDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("skills dir holds %d files (%v), want 3 — one per tool, not per role", len(entries), names)
	}

	// Idempotent: a second run creates nothing and destroys nothing.
	again, err := ScaffoldForCapabilities(f.root, caps)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("a second run created %v; scaffolding must be idempotent", again)
	}
}

// TestScaffoldSkipsUnusableToolNamesWithoutAbortingOnboarding: a capability map
// naming an unusable tool must not cost the operator the packs that CAN be
// written.
func TestScaffoldSkipsUnusableToolNamesWithoutAbortingOnboarding(t *testing.T) {
	f := newFixture(t)
	created, err := ScaffoldForCapabilities(f.root, CapabilityMap{
		RoleGit:           "../evil",
		RoleOrchestration: "kubernetes",
	})
	if err != nil {
		t.Fatalf("one bad tool name must not fail the whole scaffold: %v", err)
	}
	if len(created) != 1 || !strings.HasSuffix(created[0], "kubernetes.md") {
		t.Errorf("created = %v, want just the kubernetes pack", created)
	}
	if _, err := os.Stat(filepath.Join(f.root, ".opslify", "evil.md")); err == nil {
		t.Fatal("the unsafe tool name was written anyway")
	}
}

// TestScaffoldRefusesASymlinkedPack: the workspace is untrusted, so a pack that
// is already a symlink must not be treated as "exists, leave alone" in a way
// that later lets it be read — Assemble refuses it, and scaffolding must not
// silently bless it either.
func TestScaffoldRefusesASymlinkedPack(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(t.TempDir(), "id_rsa")
	if err := os.WriteFile(secret, []byte("PRIVATE-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.root, skillsRelDir, "kubernetes.md")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// Scaffolding leaves it (it exists), but the assembly must refuse to read it.
	if _, _, err := ScaffoldSkill(f.root, "kubernetes"); err != nil {
		t.Fatalf("ScaffoldSkill: %v", err)
	}
	f.writeHouseRules(t, houseRuleText)
	a, err := Assemble(f.sources())
	if err == nil {
		if strings.Contains(a.Render(), "PRIVATE-KEY") {
			t.Fatal("BLOCKING: a symlinked skill pack leaked a host file into the context")
		}
		t.Fatal("a symlinked pack must be refused")
	}
	if !errors.Is(err, ErrUnsafeSource) {
		t.Errorf("want ErrUnsafeSource, got %v", err)
	}
}
