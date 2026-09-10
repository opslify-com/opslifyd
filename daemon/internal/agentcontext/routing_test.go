package agentcontext

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var estateCaps = CapabilityMap{
	RoleGit:           "gitlab",
	RoleCI:            "gitlab-ci",
	RoleDeploy:        "argocd",
	RoleOrchestration: "kubernetes",
	RoleIaC:           "terraform",
}

// TestRouteIsDeterministic: the selection is recorded in the trace and shown in
// the UI, so it must be stable — an operator asking "why did the agent not know
// about our Helm values?" needs a reproducible answer.
func TestRouteIsDeterministic(t *testing.T) {
	available := []string{"terraform", "kubernetes", "gitlab-ci", "argocd"}
	roles := []string{RoleIaC, RoleCI, RoleIaC} // duplicate on purpose
	first := Route(estateCaps, roles, available)
	for i := 0; i < 10; i++ {
		if got := Route(estateCaps, roles, available); !reflect.DeepEqual(got, first) {
			t.Fatalf("Route is not deterministic:\n%+v\n%+v", got, first)
		}
	}
	if !reflect.DeepEqual(first.Selected, []string{"gitlab-ci", "terraform"}) {
		t.Errorf("Selected = %v, want [gitlab-ci terraform]", first.Selected)
	}
	if !reflect.DeepEqual(first.Roles, []string{RoleCI, RoleIaC}) {
		t.Errorf("Roles = %v, want deduped and sorted", first.Roles)
	}
}

// TestRouteWithNoRolesLoadsEverything. Narrowing wrongly removes the one skill
// that mattered and the failure looks like a bad agent, not a routing bug — so
// with no hint the safe default is everything.
func TestRouteWithNoRolesLoadsEverything(t *testing.T) {
	available := []string{"kubernetes", "argocd"}
	r := Route(estateCaps, nil, available)
	if !r.LoadedAll {
		t.Error("no role hint must load every pack")
	}
	if !reflect.DeepEqual(r.Selected, []string{"argocd", "kubernetes"}) {
		t.Errorf("Selected = %v, want all packs sorted", r.Selected)
	}
	if r.selectionSet() != nil {
		t.Error("LoadedAll must mean no filter")
	}
}

// TestRouteReportsMissingPacks: a role that routes to a tool with no skill file
// is the signal to run `opslify skill draft`, not something to swallow.
func TestRouteReportsMissingPacks(t *testing.T) {
	r := Route(estateCaps, []string{RoleOrchestration, RoleDeploy}, []string{"kubernetes"})
	if !reflect.DeepEqual(r.Missing, []string{"argocd"}) {
		t.Errorf("Missing = %v, want [argocd]", r.Missing)
	}
	if !reflect.DeepEqual(r.Selected, []string{"kubernetes"}) {
		t.Errorf("Selected = %v, want [kubernetes]", r.Selected)
	}
}

// TestRouteIgnoresUnfilledRoles: asking for a role this estate does not have is
// not an error and not "missing" — the operator never claimed to use that tool.
func TestRouteIgnoresUnfilledRoles(t *testing.T) {
	r := Route(estateCaps, []string{RoleSecrets, RoleCloud}, []string{"kubernetes"})
	if len(r.Selected) != 0 || len(r.Missing) != 0 {
		t.Errorf("unfilled roles must select nothing and report nothing missing: %+v", r)
	}
}

// TestRoutedAssemblyLoadsOnlySelectedPacks is the end-to-end of the routing
// claim: a CI task must not carry Terraform notes.
func TestRoutedAssemblyLoadsOnlySelectedPacks(t *testing.T) {
	f := newFixture(t)
	f.writeHouseRules(t, houseRuleText)
	f.write(t, ".opslify/skills/terraform.md", "TERRAFORM-PACK: state is in the ops bucket.")
	f.write(t, ".opslify/skills/gitlab-ci.md", "CI-PACK: pipelines are on protected runners.")

	src := f.sources()
	src.Capabilities = estateCaps
	src.Roles = []string{RoleCI}

	a, err := Assemble(src)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	rendered := a.Render()
	if !strings.Contains(rendered, "CI-PACK") {
		t.Error("the routed pack must be loaded")
	}
	if strings.Contains(rendered, "TERRAFORM-PACK") {
		t.Error("an unrouted pack must not be loaded — that is the whole point of routing")
	}
	if _, ok := a.Find("skills/terraform"); ok {
		t.Error("the unrouted pack appeared as a layer")
	}
	// The decision itself must be inspectable.
	if !reflect.DeepEqual(a.Routing.Selected, []string{"gitlab-ci"}) {
		t.Errorf("Routing.Selected = %v", a.Routing.Selected)
	}
}

// TestSkillsAreNameSortedForStableHashing: readdir order is filesystem-dependent,
// so relying on it would make the same repo hash differently on two machines.
func TestSkillsAreNameSortedForStableHashing(t *testing.T) {
	f := newFixture(t)
	f.writeHouseRules(t, houseRuleText)
	for _, n := range []string{"zzz", "aaa", "mmm", "bbb"} {
		f.write(t, ".opslify/skills/"+n+".md", "pack "+n)
	}
	a, err := Assemble(f.sources())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range a.Layers {
		if l.Kind == LayerSkill {
			got = append(got, l.Name)
		}
	}
	want := []string{"skills/aaa", "skills/bbb", "skills/mmm", "skills/zzz"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("skills order = %v, want %v", got, want)
	}
}

// TestNonMarkdownAndHiddenFilesAreNotSkills keeps stray files out of the model's
// context — a .env or a backup file in the skills dir is not documentation.
func TestNonMarkdownAndHiddenFilesAreNotSkills(t *testing.T) {
	f := newFixture(t)
	f.writeHouseRules(t, houseRuleText)
	f.write(t, ".opslify/skills/real.md", "REAL-PACK")
	f.write(t, ".opslify/skills/.env", "SHOULD-NOT-LOAD-secret=1")
	f.write(t, ".opslify/skills/notes.txt", "SHOULD-NOT-LOAD-txt")
	f.write(t, ".opslify/skills/.hidden.md", "SHOULD-NOT-LOAD-hidden")
	f.write(t, ".opslify/skills/backup.md.bak", "SHOULD-NOT-LOAD-bak")
	// A DIRECTORY named like a skill must not be read either.
	if err := os.MkdirAll(filepath.Join(f.root, ".opslify/skills/dir.md"), 0o755); err != nil {
		t.Fatal(err)
	}

	a, err := Assemble(f.sources())
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	rendered := a.Render()
	if !strings.Contains(rendered, "REAL-PACK") {
		t.Error("the real skill pack must load")
	}
	if strings.Contains(rendered, "SHOULD-NOT-LOAD") {
		t.Errorf("a non-skill file was loaded into the context:\n%s", rendered)
	}
	if _, ok := a.Find("skills/dir"); ok {
		t.Error("a directory named *.md was treated as a skill")
	}
}

// TestRenderLabelsAuthority: the model must be told which text a repo commit
// could have written and which it could not, or a house rule and an
// agent-authored note look identical.
func TestRenderLabelsAuthority(t *testing.T) {
	f := newFixture(t)
	f.writeHouseRules(t, houseRuleText)
	f.write(t, ".opslify/instructions.md", "Diagnose first.")
	a, err := Assemble(f.sources())
	if err != nil {
		t.Fatal(err)
	}
	rendered := a.Render()
	if !strings.Contains(rendered, "authority=daemon-operator (repo cannot change)") {
		t.Errorf("the house-rules layer must be labelled as repo-unchangeable:\n%s", rendered)
	}
	if !strings.Contains(rendered, "authority=repo (reviewed commit)") {
		t.Errorf("repo layers must be labelled as repo-sourced:\n%s", rendered)
	}
}

// TestDeclaredToolsWithNoPackAreReportedEvenWhenLoadingEverything: the capability
// map must have an effect even with no role hint, or it is inert until some
// future task supplies one — and the gap it describes ("you told us you use
// argocd; there is no argocd pack") stays invisible for that whole time.
func TestDeclaredToolsWithNoPackAreReportedEvenWhenLoadingEverything(t *testing.T) {
	r := Route(estateCaps, nil, []string{"kubernetes"})
	if !r.LoadedAll {
		t.Fatal("no role hint must still load every pack")
	}
	// gitlab, gitlab-ci, argocd and terraform are declared; only kubernetes exists.
	want := []string{"argocd", "gitlab", "gitlab-ci", "terraform"}
	if !reflect.DeepEqual(r.Missing, want) {
		t.Errorf("Missing = %v, want %v", r.Missing, want)
	}
	// An estate whose declared tools all have packs reports nothing missing.
	full := Route(CapabilityMap{RoleOrchestration: "kubernetes"}, nil, []string{"kubernetes"})
	if len(full.Missing) != 0 {
		t.Errorf("Missing = %v, want none", full.Missing)
	}
	// And with no capability map at all there is nothing to be missing.
	if none := Route(nil, nil, []string{"kubernetes"}); len(none.Missing) != 0 {
		t.Errorf("Missing = %v with no capability map", none.Missing)
	}
}

// TestAssemblyWarnsAboutDeclaredToolsWithNoPack ties it to the operator-facing
// output: the warning is what turns the gap into an action.
func TestAssemblyWarnsAboutDeclaredToolsWithNoPack(t *testing.T) {
	f := newFixture(t)
	f.writeHouseRules(t, houseRuleText)
	f.write(t, ".opslify/skills/kubernetes.md", "Drain first.")

	src := f.sources()
	src.Capabilities = CapabilityMap{RoleOrchestration: "kubernetes", RoleDeploy: "argocd"}
	a, err := Assemble(src)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, w := range a.Warnings {
		if strings.Contains(w, "argocd") && strings.Contains(w, "skill draft") {
			found = true
		}
	}
	if !found {
		t.Errorf("a declared tool with no pack must produce an actionable warning; got %v", a.Warnings)
	}
}
