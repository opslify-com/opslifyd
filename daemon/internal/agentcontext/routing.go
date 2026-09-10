package agentcontext

import "sort"

// Roles are the capability slots an estate fills with concrete tools. Onboarding
// records the mapping (git=gitlab, ci=gitlab-ci, deploy=argocd,
// orchestration=kubernetes, iac=terraform) and routing uses it to decide which
// skill packs a task needs — so a CI task is not carrying Terraform provider
// notes it will never use.
const (
	RoleGit           = "git"
	RoleCI            = "ci"
	RoleDeploy        = "deploy"
	RoleOrchestration = "orchestration"
	RoleIaC           = "iac"
	RoleCloud         = "cloud"
	RoleSecrets       = "secrets"
)

// CapabilityMap maps a role to the tool that fills it.
type CapabilityMap map[string]string

// Routing is the pack-selection decision, kept as data so it can be shown in the
// UI and recorded in the trace. Routing must be inspectable: an operator asking
// "why did the agent not know about our Helm values?" needs to see that the helm
// pack was not selected, rather than guess.
type Routing struct {
	// Roles are the roles the task was routed for. Empty means "no hint given",
	// which loads every available pack rather than guessing a subset — an agent
	// missing the one skill that mattered is worse than a larger context.
	Roles []string `json:"roles,omitempty"`
	// Tools are the tools those roles resolved to, sorted.
	Tools []string `json:"tools,omitempty"`
	// Selected are the skill packs chosen, sorted.
	Selected []string `json:"selected,omitempty"`
	// Missing are packs a role asked for that have no file in the repo. Reported
	// rather than silently ignored: it is the signal to run `opslify skill draft`.
	Missing []string `json:"missing,omitempty"`
	// LoadedAll records that no role hint was given, so everything was loaded.
	LoadedAll bool `json:"loaded_all"`
}

// Route resolves roles to skill packs against a capability map and what is
// actually on disk. It is deterministic: same inputs, same output, every time.
//
// With no roles requested it selects EVERYTHING. That is deliberate: a wrong
// narrowing silently removes the knowledge the agent needed, and the failure
// looks like the agent being bad at its job rather than like a routing bug.
// Callers that want a narrow context must say which roles they want.
func Route(caps CapabilityMap, roles []string, available []string) Routing {
	have := make(map[string]bool, len(available))
	for _, s := range available {
		have[s] = true
	}
	if len(roles) == 0 {
		sel := append([]string(nil), available...)
		sort.Strings(sel)
		return Routing{Selected: sel, LoadedAll: true}
	}

	wantRoles := dedupeSorted(roles)
	toolSet := map[string]bool{}
	var missing []string
	for _, role := range wantRoles {
		tool, ok := caps[role]
		if !ok || tool == "" {
			// The role is unfilled in this estate; there is nothing to load and
			// nothing missing — the operator never claimed to have that tool.
			continue
		}
		toolSet[tool] = true
		if !have[tool] {
			missing = append(missing, tool)
		}
	}
	var tools, selected []string
	for tool := range toolSet {
		tools = append(tools, tool)
		if have[tool] {
			selected = append(selected, tool)
		}
	}
	sort.Strings(tools)
	sort.Strings(selected)
	sort.Strings(missing)
	return Routing{Roles: wantRoles, Tools: tools, Selected: selected, Missing: missing}
}

// sortStrings is sort.Strings, named locally so scaffold.go does not need its own
// sort import.
func sortStrings(s []string) { sort.Strings(s) }

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// selectionSet turns a Routing into the lookup loadSkills wants. It returns nil
// when everything should load, which loadSkills treats as "no filter".
func (r Routing) selectionSet() map[string]bool {
	if r.LoadedAll {
		return nil
	}
	set := make(map[string]bool, len(r.Selected))
	for _, s := range r.Selected {
		set[s] = true
	}
	return set
}
