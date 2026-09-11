package main

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/opslify-com/opslifyd/internal/entitle"
)

// towerRoute is one daemon endpoint the cockpit may reach, with the CLI command
// that does the same thing.
//
// The CLI pairing is not documentation — an inventory test asserts every route
// has one. A capability the cockpit has and the CLI does not would make the OSS
// daemon incomplete standalone, which is the split D3 exists to prevent.
type towerRoute struct {
	Method string
	// Path is an exact path, or a prefix when it ends in "/".
	Path string
	// CLI is the equivalent `opslify` invocation.
	CLI string
	// Feature gates the route for a future commercial edition. Everything is
	// allowed today; the seam exists so adding a gate later is one line here.
	Feature entitle.Feature
}

// towerRoutes is the COMPLETE set the cockpit may proxy. Anything not listed is
// refused.
//
// An allowlist, not a denylist: the daemon's API grows, and a route added
// tomorrow must not become browser-reachable merely because nobody thought to
// forbid it. The cockpit is the widest local surface in the product, and every
// capability it has is safe only because this list is short and deliberate.
//
// Deliberately ABSENT, and why:
//   - GET /v1/secrets/{ref} — there is no such route, and if one is ever added it
//     must not be reachable here. The browser sees refs and metadata, never values.
//   - Any /v1/sessions/{id}/files route — raw workspace bytes stay out of the
//     browser (the F3.6 refusal stays closed).
//   - POST /v1/changes/{id}/decision with ?force — forcing is CLI-only, where the
//     operator is shown what they are breaking first.
//   - DELETE /v1/secrets and DELETE /v1/secrets/{ref} — removing a credential can
//     silently break every connection bound to it, so it stays CLI-only where the
//     consumer list is printed first. Storing one is allowed; destroying is not.
//   - PUT /v1/secrets/{ref} — rotation is the same destructive shape as deletion
//     for anything already holding the old value.
//   - DELETE /v1/workspaces/{name} — host-linked directories are not the browser's
//     to remove.
//   - POST /v1/agents and POST /v1/agents/test — registering an agent PROBES it,
//     which runs the submitted command on the host (agents.Registry.Add →
//     prober.Probe). The environment it runs with is allowlisted; the command
//     itself is not. Admitting that would make the launch token the only thing
//     between a web page and host code execution, so `opslify agent add` stays on
//     the CLI. Binding an already-registered agent moves a pointer and executes
//     nothing, so POST /v1/agents/{name}/bind is admitted.
var towerRoutes = []towerRoute{
	// --- read-only context -------------------------------------------------
	{http.MethodGet, "/v1/sessions", "opslify session ls", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/projects", "opslify project ls", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/projects/*", "opslify project show <id>", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/projects/*/environments", "opslify project env ls <id>", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/workspaces", "opslify ws ls", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/approvals", "opslify approvals", entitle.FeatureCockpit},

	// --- the P8 surfaces ----------------------------------------------------
	{http.MethodGet, "/v1/connections", "opslify connection ls", entitle.FeatureConnections},
	{http.MethodGet, "/v1/secrets", "opslify secrets ls", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/secrets/consumers", "opslify secrets consumers", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/agents", "opslify agent ls", entitle.FeatureAgentRegistry},
	{http.MethodGet, "/v1/changes", "opslify change ls", entitle.FeatureChanges},
	{http.MethodGet, "/v1/changes/*", "opslify change show <id>", entitle.FeatureChanges},
	{http.MethodGet, "/v1/policy", "opslify policy show", entitle.FeaturePolicyEdit},
	{http.MethodGet, "/v1/policy/diff", "opslify policy diff <a> <b>", entitle.FeaturePolicyEdit},

	// F8.10 memory. Read-only plus the operator's enable/disable — there is no
	// route here that WRITES a document, and there must not be: memory is a folder
	// of reviewed files in the project's workspace, and a second unreviewed path
	// into what the agent reads is the whole thing the review exists to prevent.
	{http.MethodGet, "/v1/workspace", "opslify ws ls", entitle.FeatureCockpit},

	// The catalogue and install route are how an agent gets connected from the
	// cockpit without the browser ever naming a command: install takes a
	// CATALOGUE ENTRY, the daemon owns the paths. POST /v1/agents, which takes a
	// caller-supplied command, stays refused.
	{http.MethodGet, "/v1/agents/catalogue", "opslify agent catalogue", entitle.FeatureAgentRegistry},
	{http.MethodPost, "/v1/agents/install", "opslify agent install <entry>", entitle.FeatureAgentRegistry},

	{http.MethodGet, "/v1/memory", "opslify memory ls", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/memory/search", "opslify memory search <query>", entitle.FeatureCockpit},
	{http.MethodPost, "/v1/memory/enable", "opslify memory enable|disable <doc>", entitle.FeatureCockpit},

	// --- reads that the cockpit's own screens need --------------------------
	{http.MethodGet, "/v1/health", "opslify status", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/sessions/history", "opslify session history", entitle.FeatureCockpit},

	// --- mutations, each routed through the SAME daemon path as the CLI -----
	{http.MethodPost, "/v1/sessions", "opslify session create", entitle.FeatureCockpit},

	// Creating the objects an operator onboards with. These were absent until the
	// cockpit was built to its design: the daemon has had POST /v1/projects since
	// F8.1, but the allowlist carried only the GET, so the UI could show a project
	// and never make one. A read-only console is not an operator surface.
	{http.MethodPost, "/v1/projects", "opslify project create <name>", entitle.FeatureCockpit},
	{http.MethodPost, "/v1/projects/*/environments", "opslify project env add <id> <env>", entitle.FeatureCockpit},
	// Tools are the project's role → tool map. Editing it is not a policy change:
	// it records which tools a project uses, and the gates and egress a tool
	// implies are separate edits that ARE classified.
	{http.MethodPut, "/v1/projects/*/capabilities", "opslify project tools add|rm <id>", entitle.FeatureCockpit},
	{http.MethodDelete, "/v1/projects/*", "opslify project rm <id>", entitle.FeatureCockpit},
	{http.MethodDelete, "/v1/projects/*/environments/*", "opslify project env rm <id> <env>", entitle.FeatureCockpit},
	{http.MethodPost, "/v1/connections", "opslify connection add", entitle.FeatureConnections},
	{http.MethodPost, "/v1/connections/test", "opslify connection test", entitle.FeatureConnections},
	{http.MethodDelete, "/v1/connections/*", "opslify connection rm <name>", entitle.FeatureConnections},
	// Binding and removing an agent move a pointer; REGISTERING one does not —
	// see the absence note above.
	{http.MethodPost, "/v1/agents/*/bind", "opslify agent bind <name>", entitle.FeatureAgentRegistry},
	// F8.9: hand a registered agent a prompt. This does NOT run a command the
	// browser chose — it runs the one the registry already probed, under the
	// daemon's own confinement recipe, which is why it is admitted where
	// POST /v1/agents is not.
	{http.MethodPost, "/v1/agents/*/run", "opslify agent run <name> <prompt>", entitle.FeatureAgentRegistry},
	{http.MethodDelete, "/v1/agents/*", "opslify agent rm <name>", entitle.FeatureAgentRegistry},

	// Storing a secret is a WRITE of a value the browser already holds — the
	// operator typed it. That is the opposite direction to reading one out, which
	// stays refused: POST carries a value in, no route carries one back.
	{http.MethodPost, "/v1/secrets", "opslify secrets add <ref>", entitle.FeatureCockpit},

	{http.MethodDelete, "/v1/sessions/*", "opslify session kill <id>", entitle.FeatureCockpit},
	{http.MethodPost, "/v1/sessions/*/exec", "opslify session exec <id>", entitle.FeatureCockpit},
	{http.MethodPost, "/v1/sessions/*/approvals/*", "opslify session approve <id> <exec>", entitle.FeatureCockpit},
	{http.MethodPost, "/v1/changes/*/decision", "opslify change approve|deny <id>", entitle.FeatureChanges},
	// Policy edits go through F8.7: a widening becomes a Change and the cockpit
	// cannot apply one directly, because the daemon refuses — not because the UI
	// declines to offer it.
	{http.MethodPost, "/v1/policy/edit", "opslify policy allow-egress|gate", entitle.FeaturePolicyEdit},
}

// admit reports why a request is refused, or "" if it may proceed.
func admit(method string, u *url.URL) string {
	if u.RawQuery != "" {
		if reason := admitQuery(u); reason != "" {
			return reason
		}
	}
	for _, rt := range towerRoutes {
		if !matches(rt, method, u.Path) {
			continue
		}
		if !entitle.Allows(rt.Feature) {
			return "opslify tower: " + entitle.Reason(rt.Feature)
		}
		return ""
	}
	return "opslify tower: " + method + " " + u.Path + " is not on the cockpit's allowlist"
}

// admitQuery refuses parameters the cockpit must never send.
func admitQuery(u *url.URL) string {
	for key := range u.Query() {
		// Case-insensitive: a guard that is exactly as strict as the thing it
		// protects stops protecting it the moment the other side is relaxed.
		if strings.EqualFold(key, "force") {
			return "opslify tower: ?force is not permitted from the cockpit — " +
				"run the CLI, which shows you what the removal breaks first"
		}
	}
	return ""
}

// matches reports whether a request hits this route.
//
// Three path shapes, in increasing precision:
//
//	/v1/changes          exact
//	/v1/changes/         prefix — any non-empty remainder
//	/v1/agents/*/bind    segments, where * is exactly ONE segment
//
// The wildcard form exists because a prefix is too blunt for a surface like
// this: "/v1/agents/" was meant to admit `{name}/bind`, and silently admitted
// `/v1/agents/test` — a route that runs a command on the host. A guard whose
// reach is wider than its intent is how a refusal becomes an admission by
// accident, so anything with a fixed tail is written as a wildcard.
func matches(rt towerRoute, method, path string) bool {
	if rt.Method != method {
		return false
	}
	// No traversal reaches a comparison, whatever the shape.
	if strings.Contains(path, "..") {
		return false
	}
	if strings.Contains(rt.Path, "*") {
		return matchSegments(rt.Path, path)
	}
	if strings.HasSuffix(rt.Path, "/") {
		// A prefix route still requires a non-empty remainder, so "/v1/changes/"
		// does not admit a bare "/v1/changes/" with nothing after it.
		rest, ok := strings.CutPrefix(path, rt.Path)
		return ok && rest != ""
	}
	return rt.Path == path
}

// matchSegments compares a "*"-containing pattern to a path, segment by segment.
// A "*" matches exactly one non-empty segment — never a "/" and never nothing.
func matchSegments(pattern, path string) bool {
	pp := strings.Split(pattern, "/")
	sp := strings.Split(path, "/")
	if len(pp) != len(sp) {
		return false
	}
	for i, want := range pp {
		got := sp[i]
		if want == "*" {
			if got == "" {
				return false
			}
			continue
		}
		if want != got {
			return false
		}
	}
	return true
}
