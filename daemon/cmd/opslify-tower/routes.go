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
var towerRoutes = []towerRoute{
	// --- read-only context -------------------------------------------------
	{http.MethodGet, "/v1/sessions", "opslify session ls", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/projects", "opslify project ls", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/projects/", "opslify project show <id>", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/workspaces", "opslify ws ls", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/approvals", "opslify approvals", entitle.FeatureCockpit},

	// --- the P8 surfaces ----------------------------------------------------
	{http.MethodGet, "/v1/connections", "opslify connection ls", entitle.FeatureConnections},
	{http.MethodGet, "/v1/secrets", "opslify secrets ls", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/secrets/consumers", "opslify secrets consumers", entitle.FeatureCockpit},
	{http.MethodGet, "/v1/agents", "opslify agent ls", entitle.FeatureAgentRegistry},
	{http.MethodGet, "/v1/changes", "opslify change ls", entitle.FeatureChanges},
	{http.MethodGet, "/v1/changes/", "opslify change show <id>", entitle.FeatureChanges},
	{http.MethodGet, "/v1/policy", "opslify policy show", entitle.FeaturePolicyEdit},
	{http.MethodGet, "/v1/policy/diff", "opslify policy diff <a> <b>", entitle.FeaturePolicyEdit},

	// --- mutations, each routed through the SAME daemon path as the CLI -----
	{http.MethodPost, "/v1/sessions", "opslify session create", entitle.FeatureCockpit},
	{http.MethodDelete, "/v1/sessions/", "opslify session kill <id>", entitle.FeatureCockpit},
	{http.MethodPost, "/v1/sessions/", "opslify session exec / approve", entitle.FeatureCockpit},
	{http.MethodPost, "/v1/changes/", "opslify change approve|deny <id>", entitle.FeatureChanges},
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

func matches(rt towerRoute, method, path string) bool {
	if rt.Method != method {
		return false
	}
	if strings.HasSuffix(rt.Path, "/") {
		// A prefix route still requires a non-empty remainder, so "/v1/changes/"
		// does not admit a bare "/v1/changes/" with nothing after it.
		rest, ok := strings.CutPrefix(path, rt.Path)
		return ok && rest != "" && !strings.Contains(rest, "..")
	}
	return rt.Path == path
}
