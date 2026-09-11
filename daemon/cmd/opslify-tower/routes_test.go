package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/entitle"
	"github.com/opslify-com/opslifyd/internal/uiguard"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// --- the inventory: no cockpit-only capability ---------------------------------

// TestEveryTowerRouteHasACLIEquivalent is the acceptance criterion, and the
// architectural point of the split: a capability the cockpit has and the CLI does
// not would make the OSS daemon incomplete standalone.
func TestEveryTowerRouteHasACLIEquivalent(t *testing.T) {
	for _, rt := range towerRoutes {
		if strings.TrimSpace(rt.CLI) == "" {
			t.Errorf("%s %s has no CLI equivalent — a tower-only capability is a design smell",
				rt.Method, rt.Path)
		}
		if !strings.HasPrefix(rt.CLI, "opslify ") {
			t.Errorf("%s %s: CLI equivalent %q should be an `opslify` invocation",
				rt.Method, rt.Path, rt.CLI)
		}
		if rt.Feature == "" {
			t.Errorf("%s %s carries no entitlement feature; every route must be gateable later",
				rt.Method, rt.Path)
		}
	}
}

// TestEveryRouteIsAllowedInThisPhase: the entitlement seam exists but gates
// nothing yet, and that claim should be checkable rather than assumed.
func TestEveryRouteIsAllowedInThisPhase(t *testing.T) {
	for _, rt := range towerRoutes {
		if !entitle.Allows(rt.Feature) {
			t.Errorf("%s %s is gated in a phase where nothing should be", rt.Method, rt.Path)
		}
	}
}

// --- the allowlist -------------------------------------------------------------

// TestOnlyAllowlistedRoutesAreAdmitted. The daemon's API grows, and a route added
// tomorrow must not become browser-reachable merely because nobody forbade it.
func TestOnlyAllowlistedRoutesAreAdmitted(t *testing.T) {
	for _, tc := range []struct{ method, path string }{
		// Things that exist on the daemon but must NOT be reachable from a page.
		{http.MethodGet, "/v1/secrets/gitlab-token"},    // a value route, if one ever exists
		{http.MethodDelete, "/v1/secrets/gitlab-token"}, // deletion is CLI-only
		{http.MethodDelete, "/v1/secrets"},              // bulk deletion likewise
		{http.MethodPut, "/v1/secrets/gitlab-token"},    // rotation breaks live holders
		{http.MethodGet, "/v1/sessions/s1/files"},       // raw workspace bytes
		{http.MethodPut, "/v1/sessions/s1/files"},
		{http.MethodGet, "/v1/sessions/s1/trace"}, // the trace drawer reads it via SSE, not here
		{http.MethodDelete, "/v1/workspaces/ws1"}, // host-linked dirs are not the browser's
		// Registering an agent runs the submitted command on the host. Binding one
		// does not, which is why bind is admitted and this is not.
		{http.MethodPost, "/v1/agents"},
		{http.MethodPost, "/v1/agents/test"},
		{http.MethodGet, "/v1/admin"},      // anything unknown
		{http.MethodPatch, "/v1/sessions"}, // an unexpected method on a known path
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if reason := admit(tc.method, mustURL(t, tc.path)); reason == "" {
				t.Fatalf("%s %s must NOT be reachable from the cockpit", tc.method, tc.path)
			}
		})
	}
}

// TestAllowlistedRoutesAreAdmitted keeps the guard from being a blanket refusal.
func TestAllowlistedRoutesAreAdmitted(t *testing.T) {
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/sessions"},
		{http.MethodGet, "/v1/changes"},
		{http.MethodGet, "/v1/changes/chg-1"},
		{http.MethodGet, "/v1/connections"},
		{http.MethodGet, "/v1/secrets/consumers"},
		{http.MethodGet, "/v1/agents"},
		{http.MethodGet, "/v1/policy"},
		{http.MethodPost, "/v1/policy/edit"},
		{http.MethodDelete, "/v1/sessions/s1"},

		// The cockpit must be able to CREATE what an operator onboards with. These
		// were refused until the UI was built to its design, which made the whole
		// surface read-only — see the note on towerRoutes.
		{http.MethodPost, "/v1/projects"},
		{http.MethodPost, "/v1/projects/tripon/environments"},
		{http.MethodPut, "/v1/projects/tripon/capabilities"},
		{http.MethodDelete, "/v1/projects/tripon"},
		{http.MethodDelete, "/v1/projects/tripon/environments/staging"},
		{http.MethodPost, "/v1/connections"},
		{http.MethodPost, "/v1/connections/test"},
		{http.MethodDelete, "/v1/connections/gitlab"},
		{http.MethodPost, "/v1/agents/claude/bind"},
		{http.MethodDelete, "/v1/agents/claude"},
		// Storing a value the operator typed carries it IN. No route carries one
		// back out, which is the invariant that actually matters.
		{http.MethodPost, "/v1/secrets"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if reason := admit(tc.method, mustURL(t, tc.path)); reason != "" {
				t.Fatalf("%s %s should be admitted: %s", tc.method, tc.path, reason)
			}
		})
	}
}

// TestForceIsNeverAdmitted: forcing past the in-use guard is CLI-only, where the
// operator is shown what they are breaking first.
func TestForceIsNeverAdmitted(t *testing.T) {
	for _, raw := range []string{
		"/v1/sessions?force=true",
		"/v1/changes?FORCE=true",
		"/v1/policy?Force=1",
		"/v1/sessions/s1?force=true",
	} {
		if reason := admit(http.MethodGet, mustURL(t, raw)); reason == "" {
			t.Errorf("%s carries ?force and must be refused", raw)
		}
	}
}

// TestPrefixRoutesRequireARemainder: "/v1/changes/" must not admit a bare prefix
// or a traversal.
func TestPrefixRoutesRequireARemainder(t *testing.T) {
	for _, raw := range []string{"/v1/changes/", "/v1/changes/../secrets", "/v1/sessions/"} {
		if reason := admit(http.MethodGet, mustURL(t, raw)); reason == "" {
			t.Errorf("%q must not be admitted", raw)
		}
	}
}

// --- the guards ------------------------------------------------------------------

// TestNoRouteIsReachableWithoutAToken. Every capability the cockpit has is safe
// ONLY because the launch token gates it; a route outside the guard is reachable
// by any local page.
func TestNoRouteIsReachableWithoutAToken(t *testing.T) {
	h, err := newTowerServer("/nonexistent.sock", "the-launch-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/cockpit.js", "/v1/sessions", "/v1/changes", "/v1/policy"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1:4646"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token = %d, want 401", path, rec.Code)
		}
	}
}

// TestAForeignHostIsRefusedEvenWithAToken is the DNS-rebinding guard: a stolen
// token must not be usable from a page that should never have loaded.
func TestAForeignHostIsRefusedEvenWithAToken(t *testing.T) {
	h, err := newTowerServer("/nonexistent.sock", "the-launch-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"evil.example.com", "attacker.test:4646", "10.0.0.5:4646"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
		req.Host = host
		req.Header.Set(uiguard.TokenHeader, "the-launch-token")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("host %q was admitted with a valid token", host)
		}
	}
}

// TestAValidTokenOnLoopbackReachesTheProxy: with both guards satisfied the
// request gets as far as the daemon — which is absent here, so a 502 proves the
// guards passed and the proxy tried.
func TestAValidTokenOnLoopbackReachesTheProxy(t *testing.T) {
	h, err := newTowerServer("/nonexistent.sock", "the-launch-token")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	req.Host = "127.0.0.1:4646"
	req.Header.Set(uiguard.TokenHeader, "the-launch-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (guards passed, daemon absent): %s", rec.Code, rec.Body.String())
	}
	// The message must name the likely cause rather than leaving an operator with
	// a bare "connection refused".
	if !strings.Contains(rec.Body.String(), "is it running") {
		t.Errorf("the error should say the daemon may not be running: %s", rec.Body.String())
	}
}

// TestARefusedRouteIs403NotSilent: a cockpit that quietly rendered an empty panel
// would leave an operator unable to tell "nothing defined" from "not permitted".
func TestARefusedRouteIs403NotSilent(t *testing.T) {
	h, err := newTowerServer("/nonexistent.sock", "tok")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/v1/secrets/gitlab-token", nil)
	req.Host = "127.0.0.1:4646"
	req.Header.Set(uiguard.TokenHeader, "tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "allowlist") {
		t.Errorf("the refusal should say why: %s", rec.Body.String())
	}
}

// --- the SPA ----------------------------------------------------------------------

// TestTheCockpitIsSelfContained: no external asset host anywhere. The page is
// served to an operator who may be air-gapped, and a CDN reference would both
// break there and hand a third party a log of when the cockpit is opened.
func TestTheCockpitIsSelfContained(t *testing.T) {
	for _, name := range []string{"cockpit/index.html", "cockpit/cockpit.css", "cockpit/cockpit.js"} {
		b, err := cockpitFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body := string(b)
		for _, forbidden := range []string{"http://", "https://", "//cdn", "fonts.googleapis", "unpkg", "jsdelivr"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s references an external origin (%q); the SPA must be self-contained",
					name, forbidden)
			}
		}
	}
}

// TestTheCockpitNeverReadsASecretValue pins the invariant that actually matters:
// a value may travel IN (the operator typed it into the store-a-secret form) and
// must never travel BACK OUT.
//
// The earlier version of this test forbade the string "value_b64" outright, which
// was right while the cockpit was read-only and wrong once it could store a
// credential — it would have failed the wizard's credentials step for carrying a
// value in the correct direction. Direction is the thing to assert, so it is
// asserted structurally: "value_b64" may appear as a key being WRITTEN into a
// request body, never as a property READ off a response.
func TestTheCockpitNeverReadsASecretValue(t *testing.T) {
	b, err := cockpitFS.ReadFile("cockpit/cockpit.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)

	// Reading one back, in every spelling a reader would recognise.
	for _, forbidden := range []string{
		".value_b64",      // response.value_b64
		"['value_b64']",   //
		"[\"value_b64\"]", //
		"secret_value",
		"reveal",
		"unmask",
		"showSecret",
	} {
		if strings.Contains(js, forbidden) {
			t.Errorf("the cockpit contains %q — a value must never be read back into the page",
				forbidden)
		}
	}

	// Every mention of value_b64 must be a key being written into a body.
	for _, m := range regexp.MustCompile(`.{0,40}value_b64.{0,10}`).FindAllString(js, -1) {
		if !strings.Contains(m, "value_b64:") {
			t.Errorf("value_b64 appears somewhere other than an outgoing body: %q", m)
		}
	}

	// No GET of a per-ref secrets path, which is the route that would return one
	// if it ever existed.
	for _, forbidden := range []string{"/v1/secrets/' +", `/v1/secrets/" +`, "/v1/secrets/${"} {
		if strings.Contains(js, forbidden) {
			t.Errorf("the cockpit builds a per-ref secrets URL (%q); only the list and "+
				"the consumers route are hers", forbidden)
		}
	}

	// And it must say so on the page, because an operator should not have to trust
	// a promise made in a test.
	if !strings.Contains(js, "Values are never shown here") {
		t.Error("the secrets panel should state that values are never shown")
	}
}

// TestTheCockpitStoresSecretsButCannotDestroyThem: storing is admitted, and the
// destructive verbs stay out of the page entirely, so a stray button cannot call
// a route the allowlist would refuse anyway.
func TestTheCockpitStoresSecretsButCannotDestroyThem(t *testing.T) {
	b, err := cockpitFS.ReadFile("cockpit/cockpit.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, "'POST', '/v1/secrets'") {
		t.Error("the cockpit should be able to store a secret — the wizard needs it")
	}
	for _, forbidden := range []string{"'DELETE', '/v1/secrets", "'PUT', '/v1/secrets"} {
		if strings.Contains(js, forbidden) {
			t.Errorf("the cockpit contains %q; deletion and rotation are CLI-only", forbidden)
		}
	}
}

// TestTheCockpitShipsAStrictCSP.
func TestTheCockpitShipsAStrictCSP(t *testing.T) {
	h := cockpitHandler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP is missing %q: %q", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-eval") {
		t.Error("the CSP must not allow eval")
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Error("the CSP must not allow inline script")
	}
}

// TestTheCockpitRefusesToServeOffLoopback is asserted at the guard level: a
// cockpit on a routable address has one control where there should be two.
func TestTheCockpitRefusesToServeOffLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:4646", "10.0.0.5:4646", "[::]:4646", "example.com:4646"} {
		if err := uiguard.AssertLoopbackBindAddr(addr); err == nil {
			t.Errorf("%q must be refused as a cockpit bind address", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:4646", "localhost:4646", "[::1]:4646"} {
		if err := uiguard.AssertLoopbackBindAddr(addr); err != nil {
			t.Errorf("%q is loopback and should be allowed: %v", addr, err)
		}
	}
}

// TestAWildcardMatchesExactlyOneSegment pins the matcher that replaced prefix
// matching on routes with a fixed tail.
//
// This exists because a prefix did not: "/v1/agents/" was written to admit
// `{name}/bind` and also admitted `/v1/agents/test`, which runs the submitted
// command on the host. The bug was in the matcher's reach, not in the list, so
// the matcher is what gets pinned.
func TestAWildcardMatchesExactlyOneSegment(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
		why           string
	}{
		{"/v1/agents/*/bind", "/v1/agents/claude/bind", true, "the intended shape"},
		{"/v1/agents/*/bind", "/v1/agents/test", false, "the exec route must not slip in"},
		{"/v1/agents/*/bind", "/v1/agents/bind", false, "a missing name is not a match"},
		{"/v1/agents/*/bind", "/v1/agents//bind", false, "an empty segment is not a name"},
		{"/v1/agents/*/bind", "/v1/agents/a/b/bind", false, "* is one segment, not many"},
		{"/v1/agents/*/bind", "/v1/agents/claude/bind/extra", false, "no trailing remainder"},
		{"/v1/agents/*", "/v1/agents/claude", true, "a bare id"},
		{"/v1/agents/*", "/v1/agents/claude/bind", false, "* does not span a slash"},
		{"/v1/projects/*/environments", "/v1/projects/tripon/environments", true, "env add"},
		{"/v1/projects/*/environments", "/v1/projects/tripon", false, "the tail is required"},
		{"/v1/sessions/*/exec", "/v1/sessions/s1/exec", true, "exec"},
		{"/v1/sessions/*/exec", "/v1/sessions/s1/files", false, "raw bytes stay refused"},
	} {
		t.Run(tc.pattern+" vs "+tc.path, func(t *testing.T) {
			if got := matchSegments(tc.pattern, tc.path); got != tc.want {
				t.Fatalf("matchSegments(%q, %q) = %v, want %v — %s",
					tc.pattern, tc.path, got, tc.want, tc.why)
			}
		})
	}
}

// TestNoRouteAdmitsPathTraversal keeps "..' out of every shape, not just the
// prefix one it was originally checked in.
func TestNoRouteAdmitsPathTraversal(t *testing.T) {
	for _, path := range []string{
		"/v1/agents/../secrets/gitlab-token",
		"/v1/projects/../../etc/passwd",
		"/v1/changes/..%2f..%2fsecrets",
		"/v1/sessions/s1/../../secrets",
	} {
		t.Run(path, func(t *testing.T) {
			for _, m := range []string{
				http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPut,
			} {
				u, err := url.Parse(path)
				if err != nil {
					continue
				}
				if reason := admit(m, u); reason == "" {
					t.Fatalf("%s %s was admitted; traversal must never match a route", m, path)
				}
			}
		})
	}
}

// TestEveryAllowlistedMutationIsOnTheDaemon guards the other direction: a route
// the cockpit may call that the daemon does not serve is a dead button.
func TestEveryAllowlistedMutationIsOnTheDaemon(t *testing.T) {
	// The daemon's registered patterns, as of internal/daemon. Kept as literals
	// rather than reflected out of the daemon package so that deleting a handler
	// there fails HERE, loudly, instead of quietly agreeing with itself.
	daemonServes := map[string]bool{
		"POST /v1/projects":                    true,
		"POST /v1/projects/*/environments":     true,
		"PUT /v1/projects/*/capabilities":      true,
		"DELETE /v1/projects/*":                true,
		"DELETE /v1/projects/*/environments/*": true,
		"POST /v1/connections":                 true,
		"POST /v1/connections/test":            true,
		"DELETE /v1/connections/*":             true,
		"POST /v1/agents/*/bind":               true,
		"DELETE /v1/agents/*":                  true,
		"POST /v1/secrets":                     true,
		"POST /v1/sessions":                    true,
		"DELETE /v1/sessions/*":                true,
		"POST /v1/sessions/*/exec":             true,
		"POST /v1/sessions/*/approvals/*":      true,
		"POST /v1/changes/*/decision":          true,
		"POST /v1/policy/edit":                 true,
	}
	for _, rt := range towerRoutes {
		if rt.Method == http.MethodGet {
			continue
		}
		key := rt.Method + " " + rt.Path
		if !daemonServes[key] {
			t.Errorf("the cockpit may call %s but the daemon does not serve it — dead button", key)
		}
	}
}

// TestEveryClickHookIsWired: every data-* attribute the SPA renders as a click
// target must appear in the delegated listener's selector, and every selector
// entry must be acted on.
//
// This is here because the + buttons shipped dead once already: the sidebar was
// rewritten to OptionC2's explorer, the handlers were consolidated behind one
// data-add dispatcher, and two screens kept emitting the old data-addconn /
// data-addsecret attributes that nothing listened for any more. The page looked
// finished and two of its buttons did nothing.
func TestEveryClickHookIsWired(t *testing.T) {
	b, err := cockpitFS.ReadFile("cockpit/cockpit.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)

	sel := regexp.MustCompile(`(?s)ev\.target\.closest\((.*?)\);`).FindStringSubmatch(js)
	if sel == nil {
		t.Fatal("could not find the delegated click listener's selector")
	}
	inSelector := map[string]bool{}
	for _, m := range regexp.MustCompile(`data-([a-z]+)\]`).FindAllStringSubmatch(sel[1], -1) {
		inSelector[m[1]] = true
	}

	acted := map[string]bool{}
	for _, m := range regexp.MustCompile(`a\('data-([a-z]+)'\)`).FindAllStringSubmatch(js, -1) {
		acted[m[1]] = true
	}

	// Attributes read off an element rather than clicked. Listed explicitly so
	// adding one is a decision, not an accident.
	readOnly := map[string]bool{"chg": true, "wizref": true, "wizval": true, "tab": true}

	emitted := map[string]bool{}
	for _, m := range regexp.MustCompile(`data-([a-z]+)=`).FindAllStringSubmatch(js, -1) {
		emitted[m[1]] = true
	}

	for name := range emitted {
		if readOnly[name] || inSelector[name] {
			continue
		}
		t.Errorf("the SPA renders data-%s but the click listener does not select it — dead control", name)
	}
	for name := range inSelector {
		if !acted[name] && name != "tab" {
			t.Errorf("data-%s is in the selector but nothing acts on it", name)
		}
	}
}

// TestTheExplorerOffersAnAddForEverySectionThatHasOne: the sections an operator
// creates things in must each carry a +, and the dispatcher must know them all.
func TestTheExplorerOffersAnAddForEverySectionThatHasOne(t *testing.T) {
	b, err := cockpitFS.ReadFile("cockpit/cockpit.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, kind := range []string{"env", "tool", "conn", "secret", "session"} {
		if !strings.Contains(js, `'`+kind+`'`) && !strings.Contains(js, kind+":") {
			t.Errorf("the add dispatcher has no entry for %q", kind)
		}
		if !strings.Contains(js, `data-add="'+esc(addAction)`) &&
			!strings.Contains(js, "esc(addAction)") {
			t.Fatal("the section header does not render a + at all")
		}
	}
	// Agents deliberately have no +: registering one runs a command on the host.
	if regexp.MustCompile(`esec\('Agents', [^,]+, '`).MatchString(js) {
		t.Error("the Agents section offers a + — registering an agent runs a command " +
			"on the host and must stay on the CLI")
	}
}
