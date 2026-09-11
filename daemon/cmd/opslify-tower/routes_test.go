package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
		{http.MethodPost, "/v1/secrets"},                // adding a value from a browser
		{http.MethodPut, "/v1/secrets/gitlab-token"},    // rotation
		{http.MethodGet, "/v1/sessions/s1/files"},       // raw workspace bytes
		{http.MethodPut, "/v1/sessions/s1/files"},
		{http.MethodGet, "/v1/sessions/s1/trace"}, // the trace drawer reads it via SSE, not here
		{http.MethodDelete, "/v1/projects/tripon"},
		{http.MethodPost, "/v1/agents"}, // registering an agent runs a command
		{http.MethodDelete, "/v1/connections/gitlab"},
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

// TestTheCockpitNeverAsksForASecretValue: the page must not contain a request for
// a value route, so a reviewer can confirm the claim by reading it.
func TestTheCockpitNeverAsksForASecretValue(t *testing.T) {
	b, err := cockpitFS.ReadFile("cockpit/cockpit.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, forbidden := range []string{"value_b64", "/v1/secrets/'", "secret_value", "reveal"} {
		if strings.Contains(js, forbidden) {
			t.Errorf("the cockpit references %q; it must show refs and metadata only", forbidden)
		}
	}
	// And it must say so on the page, because an operator should not have to trust
	// a promise made in a test.
	if !strings.Contains(js, "Values are never shown here") {
		t.Error("the secrets panel should state that values are never shown")
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
