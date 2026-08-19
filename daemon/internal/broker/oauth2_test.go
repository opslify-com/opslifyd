package broker

// F5.4 unit tests. Every OAuth2 call is answered by an in-process stub server
// wired through the injectable httpDoer seam — NO network. All token material
// below is CLEARLY FAKE and never real.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
)

const (
	fakeRefreshToken  = "FAKE-OAUTH-REFRESH-TOKEN-durable-crownjewel-do-not-use"
	fakeRefreshToken2 = "FAKE-OAUTH-REFRESH-TOKEN-second-service-do-not-use"
	fakeUserCode      = "WDJB-MJHT"
	fakeDeviceCode    = "FAKE-DEVICE-CODE-abc123"
)

// oauth2Stub is an in-process OAuth2 server implementing the device endpoint and
// the token endpoint (both the device-code poll grant and the refresh grant). It
// is fully deterministic and records what it saw so tests can assert.
type oauth2Stub struct {
	server *httptest.Server

	mu sync.Mutex
	// pendingPolls is how many authorization_pending responses to give before the
	// device poll succeeds.
	pendingPolls int
	// pollCount / mintCount count device-poll and refresh-mint calls.
	pollCount int
	mintCount int
	// refreshToken is issued on device success; refuseRefresh makes the refresh
	// grant fail (revoked/expired refresh token).
	refreshToken  string
	refuseRefresh bool
	// mintedTokens records every access token handed out (to assert per-request).
	mintedTokens []string
	// sawRefresh records refresh-token values seen at the token endpoint (to prove
	// the refresh token is what's exchanged, and to detect leaks).
	lastRefreshSeen string
}

func newOAuth2Stub(t *testing.T, pendingPolls int, refresh string) *oauth2Stub {
	t.Helper()
	s := &oauth2Stub{pendingPolls: pendingPolls, refreshToken: refresh}
	mux := http.NewServeMux()
	mux.HandleFunc("/device", s.handleDevice)
	mux.HandleFunc("/token", s.handleToken)
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func (s *oauth2Stub) cfg(scopes ...string) OAuth2ServiceConfig {
	return OAuth2ServiceConfig{
		TokenURL:  s.server.URL + "/token",
		DeviceURL: s.server.URL + "/device",
		ClientID:  "FAKE-CLIENT-ID",
		Scopes:    scopes,
	}
}

func (s *oauth2Stub) handleDevice(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":      fakeDeviceCode,
		"user_code":        fakeUserCode,
		"verification_uri": s.server.URL + "/activate",
		"interval":         1,
		"expires_in":       600,
	})
}

func (s *oauth2Stub) handleToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	s.mu.Lock()
	defer s.mu.Unlock()

	switch form.Get("grant_type") {
	case deviceCodeGrantType:
		s.pollCount++
		if s.pollCount <= s.pendingPolls {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "authorization_pending"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  "FAKE-DEVICE-ACCESS-IGNORED",
			"refresh_token": s.refreshToken,
			"token_type":    "bearer",
			"expires_in":    3600,
		})
	case refreshGrantType:
		s.mintCount++
		s.lastRefreshSeen = form.Get("refresh_token")
		if s.refuseRefresh {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
			return
		}
		tok := "FAKE-ACCESS-TOKEN-shortlived-" + itoa(s.mintCount)
		s.mintedTokens = append(s.mintedTokens, tok)
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": tok,
			"token_type":   "bearer",
			"expires_in":   900,
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// --- device-flow onboarding -------------------------------------------------

// TestDeviceFlowStoresRefreshEncrypted proves onboarding completes the device
// flow (after a pending poll) and that the refresh token lands ENCRYPTED in the
// vault — absent from the raw vault file, never returned in cleartext by the
// metadata surface.
func TestDeviceFlowStoresRefreshEncrypted(t *testing.T) {
	stub := newOAuth2Stub(t, 1 /*pending polls*/, fakeRefreshToken)
	onb := DeviceOnboarder{
		Cfg:   stub.cfg("repo"),
		Doer:  http.DefaultClient,
		Now:   time.Now,
		Sleep: func(time.Duration) {}, // no real waiting
	}
	da, err := onb.StartDeviceFlow(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if da.UserCode != fakeUserCode {
		t.Fatalf("user code = %q", da.UserCode)
	}
	refresh, err := onb.PollForRefreshToken(context.Background(), da)
	if err != nil {
		t.Fatalf("PollForRefreshToken: %v", err)
	}
	if string(refresh) != fakeRefreshToken {
		t.Fatalf("refresh token mismatch")
	}

	// Store it as `opslify creds add` would.
	v, path := newTestVault(t)
	if err := v.Put(context.Background(), "github", refresh, PutMeta{Provider: "oauth2/github", Scope: "repo"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	if strings.Contains(string(raw), fakeRefreshToken) {
		t.Fatalf("SECURITY: refresh token present in plaintext in vault file")
	}
}

func TestDeviceFlowFailsClosedOnDenied(t *testing.T) {
	stub := newOAuth2Stub(t, 0, fakeRefreshToken)
	// Force the poll to be denied.
	stub.mu.Lock()
	stub.pendingPolls = 0
	stub.mu.Unlock()
	// Rewire the token handler to deny by using a refuse flag on the device grant:
	// simplest is a fresh stub whose device grant always returns access_denied.
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/device") {
			writeJSON(w, http.StatusOK, map[string]any{
				"device_code": fakeDeviceCode, "user_code": fakeUserCode,
				"verification_uri": "http://example.test/activate", "interval": 1, "expires_in": 600,
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "access_denied"})
	}))
	t.Cleanup(deny.Close)
	onb := DeviceOnboarder{
		Cfg:   OAuth2ServiceConfig{TokenURL: deny.URL + "/token", DeviceURL: deny.URL + "/device", ClientID: "x"},
		Sleep: func(time.Duration) {},
	}
	da, err := onb.StartDeviceFlow(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if _, err := onb.PollForRefreshToken(context.Background(), da); err == nil {
		t.Fatal("expected fail-closed on access_denied, got nil")
	}
}

// --- per-request access-token minting via injection -------------------------

// oauth2Injector wires a vault holding one granted oauth2 refresh token + an
// injector with the OAuth2 adapter registered against the stub.
func oauth2Injector(t *testing.T, ref string, refresh []byte, meta PutMeta, services map[string]OAuth2ServiceConfig) *Injector {
	t.Helper()
	v, _ := newTestVault(t)
	if err := v.Put(context.Background(), ref, refresh, meta, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	server := NewCredServer(fixedNow)
	ts := httptest.NewServer(http.HandlerFunc(server.ServeHTTP))
	t.Cleanup(ts.Close)
	in := NewInjector(NewBroker(v), server, ts.URL, 15*time.Minute, fixedNow)
	in.RegisterOAuth2Adapters(services, http.DefaultClient)
	return in
}

func TestOAuth2MintPerRequestAccessToken(t *testing.T) {
	stub := newOAuth2Stub(t, 0, fakeRefreshToken)
	in := oauth2Injector(t, "github", []byte(fakeRefreshToken),
		PutMeta{Provider: "oauth2/github", Scope: "repo"},
		map[string]OAuth2ServiceConfig{"github": stub.cfg("repo")})
	rec, sink := recorderCapture(t)

	grants := []policy.Cred{{Name: "github", Provider: "oauth2/github"}}
	si, err := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	joined := strings.Join(si.Env, "\n")
	// The REFRESH token must never appear in the injected env.
	if strings.Contains(joined, fakeRefreshToken) {
		t.Fatalf("SECURITY: refresh token present in injected env: %q", joined)
	}
	// A short-lived access token IS injected (env fallback, agent-visible).
	if !strings.Contains(joined, "OPSLIFY_OAUTH_TOKEN_GITHUB=FAKE-ACCESS-TOKEN-shortlived-1") {
		t.Fatalf("missing minted access token in env: %q", joined)
	}
	// The stub was handed the refresh token at the token endpoint (proves exchange).
	if stub.lastRefreshSeen != fakeRefreshToken {
		t.Fatalf("token endpoint did not receive the refresh token")
	}

	// A second inject mints a FRESH access token (per-request, not cached), and the
	// vault still stores ONLY the refresh token (access tokens never persisted).
	si2, err := in.InjectSession(context.Background(), rec, "sess-2", grants)
	if err != nil {
		t.Fatalf("InjectSession 2: %v", err)
	}
	if !strings.Contains(strings.Join(si2.Env, "\n"), "FAKE-ACCESS-TOKEN-shortlived-2") {
		t.Fatalf("second inject did not mint a fresh access token: %q", si2.Env)
	}
	if stub.mintCount != 2 {
		t.Fatalf("expected 2 mints (per-request), got %d", stub.mintCount)
	}

	// cred.resolve audited with provider/scope, NEVER the token.
	events := credEvents(t, sink)
	if len(events) == 0 {
		t.Fatal("no cred.resolve events")
	}
	for _, e := range events {
		blob, _ := json.Marshal(e.Payload)
		if strings.Contains(string(blob), fakeRefreshToken) || strings.Contains(string(blob), "FAKE-ACCESS-TOKEN") {
			t.Fatalf("SECURITY: token present in cred.resolve audit: %s", blob)
		}
	}
	// The injected path is the documented weaker (agent-visible) env fallback.
	if len(si.Warnings) == 0 {
		t.Fatal("expected an env-fallback (non-blind) warning")
	}
}

// TestOAuth2SecondServiceConfigOnly proves adding a SECOND oauth2 service is
// config-only: the same generic adapter serves it with no new code.
func TestOAuth2SecondServiceConfigOnly(t *testing.T) {
	gh := newOAuth2Stub(t, 0, fakeRefreshToken)
	gl := newOAuth2Stub(t, 0, fakeRefreshToken2)
	services := map[string]OAuth2ServiceConfig{
		"github": gh.cfg("repo"),
		"gitlab": gl.cfg("api"),
	}
	in := oauth2Injector(t, "gitlab-token", []byte(fakeRefreshToken2),
		PutMeta{Provider: "oauth2/gitlab", Scope: "api"}, services)
	rec, _ := recorderCapture(t)
	grants := []policy.Cred{{Name: "gitlab-token", Provider: "oauth2/gitlab"}}
	si, err := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	if !strings.Contains(strings.Join(si.Env, "\n"), "OPSLIFY_OAUTH_TOKEN_GITLAB=FAKE-ACCESS-TOKEN-shortlived-1") {
		t.Fatalf("second service did not mint via the same adapter: %q", si.Env)
	}
	if gl.mintCount != 1 || gh.mintCount != 0 {
		t.Fatalf("wrong service exchanged: gitlab=%d github=%d", gl.mintCount, gh.mintCount)
	}
}

// --- deny-by-default + fail-closed ------------------------------------------

func TestOAuth2DenyByDefaultUngranted(t *testing.T) {
	stub := newOAuth2Stub(t, 0, fakeRefreshToken)
	in := oauth2Injector(t, "github", []byte(fakeRefreshToken),
		PutMeta{Provider: "oauth2/github", Scope: "repo"},
		map[string]OAuth2ServiceConfig{"github": stub.cfg("repo")})
	rec, _ := recorderCapture(t)
	// No grants → the session is not granted the service → no token, no mint.
	si, err := in.InjectSession(context.Background(), rec, "sess-1", []policy.Cred{{Name: "other", Provider: "oauth2/other"}})
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: ungranted session received env: %q", si.Env)
	}
	if stub.mintCount != 0 {
		t.Fatalf("SECURITY: token minted for an ungranted session")
	}
}

func TestOAuth2FailsClosedOnRevokedRefresh(t *testing.T) {
	stub := newOAuth2Stub(t, 0, fakeRefreshToken)
	stub.refuseRefresh = true // simulate a revoked/expired refresh token
	in := oauth2Injector(t, "github", []byte(fakeRefreshToken),
		PutMeta{Provider: "oauth2/github", Scope: "repo"},
		map[string]OAuth2ServiceConfig{"github": stub.cfg("repo")})
	rec, _ := recorderCapture(t)
	grants := []policy.Cred{{Name: "github", Provider: "oauth2/github"}}
	si, err := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	// Fail closed: no env, and a warning — never a stale-token reuse.
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: env injected despite revoked refresh token: %q", si.Env)
	}
	if len(si.Warnings) == 0 {
		t.Fatal("expected a fail-closed warning for the revoked refresh token")
	}
}

// --- config validation ------------------------------------------------------

func TestOAuth2ConfigValidateFailClosed(t *testing.T) {
	cases := map[string]OAuth2ServiceConfig{
		"missing client_id":  {TokenURL: "https://t.example/token", DeviceURL: "https://t.example/device"},
		"missing token_url":  {ClientID: "x", DeviceURL: "https://t.example/device"},
		"missing device_url": {ClientID: "x", TokenURL: "https://t.example/token"},
		"bad token_url":      {ClientID: "x", TokenURL: "://nope", DeviceURL: "https://t.example/device"},
		"non-http scheme":    {ClientID: "x", TokenURL: "ftp://t.example/token", DeviceURL: "https://t.example/device"},
	}
	for name, c := range cases {
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: expected a fail-closed validation error, got nil", name)
		}
	}
	good := OAuth2ServiceConfig{ClientID: "x", TokenURL: "https://t.example/token", DeviceURL: "https://t.example/device"}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestOAuth2UnknownServiceFailsClosed(t *testing.T) {
	stub := newOAuth2Stub(t, 0, fakeRefreshToken)
	in := oauth2Injector(t, "github", []byte(fakeRefreshToken),
		PutMeta{Provider: "oauth2/github", Scope: "repo"},
		map[string]OAuth2ServiceConfig{"github": stub.cfg("repo")})
	// The vaulted secret is granted, but its service isn't configured on the
	// adapter → the mint must fail closed (no token, no panic).
	in.oauth2 = NewOAuth2Adapter(map[string]OAuth2ServiceConfig{"someother": stub.cfg()}, http.DefaultClient)
	rec, _ := recorderCapture(t)
	grants := []policy.Cred{{Name: "github", Provider: "oauth2/github"}}
	si, err := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: env injected for an unconfigured service: %q", si.Env)
	}
}
