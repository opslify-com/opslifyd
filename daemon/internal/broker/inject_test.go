package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// fixedNow returns a deterministic clock for TTL/expiry assertions.
func fixedNow() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }

// awsCredDoc is a FAKE AWS container-credentials document. The SecretAccessKey is
// the durable-secret marker the adversarial tests hunt for in the container env.
const awsSecretMarker = "FAKE-SECRETACCESSKEY-do-not-use-crownjewel"

func awsCredDoc() []byte {
	b, _ := json.Marshal(map[string]any{
		"AccessKeyId":     "AKIAFAKE",
		"SecretAccessKey": awsSecretMarker,
		"Token":           "FAKE-session-token",
	})
	return b
}

// injectorWithAWS wires a broker over a vault holding one granted AWS cred and an
// injector with a live creds endpoint. Returns the injector, the endpoint server,
// and the endpoint base URL.
func injectorWithAWS(t *testing.T, ref string, value []byte, meta PutMeta) (*Injector, *CredServer, string) {
	t.Helper()
	v, _ := newTestVault(t)
	if err := v.Put(context.Background(), ref, value, meta, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	b := NewBroker(v)
	server := NewCredServer(fixedNow)
	ts := httptest.NewServer(http.HandlerFunc(server.ServeHTTP))
	t.Cleanup(ts.Close)
	in := NewInjector(b, server, ts.URL, 15*time.Minute, fixedNow)
	return in, server, ts.URL
}

// TestInjectAWSNoRawSecretInEnv proves the AWS blind path: granted cred → the
// injected env carries ONLY the endpoint URI + a per-session token, and the raw
// secret appears NOWHERE in the env (it is served by the endpoint instead).
func TestInjectAWSNoRawSecretInEnv(t *testing.T) {
	in, _, base := injectorWithAWS(t, "aws/deploy", awsCredDoc(), PutMeta{Provider: "aws"})
	rec, sink := recorderCapture(t)

	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	si, err := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}

	joined := strings.Join(si.Env, "\n")
	if strings.Contains(joined, awsSecretMarker) {
		t.Fatalf("SECURITY: raw secret present in injected env: %q", joined)
	}
	if !strings.Contains(joined, "AWS_CONTAINER_CREDENTIALS_FULL_URI="+base+CredPath+"sess-1") {
		t.Fatalf("missing/incorrect FULL_URI: %q", joined)
	}
	if !strings.Contains(joined, "AWS_CONTAINER_CREDENTIALS_TOKEN=") {
		t.Fatalf("missing per-session token: %q", joined)
	}
	// The blind path must NOT warn about being agent-visible.
	for _, w := range si.Warnings {
		if strings.Contains(w, "AGENT-VISIBLE") {
			t.Fatalf("AWS blind path wrongly flagged agent-visible: %q", w)
		}
	}
	// cred.resolve audit fired and carries NO value.
	evs := credEvents(t, sink)
	if len(evs) != 1 {
		t.Fatalf("want 1 cred.resolve, got %d", len(evs))
	}
	assertAuditNoValue(t, evs[0], []byte(awsSecretMarker), true, "aws/deploy")
}

// TestCredEndpointTokenGate proves the endpoint is reachable ONLY with the owning
// session's token: the right token returns the scoped cred; a wrong token, a
// missing token, and a cross-session token are all refused with 403.
func TestCredEndpointTokenGate(t *testing.T) {
	in, _, base := injectorWithAWS(t, "aws/deploy", awsCredDoc(), PutMeta{Provider: "aws"})
	rec, _ := recorderCapture(t)
	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	si, err := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	token := envValue(t, si.Env, "AWS_CONTAINER_CREDENTIALS_TOKEN")
	uri := envValue(t, si.Env, "AWS_CONTAINER_CREDENTIALS_FULL_URI")

	// Right token → 200 + the scoped cred (with a stamped Expiration).
	body, code := fetch(t, uri, token)
	if code != http.StatusOK {
		t.Fatalf("right token: code %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("cred body not JSON: %v", err)
	}
	if doc["Expiration"] == nil {
		t.Fatal("served cred missing TTL-bounded Expiration")
	}
	// The endpoint DOES serve the credential material (this is the value the SDK
	// fetches); the point of F5.1 is that it is not in the CONTAINER ENV and that the
	// fetch is token-gated. Under F5.3 this body becomes a short-lived STS mint.

	// Wrong token → 403.
	if _, code := fetch(t, uri, "deadbeef"); code != http.StatusForbidden {
		t.Fatalf("wrong token: code %d, want 403", code)
	}
	// No token → 403.
	if _, code := fetch(t, uri, ""); code != http.StatusForbidden {
		t.Fatalf("no token: code %d, want 403", code)
	}
	// Cross-session: a valid token but against ANOTHER session's path → 403.
	crossURI := base + CredPath + "sess-2"
	if _, code := fetch(t, crossURI, token); code != http.StatusForbidden {
		t.Fatalf("cross-session: code %d, want 403", code)
	}
	// A different session's token against sess-1 → 403.
	si2, _ := in.InjectSession(context.Background(), rec, "sess-2", grants)
	otherToken := envValue(t, si2.Env, "AWS_CONTAINER_CREDENTIALS_TOKEN")
	if _, code := fetch(t, uri, otherToken); code != http.StatusForbidden {
		t.Fatalf("foreign token vs sess-1: code %d, want 403", code)
	}
}

// TestCredEndpointExpiry proves the served credential is TTL-bounded: after expiry
// the endpoint refuses even the right token (no replay past TTL).
func TestCredEndpointExpiry(t *testing.T) {
	server := NewCredServer(fixedNow)
	server.Register("sess-1", "tok", []byte(`{"ok":true}`), "application/json", fixedNow().Add(1*time.Minute))
	ts := httptest.NewServer(http.HandlerFunc(server.ServeHTTP))
	defer ts.Close()
	uri := ts.URL + CredPath + "sess-1"

	if _, code := fetch(t, uri, "tok"); code != http.StatusOK {
		t.Fatalf("before expiry: code %d", code)
	}
	// Advance past expiry.
	server.now = func() time.Time { return fixedNow().Add(2 * time.Minute) }
	if _, code := fetch(t, uri, "tok"); code != http.StatusForbidden {
		t.Fatalf("after expiry: code %d, want 403", code)
	}
}

// TestReleaseDropsEndpointCred proves teardown revokes the token: after Release the
// right token no longer fetches.
func TestReleaseDropsEndpointCred(t *testing.T) {
	in, _, _ := injectorWithAWS(t, "aws/deploy", awsCredDoc(), PutMeta{Provider: "aws"})
	rec, _ := recorderCapture(t)
	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	si, _ := in.InjectSession(context.Background(), rec, "sess-1", grants)
	uri := envValue(t, si.Env, "AWS_CONTAINER_CREDENTIALS_FULL_URI")
	token := envValue(t, si.Env, "AWS_CONTAINER_CREDENTIALS_TOKEN")

	if _, code := fetch(t, uri, token); code != http.StatusOK {
		t.Fatal("pre-release fetch should succeed")
	}
	in.Release("sess-1")
	if _, code := fetch(t, uri, token); code != http.StatusForbidden {
		t.Fatalf("post-release: code %d, want 403", code)
	}
}

// TestInjectUngrantedDenyByDefault proves deny-by-default: a ref not in the grant
// set is not injected (no env, a warning), and no credential is served.
func TestInjectUngrantedDenyByDefault(t *testing.T) {
	in, server, _ := injectorWithAWS(t, "aws/deploy", awsCredDoc(), PutMeta{Provider: "aws"})
	rec, _ := recorderCapture(t)
	// Grant a DIFFERENT ref than what is stored — Resolve denies it by default.
	grants := []policy.Cred{{Name: "aws/other", Provider: "aws"}}
	si, err := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: ungranted cred produced env: %q", si.Env)
	}
	if len(si.Warnings) == 0 {
		t.Fatal("expected a fail-closed warning for the ungranted cred")
	}
	// Nothing registered on the endpoint.
	server.mu.Lock()
	n := len(server.entries)
	server.mu.Unlock()
	if n != 0 {
		t.Fatalf("SECURITY: endpoint registered a cred for an ungranted ref (%d entries)", n)
	}
}

// TestInjectAWSNoEndpointFailsClosed proves the AWS path fails closed with no
// endpoint: it does NOT fall back to putting the raw secret in the env.
func TestInjectAWSNoEndpointFailsClosed(t *testing.T) {
	v, _ := newTestVault(t)
	_ = v.Put(context.Background(), "aws/deploy", awsCredDoc(), PutMeta{Provider: "aws"}, false)
	in := NewInjector(NewBroker(v), nil, "", 15*time.Minute, fixedNow) // no server
	rec, _ := recorderCapture(t)
	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	si, err := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: AWS path injected env with no endpoint: %q", si.Env)
	}
	if len(si.Warnings) == 0 {
		t.Fatal("expected a fail-closed warning")
	}
}

// TestInjectGCPEnvFallbackWeaker proves the GCP/Azure v1 path: a short-lived token
// IS injected into the env (visible) and is flagged as the weaker, agent-visible
// path. This is the honest-scope test.
func TestInjectGCPEnvFallbackWeaker(t *testing.T) {
	in, server, _ := injectorWithAWS(t, "gcp/deploy", []byte("FAKE-gcp-oauth-token"), PutMeta{Provider: "gcp"})
	rec, _ := recorderCapture(t)
	grants := []policy.Cred{{Name: "gcp/deploy", Provider: "gcp"}}
	si, err := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	if v := envValue(t, si.Env, "CLOUDSDK_AUTH_ACCESS_TOKEN"); v != "FAKE-gcp-oauth-token" {
		t.Fatalf("gcp token not env-injected: %q", si.Env)
	}
	// Honest labelling: the weaker path warns it is agent-visible.
	var warned bool
	for _, w := range si.Warnings {
		if strings.Contains(w, "AGENT-VISIBLE") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("GCP env fallback not flagged agent-visible: %v", si.Warnings)
	}
	// The env fallback uses NO endpoint entry.
	server.mu.Lock()
	n := len(server.entries)
	server.mu.Unlock()
	if n != 0 {
		t.Fatalf("env fallback should not register an endpoint cred, got %d", n)
	}
}

// TestInjectTTLFromMeta proves the served credential's Expiration honours the
// secret's own meta.TTL.
func TestInjectTTLFromMeta(t *testing.T) {
	in, _, _ := injectorWithAWS(t, "aws/deploy", awsCredDoc(), PutMeta{Provider: "aws", TTL: "5m"})
	rec, _ := recorderCapture(t)
	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	si, _ := in.InjectSession(context.Background(), rec, "sess-1", grants)
	uri := envValue(t, si.Env, "AWS_CONTAINER_CREDENTIALS_FULL_URI")
	token := envValue(t, si.Env, "AWS_CONTAINER_CREDENTIALS_TOKEN")
	body, _ := fetch(t, uri, token)
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	want := fixedNow().Add(5 * time.Minute).Format(time.RFC3339)
	if doc["Expiration"] != want {
		t.Fatalf("Expiration = %v, want %v (meta.TTL=5m)", doc["Expiration"], want)
	}
}

// TestAWSNonJSONFailsClosed proves an unshaped raw AWS secret is refused rather
// than served/leaked.
func TestAWSNonJSONFailsClosed(t *testing.T) {
	in, _, _ := injectorWithAWS(t, "aws/deploy", []byte("raw-not-json-secret"), PutMeta{Provider: "aws"})
	rec, _ := recorderCapture(t)
	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	si, _ := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: non-JSON AWS secret produced env: %q", si.Env)
	}
	if len(si.Warnings) == 0 {
		t.Fatal("expected fail-closed warning for non-JSON aws secret")
	}
}

func fetch(t *testing.T, url, token string) ([]byte, int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode
}

func envValue(t *testing.T, env []string, key string) string {
	t.Helper()
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			return v
		}
	}
	return ""
}

var _ = bytes.Contains
