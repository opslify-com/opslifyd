package broker

// F5.3 unit tests. Every real cloud call is answered by an in-process stub
// (httptest) wired through the injectable httpDoer/endpoint seam — NO network,
// NO real cloud. Real-cloud exercise is integration-gated (documented at the
// bottom of this file). All secret material below is CLEARLY FAKE.

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// ---- fake source identities (clearly fake; never real) --------------------

const (
	fakeAWSSourceKey   = "FAKE-AWS-SOURCE-SECRETKEY-crownjewel-do-not-use"
	fakeAWSMintedKey   = "FAKE-AWS-MINTED-SECRETKEY-scoped-shortlived"
	fakeAWSMintedTok   = "FAKE-AWS-MINTED-SESSION-TOKEN"
	fakeMintedTokenGCP = "FAKE-GCP-IMPERSONATED-TOKEN"
	fakeMintedAzureTok = "FAKE-AZURE-SCOPED-TOKEN"
)

// scopeDownPolicy is a minimal valid IAM policy used as the AWS scope-down
// session policy (meta.Scope).
const scopeDownPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`

func awsSourceDocJSON() []byte {
	b, _ := json.Marshal(map[string]any{
		"AccessKeyId":     "AKIAFAKESOURCE",
		"SecretAccessKey": fakeAWSSourceKey,
		"RoleArn":         "arn:aws:iam::123456789012:role/opslify-target",
		"Region":          "us-east-1",
	})
	return b
}

// stsStub answers AssumeRole with a canned minted credential and records the
// last request form so a test can assert the scope-down policy + duration.
type stsStub struct {
	server   *httptest.Server
	lastForm url.Values
}

func newSTSStub(t *testing.T) *stsStub {
	t.Helper()
	s := &stsStub{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.lastForm, _ = url.ParseQuery(string(body))
		// A real STS response would never echo the source key; the stub asserts
		// nothing about auth (SigV4 still ran on the daemon side).
		exp := fixedNow().Add(15 * time.Minute).UTC().Format(time.RFC3339)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<AssumeRoleResponse><AssumeRoleResult><Credentials>` +
			`<AccessKeyId>AKIAFAKEMINTED</AccessKeyId>` +
			`<SecretAccessKey>` + fakeAWSMintedKey + `</SecretAccessKey>` +
			`<SessionToken>` + fakeAWSMintedTok + `</SessionToken>` +
			`<Expiration>` + exp + `</Expiration>` +
			`</Credentials></AssumeRoleResult></AssumeRoleResponse>`))
	}))
	t.Cleanup(s.server.Close)
	return s
}

// cloudInjector wires a broker over a vault holding one granted cred plus an
// injector with a live creds endpoint and the F5.3 cloud adapters registered
// against the given stub endpoints.
func cloudInjector(t *testing.T, ref string, value []byte, meta PutMeta, cfg CloudConfig) (*Injector, *CredServer, string) {
	t.Helper()
	v, _ := newTestVault(t)
	if err := v.Put(context.Background(), ref, value, meta, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	server := NewCredServer(fixedNow)
	ts := httptest.NewServer(http.HandlerFunc(server.ServeHTTP))
	t.Cleanup(ts.Close)
	in := NewInjector(NewBroker(v), server, ts.URL, 15*time.Minute, fixedNow)
	in.RegisterCloudAdapters(cfg)
	return in, server, ts.URL
}

// TestAWSSTSMintScopedCred proves: an AWS grant mints an AssumeRole scoped-down,
// <=15-min session credential that the F5.1 endpoint serves — and the DURABLE
// SOURCE KEY appears nowhere in the env NOR in the served body (only the minted
// scoped cred).
func TestAWSSTSMintScopedCred(t *testing.T) {
	sts := newSTSStub(t)
	in, _, base := cloudInjector(t, "aws/deploy", awsSourceDocJSON(),
		PutMeta{Provider: "aws", Scope: scopeDownPolicy},
		CloudConfig{AWSEndpoint: sts.server.URL})
	rec, sink := recorderCapture(t)

	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	si, err := in.InjectSession(context.Background(), rec, "sess-1", grants)
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	joined := strings.Join(si.Env, "\n")
	if strings.Contains(joined, fakeAWSSourceKey) {
		t.Fatalf("SECURITY: durable source key present in env: %q", joined)
	}
	if !strings.Contains(joined, "AWS_CONTAINER_CREDENTIALS_FULL_URI="+base+CredPath+"sess-1") {
		t.Fatalf("missing FULL_URI: %q", joined)
	}

	// Scope-down: STS request carried the session policy + a clamped duration.
	if got := sts.lastForm.Get("Policy"); got != scopeDownPolicy {
		t.Fatalf("STS session policy = %q, want scope-down policy", got)
	}
	if got := sts.lastForm.Get("DurationSeconds"); got != "900" {
		t.Fatalf("DurationSeconds = %q, want 900 (<=15m)", got)
	}

	// The endpoint serves the MINTED scoped cred, never the durable source key.
	token := envValue(t, si.Env, "AWS_CONTAINER_CREDENTIALS_TOKEN")
	uri := envValue(t, si.Env, "AWS_CONTAINER_CREDENTIALS_FULL_URI")
	body, code := fetch(t, uri, token)
	if code != http.StatusOK {
		t.Fatalf("endpoint fetch code %d", code)
	}
	if strings.Contains(string(body), fakeAWSSourceKey) {
		t.Fatalf("SECURITY: served body contains the DURABLE source key: %s", body)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("served body not JSON: %v", err)
	}
	if doc["SecretAccessKey"] != fakeAWSMintedKey {
		t.Fatalf("served SecretAccessKey = %v, want the MINTED key", doc["SecretAccessKey"])
	}
	if doc["Token"] != fakeAWSMintedTok {
		t.Fatalf("served Token = %v, want the minted session token", doc["Token"])
	}
	if doc["Expiration"] == nil {
		t.Fatal("served minted cred missing Expiration")
	}
	// cred.resolve audited with no value/token.
	evs := credEvents(t, sink)
	if len(evs) != 1 {
		t.Fatalf("want 1 cred.resolve, got %d", len(evs))
	}
	assertAuditNoValue(t, evs[0], []byte(fakeAWSSourceKey), true, "aws/deploy")
	// Provider + scope present in the audit, never the token.
	if evs[0].Payload["provider"] != "aws" {
		t.Fatalf("audit provider = %v", evs[0].Payload["provider"])
	}
	raw, _ := json.Marshal(evs[0])
	if strings.Contains(string(raw), fakeAWSMintedKey) || strings.Contains(string(raw), fakeAWSMintedTok) {
		t.Fatal("SECURITY: minted token present in cred.resolve audit")
	}
}

// TestAWSTTLClampedToCeiling proves a TTL request beyond 15 min is CLAMPED
// (broader request clamped) — DurationSeconds never exceeds 900.
func TestAWSTTLClampedToCeiling(t *testing.T) {
	sts := newSTSStub(t)
	in, _, _ := cloudInjector(t, "aws/deploy", awsSourceDocJSON(),
		PutMeta{Provider: "aws", Scope: scopeDownPolicy, TTL: "60m"},
		CloudConfig{AWSEndpoint: sts.server.URL})
	rec, _ := recorderCapture(t)
	if _, err := in.InjectSession(context.Background(), rec, "sess-1",
		[]policy.Cred{{Name: "aws/deploy", Provider: "aws"}}); err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	if got := sts.lastForm.Get("DurationSeconds"); got != "900" {
		t.Fatalf("DurationSeconds = %q, want 900 (60m clamped)", got)
	}
}

// TestAWSNoScopeDownFailsClosed proves an AWS grant with NO scope-down policy is
// refused — never an unscoped AssumeRole (no full-role credential).
func TestAWSNoScopeDownFailsClosed(t *testing.T) {
	sts := newSTSStub(t)
	in, server, _ := cloudInjector(t, "aws/deploy", awsSourceDocJSON(),
		PutMeta{Provider: "aws"}, // no Scope
		CloudConfig{AWSEndpoint: sts.server.URL})
	rec, _ := recorderCapture(t)
	si, _ := in.InjectSession(context.Background(), rec, "sess-1",
		[]policy.Cred{{Name: "aws/deploy", Provider: "aws"}})
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: unscoped AWS grant produced env: %q", si.Env)
	}
	if len(si.Warnings) == 0 {
		t.Fatal("expected a fail-closed warning for the unscoped grant")
	}
	server.mu.Lock()
	n := len(server.entries)
	server.mu.Unlock()
	if n != 0 {
		t.Fatalf("SECURITY: endpoint registered a cred for an unscoped grant (%d)", n)
	}
}

// TestAWSSTSFailureFailsClosed proves a rejected AssumeRole yields NO credential
// and NO fallback to the durable source key.
func TestAWSSTSFailureFailsClosed(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "AccessDenied", http.StatusForbidden)
	}))
	defer stub.Close()
	in, server, _ := cloudInjector(t, "aws/deploy", awsSourceDocJSON(),
		PutMeta{Provider: "aws", Scope: scopeDownPolicy},
		CloudConfig{AWSEndpoint: stub.URL})
	rec, _ := recorderCapture(t)
	si, _ := in.InjectSession(context.Background(), rec, "sess-1",
		[]policy.Cred{{Name: "aws/deploy", Provider: "aws"}})
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: failed STS exchange still injected env: %q", si.Env)
	}
	if len(si.Warnings) == 0 {
		t.Fatal("expected a fail-closed warning on STS failure")
	}
	server.mu.Lock()
	n := len(server.entries)
	server.mu.Unlock()
	if n != 0 {
		t.Fatalf("SECURITY: endpoint registered a cred after STS failure (%d)", n)
	}
}

// ---- GCP ------------------------------------------------------------------

func gcpSourceDocJSON(privKeyPEM, scopes string) []byte {
	b, _ := json.Marshal(map[string]any{
		"client_email": "sa@proj.iam.gserviceaccount.com",
		"private_key":  privKeyPEM,
		"scopes":       scopes,
	})
	return b
}

// newGCPStub answers both the token exchange and generateAccessToken. It records
// the requested scopes.
func newGCPStub(t *testing.T) (tokenURL, iamURL string, gotScopes *[]string) {
	t.Helper()
	scopes := &[]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"FAKE-GCP-SOURCE-TOKEN","expires_in":3600}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// generateAccessToken
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if sc, ok := body["scope"].([]any); ok {
			for _, s := range sc {
				*scopes = append(*scopes, s.(string))
			}
		}
		exp := fixedNow().Add(15 * time.Minute).UTC().Format(time.RFC3339)
		_, _ = w.Write([]byte(`{"accessToken":"` + fakeMintedTokenGCP + `","expireTime":"` + exp + `"}`))
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s.URL + "/token", s.URL, scopes
}

// TestGCPImpersonationScoped proves a GCP grant mints a short-lived impersonated
// token scoped to the granted scopes (stub); the durable private key never
// appears in the injected env.
func TestGCPImpersonationScoped(t *testing.T) {
	tokenURL, iamURL, gotScopes := newGCPStub(t)
	key := testRSAKeyPEM(t)
	in, _, _ := cloudInjector(t, "gcp/deploy",
		gcpSourceDocJSON(key, ""),
		PutMeta{Provider: "gcp", Scope: "https://www.googleapis.com/auth/devstorage.read_only"},
		CloudConfig{GCPTokenEndpoint: tokenURL, GCPIAMEndpoint: iamURL})
	rec, sink := recorderCapture(t)
	si, err := in.InjectSession(context.Background(), rec, "sess-1",
		[]policy.Cred{{Name: "gcp/deploy", Provider: "gcp"}})
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	if v := envValue(t, si.Env, "CLOUDSDK_AUTH_ACCESS_TOKEN"); v != fakeMintedTokenGCP {
		t.Fatalf("gcp minted token not injected: %q", si.Env)
	}
	if strings.Contains(strings.Join(si.Env, "\n"), key) {
		t.Fatal("SECURITY: durable private key present in env")
	}
	if len(*gotScopes) != 1 || (*gotScopes)[0] != "https://www.googleapis.com/auth/devstorage.read_only" {
		t.Fatalf("scopes requested = %v, want the single granted scope", *gotScopes)
	}
	// Env fallback path is honestly flagged agent-visible.
	var warned bool
	for _, w := range si.Warnings {
		if strings.Contains(w, "AGENT-VISIBLE") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("gcp path not flagged agent-visible: %v", si.Warnings)
	}
	evs := credEvents(t, sink)
	assertAuditNoValue(t, evs[0], []byte(key), true, "gcp/deploy")
}

// TestGCPScopeWideningDenied proves scope-down is REAL + fail-closed: a source
// doc requesting a scope BEYOND the granted ceiling is denied (no token).
func TestGCPScopeWideningDenied(t *testing.T) {
	tokenURL, iamURL, _ := newGCPStub(t)
	key := testRSAKeyPEM(t)
	// Ceiling grants read-only; the doc requests read_write → widening.
	in, _, _ := cloudInjector(t, "gcp/deploy",
		gcpSourceDocJSON(key, "https://www.googleapis.com/auth/devstorage.read_write"),
		PutMeta{Provider: "gcp", Scope: "https://www.googleapis.com/auth/devstorage.read_only"},
		CloudConfig{GCPTokenEndpoint: tokenURL, GCPIAMEndpoint: iamURL})
	rec, _ := recorderCapture(t)
	si, _ := in.InjectSession(context.Background(), rec, "sess-1",
		[]policy.Cred{{Name: "gcp/deploy", Provider: "gcp"}})
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: scope-widening request produced a token: %q", si.Env)
	}
	if len(si.Warnings) == 0 {
		t.Fatal("expected a fail-closed warning for scope widening")
	}
}

// TestGCPNoScopeFailsClosed proves an empty scope ceiling denies (no unscoped
// token).
func TestGCPNoScopeFailsClosed(t *testing.T) {
	tokenURL, iamURL, _ := newGCPStub(t)
	key := testRSAKeyPEM(t)
	in, _, _ := cloudInjector(t, "gcp/deploy", gcpSourceDocJSON(key, ""),
		PutMeta{Provider: "gcp"}, // no Scope
		CloudConfig{GCPTokenEndpoint: tokenURL, GCPIAMEndpoint: iamURL})
	rec, _ := recorderCapture(t)
	si, _ := in.InjectSession(context.Background(), rec, "sess-1",
		[]policy.Cred{{Name: "gcp/deploy", Provider: "gcp"}})
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: unscoped gcp grant produced a token: %q", si.Env)
	}
}

// ---- Azure ----------------------------------------------------------------

func azureSourceDocJSON(scopes string) []byte {
	b, _ := json.Marshal(map[string]any{
		"tenant_id":     "11111111-1111-1111-1111-111111111111",
		"client_id":     "22222222-2222-2222-2222-222222222222",
		"client_secret": "FAKE-AZURE-CLIENT-SECRET-crownjewel",
		"scopes":        scopes,
	})
	return b
}

func newAzureStub(t *testing.T) (authority string, gotScope *string) {
	t.Helper()
	got := new(string)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		*got = form.Get("scope")
		_, _ = w.Write([]byte(`{"access_token":"` + fakeMintedAzureTok + `","expires_in":3600}`))
	}))
	t.Cleanup(s.Close)
	return s.URL, got
}

// TestAzureScopedToken proves an Azure grant mints a scoped token via the token
// endpoint; the durable client secret never appears in the env.
func TestAzureScopedToken(t *testing.T) {
	authority, gotScope := newAzureStub(t)
	in, _, _ := cloudInjector(t, "azure/deploy",
		azureSourceDocJSON(""),
		PutMeta{Provider: "azure", Scope: "https://storage.azure.com/.default"},
		CloudConfig{AzureAuthority: authority})
	rec, _ := recorderCapture(t)
	si, err := in.InjectSession(context.Background(), rec, "sess-1",
		[]policy.Cred{{Name: "azure/deploy", Provider: "azure"}})
	if err != nil {
		t.Fatalf("InjectSession: %v", err)
	}
	if v := envValue(t, si.Env, "AZURE_ACCESS_TOKEN"); v != fakeMintedAzureTok {
		t.Fatalf("azure token not injected: %q", si.Env)
	}
	if strings.Contains(strings.Join(si.Env, "\n"), "FAKE-AZURE-CLIENT-SECRET-crownjewel") {
		t.Fatal("SECURITY: durable client secret present in env")
	}
	if *gotScope != "https://storage.azure.com/.default" {
		t.Fatalf("requested scope = %q, want the granted scope", *gotScope)
	}
}

// TestAzureScopeWideningDenied proves the Azure scope-down is fail-closed.
func TestAzureScopeWideningDenied(t *testing.T) {
	authority, _ := newAzureStub(t)
	in, _, _ := cloudInjector(t, "azure/deploy",
		azureSourceDocJSON("https://management.azure.com/.default"),
		PutMeta{Provider: "azure", Scope: "https://storage.azure.com/.default"},
		CloudConfig{AzureAuthority: authority})
	rec, _ := recorderCapture(t)
	si, _ := in.InjectSession(context.Background(), rec, "sess-1",
		[]policy.Cred{{Name: "azure/deploy", Provider: "azure"}})
	if len(si.Env) != 0 {
		t.Fatalf("SECURITY: azure scope-widening produced a token: %q", si.Env)
	}
}

// ---- scope-down unit ------------------------------------------------------

func TestClampScopes(t *testing.T) {
	// Empty ceiling → deny.
	if _, err := clampScopes(nil, nil); err == nil {
		t.Fatal("empty ceiling must deny")
	}
	// Empty request → exactly the ceiling.
	out, err := clampScopes([]string{"a", "b"}, nil)
	if err != nil || len(out) != 2 {
		t.Fatalf("default to ceiling failed: %v %v", out, err)
	}
	// Subset → allowed.
	out, err = clampScopes([]string{"a", "b"}, []string{"a"})
	if err != nil || len(out) != 1 || out[0] != "a" {
		t.Fatalf("subset clamp failed: %v %v", out, err)
	}
	// Widening → deny.
	if _, err := clampScopes([]string{"a"}, []string{"a", "c"}); err == nil {
		t.Fatal("widening must deny")
	}
}

// ---- test RSA key ---------------------------------------------------------

// testRSAKeyPEM generates a throwaway RSA private key in PKCS8 PEM for the GCP
// JWT-signing path (clearly not a real SA key).
func testRSAKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// INTEGRATION-GATED REAL CLOUD: these unit tests never touch a real cloud. A
// real-cloud smoke (a live STS AssumeRole / GCP generateAccessToken / Azure
// token exchange with genuine, tightly-scoped fixtures) is out of scope for the
// unit suite and belongs behind a build tag / env-gated integration harness so
// CI stays hermetic and no real credential is ever committed.
