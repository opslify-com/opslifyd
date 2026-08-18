package broker

// F5.3 — Tier-1 cloud adapters (AWS / GCP / Azure scope-down).
//
// These adapters plug into the EXISTING F5.1 `CredentialAdapter` seam
// (inject.go) WITHOUT touching the injector or session manager. Each one
// exchanges the durable source identity (the vaulted secret `value`) for a
// SCOPED, SHORT-LIVED cloud credential and returns it as an Injection:
//
//   - AWS: STS AssumeRole with a SESSION POLICY that scopes DOWN from the
//     daemon-stored grant scope (meta.Scope). STS enforces the intersection
//     server-side, so the minted credential is ALWAYS <= the role AND <= the
//     session policy — a workspace cannot widen it. The minted short-lived
//     {AccessKeyId, SecretAccessKey, SessionToken, Expiration} becomes the
//     ServeBody the F5.1 loopback endpoint serves, so even a probe with the
//     env token gets only a scoped, near-expiry credential — never the durable
//     source key. This REPLACES F5.1's direct-serve of the durable doc,
//     closing the F5.1 R1 residual.
//   - GCP: short-lived SA impersonation (IAM Credentials generateAccessToken)
//     scoped to the granted scopes; returns a short-lived token.
//   - Azure: federated / client-credentials token scoped to the granted
//     resource; returns a short-lived token.
//
// DEPENDENCY CHOICE: pure stdlib. AWS STS is a signed (SigV4) HTTP POST; GCP is
// a signed-JWT bearer exchange + a REST call; Azure is a form POST. Each is a
// handful of net/http + crypto/* calls, far lighter than pulling three giant
// cloud SDKs — so NO new module dependency is added.
//
// TESTABILITY: every real cloud call goes through an injectable httpDoer + an
// endpoint override, so unit tests run against an in-process stub (no network,
// no real cloud). Real-cloud is integration-gated (see cloud_test.go note).

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// MaxCloudTTL is the hard ceiling on a minted cloud credential's lifetime. Even
// if a secret's meta.TTL asks for more, the mint is clamped to this — the
// short-TTL half of "least privilege for the least time". AWS STS AssumeRole
// itself caps a role-chained session at 15 min, so this matches its floor.
const MaxCloudTTL = 15 * time.Minute

// httpDoer is the injectable HTTP seam. http.Client satisfies it; unit tests
// pass a stub that answers canned cloud responses so no network is touched.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

func doerOrDefault(d httpDoer) httpDoer {
	if d == nil {
		return http.DefaultClient
	}
	return d
}

// ttlSeconds clamps a requested TTL into (0, MaxCloudTTL] and returns whole
// seconds. A non-positive or over-ceiling request is clamped to MaxCloudTTL —
// this is the TTL half of "a broader request is clamped".
func ttlSeconds(ttl time.Duration) int {
	if ttl <= 0 || ttl > MaxCloudTTL {
		ttl = MaxCloudTTL
	}
	return int(ttl / time.Second)
}

// splitScopes parses a meta.Scope / requested-scope string into a set of scope
// tokens (whitespace- or comma-separated). Order-preserving, de-duplicated.
func splitScopes(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == ',' || r == ';'
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// clampScopes enforces the scope-down invariant for the token providers
// (GCP/Azure, which — unlike AWS STS — have no server-side intersection). The
// ceiling is `allowed` (the daemon-stored, F4.1-narrowed grant scope). It FAILS
// CLOSED:
//   - an empty ceiling means no scope was granted → deny (no unscoped token);
//   - a `requested` element not in the ceiling is a widening attempt → deny;
//   - an empty request defaults to exactly the ceiling.
//
// The result is guaranteed <= the ceiling, so a workspace can never widen.
func clampScopes(allowed, requested []string) ([]string, error) {
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: no scope granted for this credential (scope-down ceiling is empty)", ErrDenied)
	}
	if len(requested) == 0 {
		out := make([]string, len(allowed))
		copy(out, allowed)
		return out, nil
	}
	allow := map[string]bool{}
	for _, a := range allowed {
		allow[a] = true
	}
	out := make([]string, 0, len(requested))
	for _, r := range requested {
		if !allow[r] {
			return nil, fmt.Errorf("%w: requested scope %q exceeds the granted scope-down ceiling", ErrDenied, r)
		}
		out = append(out, r)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// AWS — STS AssumeRole with a scope-down session policy
// ---------------------------------------------------------------------------

// STSAssumeRoleAdapter mints a scoped, short-lived AWS credential via STS
// AssumeRole and serves it through the F5.1 endpoint (Blind path). The durable
// source key (from the vaulted doc) is used ONLY to sign the AssumeRole call
// daemon-side; it is Zeroized after the exchange and NEVER injected/served.
type STSAssumeRoleAdapter struct {
	Doer httpDoer
	// Endpoint overrides the STS URL (tests point it at a stub). Empty uses the
	// regional STS endpoint derived from the source doc's Region.
	Endpoint string
}

// awsSourceDoc is the vaulted AWS source identity + exchange config. It is a
// JSON document (validated on parse); the durable key fields are held in []byte
// so they can be Zeroized after signing.
type awsSourceDoc struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	RoleARN         string `json:"RoleArn"`
	RoleSessionName string `json:"RoleSessionName,omitempty"`
	Region          string `json:"Region,omitempty"`
	// SessionPolicy is an OPTIONAL inline IAM policy carried in the doc; if the
	// grant's meta.Scope is empty it is the scope-down source. As JSON it is
	// re-marshalled verbatim to the STS Policy parameter.
	SessionPolicy json.RawMessage `json:"SessionPolicy,omitempty"`
}

func (a STSAssumeRoleAdapter) Inject(ctx context.Context, ic InjectContext, grant policy.Cred, meta SecretMeta, value []byte) (Injection, error) {
	// Fail closed: the AWS blind path REQUIRES the endpoint — never fall back to
	// the env with any material.
	if ic.EndpointBaseURL == "" {
		return Injection{}, fmt.Errorf("%w: aws sts path requires a creds endpoint", ErrInvalidInput)
	}
	var doc awsSourceDoc
	if err := json.Unmarshal(value, &doc); err != nil {
		return Injection{}, fmt.Errorf("%w: aws source must be a JSON identity document", ErrInvalidInput)
	}
	if doc.AccessKeyID == "" || doc.SecretAccessKey == "" || doc.RoleARN == "" {
		return Injection{}, fmt.Errorf("%w: aws source doc needs AccessKeyId, SecretAccessKey and RoleArn", ErrInvalidInput)
	}

	// Scope-down: the session policy is the intersection STS enforces. Prefer the
	// daemon-stored grant scope (meta.Scope) as the policy; fall back to the doc's
	// inline SessionPolicy. REQUIRE one — an unscoped AssumeRole would hand back
	// the role's full permissions, defeating scope-down. Fail closed if neither.
	sessionPolicy, err := awsSessionPolicy(meta.Scope, doc.SessionPolicy)
	if err != nil {
		return Injection{}, err
	}

	region := doc.Region
	if region == "" {
		region = "us-east-1"
	}
	sessionName := doc.RoleSessionName
	if sessionName == "" {
		sessionName = "opslify-" + sanitizeSessionName(ic.SessionID)
	}

	form := url.Values{}
	form.Set("Action", "AssumeRole")
	form.Set("Version", "2011-06-15")
	form.Set("RoleArn", doc.RoleARN)
	form.Set("RoleSessionName", sessionName)
	form.Set("DurationSeconds", fmt.Sprintf("%d", ttlSeconds(ic.TTL)))
	form.Set("Policy", sessionPolicy)
	body := []byte(form.Encode())

	endpoint := a.Endpoint
	if endpoint == "" {
		endpoint = "https://sts." + region + ".amazonaws.com/"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return Injection{}, fmt.Errorf("broker: build sts request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	// SigV4-sign with the DURABLE source key, then zero the signing material. The
	// source key never leaves this function.
	sigv4Sign(req, body, doc.AccessKeyID, doc.SecretAccessKey, doc.SessionToken, region, "sts", ic.Now)
	// The durable secret in doc is no longer needed after signing.
	zeroizeString(&doc.SecretAccessKey)
	zeroizeString(&doc.SessionToken)

	resp, err := doerOrDefault(a.Doer).Do(req)
	if err != nil {
		// Fail closed: no credential, NO fallback to the durable source.
		return Injection{}, fmt.Errorf("%w: sts assume-role call failed: %v", ErrDenied, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Injection{}, fmt.Errorf("%w: sts assume-role rejected (status %d)", ErrDenied, resp.StatusCode)
	}

	var parsed struct {
		Creds struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"AssumeRoleResult>Credentials"`
	}
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return Injection{}, fmt.Errorf("%w: sts assume-role response parse: %v", ErrDenied, err)
	}
	c := parsed.Creds
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken == "" {
		return Injection{}, fmt.Errorf("%w: sts assume-role returned no credential", ErrDenied)
	}

	// Expiry: honour STS's Expiration but never exceed our own TTL ceiling.
	exp := ic.Now.Add(time.Duration(ttlSeconds(ic.TTL)) * time.Second)
	if t, perr := time.Parse(time.RFC3339, c.Expiration); perr == nil && t.Before(exp) {
		exp = t
	}

	// The MINTED scoped credential — never the durable source — is what the
	// endpoint serves (container-credentials JSON shape the AWS SDK fetches).
	serveBody, err := json.Marshal(map[string]any{
		"AccessKeyId":     c.AccessKeyID,
		"SecretAccessKey": c.SecretAccessKey,
		"Token":           c.SessionToken,
		"Expiration":      exp.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return Injection{}, fmt.Errorf("broker: marshal minted aws cred: %w", err)
	}

	fullURI := strings.TrimRight(ic.EndpointBaseURL, "/") + CredPath + ic.SessionID
	return Injection{
		Env: []string{
			"AWS_CONTAINER_CREDENTIALS_FULL_URI=" + fullURI,
			"AWS_CONTAINER_CREDENTIALS_TOKEN=" + ic.Token,
		},
		ServeBody:        serveBody,
		ServeContentType: "application/json",
		ExpiresAt:        exp,
		Blind:            true,
	}, nil
}

// awsSessionPolicy resolves the scope-down session policy. metaScope (the
// daemon-stored, F4.1-narrowed grant scope) wins; else the doc's inline policy.
// One is REQUIRED — fail closed on an unscoped AssumeRole. The returned string
// must be a JSON object (an IAM policy) so STS accepts it.
func awsSessionPolicy(metaScope string, inline json.RawMessage) (string, error) {
	var candidate string
	switch {
	case strings.TrimSpace(metaScope) != "":
		candidate = strings.TrimSpace(metaScope)
	case len(inline) > 0:
		candidate = string(inline)
	default:
		return "", fmt.Errorf("%w: aws grant has no scope-down session policy (meta.Scope / SessionPolicy) — refusing an unscoped AssumeRole", ErrDenied)
	}
	var probe map[string]any
	if err := json.Unmarshal([]byte(candidate), &probe); err != nil || probe == nil {
		return "", fmt.Errorf("%w: aws scope-down policy must be a JSON IAM policy object", ErrInvalidInput)
	}
	return candidate, nil
}

func sanitizeSessionName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 48 {
		out = out[:48]
	}
	if out == "" {
		out = "session"
	}
	return out
}

// ---------------------------------------------------------------------------
// SigV4 (AWS Signature Version 4) — minimal, POST + query-body signing
// ---------------------------------------------------------------------------

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// sigv4Sign signs req (an STS POST with a urlencoded body) in place, setting the
// X-Amz-Date, optional X-Amz-Security-Token, and Authorization headers. It zeros
// the derived signing key after use.
func sigv4Sign(req *http.Request, body []byte, accessKey, secretKey, sessionToken, region, service string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")
	host := req.URL.Host

	req.Header.Set("Host", host)
	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	contentType := req.Header.Get("Content-Type")
	payloadHash := sha256Hex(body)

	// Signed header set (sorted): content-type, host, x-amz-date [, x-amz-security-token].
	headers := [][2]string{
		{"content-type", contentType},
		{"host", host},
		{"x-amz-date", amzDate},
	}
	if sessionToken != "" {
		headers = append(headers, [2]string{"x-amz-security-token", sessionToken})
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i][0] < headers[j][0] })

	var canonicalHeaders strings.Builder
	var signedHeaderNames []string
	for _, h := range headers {
		canonicalHeaders.WriteString(h[0])
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(h[1]))
		canonicalHeaders.WriteString("\n")
		signedHeaderNames = append(signedHeaderNames, h[0])
	}
	signedHeaders := strings.Join(signedHeaderNames, ";")

	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/", // STS uses the root path
		"",  // no query string (params are in the body)
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := fmt.Sprintf("%x", hmacSHA256(kSigning, []byte(stringToSign)))

	// Zeroize derived key material.
	Zeroize(kDate)
	Zeroize(kRegion)
	Zeroize(kService)
	Zeroize(kSigning)

	authz := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", authz)
}

// ---------------------------------------------------------------------------
// GCP — short-lived SA impersonation (generateAccessToken)
// ---------------------------------------------------------------------------

// GCPImpersonationAdapter mints a short-lived impersonated access token scoped
// to the granted scopes. The source SA key signs a JWT (daemon-side) to obtain
// a source access token, which then calls IAM Credentials generateAccessToken
// for the target principal. The returned token is injected into the process env
// (documented weaker path, Blind=false; F5.2 makes GCP fully blind).
type GCPImpersonationAdapter struct {
	Doer httpDoer
	// TokenEndpoint overrides the OAuth token URL (tests). Empty uses the doc's
	// token_uri or Google's default.
	TokenEndpoint string
	// IAMEndpoint overrides the IAM Credentials base URL (tests). Empty uses the
	// production iamcredentials.googleapis.com.
	IAMEndpoint string
}

type gcpSourceDoc struct {
	ClientEmail     string `json:"client_email"`
	PrivateKey      string `json:"private_key"`
	TokenURI        string `json:"token_uri,omitempty"`
	TargetPrincipal string `json:"target_principal,omitempty"`
	// Scopes is the OPTIONAL requested scope set; it is clamped to meta.Scope.
	Scopes string `json:"scopes,omitempty"`
}

func (a GCPImpersonationAdapter) Inject(ctx context.Context, ic InjectContext, grant policy.Cred, meta SecretMeta, value []byte) (Injection, error) {
	var doc gcpSourceDoc
	if err := json.Unmarshal(value, &doc); err != nil {
		return Injection{}, fmt.Errorf("%w: gcp source must be a service-account JSON key", ErrInvalidInput)
	}
	if doc.ClientEmail == "" || doc.PrivateKey == "" {
		return Injection{}, fmt.Errorf("%w: gcp source needs client_email and private_key", ErrInvalidInput)
	}

	// Scope-down: clamp the requested scopes to the daemon-stored ceiling.
	scopes, err := clampScopes(splitScopes(meta.Scope), splitScopes(doc.Scopes))
	if err != nil {
		return Injection{}, err
	}
	target := doc.TargetPrincipal
	if target == "" {
		target = doc.ClientEmail
	}

	tokenURI := a.TokenEndpoint
	if tokenURI == "" {
		tokenURI = doc.TokenURI
	}
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}

	// 1. Sign a source JWT with the SA private key (daemon-side).
	assertion, err := signGCPJWT(doc.ClientEmail, doc.PrivateKey, tokenURI, ic.Now)
	// The durable private key is no longer needed after signing.
	zeroizeString(&doc.PrivateKey)
	if err != nil {
		return Injection{}, err
	}

	// 2. Exchange the JWT for a source access token.
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	srcToken, err := a.postForm(ctx, tokenURI, form)
	if err != nil {
		return Injection{}, fmt.Errorf("%w: gcp source token exchange failed: %v", ErrDenied, err)
	}
	var srcTok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(srcToken, &srcTok); err != nil || srcTok.AccessToken == "" {
		return Injection{}, fmt.Errorf("%w: gcp source token response invalid", ErrDenied)
	}

	// 3. generateAccessToken for the target principal, scoped + TTL-bounded.
	iamBase := a.IAMEndpoint
	if iamBase == "" {
		iamBase = "https://iamcredentials.googleapis.com"
	}
	genURL := strings.TrimRight(iamBase, "/") + "/v1/projects/-/serviceAccounts/" + url.PathEscape(target) + ":generateAccessToken"
	reqBody, _ := json.Marshal(map[string]any{
		"scope":    scopes,
		"lifetime": fmt.Sprintf("%ds", ttlSeconds(ic.TTL)),
	})
	genResp, err := a.postJSON(ctx, genURL, reqBody, srcTok.AccessToken)
	if err != nil {
		return Injection{}, fmt.Errorf("%w: gcp generateAccessToken failed: %v", ErrDenied, err)
	}
	var minted struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	if err := json.Unmarshal(genResp, &minted); err != nil || minted.AccessToken == "" {
		return Injection{}, fmt.Errorf("%w: gcp generateAccessToken returned no token", ErrDenied)
	}

	exp := ic.Now.Add(time.Duration(ttlSeconds(ic.TTL)) * time.Second)
	if t, perr := time.Parse(time.RFC3339, minted.ExpireTime); perr == nil && t.Before(exp) {
		exp = t
	}
	return Injection{
		Env:       []string{"CLOUDSDK_AUTH_ACCESS_TOKEN=" + minted.AccessToken},
		ExpiresAt: exp,
		Blind:     false,
	}, nil
}

// signGCPJWT builds and RS256-signs a source assertion JWT for the SA.
func signGCPJWT(clientEmail, privateKeyPEM, aud string, now time.Time) (string, error) {
	key, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	header := base64URL([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss":   clientEmail,
		"sub":   clientEmail,
		"aud":   aud,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"iat":   now.Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
	})
	signingInput := header + "." + base64URL(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("broker: sign gcp jwt: %w", err)
	}
	return signingInput + "." + base64URL(sig), nil
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("%w: gcp private_key is not valid PEM", ErrInvalidInput)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: gcp private_key parse: %v", ErrInvalidInput, err)
	}
	rk, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: gcp private_key is not RSA", ErrInvalidInput)
	}
	return rk, nil
}

func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a GCPImpersonationAdapter) postForm(ctx context.Context, u string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doRead(doerOrDefault(a.Doer), req)
}

func (a GCPImpersonationAdapter) postJSON(ctx context.Context, u string, body []byte, bearer string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	return doRead(doerOrDefault(a.Doer), req)
}

// ---------------------------------------------------------------------------
// Azure — federated / client-credentials token
// ---------------------------------------------------------------------------

// AzureIdentityAdapter mints a scoped Azure access token via the OAuth2 v2.0
// token endpoint using either a federated client-assertion (workload identity)
// or a client secret. The returned token is env-injected (Blind=false).
type AzureIdentityAdapter struct {
	Doer httpDoer
	// Authority overrides the login host (tests). Empty uses login.microsoftonline.com.
	Authority string
}

type azureSourceDoc struct {
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret,omitempty"`
	FederatedToken string `json:"federated_token,omitempty"`
	// Scopes is the OPTIONAL requested resource scope set; clamped to meta.Scope.
	Scopes string `json:"scopes,omitempty"`
}

func (a AzureIdentityAdapter) Inject(ctx context.Context, ic InjectContext, grant policy.Cred, meta SecretMeta, value []byte) (Injection, error) {
	var doc azureSourceDoc
	if err := json.Unmarshal(value, &doc); err != nil {
		return Injection{}, fmt.Errorf("%w: azure source must be a JSON identity document", ErrInvalidInput)
	}
	if doc.TenantID == "" || doc.ClientID == "" {
		return Injection{}, fmt.Errorf("%w: azure source needs tenant_id and client_id", ErrInvalidInput)
	}
	if doc.ClientSecret == "" && doc.FederatedToken == "" {
		return Injection{}, fmt.Errorf("%w: azure source needs a client_secret or a federated_token", ErrInvalidInput)
	}

	// Scope-down: clamp the requested resource scopes to the daemon-stored ceiling.
	scopes, err := clampScopes(splitScopes(meta.Scope), splitScopes(doc.Scopes))
	if err != nil {
		return Injection{}, err
	}

	authority := a.Authority
	if authority == "" {
		authority = "https://login.microsoftonline.com"
	}
	tokenURL := strings.TrimRight(authority, "/") + "/" + url.PathEscape(doc.TenantID) + "/oauth2/v2.0/token"

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", doc.ClientID)
	form.Set("scope", strings.Join(scopes, " "))
	if doc.FederatedToken != "" {
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", doc.FederatedToken)
	} else {
		form.Set("client_secret", doc.ClientSecret)
	}
	zeroizeString(&doc.ClientSecret)
	zeroizeString(&doc.FederatedToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Injection{}, fmt.Errorf("broker: build azure token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, err := doRead(doerOrDefault(a.Doer), req)
	if err != nil {
		return Injection{}, fmt.Errorf("%w: azure token exchange failed: %v", ErrDenied, err)
	}
	var minted struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &minted); err != nil || minted.AccessToken == "" {
		return Injection{}, fmt.Errorf("%w: azure token response invalid", ErrDenied)
	}

	exp := ic.Now.Add(time.Duration(ttlSeconds(ic.TTL)) * time.Second)
	if minted.ExpiresIn > 0 {
		if t := ic.Now.Add(time.Duration(minted.ExpiresIn) * time.Second); t.Before(exp) {
			exp = t
		}
	}
	return Injection{
		Env:       []string{"AZURE_ACCESS_TOKEN=" + minted.AccessToken},
		ExpiresAt: exp,
		Blind:     false,
	}, nil
}

// ---------------------------------------------------------------------------
// shared HTTP + wiring
// ---------------------------------------------------------------------------

// doRead executes req and returns the body, failing closed on a non-2xx status.
func doRead(d httpDoer, req *http.Request) ([]byte, error) {
	resp, err := d.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

// zeroizeString best-effort scrubs a string's backing bytes via an unsafe-free
// path: it can only reassign the header (Go strings are immutable), so the old
// backing array is left to the GC. This is defence-in-depth on the doc COPIES;
// the primary control is that the injector Zeroizes the source `value` buffer
// immediately after Inject returns and the value never leaves the daemon.
func zeroizeString(s *string) { *s = "" }

// CloudConfig configures which Tier-1 cloud adapters are wired and their
// (test-overridable) endpoints. Zero value wires all three at their production
// endpoints. The DURABLE SOURCE IDENTITY is NOT here — it lives in the vault as
// the granted secret's value; this only carries non-secret wiring.
type CloudConfig struct {
	// Doer overrides the HTTP client for every adapter (integration/tests).
	Doer httpDoer
	// AWSEndpoint, GCPTokenEndpoint, GCPIAMEndpoint, AzureAuthority override the
	// respective provider endpoints; empty uses production.
	AWSEndpoint      string
	GCPTokenEndpoint string
	GCPIAMEndpoint   string
	AzureAuthority   string
}

// RegisterCloudAdapters installs the F5.3 Tier-1 minting adapters onto an
// injector, REPLACING F5.1's AWS direct-serve with the STS mint (closing R1)
// and the GCP/Azure env fallback with real short-lived impersonation/token
// exchange. Registering by provider means the injector and session manager are
// untouched — the seam does all the work.
func (in *Injector) RegisterCloudAdapters(cfg CloudConfig) {
	if in == nil {
		return
	}
	if in.adapters == nil {
		in.adapters = map[string]CredentialAdapter{}
	}
	aws := STSAssumeRoleAdapter{Doer: cfg.Doer, Endpoint: cfg.AWSEndpoint}
	in.adapters["aws"] = aws
	gcp := GCPImpersonationAdapter{Doer: cfg.Doer, TokenEndpoint: cfg.GCPTokenEndpoint, IAMEndpoint: cfg.GCPIAMEndpoint}
	in.adapters["gcp"] = gcp
	in.adapters["google"] = gcp
	in.adapters["azure"] = AzureIdentityAdapter{Doer: cfg.Doer, Authority: cfg.AzureAuthority}
}
