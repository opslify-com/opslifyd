package broker

// F5.4 — Tier-2 OAuth2 adapter.
//
// ONE generic OAuth2 adapter, driven by PER-SERVICE config, plugs into the
// EXISTING F5.1 `CredentialAdapter` seam (inject.go) WITHOUT touching the
// injector or the session manager. Adding a new OAuth2-backed service is
// CONFIG ONLY (the per-service {auth_url, token_url, device_url, scopes,
// client_id}) — no bespoke per-provider code to audit.
//
// SECURITY POSTURE (read before touching this file):
//   - The REFRESH token is the durable secret. It is obtained ONCE via the
//     device-authorization flow (`opslify creds add <service>`) and stored
//     ENCRYPTED in the F5.6 vault (via Put). It is NEVER printed, NEVER in
//     argv, NEVER logged, and never returned to any external caller — the
//     F5.6 value-write-only invariant holds.
//   - On a policy-GRANTED resolve, the adapter exchanges the stored refresh
//     token for a SHORT-LIVED access token (minted PER REQUEST, NEVER
//     persisted) and hands it to the injection path. The refresh token itself
//     is never injected; it is Zeroized by the injector immediately after
//     Inject returns.
//   - The sandbox never receives a token as a VALUE on the fully blind path
//     (that is F5.2 header injection). Until F5.2 lands, the access token is
//     env-injected — short-lived but AGENT-VISIBLE — exactly like the F5.3
//     GCP/Azure fallback, so Blind is false and the operator is warned.
//   - Fail closed: a device-flow error, a bad config, or a revoked/expired
//     refresh token (token endpoint 4xx) yields NO token — never a stale-token
//     reuse.
//
// TESTABILITY: every OAuth2 HTTP call goes through the injectable httpDoer seam
// (shared with F5.3), so unit tests run against an in-process stub OAuth2 server
// — no network.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// OAuth2Provider is the reserved provider prefix an OAuth2-backed grant/secret
// carries. A secret stored by `opslify creds add github` has provider
// "oauth2/github"; the injector routes any "oauth2" / "oauth2/<service>"
// provider to the single generic OAuth2 adapter, which selects the per-service
// config by service name.
const OAuth2Provider = "oauth2"

// deviceCodeGrantType is the RFC 8628 device-authorization grant token-exchange
// grant_type. refreshGrantType is the RFC 6749 refresh-token grant used to mint
// a per-request access token.
const (
	deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"
	refreshGrantType    = "refresh_token"
)

// OAuth2ServiceConfig is the PER-SERVICE OAuth2 wiring — the whole of what an
// operator supplies (in YAML) to add a new OAuth2-backed service. It carries NO
// secret: client_id is a public identifier (device flow is a public-client
// flow), and the durable refresh token lives only in the vault. Adding a service
// is this config plus one `opslify creds add`.
type OAuth2ServiceConfig struct {
	// AuthURL is the authorization endpoint (recorded for completeness; the
	// device flow does not use it directly). Optional; validated if present.
	AuthURL string `yaml:"auth_url,omitempty" json:"auth_url,omitempty"`
	// TokenURL is the token endpoint — used BOTH to poll the device grant during
	// onboarding AND to mint a per-request access token from the refresh token.
	// REQUIRED.
	TokenURL string `yaml:"token_url" json:"token_url"`
	// DeviceURL is the device-authorization endpoint (RFC 8628) used by
	// `opslify creds add`. REQUIRED.
	DeviceURL string `yaml:"device_url" json:"device_url"`
	// Scopes is the requested OAuth scope set for onboarding. Optional.
	Scopes []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	// ClientID is the public OAuth client identifier. REQUIRED.
	ClientID string `yaml:"client_id" json:"client_id"`
	// EnvVar, if set, is the process-env variable the minted access token is
	// injected under (e.g. "GH_TOKEN"). Empty => a namespaced default
	// (OPSLIFY_OAUTH_TOKEN_<SERVICE>), so a token is always at least addressable.
	EnvVar string `yaml:"env_var,omitempty" json:"env_var,omitempty"`
}

// Validate fails CLOSED on a bad per-service config with a LEGIBLE, layer-tagged
// error naming the exact missing/invalid field. It requires token_url,
// device_url and client_id, and rejects any non-http(s) URL. An invalid service
// never silently degrades to an unusable or insecure adapter.
func (c OAuth2ServiceConfig) Validate() error {
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("%w: oauth2 service: client_id is required", ErrInvalidInput)
	}
	if err := validHTTPURL("token_url", c.TokenURL); err != nil {
		return err
	}
	if err := validHTTPURL("device_url", c.DeviceURL); err != nil {
		return err
	}
	if c.AuthURL != "" {
		if err := validHTTPURL("auth_url", c.AuthURL); err != nil {
			return err
		}
	}
	return nil
}

// validHTTPURL checks that raw is a well-formed absolute http(s) URL, naming the
// field on failure. An empty required URL is rejected by the caller.
func validHTTPURL(field, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%w: oauth2 service: %s is required", ErrInvalidInput, field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: oauth2 service: %s %q is not a valid URL: %v", ErrInvalidInput, field, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: oauth2 service: %s %q must be http(s)", ErrInvalidInput, field, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: oauth2 service: %s %q has no host", ErrInvalidInput, field, raw)
	}
	return nil
}

// OAuth2Adapter is the SINGLE generic OAuth2 CredentialAdapter. It holds the
// per-service config map (keyed by service name) and mints a per-request access
// token from the resolved refresh token. One adapter serves every configured
// service; adding a service is a config entry, never new code.
type OAuth2Adapter struct {
	// services maps a service name (e.g. "github") to its config.
	services map[string]OAuth2ServiceConfig
	// Doer is the injectable HTTP seam (tests point it at a stub). nil =>
	// http.DefaultClient.
	Doer httpDoer
}

// NewOAuth2Adapter builds the adapter from a validated per-service config map. It
// copies the map so a later caller mutation cannot change the wired adapter.
func NewOAuth2Adapter(services map[string]OAuth2ServiceConfig, doer httpDoer) *OAuth2Adapter {
	cp := make(map[string]OAuth2ServiceConfig, len(services))
	for k, v := range services {
		cp[k] = v
	}
	return &OAuth2Adapter{services: cp, Doer: doer}
}

// Service returns the config + true for a configured service name.
func (a *OAuth2Adapter) Service(name string) (OAuth2ServiceConfig, bool) {
	c, ok := a.services[name]
	return c, ok
}

// isOAuth2Provider reports whether a grant/secret provider routes to the OAuth2
// adapter: the bare "oauth2" or a namespaced "oauth2/<service>".
func isOAuth2Provider(provider string) bool {
	return provider == OAuth2Provider || strings.HasPrefix(provider, OAuth2Provider+"/")
}

// oauth2ServiceName derives the service name from a grant. A namespaced
// "oauth2/<service>" provider names the service directly; a bare "oauth2"
// provider falls back to the grant Name (ref) as the service key.
func oauth2ServiceName(grant policy.Cred) string {
	if s := strings.TrimPrefix(grant.Provider, OAuth2Provider+"/"); s != "" && s != grant.Provider {
		return s
	}
	return grant.Name
}

// Inject mints a per-request short-lived access token from the resolved REFRESH
// token (value) and returns it as an env injection. It FAILS CLOSED: an unknown
// service, or a token-endpoint rejection (revoked/expired refresh token), yields
// NO token — never a stale reuse. The refresh token is neither injected nor
// logged; the injector Zeroizes it right after this returns.
func (a *OAuth2Adapter) Inject(ctx context.Context, ic InjectContext, grant policy.Cred, _ SecretMeta, value []byte) (Injection, error) {
	service := oauth2ServiceName(grant)
	cfg, ok := a.services[service]
	if !ok {
		return Injection{}, fmt.Errorf("%w: no oauth2 service config for %q", ErrInvalidInput, service)
	}
	tok, err := a.mintAccessToken(ctx, cfg, value, cfg.scopeString())
	if err != nil {
		// Fail closed: revoked/expired refresh token or endpoint error → no token.
		return Injection{}, fmt.Errorf("%w: oauth2 %s token mint failed: %v", ErrDenied, service, err)
	}
	// Bound the access token's injected lifetime by the smaller of the endpoint's
	// expires_in and our own TTL ceiling.
	exp := ic.Now.Add(ic.TTL)
	if tok.ExpiresIn > 0 {
		if t := ic.Now.Add(time.Duration(tok.ExpiresIn) * time.Second); t.Before(exp) {
			exp = t
		}
	}
	envName := cfg.EnvVar
	if envName == "" {
		envName = "OPSLIFY_OAUTH_TOKEN_" + sanitizeEnvKey(service)
	}
	inj := Injection{
		// Env fallback: short-lived but AGENT-VISIBLE. The fully blind header path
		// is F5.2; Blind is false so the operator is warned (matches F5.3 GCP/Azure).
		Env:       []string{envName + "=" + tok.AccessToken},
		ExpiresAt: exp,
		Blind:     false,
	}
	// Best-effort scrub the local access-token copy; the env entry now owns a copy
	// the injector hands to the executor. (Go strings are immutable — reassign.)
	tok.AccessToken = ""
	return inj, nil
}

// scopeString renders the configured scopes as a space-delimited OAuth scope
// parameter.
func (c OAuth2ServiceConfig) scopeString() string {
	return strings.Join(c.Scopes, " ")
}

// tokenResponse is the subset of an OAuth2 token-endpoint JSON response this
// adapter consumes. error/error_description carry a legible failure without any
// secret. refresh_token is only read during onboarding.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// mintAccessToken exchanges a refresh token for a short-lived access token
// (RFC 6749 refresh_token grant). It NEVER logs the refresh token; on a
// non-success response it returns the endpoint's error code only.
//
// LIMITATION (rotating refresh tokens): a response's rotated `refresh_token`
// is intentionally NOT re-persisted in this iteration. For providers with a
// STABLE refresh token (e.g. GitHub device flow) this is correct. For a provider
// that ROTATES + invalidates the refresh token on each use, the first resolve
// succeeds and the next FAILS CLOSED (`invalid_grant` -> ErrDenied, no token, no
// stale reuse) — a functionality gap, never a security break. Re-persist-on-
// refresh (a vault write from the resolve path) is future work.
func (a *OAuth2Adapter) mintAccessToken(ctx context.Context, cfg OAuth2ServiceConfig, refresh []byte, scope string) (tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", refreshGrantType)
	form.Set("refresh_token", string(refresh))
	form.Set("client_id", cfg.ClientID)
	if scope != "" {
		form.Set("scope", scope)
	}
	resp, err := a.postToken(ctx, cfg.TokenURL, form)
	if err != nil {
		return tokenResponse{}, err
	}
	if resp.Error != "" {
		return tokenResponse{}, fmt.Errorf("token endpoint: %s", resp.Error)
	}
	if resp.AccessToken == "" {
		return tokenResponse{}, fmt.Errorf("token endpoint returned no access_token")
	}
	return resp, nil
}

// postToken POSTs a urlencoded form to an OAuth2 token/device endpoint and
// decodes the JSON body. It tolerates a 4xx that still carries a JSON
// {error:...} body (the standard OAuth error shape) so the caller can branch on
// the error code (e.g. authorization_pending) rather than a bare status.
func (a *OAuth2Adapter) postToken(ctx context.Context, endpoint string, form url.Values) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	body, err := readBody(doerOrDefault(a.Doer), req)
	if err != nil {
		return tokenResponse{}, err
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return tokenResponse{}, fmt.Errorf("token endpoint response parse: %w", err)
	}
	return tr, nil
}

// readBody reads a response body (bounded) REGARDLESS of status code. Unlike
// doRead (cloud.go), it does not fail on a non-2xx: the OAuth2 device flow
// returns a 400 with a JSON {error:"authorization_pending"} body that the poller
// MUST inspect. A transport-level error still fails closed.
func readBody(d httpDoer, req *http.Request) ([]byte, error) {
	resp, err := d.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, nil
}

// ---------------------------------------------------------------------------
// Device-authorization flow (RFC 8628) — `opslify creds add <service>`
// ---------------------------------------------------------------------------

// DeviceAuth is the device-authorization response the operator acts on: they
// visit VerificationURI and enter UserCode. DeviceCode + Interval drive the
// poll. It carries NO secret (the user code is a short human-typed pairing code,
// not a credential).
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Error                   string `json:"error"`
	ErrorDescription        string `json:"error_description"`
}

// DeviceOnboarder runs the device-authorization onboarding for a service. It is
// the piece `opslify creds add` calls: StartDeviceFlow to obtain the user code +
// verification URL to show the operator, then PollForRefreshToken to block until
// the operator authorizes — returning the durable REFRESH token (bytes, never a
// string that lingers, never logged/printed). It reuses the injectable httpDoer
// so onboarding is unit-tested against a stub OAuth2 server.
type DeviceOnboarder struct {
	Cfg  OAuth2ServiceConfig
	Doer httpDoer
	// Now/Sleep are injected in tests so polling is deterministic (no real wall
	// clock). nil => time.Now / time.Sleep.
	Now   func() time.Time
	Sleep func(time.Duration)
}

// StartDeviceFlow requests a device + user code from the device endpoint. It
// fails CLOSED on a malformed config or an endpoint error.
func (o DeviceOnboarder) StartDeviceFlow(ctx context.Context) (DeviceAuth, error) {
	if err := o.Cfg.Validate(); err != nil {
		return DeviceAuth{}, err
	}
	form := url.Values{}
	form.Set("client_id", o.Cfg.ClientID)
	if s := o.Cfg.scopeString(); s != "" {
		form.Set("scope", s)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Cfg.DeviceURL, strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceAuth{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	body, err := readBody(doerOrDefault(o.Doer), req)
	if err != nil {
		return DeviceAuth{}, fmt.Errorf("%w: oauth2 device authorization request failed: %v", ErrDenied, err)
	}
	var da DeviceAuth
	if err := json.Unmarshal(body, &da); err != nil {
		return DeviceAuth{}, fmt.Errorf("%w: oauth2 device authorization response parse: %v", ErrInvalidInput, err)
	}
	if da.Error != "" {
		return DeviceAuth{}, fmt.Errorf("%w: oauth2 device authorization rejected: %s", ErrDenied, da.Error)
	}
	if da.DeviceCode == "" || da.UserCode == "" || da.VerificationURI == "" {
		return DeviceAuth{}, fmt.Errorf("%w: oauth2 device authorization response incomplete", ErrDenied)
	}
	return da, nil
}

// PollForRefreshToken polls the token endpoint with the device grant until the
// operator authorizes (returning the REFRESH token) or the flow fails/expires.
// It honours the RFC 8628 slow_down / authorization_pending signals and the
// server interval, and it FAILS CLOSED on access_denied, expired_token, or a
// context cancellation. It REQUIRES a refresh token in the success response — an
// access-token-only response is refused (this design mints access tokens
// per-request from a durable refresh token, so a refresh token is mandatory).
//
// The returned []byte is the refresh token; the caller stores it encrypted and
// Zeroizes it. It is never logged or printed here.
func (o DeviceOnboarder) PollForRefreshToken(ctx context.Context, da DeviceAuth) ([]byte, error) {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	sleep := o.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	interval := da.Interval
	if interval <= 0 {
		interval = 5 // RFC 8628 default poll interval (seconds)
	}
	adapter := &OAuth2Adapter{Doer: o.Doer}
	deadline := now().Add(time.Duration(maxNonZero(da.ExpiresIn, 600)) * time.Second)

	for {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: oauth2 device flow cancelled", ErrDenied)
		}
		if now().After(deadline) {
			return nil, fmt.Errorf("%w: oauth2 device flow expired before authorization", ErrDenied)
		}
		sleep(time.Duration(interval) * time.Second)

		form := url.Values{}
		form.Set("grant_type", deviceCodeGrantType)
		form.Set("device_code", da.DeviceCode)
		form.Set("client_id", o.Cfg.ClientID)
		resp, err := adapter.postToken(ctx, o.Cfg.TokenURL, form)
		if err != nil {
			return nil, fmt.Errorf("%w: oauth2 device token poll failed: %v", ErrDenied, err)
		}
		switch resp.Error {
		case "":
			if resp.RefreshToken == "" {
				return nil, fmt.Errorf("%w: oauth2 service returned no refresh_token (enable expiring/offline tokens for this app)", ErrDenied)
			}
			return []byte(resp.RefreshToken), nil
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5
			continue
		default:
			// access_denied, expired_token, etc. — fail closed, no stale reuse.
			return nil, fmt.Errorf("%w: oauth2 device flow denied: %s", ErrDenied, resp.Error)
		}
	}
}

func maxNonZero(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
