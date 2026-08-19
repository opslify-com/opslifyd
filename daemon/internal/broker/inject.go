package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// DefaultInjectTTL bounds an injected credential when the secret's own meta.TTL is
// unset. Injection is always TTL-bounded: the endpoint body and the env token both
// carry an expiry, so a worst-case in-sandbox capture is near-expiry.
const DefaultInjectTTL = 15 * time.Minute

// Injection is what an adapter contributes to a spawned process for ONE resolved
// credential. Env is the process environment to add — for the AWS endpoint path it
// carries ONLY the endpoint URL + the per-session bearer token, NEVER the raw
// durable secret. ServeBody, when non-nil, is the credential body the loopback
// endpoint serves for this session (the raw value stays daemon-side, TTL-bounded).
type Injection struct {
	// Env is the KEY=VALUE process-env entries to add. For the AWS endpoint path
	// this is the endpoint URI + per-session token; for the GCP/Azure v1 fallback it
	// is a short-lived token that IS visible in the process env (documented weaker).
	Env []string
	// ServeBody is the credential document the endpoint serves for this session
	// (nil for the env-only fallback). It is registered under the per-session token.
	ServeBody        []byte
	ServeContentType string
	// ExpiresAt bounds the injected credential's lifetime.
	ExpiresAt time.Time
	// Blind reports whether this path is fully credential-blind (the AWS endpoint
	// path, true) or short-lived-but-agent-visible (the GCP/Azure env fallback,
	// false). It drives an honest operator warning on the weaker path.
	Blind bool
}

// InjectContext carries the per-session facts an adapter needs: the session id, the
// creds-endpoint base URL (empty if no endpoint is wired), the per-session bearer
// token, the TTL to bound the credential to, and the injected clock's now.
type InjectContext struct {
	SessionID       string
	EndpointBaseURL string
	Token           string
	TTL             time.Duration
	Now             time.Time
}

// CredentialAdapter turns a resolved plaintext secret into a process-env injection.
// It is the F5.1 seam the F5.3 cloud adapters (AWS STS AssumeRole, GCP
// impersonation, Azure token exchange) plug into WITHOUT touching the injector or
// the session manager: they exchange the durable secret for a short-lived scoped
// credential and return it as an Injection. F5.1 ships the mechanism plus the AWS
// container-credentials adapter and a generic env-injection fallback.
//
// CONTRACT: the adapter MUST NOT place a raw durable secret into Injection.Env on
// the blind path (it goes in ServeBody, served by the token-gated endpoint). The
// injector Zeroizes value immediately after Inject returns.
type CredentialAdapter interface {
	Inject(ctx context.Context, ic InjectContext, grant policy.Cred, meta SecretMeta, value []byte) (Injection, error)
}

// AWSContainerCredentialsAdapter is the fully credential-blind path (F5.1). It
// injects AWS_CONTAINER_CREDENTIALS_FULL_URI (pointing at the daemon's per-session
// creds endpoint) + AWS_CONTAINER_CREDENTIALS_TOKEN (the per-session bearer token)
// so the AWS CLI/SDK fetches creds unmodified — the RAW secret is served only by
// the endpoint, never placed in the container env. The vaulted secret is expected
// to be an AWS container-credentials JSON document; the adapter stamps a
// TTL-bounded Expiration on it. F5.3 replaces the direct serve with an STS mint.
type AWSContainerCredentialsAdapter struct{}

func (AWSContainerCredentialsAdapter) Inject(_ context.Context, ic InjectContext, _ policy.Cred, _ SecretMeta, value []byte) (Injection, error) {
	// Fail closed: the AWS blind path REQUIRES the endpoint. Without it we do NOT
	// fall back to putting the raw secret in the env.
	if ic.EndpointBaseURL == "" {
		return Injection{}, fmt.Errorf("%w: aws container-credentials path requires a creds endpoint", ErrInvalidInput)
	}
	exp := ic.Now.Add(ic.TTL)
	body, err := awsCredBody(value, exp)
	if err != nil {
		return Injection{}, err
	}
	fullURI := strings.TrimRight(ic.EndpointBaseURL, "/") + CredPath + ic.SessionID
	return Injection{
		Env: []string{
			"AWS_CONTAINER_CREDENTIALS_FULL_URI=" + fullURI,
			"AWS_CONTAINER_CREDENTIALS_TOKEN=" + ic.Token,
		},
		ServeBody:        body,
		ServeContentType: "application/json",
		ExpiresAt:        exp,
		Blind:            true,
	}, nil
}

// awsCredBody produces the container-credentials JSON the endpoint serves. It
// parses the vaulted value as a JSON object and stamps a TTL-bounded Expiration
// (RFC3339) so the credential the sandbox fetches is always near-expiry. A value
// that is not a JSON object fails closed (F5.3 mints the proper document; F5.1
// expects it pre-shaped) rather than leaking an unshaped raw secret.
func awsCredBody(value []byte, exp time.Time) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(value, &doc); err != nil || doc == nil {
		return nil, fmt.Errorf("%w: aws credential must be a JSON container-credentials document", ErrInvalidInput)
	}
	doc["Expiration"] = exp.UTC().Format(time.RFC3339)
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("broker: marshal aws credential body: %w", err)
	}
	return out, nil
}

// EnvInjectionAdapter is the GENERIC, DOCUMENTED-WEAKER fallback (F5.1 v1) used for
// GCP/Azure and any non-AWS provider: it injects a SHORT-LIVED token straight into
// the process env. HONEST CAVEAT: unlike the AWS endpoint path this token IS
// visible to the agent in the process env — it is short-lived (TTL-bounded) but
// not blind. The L7 proxy / metadata-server path (F5.2) is what makes GCP/Azure
// fully blind; until then this is the interim, and Blind is false so the operator
// is warned.
type EnvInjectionAdapter struct{}

func (EnvInjectionAdapter) Inject(_ context.Context, ic InjectContext, grant policy.Cred, _ SecretMeta, value []byte) (Injection, error) {
	name := envVarFor(grant)
	// string(value) copies the plaintext into the env entry; the injector Zeroizes
	// the source buffer right after. The token lives in the process env (visible) —
	// this is the documented weaker path.
	return Injection{
		Env:       []string{name + "=" + string(value)},
		ExpiresAt: ic.Now.Add(ic.TTL),
		Blind:     false,
	}, nil
}

// envVarFor maps a provider to the env var its tool reads a short-lived token from.
// gcloud honours CLOUDSDK_AUTH_ACCESS_TOKEN; azure has no single standard var, so
// AZURE_ACCESS_TOKEN is used (documented); anything else gets a namespaced var
// derived from the ref so it is at least addressable.
func envVarFor(grant policy.Cred) string {
	switch grant.Provider {
	case "gcp", "google":
		return "CLOUDSDK_AUTH_ACCESS_TOKEN"
	case "azure":
		return "AZURE_ACCESS_TOKEN"
	default:
		return "OPSLIFY_CRED_" + sanitizeEnvKey(grant.Name)
	}
}

// sanitizeEnvKey upper-cases a ref and replaces every non [A-Z0-9_] rune with '_'
// so it is a valid env-var suffix (a ref may contain . / @ - per validRef).
func sanitizeEnvKey(ref string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(ref) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Injector orchestrates F5.1 injection: for each policy-granted cred it resolves
// the value through the Broker (deny-by-default + `cred.resolve` audit), runs the
// provider's adapter, registers any endpoint credential under a per-session token,
// and Zeroizes the plaintext. It returns the aggregate process env the session
// manager adds to every exec. A nil Injector (unwired) injects nothing.
type Injector struct {
	broker         *Broker
	server         *CredServer
	baseURL        string
	ttl            time.Duration
	now            func() time.Time
	adapters       map[string]CredentialAdapter
	defaultAdapter CredentialAdapter
	// oauth2 is the single generic F5.4 OAuth2 adapter. Any grant whose provider
	// is "oauth2" / "oauth2/<service>" routes here regardless of the service, so a
	// new OAuth2 service is config-only (no new adapter registration per service).
	oauth2 *OAuth2Adapter
}

// NewInjector wires the injector over a broker + creds endpoint. baseURL is the
// endpoint's sandbox-reachable base (empty disables the AWS blind path — an aws
// grant then fails closed rather than leaking the raw secret to the env). ttl<=0
// uses DefaultInjectTTL. A nil server also disables the endpoint path.
func NewInjector(brk *Broker, server *CredServer, baseURL string, ttl time.Duration, now func() time.Time) *Injector {
	if ttl <= 0 {
		ttl = DefaultInjectTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Injector{
		broker:         brk,
		server:         server,
		baseURL:        baseURL,
		ttl:            ttl,
		now:            now,
		adapters:       map[string]CredentialAdapter{"aws": AWSContainerCredentialsAdapter{}},
		defaultAdapter: EnvInjectionAdapter{},
	}
}

// SessionInjection is the result of injecting a session's granted creds: the env
// to add to every exec, and any operator warnings (weaker-path notices). It NEVER
// contains a raw durable secret on the AWS path.
type SessionInjection struct {
	Env      []string
	Warnings []string
}

// InjectSession resolves + injects every granted cred for a session. It is
// fail-closed PER GRANT: a resolve/adapter failure for one cred yields NO env for
// that cred (no raw-secret fallback) and a warning — it never aborts the other
// grants or the session. The endpoint credential (AWS path) is registered under a
// single per-session bearer token. Every resolved plaintext is Zeroized here.
//
// It returns no error for a per-grant failure (those become warnings); it returns
// an error only for an internal invariant break (token generation). A nil broker
// or no grants yields an empty injection.
func (in *Injector) InjectSession(ctx context.Context, rec *trace.Recorder, sessionID string, grants []policy.Cred) (SessionInjection, error) {
	var si SessionInjection
	if in == nil || in.broker == nil || len(grants) == 0 {
		return si, nil
	}
	token, err := newToken()
	if err != nil {
		return si, err
	}
	endpointBase := ""
	if in.server != nil {
		endpointBase = in.baseURL
	}

	for _, grant := range grants {
		value, meta, rerr := in.broker.Resolve(ctx, rec, grants, grant.Name)
		if rerr != nil {
			// Deny-by-default / fail-closed: no credential, no raw fallback. Resolve
			// already audited the denial; surface a non-secret operator warning.
			si.Warnings = append(si.Warnings, fmt.Sprintf("cred %q not injected: %v", grant.Name, rerr))
			continue
		}
		ttl := in.ttl
		if meta.TTL != "" {
			if d, perr := time.ParseDuration(meta.TTL); perr == nil && d > 0 {
				ttl = d
			}
		}
		adapter := in.adapterFor(grant)
		inj, aerr := adapter.Inject(ctx, InjectContext{
			SessionID:       sessionID,
			EndpointBaseURL: endpointBase,
			Token:           token,
			TTL:             ttl,
			Now:             in.now(),
		}, grant, meta, value)
		// Zeroize the plaintext immediately after injection — the injected artifact is
		// the scoped token/endpoint, never the raw secret.
		Zeroize(value)
		if aerr != nil {
			si.Warnings = append(si.Warnings, fmt.Sprintf("cred %q not injected: %v", grant.Name, aerr))
			continue
		}
		if inj.ServeBody != nil && in.server != nil {
			in.server.Register(sessionID, token, inj.ServeBody, inj.ServeContentType, inj.ExpiresAt)
		}
		si.Env = append(si.Env, inj.Env...)
		if !inj.Blind {
			si.Warnings = append(si.Warnings, fmt.Sprintf("cred %q injected via the env fallback (short-lived but AGENT-VISIBLE; blind path lands with F5.2)", grant.Name))
		}
	}
	return si, nil
}

// adapterFor selects the adapter for a grant: the single generic OAuth2 adapter
// for any "oauth2"/"oauth2/<service>" provider (F5.4), else a provider-registered
// adapter (F5.1/F5.3), else the generic env fallback.
func (in *Injector) adapterFor(grant policy.Cred) CredentialAdapter {
	if in.oauth2 != nil && isOAuth2Provider(grant.Provider) {
		return in.oauth2
	}
	if a, ok := in.adapters[grant.Provider]; ok {
		return a
	}
	return in.defaultAdapter
}

// RegisterOAuth2Adapters installs the F5.4 generic OAuth2 adapter with the given
// validated per-service config, so every "oauth2/<service>" grant mints a
// per-request access token from its vaulted refresh token. Registering once wires
// ALL configured services (config-only expansion); the injector and session
// manager are untouched. A nil/empty config leaves the adapter unwired (no
// oauth2 grant resolves — deny-by-default).
func (in *Injector) RegisterOAuth2Adapters(services map[string]OAuth2ServiceConfig, doer httpDoer) {
	if in == nil || len(services) == 0 {
		return
	}
	in.oauth2 = NewOAuth2Adapter(services, doer)
}

// Release drops a session's endpoint credential on teardown (idempotent).
func (in *Injector) Release(sessionID string) {
	if in == nil || in.server == nil {
		return
	}
	in.server.Release(sessionID)
}

// newToken returns a random 256-bit hex per-session bearer token.
func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("broker: generate session cred token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
