package broker

import (
	"context"
	"fmt"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// Broker is the daemon-internal resolution engine: it enforces the F4.1 policy
// `creds` grants (deny-by-default) over a SecretBackend and emits a `cred.resolve`
// audit event on EVERY resolution — granted or denied. It is the entrypoint F5.1
// injection will consume: F5.1 calls Resolve to obtain a value for a
// policy-granted session, injects it executor-side, and zeroes it — the value is
// never handed to the sandbox or any external caller.
type Broker struct {
	backend SecretBackend
}

// NewBroker wraps a backend. A nil backend yields a broker whose Resolve always
// denies (fail-closed), so an unwired daemon never resolves a secret.
func NewBroker(backend SecretBackend) *Broker {
	return &Broker{backend: backend}
}

// Resolve is the DAEMON-INTERNAL gated resolution. It:
//  1. checks the session's resolved-policy `creds` grants for ref (deny-by-default);
//  2. on a grant, calls the backend's internal Get for the value;
//  3. emits a `cred.resolve` audit event (ref/provider/scope/ttl/policy_rule/
//     success) — NEVER the value or a value length;
//  4. returns the value to the internal caller (F5.1), or ErrDenied/err with NO
//     value on any failure (fail-closed).
//
// grants is the session's resolved policy `creds` (policy.Resolved.Creds), which
// is ALREADY narrowed under the F4.1 narrows-not-widens invariant — a workspace
// cannot have self-granted a cred, so honouring these grants cannot over-grant.
// rec is the session's trace recorder (a nil recorder is a valid no-op).
//
// The caller SHOULD Zeroize the returned value after use.
func (b *Broker) Resolve(ctx context.Context, rec *trace.Recorder, grants []policy.Cred, ref string) ([]byte, SecretMeta, error) {
	grant, granted := matchGrant(grants, ref)
	if !granted {
		// Deny-by-default: no value is fetched, none is returned. Audit the denial
		// with only the ref (we know nothing else about an ungranted secret).
		b.audit(ctx, rec, SecretMeta{Ref: ref}, "deny-by-default", false)
		return nil, SecretMeta{}, fmt.Errorf("%w: %s (not in policy creds grants)", ErrDenied, ref)
	}
	if b.backend == nil {
		b.audit(ctx, rec, SecretMeta{Ref: ref, Provider: grant.Provider}, "no-backend", false)
		return nil, SecretMeta{}, fmt.Errorf("%w: no secret backend configured", ErrDenied)
	}
	value, meta, err := b.backend.Get(ctx, ref)
	if err != nil {
		// Fail closed: a granted-but-missing (or undecryptable) secret returns NO
		// value and is audited as a failed resolve.
		b.audit(ctx, rec, SecretMeta{Ref: ref, Provider: grant.Provider}, ruleFor(grant), false)
		return nil, SecretMeta{}, err
	}
	// If the grant pinned a provider, it must match the stored secret's provider —
	// otherwise a ref could be satisfied by a differently-provided secret. Fail
	// closed and zero the value we already decrypted.
	if grant.Provider != "" && meta.Provider != "" && grant.Provider != meta.Provider {
		Zeroize(value)
		b.audit(ctx, rec, meta, "provider-mismatch", false)
		return nil, SecretMeta{}, fmt.Errorf("%w: %s provider %q does not match grant %q", ErrDenied, ref, meta.Provider, grant.Provider)
	}
	b.audit(ctx, rec, meta, ruleFor(grant), true)
	return value, meta, nil
}

// matchGrant finds a `creds` grant for ref. A grant matches when its Name equals
// ref. Deny-by-default: no matching grant => not granted.
func matchGrant(grants []policy.Cred, ref string) (policy.Cred, bool) {
	for _, g := range grants {
		if g.Name == ref {
			return g, true
		}
	}
	return policy.Cred{}, false
}

// ruleFor renders the human-readable policy rule an allowed resolve matched, for
// the audit event's policy_rule field.
func ruleFor(g policy.Cred) string {
	if g.Provider != "" {
		return fmt.Sprintf("creds:%s/%s", g.Name, g.Provider)
	}
	return "creds:" + g.Name
}

// audit emits the `cred.resolve` event. It carries ref/provider/scope/ttl/
// policy_rule/success — and DELIBERATELY NEVER the value (nor a value length that
// could narrow a brute force). The Recorder runs F3.3 redaction and F3.1 chaining
// in the emit path, so the event is redacted + committed to the tamper-evident
// chain like every other event.
func (b *Broker) audit(ctx context.Context, rec *trace.Recorder, meta SecretMeta, rule string, success bool) {
	_ = rec.Emit(ctx, trace.TypeCredResolve, map[string]any{
		"ref":         meta.Ref,
		"provider":    meta.Provider,
		"scope":       meta.Scope,
		"ttl":         meta.TTL,
		"policy_rule": rule,
		"success":     success,
	})
}
