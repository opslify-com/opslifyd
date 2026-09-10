package broker

import (
	"github.com/opslify-com/opslifyd/internal/policy"
)

// The sources below cover every subsystem that addresses a secret ref TODAY.
// F8.2 connections become one more source; nothing here changes when they land.

// EgressInjectRef is one F5.7 rule reduced to what the index needs: which ref it
// injects and for which host. The config type is not imported directly so that
// internal/install can depend on broker without a cycle.
type EgressInjectRef struct {
	Host      string
	SecretRef string
}

// RegistryUpstreamRef is one F5.5 upstream's cred_ref and the ecosystem it serves.
type RegistryUpstreamRef struct {
	Ecosystem string
	CredRef   string
}

// ConfigConsumers reports the refs addressed by daemon config: egress-inject
// rules and registry upstreams. Both are daemon-authoritative, so their scope is
// empty (daemon-wide) rather than a project.
func ConfigConsumers(egress []EgressInjectRef, upstreams []RegistryUpstreamRef) ConsumerSource {
	return ConsumerSourceFunc(func() (map[string][]Consumer, error) {
		out := map[string][]Consumer{}
		for _, r := range egress {
			if r.SecretRef == "" {
				continue
			}
			out[r.SecretRef] = append(out[r.SecretRef], Consumer{
				Kind: ConsumerEgressInject,
				Name: r.Host,
			})
		}
		for _, u := range upstreams {
			if u.CredRef == "" {
				continue
			}
			out[u.CredRef] = append(out[u.CredRef], Consumer{
				Kind: ConsumerRegistryUpstream,
				Name: u.Ecosystem,
			})
		}
		return out, nil
	})
}

// PolicyScope is one resolved policy layer and the scope it governs. A grant in
// a scope means a session there MAY resolve the ref, which is exactly the thing a
// delete would break.
type PolicyScope struct {
	// Scope is the human-readable scope, e.g. "tripon/staging" or "" for the
	// daemon default policy.
	Scope string
	// Policy is the resolved policy whose `creds` grants are read.
	Policy policy.Policy
}

// PolicyConsumers reports the refs granted by a set of policy scopes. The caller
// supplies the scopes (the daemon default plus each project/environment layer),
// so this stays independent of how they are resolved.
func PolicyConsumers(scopes []PolicyScope) ConsumerSource {
	return ConsumerSourceFunc(func() (map[string][]Consumer, error) {
		out := map[string][]Consumer{}
		for _, sc := range scopes {
			for _, c := range sc.Policy.Creds {
				if c.Name == "" {
					continue
				}
				name := c.Provider
				if name == "" {
					name = "grant"
				}
				out[c.Name] = append(out[c.Name], Consumer{
					Kind:  ConsumerPolicyGrant,
					Name:  name,
					Scope: sc.Scope,
				})
			}
		}
		return out, nil
	})
}

// ConnectionConsumers reports every secret ref a connection resolves, so the
// F8.3 delete guard refuses to remove a credential a live connection depends on.
//
// This is why ConsumerKind already had a Connection value before any connection
// existed: the guard has to be complete on the day the first connection is
// created, not retrofitted after an operator has deleted something that was in
// use. Scope is carried through so the refusal can say WHICH project and
// environment would break, not merely that something would.
func ConnectionConsumers(conns []ConnectionSpec) ConsumerSource {
	return ConsumerSourceFunc(func() (map[string][]Consumer, error) {
		out := map[string][]Consumer{}
		for _, c := range conns {
			if c.SecretRef == "" {
				continue
			}
			scope := c.ProjectID
			if c.EnvironmentID != "" {
				scope = c.EnvironmentID
			}
			out[c.SecretRef] = append(out[c.SecretRef], Consumer{
				Kind:  ConsumerConnection,
				Name:  string(c.Kind) + ":" + c.Name,
				Scope: scope,
			})
		}
		return out, nil
	})
}
