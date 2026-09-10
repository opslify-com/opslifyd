package broker

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// httpConnection injects an auth header at the L7 egress proxy.
//
// What the sandbox receives: NOTHING. The header is added to the upstream clone
// of the request inside the daemon's proxy; it never appears in the sandbox's
// environment, its filesystem, or the response it reads back. This is the kind
// P5 already proves end to end, which is why it is the one the abstraction is
// built against first — an interface justified only by kinds that do not exist
// yet is an interface nobody has tested.
type httpConnection struct {
	spec ConnectionSpec
}

// NewHTTPConnection builds the http kind from a spec.
func NewHTTPConnection(spec ConnectionSpec, _ SecretResolver) (Connection, error) {
	return &httpConnection{spec: spec}, nil
}

func (c *httpConnection) Kind() Kind           { return KindHTTP }
func (c *httpConnection) Name() string         { return c.spec.Name }
func (c *httpConnection) SecretRefs() []string { return []string{c.spec.SecretRef} }

// headerName is the auth header this connection sets upstream.
func (c *httpConnection) headerName() string {
	if h := c.spec.Config["header_name"]; h != "" {
		return h
	}
	return "Authorization"
}

// headerFormat is the single-%s template applied to the resolved secret. Empty
// means the raw secret is the header value.
func (c *httpConnection) headerFormat() string { return c.spec.Config["header_format"] }

func (c *httpConnection) Validate() error {
	if err := c.spec.ValidateSpec(); err != nil {
		return err
	}
	if len(c.spec.Hosts) == 0 {
		// An http connection with no host would inject on nothing, or — far worse,
		// if a future reader "fixed" it by treating empty as a wildcard — on
		// everything. Requiring at least one host makes that impossible to reach.
		return fmt.Errorf("%w: http connection %q needs at least one host to inject on", ErrInvalidInput, c.spec.Name)
	}
	name := c.headerName()
	if strings.ContainsAny(name, " \t\r\n:\x00") || name == "" {
		return fmt.Errorf("%w: http connection %q has an invalid header name %q", ErrInvalidInput, c.spec.Name, name)
	}
	if f := c.headerFormat(); f != "" {
		// Exactly one %s, or the resolved secret lands somewhere unintended — or
		// not at all, producing a header that authenticates nothing while looking
		// like it does.
		if strings.Count(f, "%s") != 1 || strings.Count(f, "%") != 1 {
			return fmt.Errorf("%w: http connection %q header_format %q must contain exactly one %%s and no other verb",
				ErrInvalidInput, c.spec.Name, f)
		}
		if strings.ContainsAny(f, "\r\n\x00") {
			return fmt.Errorf("%w: http connection %q header_format contains a control character", ErrInvalidInput, c.spec.Name)
		}
	}
	return nil
}

// BuildForSession contributes header-injection rules and — critically — marks the
// secret ref as EXCLUDED from environment injection.
//
// The exclusion is the load-bearing half. Without it the same credential this
// connection resolves at the proxy boundary would also be resolved into the
// sandbox's environment by the F5.1 injector, placing in the sandbox exactly the
// value the connection exists to keep out of it. The kind is credential-blind
// only if both halves hold.
func (c *httpConnection) EgressRules() []HeaderInjectRule {
	rules := make([]HeaderInjectRule, 0, len(c.spec.Hosts))
	for _, host := range c.spec.Hosts {
		rules = append(rules, HeaderInjectRule{
			Host:         host,
			SecretRef:    c.spec.SecretRef,
			HeaderName:   c.headerName(),
			HeaderFormat: c.headerFormat(),
		})
	}
	return rules
}

func (c *httpConnection) BuildForSession(_ context.Context, _ SessionContext) (ConnectionInjection, io.Closer, error) {
	return ConnectionInjection{
		ExcludeRefs: []string{c.spec.SecretRef},
		// No Env and no Files, deliberately: the sandbox receives nothing.
	}, nil, nil
}
