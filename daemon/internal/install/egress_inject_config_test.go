package install

import (
	"strings"
	"testing"
)

// TestValidateEgressInjectFailClosed proves the F5.7 startup gate rejects malformed
// egress-inject rules with a legible error, and accepts a well-formed set. The
// config holds NO secret — only a `creds` ref (secret_ref).
func TestValidateEgressInjectFailClosed(t *testing.T) {
	good := DefaultConfig()
	good.EgressInject = []EgressInjectRule{
		{Host: "gitlab.com", SecretRef: "gitlab-token", HeaderName: "PRIVATE-TOKEN", HeaderFormat: "%s"},
		{Host: "api.github.com", SecretRef: "gh-token", HeaderName: "Authorization", HeaderFormat: "Bearer %s"},
		{Host: "example.com", SecretRef: "raw", HeaderName: "X-Api-Key"}, // empty format = raw secret is allowed
	}
	if err := good.ValidateEgressInject(); err != nil {
		t.Fatalf("well-formed rules rejected: %v", err)
	}

	cases := []struct {
		name string
		rule EgressInjectRule
		want string
	}{
		{"missing host", EgressInjectRule{SecretRef: "r", HeaderName: "H"}, "host is required"},
		{"host with scheme", EgressInjectRule{Host: "https://gitlab.com", SecretRef: "r", HeaderName: "H"}, "bare hostname"},
		{"host with port", EgressInjectRule{Host: "gitlab.com:443", SecretRef: "r", HeaderName: "H"}, "bare hostname"},
		{"missing secret_ref", EgressInjectRule{Host: "gitlab.com", HeaderName: "H"}, "secret_ref is required"},
		{"missing header_name", EgressInjectRule{Host: "gitlab.com", SecretRef: "r"}, "header_name is required"},
		{"bad format two verbs", EgressInjectRule{Host: "gitlab.com", SecretRef: "r", HeaderName: "H", HeaderFormat: "%s %s"}, "exactly one"},
		{"bad format wrong verb", EgressInjectRule{Host: "gitlab.com", SecretRef: "r", HeaderName: "H", HeaderFormat: "%d"}, "exactly one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			c.EgressInject = []EgressInjectRule{tc.rule}
			err := c.ValidateEgressInject()
			if err == nil {
				t.Fatalf("expected an error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing %q", err.Error(), tc.want)
			}
		})
	}

	// Duplicate host (case-insensitive) is rejected.
	dup := DefaultConfig()
	dup.EgressInject = []EgressInjectRule{
		{Host: "gitlab.com", SecretRef: "a", HeaderName: "H"},
		{Host: "GITLAB.com", SecretRef: "b", HeaderName: "H"},
	}
	if err := dup.ValidateEgressInject(); err == nil || !strings.Contains(err.Error(), "duplicate host") {
		t.Fatalf("expected duplicate-host error, got %v", err)
	}

	// Absent section is a clean no-op (opt-in).
	if err := DefaultConfig().ValidateEgressInject(); err != nil {
		t.Fatalf("absent egress_inject should validate: %v", err)
	}
}
