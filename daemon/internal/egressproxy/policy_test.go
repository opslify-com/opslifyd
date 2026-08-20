package egressproxy

import (
	"testing"

	"github.com/opslify-com/opslifyd/internal/policy"
)

func TestDecide_FailClosedAndNeverMITM(t *testing.T) {
	ref := "gh"
	cfg := BuildConfig(
		resolvedWith(
			[]string{"api.github.com", "releases.hashicorp.com", "registry.npmjs.org"},
			[]policy.Cred{{Name: ref}},
		),
		[]InjectRule{
			{Host: "api.github.com", CredRef: ref, HeaderName: "Authorization"},
			// An inject rule that ALSO names a never-MITM host must be dropped.
			{Host: "releases.hashicorp.com", CredRef: ref, HeaderName: "Authorization"},
		},
		[]string{"releases.hashicorp.com"}, // checksum-verifying: never MITM
	)

	// Granted injection host => terminate + rule.
	if d := cfg.Decide("GET", "api.github.com", "/user"); d.Mode != ModeTerminate || d.Inject == nil {
		t.Fatalf("github should terminate+inject, got %v inject=%v", d.Mode, d.Inject)
	}
	// Never-MITM host => pass-through EVEN THOUGH an inject rule named it.
	if d := cfg.Decide("GET", "releases.hashicorp.com", "/x"); d.Mode != ModePassthrough {
		t.Fatalf("SECURITY: never-MITM host got %v (must be passthrough)", d.Mode)
	}
	// Allowed but no inject rule => pass-through (SNI-validated).
	if d := cfg.Decide("GET", "registry.npmjs.org", "/pkg"); d.Mode != ModePassthrough {
		t.Fatalf("plain allowed host should passthrough, got %v", d.Mode)
	}
	// Unlisted host => deny (F1.4 default-deny).
	if d := cfg.Decide("GET", "evil.example.com", "/x"); d.Mode != ModeDeny {
		t.Fatalf("unlisted host should deny, got %v", d.Mode)
	}
}

// A workspace can only NARROW; simulate a "widened" inject rule whose host/cred is
// NOT in the resolved policy — BuildConfig must drop it fail-closed.
func TestBuildConfig_DropsUngrantedRules(t *testing.T) {
	cfg := BuildConfig(
		resolvedWith([]string{"api.github.com"}, []policy.Cred{{Name: "gh"}}),
		[]InjectRule{
			{Host: "api.github.com", CredRef: "gh", HeaderName: "Authorization"}, // ok
			{Host: "internal.evil", CredRef: "gh", HeaderName: "Authorization"},  // host not egress-allowed
			{Host: "api.github.com", CredRef: "not-granted", HeaderName: "X"},    // cred not granted
		},
		nil,
	)
	if len(cfg.injectByID) != 1 {
		t.Fatalf("want 1 surviving rule, got %d", len(cfg.injectByID))
	}
	// The widened host is not even reachable.
	if cfg.Decide("GET", "internal.evil", "/").Mode != ModeDeny {
		t.Fatal("widened host was honoured")
	}
	// The ungranted-cred rule did not become a terminate on github.
	if d := cfg.Decide("POST", "api.github.com", "/"); d.Inject == nil || d.Inject.CredRef != "gh" {
		t.Fatalf("only the granted rule should terminate, got %v", d.Inject)
	}
}

func TestHostname_StripsPort(t *testing.T) {
	if got := hostname("api.github.com:443"); got != "api.github.com" {
		t.Fatalf("hostname = %q", got)
	}
	if got := hostname("api.github.com"); got != "api.github.com" {
		t.Fatalf("hostname = %q", got)
	}
}
