package install

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
)

// TestValidateOAuth2FailClosed proves a bad per-service OAuth2 config aborts with
// a legible error naming the service; a well-formed one passes. This is the
// startup fail-closed gate for F5.4 config-only services.
func TestValidateOAuth2FailClosed(t *testing.T) {
	bad := DefaultConfig()
	bad.OAuth2 = map[string]broker.OAuth2ServiceConfig{
		"github": {DeviceURL: "https://d.example/device"}, // missing client_id + token_url
	}
	err := bad.ValidateOAuth2()
	if err == nil {
		t.Fatal("expected a fail-closed validation error")
	}
	if !strings.Contains(err.Error(), "github") {
		t.Fatalf("error should name the service: %v", err)
	}

	good := DefaultConfig()
	good.OAuth2 = map[string]broker.OAuth2ServiceConfig{
		"github": {ClientID: "x", TokenURL: "https://t.example/token", DeviceURL: "https://d.example/device"},
	}
	if err := good.ValidateOAuth2(); err != nil {
		t.Fatalf("valid oauth2 config rejected: %v", err)
	}
}

// TestOAuth2ConfigRoundTrip proves the per-service config survives a YAML
// marshal/parse round trip (config-only onboarding relies on it loading back).
func TestOAuth2ConfigRoundTrip(t *testing.T) {
	c := DefaultConfig()
	c.OAuth2 = map[string]broker.OAuth2ServiceConfig{
		"github": {
			ClientID: "cid", TokenURL: "https://t/token", DeviceURL: "https://t/device",
			Scopes: []string{"repo", "read:org"}, EnvVar: "GH_TOKEN",
		},
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := WriteConfig(path, c); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	svc, ok := got.OAuth2["github"]
	if !ok {
		t.Fatal("oauth2 service lost on round trip")
	}
	if svc.ClientID != "cid" || svc.EnvVar != "GH_TOKEN" || len(svc.Scopes) != 2 {
		t.Fatalf("round-trip mismatch: %+v", svc)
	}
}
