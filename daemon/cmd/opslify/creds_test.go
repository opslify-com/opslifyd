package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/install"
)

const fakeCLIRefresh = "FAKE-CLI-OAUTH-REFRESH-do-not-use"

// oauth2StubServer is a minimal device+token OAuth2 server for the CLI test.
func oauth2StubServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONCLI(w, map[string]any{
			"device_code": "DEV-CODE", "user_code": "WXYZ-1234",
			"verification_uri": "http://example.test/activate", "interval": 1, "expires_in": 600,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") == "urn:ietf:params:oauth:grant-type:device_code" {
			writeJSONCLI(w, map[string]any{"refresh_token": fakeCLIRefresh, "access_token": "ignored", "expires_in": 3600})
			return
		}
		writeJSONCLI(w, map[string]any{"error": "unsupported_grant_type"})
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func writeJSONCLI(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// TestCredsAddDeviceFlow proves `opslify creds add <service>` runs the device
// flow and stores the REFRESH token via the daemon — carried base64 in the body
// (never argv), never printed to stdout, under provider "oauth2/<service>".
func TestCredsAddDeviceFlow(t *testing.T) {
	oauth := oauth2StubServer(t)

	// Daemon side: capture the stored-secret request.
	var got addSecretReq
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(secretMeta{Ref: got.Ref, Provider: got.Provider})
	})
	fd := newFakeDaemon(t, mux)

	// Write a config with one oauth2 service pointing at the stub.
	cfg := install.DefaultConfig()
	cfg.OAuth2 = map[string]broker.OAuth2ServiceConfig{
		"github": {
			TokenURL:  oauth.URL + "/token",
			DeviceURL: oauth.URL + "/device",
			ClientID:  "FAKE-CLIENT",
			Scopes:    []string{"repo"},
		},
	}
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := install.WriteConfig(cfgPath, cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}

	root := rootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs([]string{"creds", "add", "github", "--config", cfgPath, "--socket", fd.socketPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v (%s)", err, errb.String())
	}

	decoded, _ := base64.StdEncoding.DecodeString(got.ValueB64)
	if string(decoded) != fakeCLIRefresh {
		t.Fatalf("daemon received %q, want the refresh token", decoded)
	}
	if got.Provider != "oauth2/github" || got.Ref != "github" {
		t.Fatalf("bad request: %+v", got)
	}
	// The refresh token must NEVER be printed.
	if strings.Contains(out.String(), fakeCLIRefresh) {
		t.Fatal("SECURITY: refresh token printed to stdout")
	}
	// The verification URL + user code ARE shown (they are not secrets).
	if !strings.Contains(out.String(), "WXYZ-1234") {
		t.Fatalf("expected the user code to be shown, got: %s", out.String())
	}
}

// TestCredsAddUnknownService fails legibly when the service isn't configured.
func TestCredsAddUnknownService(t *testing.T) {
	fd := newFakeDaemon(t, http.NewServeMux())
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := install.WriteConfig(cfgPath, install.DefaultConfig()); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, errStr, err := execRoot(t, "creds", "add", "nope", "--config", cfgPath, "--socket", fd.socketPath)
	if err == nil {
		t.Fatal("expected error for an unconfigured service")
	}
	if !strings.Contains(err.Error()+errStr, "nope") {
		t.Fatalf("error should name the service: %v / %s", err, errStr)
	}
}
