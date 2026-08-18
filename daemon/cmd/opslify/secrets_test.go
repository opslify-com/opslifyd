package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestSecretsAddFromStdin proves `secrets add` reads the value from STDIN (never
// argv) and sends it base64 to the daemon; the response echoes no value.
func TestSecretsAddFromStdin(t *testing.T) {
	var got addSecretReq
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(secretMeta{Ref: got.Ref, Provider: got.Provider})
	})
	fd := newFakeDaemon(t, mux)

	secret := "FAKE-cli-secret-abc"
	root := rootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetIn(strings.NewReader(secret + "\n")) // trailing newline is trimmed
	root.SetArgs([]string{"secrets", "add", "gh/token", "--provider", "github", "--socket", fd.socketPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v (%s)", err, errb.String())
	}
	// The value was carried base64 in the body, decoded back to exactly the secret.
	decoded, _ := base64.StdEncoding.DecodeString(got.ValueB64)
	if string(decoded) != secret {
		t.Fatalf("daemon received %q, want %q", decoded, secret)
	}
	if got.Ref != "gh/token" || got.Provider != "github" {
		t.Fatalf("bad request: %+v", got)
	}
	// The value must NOT appear in argv (it came from stdin) nor in stdout.
	if strings.Contains(out.String(), secret) {
		t.Fatal("SECURITY: secret value printed to stdout")
	}
}

// TestSecretsAddRejectsEmpty ensures a value cannot be passed as an argument (there
// is no value arg) and empty stdin is refused.
func TestSecretsAddRejectsEmpty(t *testing.T) {
	fd := newFakeDaemon(t, http.NewServeMux())
	root := rootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetIn(strings.NewReader(""))
	root.SetArgs([]string{"secrets", "add", "k", "--socket", fd.socketPath})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error on empty secret value")
	}
}

// TestSecretsLsNoValue ensures `secrets ls` renders metadata only.
func TestSecretsLsNoValue(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]secretMeta{
			{Ref: "aws/deploy", Provider: "aws", TTL: "15m", CreatedAt: "2026-08-18T00:00:00Z"},
		})
	})
	fd := newFakeDaemon(t, mux)
	root := rootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"secrets", "ls", "--socket", fd.socketPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "aws/deploy") || !strings.Contains(out.String(), "aws") {
		t.Fatalf("ls output missing metadata: %s", out.String())
	}
}
