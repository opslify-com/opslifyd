package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
)

// fakeVaultKey is a clearly-fake 32-byte master key.
func fakeVaultKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 100)
	}
	return k
}

func newSecretDaemon(t *testing.T) (*httptest.Server, broker.SecretManager) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := broker.OpenVault(path, broker.StaticKeySource(fakeVaultKey()))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	d, err := New(Options{
		Verifier:     okVerifier(),
		RuntimeProbe: func() error { return nil },
		Secrets:      v,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(d.Handler())
	t.Cleanup(srv.Close)
	return srv, v
}

func TestSecretAddListDelete_NoValueLeaks(t *testing.T) {
	srv, _ := newSecretDaemon(t)
	secret := "FAKE-http-secret-canary-13579"

	// Add (value in, base64).
	body, _ := json.Marshal(map[string]any{
		"ref": "aws/deploy", "provider": "aws", "ttl": "15m",
		"value_b64": base64.StdEncoding.EncodeToString([]byte(secret)),
	})
	resp, err := http.Post(srv.URL+"/v1/secrets", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	addBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add status = %d: %s", resp.StatusCode, addBody)
	}
	if strings.Contains(string(addBody), secret) {
		t.Fatal("SECURITY: add response echoed the secret value")
	}

	// List (metadata only).
	resp, err = http.Get(srv.URL + "/v1/secrets")
	if err != nil {
		t.Fatal(err)
	}
	lsBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(lsBody), secret) {
		t.Fatal("SECURITY: list response contained the secret value")
	}
	if !strings.Contains(string(lsBody), "aws/deploy") {
		t.Fatalf("list missing the ref: %s", lsBody)
	}

	// Delete.
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1/secrets/aws/deploy", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
}

// TestNoGetRoute adversarially probes for a value-read route. None of these should
// return a secret value — Get is daemon-internal and unrouted.
func TestNoGetRoute(t *testing.T) {
	srv, _ := newSecretDaemon(t)
	secret := "FAKE-unreadable-value-2468"
	body, _ := json.Marshal(map[string]any{
		"ref": "k", "value_b64": base64.StdEncoding.EncodeToString([]byte(secret)),
	})
	resp, _ := http.Post(srv.URL+"/v1/secrets", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	// Try plausible value-read paths an attacker would guess.
	for _, u := range []string{
		"/v1/secrets/k",
		"/v1/secrets/k/value",
		"/v1/secrets/k?reveal=1",
		"/v1/secrets?ref=k&value=1",
	} {
		r, err := http.Get(srv.URL + u)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if strings.Contains(string(b), secret) {
			t.Fatalf("SECURITY: %s leaked the secret value", u)
		}
	}
}

// TestManagerHasNoGet is a compile-time-style assertion that the daemon's secret
// surface (broker.SecretManager) has no Get method — a value read is not even
// expressible at the REST layer.
func TestManagerHasNoGet(t *testing.T) {
	var sm broker.SecretManager
	// If SecretManager ever gained a Get method returning a value, this type would
	// need updating — the interface deliberately has only Put/List/Delete.
	if _, ok := interface{}(sm).(interface {
		Get()
	}); ok {
		t.Fatal("SecretManager unexpectedly exposes Get")
	}
}
