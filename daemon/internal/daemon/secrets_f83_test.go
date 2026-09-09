package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// The canary is planted as a real secret value; if any route can be made to
// return it, these tests fail. This is the feature's whole premise.
const secretCanary = "CANARY-s3cret-value-must-never-appear"

func newSecretsTestDaemon(t *testing.T) (http.Handler, *broker.Vault) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	v, err := broker.OpenVault(t.TempDir()+"/vault.db", broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if err := v.Put(context.Background(), "gitlab-token", []byte(secretCanary),
		broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	idx := broker.NewConsumerIndex(broker.ConfigConsumers(
		[]broker.EgressInjectRef{{Host: "gitlab.example.com", SecretRef: "gitlab-token"}}, nil))
	d, err := New(Options{
		Secrets:    v,
		SecretsSvc: broker.NewSecretsService(v, idx),
		Verifier:   okVerifier(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d.Handler(), v
}

// No route may return a secret value — enumerated over the whole secrets surface,
// including the F8.3 additions.
func TestNoSecretsRouteReturnsAValue(t *testing.T) {
	h, _ := newSecretsTestDaemon(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/secrets"},
		{http.MethodGet, "/v1/secrets/consumers"},
		{http.MethodGet, "/v1/secrets/gitlab-token"},
		{http.MethodPost, "/v1/secrets"},
		{http.MethodPut, "/v1/secrets/gitlab-token"},
		{http.MethodDelete, "/v1/secrets/gitlab-token"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if strings.Contains(rec.Body.String(), secretCanary) {
			t.Fatalf("%s %s returned the secret VALUE: %s", tc.method, tc.path, rec.Body.String())
		}
	}
}

// The consumers listing reports who addresses a ref, with no value.
func TestConsumersRouteListsConsumers(t *testing.T) {
	h, _ := newSecretsTestDaemon(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/secrets/consumers", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var out []secretViewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 || out[0].Ref != "gitlab-token" {
		t.Fatalf("unexpected listing: %+v", out)
	}
	if !out[0].InUse || len(out[0].Consumers) != 1 {
		t.Fatalf("consumers not reported: %+v", out[0])
	}
	if out[0].Consumers[0].Kind != broker.ConsumerEgressInject {
		t.Fatalf("wrong consumer kind: %+v", out[0].Consumers[0])
	}
}

// DELETE is guarded: a ref something still addresses is refused with 409, and the
// secret survives. Silently deleting it would only surface at the next resolve.
func TestDeleteRouteRefusesWhileInUse(t *testing.T) {
	h, v := newSecretsTestDaemon(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/secrets/gitlab-token", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	if metas, _ := v.List(context.Background()); len(metas) != 1 {
		t.Fatal("a refused delete must leave the secret intact")
	}
	// The refusal must name what is holding it, or the operator cannot act on it.
	if !strings.Contains(rec.Body.String(), "gitlab.example.com") {
		t.Fatalf("the refusal must name the consumers, got %s", rec.Body.String())
	}

	// ?force=true proceeds.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/secrets/gitlab-token?force=true", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("forced delete status = %d, body %s", rec.Code, rec.Body.String())
	}
	if metas, _ := v.List(context.Background()); len(metas) != 0 {
		t.Fatal("a forced delete must remove the secret")
	}
}

// Rotation over the route keeps the ref and never echoes the new value.
func TestRotateRouteKeepsRefAndEchoesNoValue(t *testing.T) {
	h, v := newSecretsTestDaemon(t)
	const newVal = "ROTATED-new-value"
	body, _ := json.Marshal(rotateSecretRequest{ValueB64: b64(newVal)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/secrets/gitlab-token", strings.NewReader(string(body))))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), newVal) {
		t.Fatal("the rotate response echoed the new value")
	}
	got, _, err := v.Get(context.Background(), "gitlab-token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != newVal {
		t.Fatalf("rotation did not take effect: %q", got)
	}
}

// Rotating a ref that does not exist is refused, so a typo cannot silently create
// a second secret while the real one stays un-rotated.
func TestRotateRouteRefusesUnknownRef(t *testing.T) {
	h, _ := newSecretsTestDaemon(t)
	body, _ := json.Marshal(rotateSecretRequest{ValueB64: b64("x")})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/secrets/never-stored", strings.NewReader(string(body))))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

// --- route-level fail-closed (D5) --------------------------------------------

// TestDeleteRouteForceRequiresExactlyTrue pins the force PARSE, not just the
// guard. Loosening this one comparison — to `!= ""`, or to any truthy value —
// turns an accidental `?force=1`, or a stray query param, into an unguarded
// delete of a credential a running egress rule still injects.
func TestDeleteRouteForceRequiresExactlyTrue(t *testing.T) {
	for _, q := range []string{"", "?force=", "?force=1", "?force=TRUE", "?force=yes",
		"?force=false", "?forced=true", "?x=1&force=maybe"} {
		t.Run(q, func(t *testing.T) {
			h, v := newSecretsTestDaemon(t)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/secrets/gitlab-token"+q, nil))

			if rec.Code != http.StatusConflict {
				t.Fatalf("DELETE %q = %d, want 409: only ?force=true may bypass the in-use guard", q, rec.Code)
			}
			metas, err := v.List(context.Background())
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(metas) != 1 {
				t.Fatal("the refused delete must leave the secret in place")
			}
		})
	}
}

// TestDeleteRouteForceTrueBypasses is the other half: force=true must actually
// work, or the guard is just a broken delete.
func TestDeleteRouteForceTrueBypasses(t *testing.T) {
	h, v := newSecretsTestDaemon(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/secrets/gitlab-token?force=true", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE ?force=true = %d, want 204: %s", rec.Code, rec.Body.String())
	}
	metas, _ := v.List(context.Background())
	if len(metas) != 0 {
		t.Fatal("force=true must actually remove the secret")
	}
}

// TestDeleteRouteFailsClosedWhenConsumersUnknowable pins the most important
// route behaviour in the feature: if the index cannot answer "who uses this?",
// the delete must be REFUSED. Permitting it would silently break a running grant
// precisely when the daemon has lost the ability to warn about it.
func TestDeleteRouteFailsClosedWhenConsumersUnknowable(t *testing.T) {
	key := make([]byte, 32)
	v, err := broker.OpenVault(t.TempDir()+"/vault.db", broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if err := v.Put(context.Background(), "gitlab-token", []byte(secretCanary), broker.PutMeta{}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	idx := broker.NewConsumerIndex(broker.ConsumerSourceFunc(func() (map[string][]broker.Consumer, error) {
		return nil, errors.New("policy store unavailable")
	}))
	d, err := New(Options{Secrets: v, SecretsSvc: broker.NewSecretsService(v, idx), Verifier: okVerifier()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/secrets/gitlab-token", nil))

	if rec.Code == http.StatusNoContent {
		t.Fatal("delete succeeded while the consumer index was erroring: it must fail CLOSED")
	}
	metas, _ := v.List(context.Background())
	if len(metas) != 1 {
		t.Fatal("the secret was removed despite an unknowable consumer set")
	}
	if strings.Contains(rec.Body.String(), secretCanary) {
		t.Fatal("the error response leaked the value")
	}
}

// TestConsumersRouteWireContract pins the literal JSON the CLI decodes. Both
// sides declare their own struct (internal/daemon and cmd/opslify), and every
// other test on each side decodes with its OWN type — so a renamed field or a
// wrapped array would leave both suites green and break the real CLI. This test
// asserts the bytes.
func TestConsumersRouteWireContract(t *testing.T) {
	h, _ := newSecretsTestDaemon(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/secrets/consumers", nil))

	// A BARE array, not an object wrapping one: `var out []secretView` on the
	// client depends on it.
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the consumers listing must be a bare JSON array: %v (body %s)", err, rec.Body.String())
	}
	if len(raw) != 1 {
		t.Fatalf("want 1 view, got %d", len(raw))
	}
	for _, key := range []string{"ref", "in_use", "consumers"} {
		if _, ok := raw[0][key]; !ok {
			t.Errorf("wire contract: missing key %q — the CLI reads it (body %s)", key, rec.Body.String())
		}
	}
	var consumers []map[string]json.RawMessage
	if err := json.Unmarshal(raw[0]["consumers"], &consumers); err != nil {
		t.Fatalf("consumers must be an array: %v", err)
	}
	for _, key := range []string{"kind", "name"} {
		if _, ok := consumers[0][key]; !ok {
			t.Errorf("wire contract: consumer missing key %q", key)
		}
	}
}
