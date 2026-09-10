package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/session"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// leaks reports whether body contains the secret in ANY encoding it could
// plausibly travel in.
//
// A plaintext-only check was blind to exactly the encoding values DO travel in:
// a rotate handler echoing value_b64 straight back to the caller — a total
// defeat of the write-only premise — passed every leak assertion in the tree.
// Base64 comes in three alphabets (std/URL, padded and not) and JSON may escape
// the '+' and '/'; hex is checked too since a future handler could render bytes
// that way.
// The canary is deliberately all-unreserved ASCII with no '/', '"' or '\\': that
// makes percent-encoding and quoted-printable identity transforms on it, so the
// encodings enumerated below are the complete set that could carry it. A canary
// containing those characters would need a real un-escaper here, not the narrow
// one below.
func leaks(body, secret string) (string, bool) {
	raw := []byte(secret)
	candidates := map[string]string{
		"plaintext":      secret,
		"base64-std":     base64.StdEncoding.EncodeToString(raw),
		"base64-std-raw": base64.RawStdEncoding.EncodeToString(raw),
		"base64-url":     base64.URLEncoding.EncodeToString(raw),
		"base64-url-raw": base64.RawURLEncoding.EncodeToString(raw),
		"hex":            hex.EncodeToString(raw),
		"hex-upper":      strings.ToUpper(hex.EncodeToString(raw)),
	}
	for name, enc := range candidates {
		if enc == "" {
			continue
		}
		if strings.Contains(body, enc) {
			return name, true
		}
	}
	// A JSON-escaped base64 payload ("a\/b") would evade a raw substring check.
	if unquoted := strings.ReplaceAll(body, "\\/", "/"); unquoted != body {
		if strings.Contains(unquoted, base64.StdEncoding.EncodeToString(raw)) {
			return "base64-std (JSON-escaped)", true
		}
	}
	return "", false
}

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
// including the F8.3 additions, and checked in every encoding a value could
// travel in rather than plaintext alone.
//
// Each route that ACCEPTS a value is also sent one, so a handler that echoes its
// own request body is caught. Sending only "{}" (as this test used to) meant the
// canary was never in play on exactly the routes most able to reflect it.
func TestNoSecretsRouteReturnsAValue(t *testing.T) {
	// Bodies are per-route because the request shapes differ: POST /v1/secrets
	// carries the ref, PUT /v1/secrets/{ref} takes it from the path and REJECTS a
	// "ref" field. wantStatus is asserted so a body the handler refuses with a 400
	// cannot masquerade as a clean leak check — the first version of this test sent
	// one shape everywhere, and the rotate route 400'd before ever reaching the
	// code being probed, making the assertion vacuous on the route most able to
	// reflect a value.
	addBody := `{"ref":"gitlab-token","value_b64":"` + b64(secretCanary) + `","provider":"gitlab"}`
	rotateBody := `{"value_b64":"` + b64(secretCanary) + `","provider":"gitlab"}`
	for _, tc := range []struct {
		name, method, path, body string
		wantStatus               int
	}{
		{"list", http.MethodGet, "/v1/secrets", "{}", http.StatusOK},
		{"consumers", http.MethodGet, "/v1/secrets/consumers", "{}", http.StatusOK},
		{"add-existing", http.MethodPost, "/v1/secrets", addBody, http.StatusConflict},
		{"add-new", http.MethodPost, "/v1/secrets", `{"ref":"new-token","value_b64":"` + b64(secretCanary) + `"}`, http.StatusCreated},
		{"rotate", http.MethodPut, "/v1/secrets/gitlab-token", rotateBody, http.StatusOK},
		{"add-overwrite-existing", http.MethodPost, "/v1/secrets", `{"ref":"gitlab-token","value_b64":"` + b64(secretCanary) + `","overwrite":true}`, http.StatusOK},
		{"add-overwrite-new", http.MethodPost, "/v1/secrets", `{"ref":"fresh","value_b64":"` + b64(secretCanary) + `","overwrite":true}`, http.StatusCreated},
		{"delete-in-use", http.MethodDelete, "/v1/secrets/gitlab-token", "{}", http.StatusConflict},
		{"delete-forced", http.MethodDelete, "/v1/secrets/gitlab-token?force=true", "{}", http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newSecretsTestDaemon(t)
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s = %d, want %d — the route did not run, so this leak check proves nothing: %s",
					tc.method, tc.path, rec.Code, tc.wantStatus, rec.Body.String())
			}
			// HEADERS as well as the body: a handler setting an X-Debug header with
			// the value passed a body-only check with the whole suite green.
			if enc, bad := leaks(rec.Body.String()+fmt.Sprint(rec.Header()), secretCanary); bad {
				t.Fatalf("%s %s returned the secret VALUE as %s: body=%s headers=%v",
					tc.method, tc.path, enc, rec.Body.String(), rec.Header())
			}
		})
	}
}

// TestTheLeakDetectorActuallyDetects guards the guard. A containment check that
// silently stopped matching would make every leak assertion above vacuous, and
// nothing else in the tree would notice.
func TestTheLeakDetectorActuallyDetects(t *testing.T) {
	for _, enc := range []string{
		secretCanary,
		base64.StdEncoding.EncodeToString([]byte(secretCanary)),
		base64.RawStdEncoding.EncodeToString([]byte(secretCanary)),
		base64.URLEncoding.EncodeToString([]byte(secretCanary)),
		hex.EncodeToString([]byte(secretCanary)),
		strings.ToUpper(hex.EncodeToString([]byte(secretCanary))),
	} {
		if _, bad := leaks(`{"ref":"x","value":"`+enc+`"}`, secretCanary); !bad {
			t.Errorf("the leak detector missed encoding %q", enc)
		}
	}
	if _, bad := leaks(`{"ref":"gitlab-token","provider":"gitlab"}`, secretCanary); bad {
		t.Error("the leak detector false-positives on a clean metadata response")
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

// --- log discipline (F16) -----------------------------------------------------

// TestNoSecretRouteLogsAValue. The premise forbids a value in "any log line at
// any level", but nothing constrained the HTTP layer's log output — a handler
// added tomorrow that logged the credential it was about to store would pass
// every other test in the tree. Both the daemon's own logger and the global
// default are captured, since a handler could reach either.
func TestNoSecretRouteLogsAValue(t *testing.T) {
	var daemonLog, globalLog bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&globalLog, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	key := make([]byte, 32)
	v, err := broker.OpenVault(t.TempDir()+"/vault.db", broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if err := v.Put(context.Background(), "gitlab-token", []byte(secretCanary), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	idx := broker.NewConsumerIndex(broker.ConfigConsumers(
		[]broker.EgressInjectRef{{Host: "gitlab.example.com", SecretRef: "gitlab-token"}}, nil))
	d, err := New(Options{
		Secrets:    v,
		SecretsSvc: broker.NewSecretsService(v, idx).WithLogger(slog.New(slog.NewTextHandler(&daemonLog, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		Verifier:   okVerifier(),
		Logger:     slog.New(slog.NewTextHandler(&daemonLog, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := d.Handler()

	rotateBody := `{"value_b64":"` + b64(secretCanary) + `","provider":"gitlab"}`
	addBody := `{"ref":"another","value_b64":"` + b64(secretCanary) + `"}`
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/secrets", addBody},
		{http.MethodPut, "/v1/secrets/gitlab-token", rotateBody},
		{http.MethodGet, "/v1/secrets", "{}"},
		{http.MethodGet, "/v1/secrets/consumers", "{}"},
		{http.MethodDelete, "/v1/secrets/gitlab-token", "{}"},
		{http.MethodDelete, "/v1/secrets/gitlab-token?force=true", "{}"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
	}
	for name, buf := range map[string]*bytes.Buffer{"daemon logger": &daemonLog, "slog default": &globalLog} {
		if enc, bad := leaks(buf.String(), secretCanary); bad {
			t.Fatalf("the %s carried the secret VALUE as %s:\n%s", name, enc, buf.String())
		}
	}
	// The audit records must still be there — this test must not pass by the
	// daemon simply logging nothing.
	if !strings.Contains(daemonLog.String(), "secret.rotate") {
		t.Errorf("expected a rotation audit record in the daemon log; got:\n%s", daemonLog.String())
	}
}

// TestAddWithOverwriteIsAuditedAsARotation pins F6. `secrets add <ref>
// --overwrite` replaces a live credential, which IS a rotation whatever verb
// reached it — but it went straight to the vault, bypassing the service, so it
// produced no audit record and had none of the rotate path's atomicity. One
// operation must not have two safety levels depending on which route it entered.
func TestAddWithOverwriteIsAuditedAsARotation(t *testing.T) {
	var auditLog bytes.Buffer
	key := make([]byte, 32)
	v, err := broker.OpenVault(t.TempDir()+"/vault.db", broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if err := v.Put(context.Background(), "gitlab-token", []byte("old"), broker.PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	svc := broker.NewSecretsService(v, broker.NewConsumerIndex()).
		WithLogger(slog.New(slog.NewTextHandler(&auditLog, nil)))
	d, err := New(Options{Secrets: v, SecretsSvc: svc, Verifier: okVerifier()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	body := `{"ref":"gitlab-token","value_b64":"` + b64(secretCanary) + `","provider":"gitlab","overwrite":true}`
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(body)))
	// 200, not 201: the ref already existed, so this replaced rather than created.
	if rec.Code != http.StatusOK {
		t.Fatalf("POST overwrite of an existing ref = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(auditLog.String(), "secret.rotate") {
		t.Errorf("add --overwrite replaced a live credential with no audit record; log:\n%s", auditLog.String())
	}
	if !strings.Contains(auditLog.String(), "gitlab-token") {
		t.Errorf("the audit record must name the ref; log:\n%s", auditLog.String())
	}
	if enc, bad := leaks(auditLog.String()+rec.Body.String(), secretCanary); bad {
		t.Fatalf("the value leaked as %s", enc)
	}
	// It must still have actually rotated, and stamped RotatedAt.
	metas, _ := v.List(context.Background())
	if len(metas) != 1 || metas[0].RotatedAt.IsZero() {
		t.Errorf("add --overwrite must rotate in place and stamp RotatedAt: %+v", metas)
	}
	// And the VALUE must be the one sent. Asserting only that the ref exists is
	// what let an all-zero credential pass as success.
	assertStoredValue(t, v, "gitlab-token", secretCanary)
	// The 200 must describe the stored record, not the request: a real created_at
	// (carried forward from the original create) rather than year 1.
	if strings.Contains(rec.Body.String(), "0001-01-01") {
		t.Errorf("the response echoed the request instead of the stored record: %s", rec.Body.String())
	}
}

// assertStoredValue decrypts a ref and checks it byte-for-byte.
//
// This exists because "the ref appears in List()" is NOT evidence a credential
// was stored: a rotate-then-create pair that shared a zeroized plaintext buffer
// reported 201 Created and stored 25 zero bytes, and a test asserting only
// presence passed it.
func assertStoredValue(t *testing.T, v *broker.Vault, ref, want string) {
	t.Helper()
	got, _, err := v.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("stored %s could not be resolved: %v", ref, err)
	}
	if string(got) != want {
		allZero := len(got) > 0
		for _, b := range got {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatalf("%s stored %d ZERO bytes — the plaintext buffer was wiped before the write", ref, len(got))
		}
		t.Fatalf("%s stored %q, want %q", ref, got, want)
	}
}

// TestAddOfANewRefStillCreatesEvenWithOverwrite: routing overwrite through the
// rotate path must not break the plain create case, where the ref does not exist
// yet and rotation would (correctly) refuse.
func TestAddOfANewRefStillCreatesEvenWithOverwrite(t *testing.T) {
	h, v := newSecretsTestDaemon(t)
	body := `{"ref":"brand-new","value_b64":"` + b64("v") + `","overwrite":true}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating a new ref with overwrite=true = %d: %s", rec.Code, rec.Body.String())
	}
	metas, _ := v.List(context.Background())
	var found bool
	for _, m := range metas {
		if m.Ref == "brand-new" {
			found = true
		}
	}
	if !found {
		t.Fatal("the new ref was not created")
	}
	// The value is the point. `secrets add <new-ref> --overwrite` is the standard
	// idempotent automation pattern, and it silently stored an all-zero credential
	// that failed only at the next resolve.
	assertStoredValue(t, v, "brand-new", "v")
}

// TestConcurrentAddWithOverwriteAllSucceed: two --overwrite requests racing on a
// fresh ref must both succeed. The rotate-then-create composition let one lose to
// ErrExists, which the single atomic upsert cannot do.
func TestConcurrentAddWithOverwriteAllSucceed(t *testing.T) {
	h, v := newSecretsTestDaemon(t)
	const n = 16
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := `{"ref":"racy","value_b64":"` + b64("racy-value") + `","overwrite":true}`
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(body)))
			codes <- rec.Code
		}()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("a concurrent --overwrite got %d; every explicit overwrite must succeed", code)
		}
	}
	assertStoredValue(t, v, "racy", "racy-value")
}

// TestOversizedRequestBodyIsRefused pins F12. Nothing bounded a value, and every
// write rewrites the ENTIRE vault file under the global mutex (OpenVault reads it
// whole at startup), so one oversized value permanently slows every later
// credential injection.
func TestOversizedRequestBodyIsRefused(t *testing.T) {
	h, v := newSecretsTestDaemon(t)
	huge := b64(strings.Repeat("x", 2<<20)) // ~2 MiB raw, larger once base64'd
	body := `{"ref":"huge","value_b64":"` + huge + `"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an oversized body = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	metas, _ := v.List(context.Background())
	for _, m := range metas {
		if m.Ref == "huge" {
			t.Fatal("the oversized secret was stored anyway")
		}
	}

	// A chunked body (ContentLength = -1) must be bounded too, or the check is
	// trivially evaded by omitting Content-Length.
	req := httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(body))
	req.ContentLength = -1
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("an oversized CHUNKED body = %d, want 400: %s", rec2.Code, rec2.Body.String())
	}
}

// TestNormalSizedSecretsStillAccepted keeps the bound from being a bug: real
// credentials (SSH keys, kubeconfigs, service-account JSON) are kilobytes.
func TestNormalSizedSecretsStillAccepted(t *testing.T) {
	h, _ := newSecretsTestDaemon(t)
	body := `{"ref":"ssh-key","value_b64":"` + b64(strings.Repeat("k", 8192)) + `"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("an 8 KiB credential = %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

// TestBodyBoundsArePerRoute pins N3. A single flat bound on the shared decoder
// silently broke every workspace upload over ~768 KiB — `workspace sync`, the
// F7.3/F7.4 linked-directory sync engine and the MCP upload tool each passed
// their own 64 MiB check and were then refused downstream by a limit none of them
// advertised. The tight bound belongs on the secret routes only.
func TestBodyBoundsArePerRoute(t *testing.T) {
	// The secret bound must be far tighter than the general one, and the general
	// one must accommodate the largest file the API says it accepts.
	if maxSecretBody >= maxRequestBody {
		t.Fatalf("maxSecretBody (%d) must be tighter than maxRequestBody (%d)", maxSecretBody, maxRequestBody)
	}
	// base64 expands 4/3, so the general bound must clear that for a full-size file
	// or uploads fail at a limit no caller was told about.
	needed := int64(session.MaxFileBytes) * 4 / 3
	if maxRequestBody < needed {
		t.Fatalf("maxRequestBody (%d) is below the base64-expanded size of session.MaxFileBytes (%d): uploads the API advertises would be refused",
			maxRequestBody, needed)
	}
}

// TestSecretRoutesRejectOversizedButUploadRouteDoesNot is the behavioural half:
// the same body size must be refused as a secret and accepted by the decoder used
// for file uploads.
func TestSecretRoutesRejectOversizedButUploadRouteDoesNot(t *testing.T) {
	h, _ := newSecretsTestDaemon(t)
	// ~2 MiB raw -> ~2.7 MiB of JSON: over the secret bound, well under the general one.
	body := `{"ref":"big","value_b64":"` + b64(strings.Repeat("x", 2<<20)) + `"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a 2 MiB secret = %d, want 400 (secrets are kilobytes)", rec.Code)
	}

	// The SAME body must get past the general decoder. Decoding directly is the
	// honest check here: it isolates the bound from the upload route's own
	// session/path validation, which is what this test is not about.
	req := httptest.NewRequest(http.MethodPut, "/v1/sessions/s1/files", strings.NewReader(body))
	var into struct {
		Ref      string `json:"ref"`
		ValueB64 string `json:"value_b64"`
	}
	if err := decodeJSON(req, &into); err != nil {
		t.Fatalf("the general bound refused a %d-byte body that the file routes must accept: %v", len(body), err)
	}
	if len(into.ValueB64) == 0 {
		t.Fatal("the body did not decode")
	}
}

// TestUnknownFieldsAreStillRejected pins DisallowUnknownFields, which the
// per-route refactor could have dropped. It is load-bearing: a request with a
// misspelled field must be a legible 400, not a silently-ignored value — and a
// rotate body carrying a stray "ref" field 400ing is what once made a leak test
// vacuous without anyone noticing.
func TestUnknownFieldsAreStillRejected(t *testing.T) {
	h, _ := newSecretsTestDaemon(t)
	for _, tc := range []struct{ name, method, path, body string }{
		{"add", http.MethodPost, "/v1/secrets", `{"ref":"x","value_b64":"` + b64("v") + `","typoed":1}`},
		{"rotate", http.MethodPut, "/v1/secrets/gitlab-token", `{"value_b64":"` + b64("v") + `","ref":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("an unknown field = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "unknown field") {
				t.Errorf("the 400 must name the problem: %s", rec.Body.String())
			}
		})
	}
}

// TestRotateFallbackIsNotFedBySecurityRefusals pins N7. The add handler treats an
// ErrNotFound from the upsert path as "this is a create". Nothing pinned that it
// is ErrNotFound-ONLY, so a rotation refused for a SECURITY reason — a
// non-atomic backend, a control-char provider — would have fallen through to a
// plain create, converting a refusal into a write.
func TestRotateFallbackIsNotFedBySecurityRefusals(t *testing.T) {
	h, v := newSecretsTestDaemon(t)
	// A control character in the provider is refused by the write path. The
	// request must FAIL, not quietly land as a create.
	body := `{"ref":"sneaky","value_b64":"` + b64("v") + `","provider":"x\nforged","overwrite":true}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(body)))
	if rec.Code == http.StatusCreated || rec.Code == http.StatusOK {
		t.Fatalf("a refused write returned %d — a security refusal must not become a create", rec.Code)
	}
	metas, _ := v.List(context.Background())
	for _, m := range metas {
		if m.Ref == "sneaky" {
			t.Fatal("a refused write created the ref anyway")
		}
	}
}

// TestListRouteFailsClosedWhenConsumersUnknowable pins N8. `List` swallowing the
// index error made `secrets consumers` report in_use:false for EVERY secret while
// grants existed — an information-path fail-open, which is worse than a hard
// error because the operator reads "nothing uses this" and reaches for --force.
func TestListRouteFailsClosedWhenConsumersUnknowable(t *testing.T) {
	key := make([]byte, 32)
	v, err := broker.OpenVault(t.TempDir()+"/vault.db", broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if err := v.Put(context.Background(), "gitlab-token", []byte("v"), broker.PutMeta{}, false); err != nil {
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
	d.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/secrets/consumers", nil))

	if rec.Code == http.StatusOK {
		if strings.Contains(rec.Body.String(), `"in_use":false`) {
			t.Fatal("the listing reported in_use:false while the consumer index was erroring — an operator would read that as 'safe to delete'")
		}
		t.Fatalf("the consumers listing must not return 200 when consumers are unknowable: %s", rec.Body.String())
	}
}

// TestListRouteCarriesRotationHygiene pins N14: last_used and rotated_at must
// reach the PRIMARY listing verb, which is the stated reason they were added —
// answering "which credentials are stale?" from `secrets ls`.
func TestListRouteCarriesRotationHygiene(t *testing.T) {
	h, v := newSecretsTestDaemon(t)
	ctx := context.Background()
	if _, _, err := v.Get(ctx, "gitlab-token"); err != nil { // stamps LastUsed
		t.Fatalf("Get: %v", err)
	}
	if _, _, err := v.Upsert(ctx, "gitlab-token", []byte("new"), broker.PutMeta{Provider: "gitlab"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/secrets", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	for _, key := range []string{"last_used", "rotated_at"} {
		if !strings.Contains(rec.Body.String(), key) {
			t.Errorf("GET /v1/secrets omits %q — the primary listing verb still cannot answer 'which credentials are stale?': %s",
				key, rec.Body.String())
		}
	}
	if enc, bad := leaks(rec.Body.String(), secretCanary); bad {
		t.Fatalf("the listing leaked the value as %s", enc)
	}
}

// needsQueryForm reports a ref that cannot survive URL path normalisation, and
// therefore cannot be addressed as a path segment at all: ServeMux cleans the
// path before routing and 307-redirects. A "." or ".." segment, a leading slash
// and an empty interior segment are all rewritten. Such a ref is exactly why the
// query form exists.
func needsQueryForm(ref string) bool {
	if strings.HasPrefix(ref, "/") || strings.Contains(ref, "//") {
		return true
	}
	for _, seg := range strings.Split(ref, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// TestDeleteRouteRemovesALegacyRef pins N5 at the ROUTE, where the lockout lived.
// A secret stored under an earlier, looser ref rule must stay removable: the
// route re-applying the current rule made such a secret listed, live, resolvable
// and permanently un-deletable — removable only by hand-editing an encrypted
// vault file. Enforcement belongs on the write path, not on delete.
func TestDeleteRouteRemovesALegacyRef(t *testing.T) {
	for _, legacy := range []string{"trail/", "/etc/passwd", "./tok", "a//b", "x/../y"} {
		t.Run(legacy, func(t *testing.T) {
			key := make([]byte, 32)
			path := t.TempDir() + "/vault.db"
			v, err := broker.OpenVault(path, broker.StaticKeySource(key))
			if err != nil {
				t.Fatalf("OpenVault: %v", err)
			}
			// The write path must refuse the shape...
			if err := v.Put(context.Background(), legacy, []byte("v"), broker.PutMeta{}, false); err == nil {
				t.Fatalf("the write path must refuse %q", legacy)
			}
			// ...but one already on disk must be deletable through the API.
			broker.PlantLegacyRefForTest(t, v, legacy)
			d, err := New(Options{
				Secrets:    v,
				SecretsSvc: broker.NewSecretsService(v, broker.NewConsumerIndex()),
				Verifier:   okVerifier(),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			// The path form when the ref can be expressed as a path, and the
			// query form when it cannot — a "." or ".." segment is normalised away
			// by ServeMux before routing, so such a ref is unreachable by path.
			target := "/v1/secrets/" + legacy
			if needsQueryForm(legacy) {
				target = "/v1/secrets?ref=" + url.QueryEscape(legacy)
			}
			rec := httptest.NewRecorder()
			d.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, target, nil))
			if rec.Code != http.StatusNoContent {
				t.Fatalf("DELETE of legacy ref %q via %s = %d, want 204: %s", legacy, target, rec.Code, rec.Body.String())
			}
			metas, _ := v.List(context.Background())
			for _, m := range metas {
				if m.Ref == legacy {
					t.Fatal("the legacy ref survived deletion")
				}
			}
		})
	}
}

// TestDeleteByQueryIsGuardedIdentically: the path-free form changes how the ref
// is transported, not what is permitted. If it were unguarded it would be a
// trivial bypass of the whole in-use guard.
func TestDeleteByQueryIsGuardedIdentically(t *testing.T) {
	h, v := newSecretsTestDaemon(t)
	// gitlab-token is in use by an egress-inject rule in this fixture.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/secrets?ref=gitlab-token", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("DELETE ?ref= of an in-use secret = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if metas, _ := v.List(context.Background()); len(metas) != 1 {
		t.Fatal("the refused delete removed the secret anyway")
	}
	// force must behave the same way as on the path form.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/secrets?ref=gitlab-token&force=true", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE ?ref=&force=true = %d, want 204: %s", rec.Code, rec.Body.String())
	}
}

// TestDeleteByQueryRequiresARef: without one it must be a legible 400, never a
// wildcard delete.
func TestDeleteByQueryRequiresARef(t *testing.T) {
	h, v := newSecretsTestDaemon(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/secrets", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("DELETE /v1/secrets with no ref = %d, want 400", rec.Code)
	}
	if metas, _ := v.List(context.Background()); len(metas) != 1 {
		t.Fatal("a ref-less delete removed secrets")
	}
}

// TestAddResponseDescribesTheStoredRecord pins N9. The 201 echoed the REQUEST, so
// every add reported created_at of year 1, and an --overwrite echoed the caller's
// (often empty) provider while the stored record carried the previous values
// forward. A response that describes the request rather than the record is a
// quiet lie an operator has no way to check.
func TestAddResponseDescribesTheStoredRecord(t *testing.T) {
	h, _ := newSecretsTestDaemon(t)
	body := `{"ref":"fresh","value_b64":"` + b64("v") + `","provider":"azure","scope":"tripon/prod","ttl":"1h"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("add = %d: %s", rec.Code, rec.Body.String())
	}
	var got secretMetaResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.CreatedAt.IsZero() || got.CreatedAt.Year() < 2000 {
		t.Errorf("created_at = %v — the response echoed the request instead of the stored record", got.CreatedAt)
	}
	if got.Ref != "fresh" || got.Provider != "azure" || got.Scope != "tripon/prod" || got.TTL != "1h" {
		t.Errorf("response = %+v, want the stored metadata", got)
	}
}

// TestOverwriteResponseCarriesForwardMetadata: an --overwrite that restates
// nothing must report the metadata the record actually kept, not the empty
// request fields.
func TestOverwriteResponseCarriesForwardMetadata(t *testing.T) {
	h, _ := newSecretsTestDaemon(t)
	// gitlab-token exists with provider "gitlab". Overwrite it restating nothing.
	body := `{"ref":"gitlab-token","value_b64":"` + b64("new") + `","overwrite":true}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("overwrite = %d: %s", rec.Code, rec.Body.String())
	}
	var got secretMetaResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Provider != "gitlab" {
		t.Errorf("provider = %q, want the carried-forward %q", got.Provider, "gitlab")
	}
	if got.RotatedAt == nil {
		t.Error("an overwrite of an existing ref must report rotated_at")
	}
	if got.CreatedAt.IsZero() || got.CreatedAt.Year() < 2000 {
		t.Errorf("created_at = %v — it must be the ORIGINAL creation time", got.CreatedAt)
	}
}
