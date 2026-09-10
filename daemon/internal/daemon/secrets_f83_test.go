package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
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
			if enc, bad := leaks(rec.Body.String(), secretCanary); bad {
				t.Fatalf("%s %s returned the secret VALUE as %s: %s", tc.method, tc.path, enc, rec.Body.String())
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
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST overwrite = %d: %s", rec.Code, rec.Body.String())
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
