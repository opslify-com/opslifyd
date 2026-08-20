package regproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// --- test scaffolding -------------------------------------------------------

// recorderCapture wires a Recorder over a MemSink, seeded with a session.start so
// the chain has a binding root (mirrors the broker/trace test helpers).
func recorderCapture(t *testing.T) (*trace.Recorder, *trace.MemSink) {
	t.Helper()
	sink := trace.NewMemSink(nil)
	rec := trace.NewRecorder(sink, "sess-1", nil, nil)
	if err := rec.Emit(context.Background(), trace.TypeSessionStart, map[string]any{
		"image_digest": "sha256:test", "policy_hash": "h",
	}); err != nil {
		t.Fatalf("seed session.start: %v", err)
	}
	return rec, sink
}

func installEvents(t *testing.T, sink *trace.MemSink) []trace.Event {
	t.Helper()
	events, _, ok := sink.Export("sess-1")
	if !ok {
		t.Fatal("no events exported")
	}
	var out []trace.Event
	for _, e := range events {
		if e.Type == trace.TypePkgInstall {
			out = append(out, e)
		}
	}
	return out
}

// brokerWithSecret builds a broker over a fresh vault holding a fake private-
// registry token under ref, granted to the session.
func brokerWithSecret(t *testing.T, ref, token string) (*broker.Broker, []policy.Cred) {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	v, err := broker.OpenVault(dir+"/vault.db", broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if err := v.Put(context.Background(), ref, []byte(token), broker.PutMeta{Provider: "registry"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return broker.NewBroker(v), []policy.Cred{{Name: ref}}
}

// --- checksum-safe fetch + private-registry auth (AC1, QA1) -----------------

// TestFetchServesUpstreamBytesUnchanged proves the CHECKSUM-SAFE core: the served
// artifact bytes are byte-for-byte the upstream bytes (hash equal), so the
// client's own checksum/signature verification is intact, AND the private-registry
// credential is injected ONLY on the proxy->upstream request (asserted on the stub)
// — never sent by / visible to the client.
func TestFetchServesUpstreamBytesUnchanged(t *testing.T) {
	artifact := []byte("FAKE-WHEEL-BYTES-\x00\x01\x02-checksum-verifiable")
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(artifact)
	}))
	defer upstream.Close()

	brk, grants := brokerWithSecret(t, "pypi/token", "FAKE-registry-token")
	rec, sink := recorderCapture(t)
	p := newProxy(t, Config{
		CacheDir: t.TempDir(),
		Upstreams: []Upstream{{
			Ecosystem: EcosystemPyPI, BaseURL: upstream.URL,
			CredRef: "pypi/token", HeaderFormat: "Bearer %s",
		}},
		Allow: []AllowEntry{{Ecosystem: EcosystemPyPI, Name: "requests"}},
	}, brk, grants, rec, nil)

	// Drive it through the real HTTP handler (the sandbox-facing surface): plain
	// HTTP, NO MITM. The client sends no auth header.
	client := httptest.NewServer(p)
	defer client.Close()
	resp, err := http.Get(client.URL + "/pypi/packages/aa/requests-2.31.0-py3-none-any.whl")
	if err != nil {
		t.Fatalf("client GET: %v", err)
	}
	served, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Checksum-safety: served == upstream, hashes equal.
	if sha256.Sum256(served) != sha256.Sum256(artifact) {
		t.Fatalf("served bytes differ from upstream bytes (checksum verification would BREAK)")
	}
	// Auth was injected on the upstream leg only.
	if gotAuth != "Bearer FAKE-registry-token" {
		t.Fatalf("upstream did not receive injected credential, got %q", gotAuth)
	}
	// The credential must NOT appear in the served response.
	if strings.Contains(string(served), "FAKE-registry-token") {
		t.Fatal("credential leaked into the served artifact")
	}
	// A pkg.install event was emitted with the sha256 of the REAL bytes; no cred.
	assertInstallEvent(t, sink, "pypi", "requests", "2.31.0", artifact)
}

func TestNpmAndGoFlowThrough(t *testing.T) {
	cases := []struct {
		name    string
		eco     Ecosystem
		allow   string
		path    string
		wantVer string
		wantPkg string
	}{
		{"npm", EcosystemNPM, "left-pad", "/npm/left-pad/-/left-pad-1.3.0.tgz", "1.3.0", "left-pad"},
		{"go", EcosystemGo, "golang.org/x/text", "/go/golang.org/x/text/@v/v0.14.0.zip", "v0.14.0", "golang.org/x/text"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			artifact := []byte("FAKE-" + tc.name + "-artifact-bytes")
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(artifact)
			}))
			defer upstream.Close()
			rec, sink := recorderCapture(t)
			p := newProxy(t, Config{
				CacheDir:  t.TempDir(),
				Upstreams: []Upstream{{Ecosystem: tc.eco, BaseURL: upstream.URL}},
				Allow:     []AllowEntry{{Ecosystem: tc.eco, Name: tc.allow}},
			}, nil, nil, rec, nil)
			got, _, err := p.Fetch(context.Background(), tc.path)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if sha256.Sum256(got) != sha256.Sum256(artifact) {
				t.Fatal("served bytes differ from upstream")
			}
			assertInstallEvent(t, sink, string(tc.eco), tc.wantPkg, tc.wantVer, artifact)
		})
	}
}

// --- allowlist fail-closed (AC2, QA2) ---------------------------------------

func TestUnallowlistedPackageRefused(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		_, _ = w.Write([]byte("evil"))
	}))
	defer upstream.Close()
	p := newProxy(t, Config{
		CacheDir:  t.TempDir(),
		Upstreams: []Upstream{{Ecosystem: EcosystemPyPI, BaseURL: upstream.URL}},
		Allow:     []AllowEntry{{Ecosystem: EcosystemPyPI, Name: "requests"}},
	}, nil, nil, nil, nil)

	_, _, err := p.Fetch(context.Background(), "/pypi/packages/aa/evilpkg-1.0.0-py3-none-any.whl")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if hit {
		t.Fatal("un-allowlisted fetch reached upstream (should be refused BEFORE any fetch)")
	}
}

func TestUnknownEcosystemAndEmptyAllowlistDeny(t *testing.T) {
	p := newProxy(t, Config{
		CacheDir:  t.TempDir(),
		Upstreams: []Upstream{{Ecosystem: EcosystemPyPI, BaseURL: "https://pypi.org"}},
		// empty allowlist => nothing resolves
	}, nil, nil, nil, nil)
	if _, _, err := p.Fetch(context.Background(), "/pypi/simple/requests/"); !errors.Is(err, ErrDenied) {
		t.Fatalf("empty allowlist should deny, got %v", err)
	}
	if _, _, err := p.Fetch(context.Background(), "/cargo/foo"); err == nil {
		t.Fatal("unknown ecosystem should error")
	}
}

// --- attestation seam (AC4, QA2) --------------------------------------------

func TestAttestationFailClosed(t *testing.T) {
	artifact := []byte("FAKE-artifact")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer upstream.Close()
	cfg := Config{
		CacheDir:  t.TempDir(),
		Upstreams: []Upstream{{Ecosystem: EcosystemPyPI, BaseURL: upstream.URL, RequireAttestation: true}},
		Allow:     []AllowEntry{{Ecosystem: EcosystemPyPI, Name: "requests"}},
	}
	path := "/pypi/packages/aa/requests-2.31.0-py3-none-any.whl"

	// Unattested + RequireAttestation => refused.
	ver := NewStubVerifier()
	p := newProxy(t, cfg, nil, nil, nil, ver)
	if _, _, err := p.Fetch(context.Background(), path); !errors.Is(err, ErrUnattested) {
		t.Fatalf("unattested package should be refused, got %v", err)
	}

	// Nil verifier + RequireAttestation => refused (fail-closed).
	pNil := newProxy(t, cfg, nil, nil, nil, nil)
	if _, _, err := pNil.Fetch(context.Background(), path); !errors.Is(err, ErrUnattested) {
		t.Fatalf("nil verifier should refuse a require-attestation upstream, got %v", err)
	}

	// Stub-attested => passes.
	ver.Attest(EcosystemPyPI, "requests", "2.31.0")
	pOK := newProxy(t, cfg, nil, nil, nil, ver)
	got, _, err := pOK.Fetch(context.Background(), path)
	if err != nil {
		t.Fatalf("attested package should pass: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(artifact) {
		t.Fatal("served bytes differ from upstream")
	}
}

// --- credential never leaks to trace/log (AC5, QA4) -------------------------

func TestCredentialNeverInTrace(t *testing.T) {
	token := "FAKE-super-secret-registry-token"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("artifact"))
	}))
	defer upstream.Close()
	brk, grants := brokerWithSecret(t, "npm/token", token)
	rec, sink := recorderCapture(t)
	p := newProxy(t, Config{
		CacheDir:  t.TempDir(),
		Upstreams: []Upstream{{Ecosystem: EcosystemNPM, BaseURL: upstream.URL, CredRef: "npm/token", HeaderFormat: "Bearer %s"}},
		Allow:     []AllowEntry{{Ecosystem: EcosystemNPM, Name: "left-pad"}},
	}, brk, grants, rec, nil)
	if _, _, err := p.Fetch(context.Background(), "/npm/left-pad/-/left-pad-1.3.0.tgz"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	events, _, _ := sink.Export("sess-1")
	blob, _ := json.Marshal(events)
	if strings.Contains(string(blob), token) {
		t.Fatal("credential leaked into the trace event stream")
	}
}

// --- pkg.install chained + hash accurate (AC3, QA3) -------------------------

func TestInstallEventChained(t *testing.T) {
	artifact := []byte("FAKE-chained-artifact")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer upstream.Close()
	rec, sink := recorderCapture(t)
	p := newProxy(t, Config{
		CacheDir:  t.TempDir(),
		Upstreams: []Upstream{{Ecosystem: EcosystemPyPI, BaseURL: upstream.URL}},
		Allow:     []AllowEntry{{Ecosystem: EcosystemPyPI, Name: "requests"}},
	}, nil, nil, rec, nil)
	if _, _, err := p.Fetch(context.Background(), "/pypi/packages/aa/requests-2.31.0-py3-none-any.whl"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	events, _, _ := sink.Export("sess-1")
	// The whole chain (session.start + pkg.install) must verify structurally.
	if res := trace.Verify(events, nil, nil); !res.OK {
		t.Fatalf("chain does not verify: %s", res.Reason)
	}
	ev := installEvents(t, sink)
	if len(ev) != 1 {
		t.Fatalf("want 1 pkg.install, got %d", len(ev))
	}
}

// --- helpers ----------------------------------------------------------------

func newProxy(t *testing.T, cfg Config, brk *broker.Broker, grants []policy.Cred, rec *trace.Recorder, ver AttestationVerifier) *Proxy {
	t.Helper()
	p, err := NewProxy(Options{
		SessionID: "sess-1", Config: cfg, Broker: brk, Grants: grants,
		Recorder: rec, Verifier: ver,
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	return p
}

func assertInstallEvent(t *testing.T, sink *trace.MemSink, eco, name, version string, artifact []byte) {
	t.Helper()
	ev := installEvents(t, sink)
	if len(ev) != 1 {
		t.Fatalf("want 1 pkg.install event, got %d", len(ev))
	}
	p := ev[0].Payload
	if p["ecosystem"] != eco || p["name"] != name || p["version"] != version {
		t.Fatalf("event fields wrong: %v", p)
	}
	want := hex.EncodeToString(sliceHash(artifact))
	if p["sha256"] != want {
		t.Fatalf("sha256 mismatch: event=%v want=%s (must be hash of REAL bytes)", p["sha256"], want)
	}
}

func sliceHash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
