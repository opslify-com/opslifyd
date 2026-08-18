package session

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

const awsSecretMarker = "FAKE-SECRETACCESSKEY-crownjewel-do-not-leak"

func awsCredDoc(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"AccessKeyId":     "AKIAFAKE",
		"SecretAccessKey": awsSecretMarker,
		"Token":           "FAKE-session-token",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// managerWithInjection wires a Manager with a broker + F5.1 injector over a live
// creds endpoint, a daemon default policy granting grants, and a SINGLE shared
// fake runtime (so a test can inspect the exec env the manager built). Returns the
// manager, the vault, the runtime, and the endpoint base URL.
func managerWithInjection(t *testing.T, grants []policy.Cred) (*Manager, *broker.Vault, *fakeRuntime, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	v, err := broker.OpenVault(path, broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	brk := broker.NewBroker(v)
	now := func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }
	server := broker.NewCredServer(now)
	ts := httptest.NewServer(http.HandlerFunc(server.ServeHTTP))
	t.Cleanup(ts.Close)
	injector := broker.NewInjector(brk, server, ts.URL, 15*time.Minute, now)

	rt := newFakeRuntime()
	m, err := NewManager(Options{
		Config: ManagerConfig{
			Image:         "base@sha256:deadbeef",
			WorkspaceRoot: t.TempDir(),
			DefaultTier:   runtime.TierLocalHardened,
			DefaultTTL:    30 * time.Minute,
			Limits:        runtime.ResourceLimits{MemoryBytes: 2 << 30, CPUs: 2, PidsLimit: 256},
			DefaultPolicy: policy.Policy{Creds: grants},
		},
		Resolve:      func(runtime.Tier, runtime.Location) (runtime.Runtime, error) { return rt, nil },
		Clock:        newFakeClock(time.Unix(0, 0)),
		Store:        newMemStore(),
		Trace:        trace.NewMemSink(nil),
		Broker:       brk,
		CredInjector: injector,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, v, rt, ts.URL
}

// TestExecInjectsAWSEndpointNoRawSecret is the F5.1 end-to-end acceptance: a
// granted AWS cred makes every exec carry the container-credentials endpoint URI +
// a per-session token, and the container ExecRequest.Env contains NO raw secret.
func TestExecInjectsAWSEndpointNoRawSecret(t *testing.T) {
	ctx := context.Background()
	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	m, v, rt, base := managerWithInjection(t, grants)
	if err := v.Put(ctx, "aws/deploy", awsCredDoc(t), broker.PutMeta{Provider: "aws"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"aws", "s3", "ls"}, Env: []string{"HOME=/root"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	env := rt.lastExecEnv()
	joined := strings.Join(env, "\n")

	// Adversarial: the raw durable secret must be NOWHERE in the container env.
	if strings.Contains(joined, awsSecretMarker) {
		t.Fatalf("SECURITY: raw AWS secret leaked into container env: %q", joined)
	}
	if !strings.Contains(joined, "AWS_CONTAINER_CREDENTIALS_FULL_URI="+base+broker.CredPath+s.ID) {
		t.Fatalf("missing container-credentials endpoint in env: %q", joined)
	}
	if !strings.Contains(joined, "AWS_CONTAINER_CREDENTIALS_TOKEN=") {
		t.Fatalf("missing per-session token in env: %q", joined)
	}
	// Caller env is preserved alongside the injection.
	if !strings.Contains(joined, "HOME=/root") {
		t.Fatalf("caller env dropped: %q", joined)
	}
}

// TestExecNoInjectionWithoutGrant proves deny-by-default at the session level: with
// no creds grant, no credential env is injected into the exec.
func TestExecNoInjectionWithoutGrant(t *testing.T) {
	ctx := context.Background()
	m, v, rt, _ := managerWithInjection(t, nil) // no grants
	_ = v.Put(ctx, "aws/deploy", awsCredDoc(t), broker.PutMeta{Provider: "aws"}, false)
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"ls"}, Env: []string{"HOME=/root"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	env := rt.lastExecEnv()
	for _, e := range env {
		if strings.HasPrefix(e, "AWS_CONTAINER_CREDENTIALS_") {
			t.Fatalf("SECURITY: credential injected without a grant: %q", env)
		}
	}
}

// TestInjectedCredRevokedOnTeardown proves the per-session endpoint token stops
// working once the session is destroyed.
func TestInjectedCredRevokedOnTeardown(t *testing.T) {
	ctx := context.Background()
	grants := []policy.Cred{{Name: "aws/deploy", Provider: "aws"}}
	m, v, rt, _ := managerWithInjection(t, grants)
	_ = v.Put(ctx, "aws/deploy", awsCredDoc(t), broker.PutMeta{Provider: "aws"}, false)
	s, err := m.Create(ctx, CreateRequest{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Exec(ctx, s.ID, ExecOptions{Argv: []string{"aws", "s3", "ls"}}, newCaptureSink()); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	env := rt.lastExecEnv()
	uri := credEnvVal(env, "AWS_CONTAINER_CREDENTIALS_FULL_URI")
	token := credEnvVal(env, "AWS_CONTAINER_CREDENTIALS_TOKEN")

	req, _ := http.NewRequest(http.MethodGet, uri, nil)
	req.Header.Set("Authorization", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pre-destroy fetch: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-destroy code %d", resp.StatusCode)
	}

	if err := m.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	req2, _ := http.NewRequest(http.MethodGet, uri, nil)
	req2.Header.Set("Authorization", token)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("post-destroy fetch: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("post-destroy code %d, want 403 (token should be revoked)", resp2.StatusCode)
	}
}

func credEnvVal(env []string, key string) string {
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			return v
		}
	}
	return ""
}
