package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/install"
)

// okVerifier passes verify-before-serve.
func okVerifier() ToolchainVerifier {
	return VerifierFunc(func(context.Context) error { return nil })
}

// newIdentity writes a real 0600 Ed25519 key into a temp dir and returns its
// path. Reuses F0.1's GenerateIdentity so tests exercise the real key format.
func newIdentity(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")
	if _, err := install.GenerateIdentity(keyPath); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return keyPath
}

// baseOptions returns Options wired for a non-root, tool-free unit test: temp
// socket, no socket group (skips chown), passing verifier, injected runtime
// probe, and a real identity key.
func baseOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		Config:          install.Config{Tier: "local-hardened"},
		SocketPath:      filepath.Join(t.TempDir(), "opslifyd.sock"),
		SocketGroup:     "",
		IdentityKeyPath: newIdentity(t),
		Verifier:        okVerifier(),
		RuntimeProbe:    func() error { return nil }, // pretend gVisor present
		Version:         "test",
	}
}

func TestNewRequiresVerifier(t *testing.T) {
	_, err := New(Options{IdentityKeyPath: newIdentity(t)})
	if err == nil {
		t.Fatal("expected New to reject a nil verifier (verify-before-serve non-optional)")
	}
}

func TestStartupIdentityMissing(t *testing.T) {
	opts := baseOptions(t)
	opts.IdentityKeyPath = filepath.Join(t.TempDir(), "absent.key")
	d, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.Startup(context.Background()); err == nil {
		t.Fatal("expected Startup to fail fast on a missing identity key")
	}
}

func TestStartupIdentityBadPerms(t *testing.T) {
	opts := baseOptions(t)
	// Loosen the key to 0644 — must be rejected.
	if err := os.Chmod(opts.IdentityKeyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	d, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = d.Startup(context.Background())
	if !errors.Is(err, install.ErrIdentityKeyPerms) {
		t.Fatalf("expected ErrIdentityKeyPerms, got %v", err)
	}
}

func TestStartupVerifyRefusal(t *testing.T) {
	opts := baseOptions(t)
	sentinel := errors.New("tampered digest")
	opts.Verifier = VerifierFunc(func(context.Context) error { return sentinel })
	d, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.Startup(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("expected verify-before-serve refusal, got %v", err)
	}
}

func TestStartupSucceeds(t *testing.T) {
	d, err := New(baseOptions(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.Startup(context.Background()); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if d.identity == "" {
		t.Fatal("expected identity fingerprint recorded after startup")
	}
}

// TestRunLifecycle exercises the full path: startup gates, socket creation with
// 0660 perms, a live GET /v1/health over the Unix socket, and graceful shutdown
// on context cancel with the socket unlinked afterwards.
func TestRunLifecycle(t *testing.T) {
	opts := baseOptions(t)
	d, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ready := make(chan struct{})
	d.ready = func() { close(ready) }

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("daemon never signalled ready")
	}

	// Socket perms are the trust boundary — assert exactly 0660.
	info, err := os.Stat(opts.SocketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != SocketPerm {
		t.Fatalf("socket perms = %#o, want %#o", perm, SocketPerm)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatal("socket path is not a socket")
	}

	client := unixClient(opts.SocketPath)
	resp, err := client.Get("http://unix/v1/health")
	if err != nil {
		t.Fatalf("GET /v1/health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200", resp.StatusCode)
	}
	var h Health
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if h.Status != "ok" {
		t.Fatalf("health status field = %q", h.Status)
	}
	if !h.Runtime.Available {
		t.Fatalf("runtime should be available (injected probe returns nil): %+v", h.Runtime)
	}
	if h.Runtime.Tier != "local-hardened" {
		t.Fatalf("runtime tier = %q, want local-hardened", h.Runtime.Tier)
	}
	if h.Identity == "" {
		t.Fatal("health should surface the public identity fingerprint")
	}

	// Graceful shutdown.
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not shut down within grace period")
	}
	// No orphaned socket after a clean shutdown.
	if _, err := os.Stat(opts.SocketPath); !os.IsNotExist(err) {
		t.Fatalf("socket not unlinked after shutdown: err=%v", err)
	}
}

// TestHealthRuntimeUnavailable proves the legible-detail path when the runtime
// probe reports the OCI runtime is absent (gVisor not installed).
func TestHealthRuntimeUnavailable(t *testing.T) {
	opts := baseOptions(t)
	opts.RuntimeProbe = func() error { return errors.New("runtime: OCI runtime \"runsc\" unavailable") }
	d, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := doHealth(t, d)
	if rec.Runtime.Available {
		t.Fatal("runtime should report unavailable")
	}
	if rec.Runtime.Detail == "" {
		t.Fatal("expected a legible detail when runtime unavailable")
	}
}

// unixClient returns an http.Client that dials the given Unix socket.
func unixClient(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 3 * time.Second,
	}
}

// doHealth calls the health handler via httptest-free in-process request.
func doHealth(t *testing.T, d *Daemon) Health {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := &recorder{header: http.Header{}}
	d.Handler().ServeHTTP(rr, req)
	var h Health
	if err := json.Unmarshal(rr.body, &h); err != nil {
		t.Fatalf("decode health: %v (body=%s)", err, rr.body)
	}
	return h
}

// recorder is a minimal http.ResponseWriter capturing the body.
type recorder struct {
	header http.Header
	body   []byte
	status int
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) WriteHeader(s int)   { r.status = s }
func (r *recorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	return len(b), nil
}

var _ io.Writer = (*recorder)(nil)
