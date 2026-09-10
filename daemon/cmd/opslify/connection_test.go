package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/daemon"
)

// newConnectionDaemon serves the REAL daemon connection routes over a real
// ConnectionService and store, so these tests exercise the whole path — CLI flag
// parsing, wire shape, handler, service, store — rather than a stub of it.
func newConnectionDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	store, err := broker.NewConnectionStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewConnectionStore: %v", err)
	}
	svc, err := broker.NewConnectionService(store, broker.DefaultRegistry(nil), nil)
	if err != nil {
		t.Fatalf("NewConnectionService: %v", err)
	}
	d, err := daemon.New(daemon.Options{Connections: svc, Verifier: daemon.VerifierFunc(func(context.Context) error { return nil })})
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	return newFakeDaemon(t, d.Handler())
}

// TestConnectionAddLsRmRoundTrip drives the documented workflow end to end.
func TestConnectionAddLsRmRoundTrip(t *testing.T) {
	fd := newConnectionDaemon(t)

	out, errb, err := runCLI(t, "", "connection", "add", "gitlab",
		"--kind", "http", "--secret", "gitlab-token", "--host", "gitlab.example.com",
		"--config", "header_name=PRIVATE-TOKEN", "--project", "tripon", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("add: %v (%s)", err, errb)
	}
	// The operator is told what the sandbox receives — the claim is the product.
	if !strings.Contains(out, "nothing") {
		t.Errorf("add should state what the sandbox receives:\n%s", out)
	}

	out, _, err = runCLI(t, "", "connection", "ls", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	for _, want := range []string{"gitlab", "http", "tripon", "gitlab.example.com", "gitlab-token", "SECRET REF"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls output missing %q:\n%s", want, out)
		}
	}

	out, errb, err = runCLI(t, "", "connection", "rm", "gitlab", "--project", "tripon", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("rm: %v (%s)", err, errb)
	}
	// Removing a route must not imply the credential is gone.
	if !strings.Contains(errb, "secrets rm") {
		t.Errorf("rm should say the credential still exists:\n%s", errb)
	}
	out, _, _ = runCLI(t, "", "connection", "ls", "--socket", fd.socketPath)
	if !strings.Contains(out, "no connections") {
		t.Errorf("the connection survived removal:\n%s", out)
	}
}

// TestConnectionAddRefusesUnusableDefinitions: the definition is validated by
// BUILDING it, so a broken one is refused where the operator is watching rather
// than at session start.
func TestConnectionAddRefusesUnusableDefinitions(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"unknown kind", []string{"--kind", "database", "--secret", "r", "--host", "h.example.com"}},
		{"http with no host", []string{"--kind", "http", "--secret", "r"}},
		{"ssh with no destinations", []string{"--kind", "ssh", "--secret", "r", "--config", "known_hosts_path=/etc/ssh/known_hosts"}},
		{"k8s with a user-supplied server", []string{"--kind", "kubernetes", "--secret", "r", "--host", "a.example.com", "--config", "server=https://evil"}},
		{"no secret ref", []string{"--kind", "http", "--host", "h.example.com"}},
		{"ref that could forge a query", []string{"--kind", "http", "--secret", "r?force=true", "--host", "h.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd := newConnectionDaemon(t)
			args := append([]string{"connection", "add", "c"}, tc.args...)
			args = append(args, "--socket", fd.socketPath)
			if _, _, err := runCLI(t, "", args...); err == nil {
				t.Fatal("an unusable definition must be refused at add time")
			}
			out, _, _ := runCLI(t, "", "connection", "ls", "--socket", fd.socketPath)
			if !strings.Contains(out, "no connections") {
				t.Errorf("a refused add stored something:\n%s", out)
			}
		})
	}
}

// TestConnectionTestStoresNothing: `test` is for getting config right before a
// session depends on it.
func TestConnectionTestStoresNothing(t *testing.T) {
	fd := newConnectionDaemon(t)
	out, _, err := runCLI(t, "", "connection", "test", "prod-cluster",
		"--kind", "kubernetes", "--secret", "k8s-token", "--host", "api.k8s.example.com:6443",
		"--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("test: %v", err)
	}
	if !strings.Contains(out, "no credential in it") {
		t.Errorf("test should report what the sandbox receives:\n%s", out)
	}
	if !strings.Contains(out, "Nothing was stored") {
		t.Errorf("test must say nothing was stored:\n%s", out)
	}
	listed, _, _ := runCLI(t, "", "connection", "ls", "--socket", fd.socketPath)
	if !strings.Contains(listed, "no connections") {
		t.Fatalf("`connection test` stored a record:\n%s", listed)
	}
}

// TestConnectionRmNameCannotRetargetAnotherRoute: the same ref-injection class as
// F8.3. A "." or ".." segment survives percent-escaping and would land the
// request on a different handler.
func TestConnectionRmNameCannotRetargetAnotherRoute(t *testing.T) {
	for _, bad := range []string{
		"../secrets/gitlab-token?force=true",
		"../../v1/sessions/live-1",
		"..", ".", "a/../../b",
	} {
		t.Run(bad, func(t *testing.T) {
			var hit string
			mux := http.NewServeMux()
			for pattern, name := range map[string]string{
				"DELETE /v1/connections/{name}": "connections",
				"DELETE /v1/secrets/{ref...}":   "secrets",
				"DELETE /v1/sessions/{id}":      "sessions",
			} {
				resource := name
				mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
					if hit == "" {
						hit = resource + " " + r.URL.Path + "?" + r.URL.RawQuery
					}
					w.WriteHeader(http.StatusNoContent)
				})
			}
			fd := newFakeDaemon(t, mux)
			_, _, err := runCLI(t, "", "connection", "rm", bad, "--socket", fd.socketPath)
			if err == nil {
				t.Fatalf("name %q must be refused before a request is built", bad)
			}
			if hit != "" {
				t.Fatalf("SECURITY: name %q reached %s", bad, hit)
			}
		})
	}
}

// TestDuplicateConfigFlagIsRefused: which value applied would otherwise depend on
// flag order.
func TestDuplicateConfigFlagIsRefused(t *testing.T) {
	fd := newConnectionDaemon(t)
	_, _, err := runCLI(t, "", "connection", "add", "c",
		"--kind", "http", "--secret", "r", "--host", "h.example.com",
		"--config", "header_name=A", "--config", "header_name=B", "--socket", fd.socketPath)
	if err == nil {
		t.Fatal("a repeated --config key must be refused rather than silently resolved by order")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("the error should say the key was repeated: %v", err)
	}
}

// TestMalformedConfigFlagIsRefused.
func TestMalformedConfigFlagIsRefused(t *testing.T) {
	fd := newConnectionDaemon(t)
	for _, bad := range []string{"noequals", "=novalue"} {
		if _, _, err := runCLI(t, "", "connection", "add", "c",
			"--kind", "http", "--secret", "r", "--host", "h.example.com",
			"--config", bad, "--socket", fd.socketPath); err == nil {
			t.Errorf("--config %q must be refused", bad)
		}
	}
}
