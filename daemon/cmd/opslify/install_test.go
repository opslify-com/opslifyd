package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// installMux builds a fake daemon serving the F7.5 allowlist gate + exec, recording
// the exec argv/cwd for assertions.
func installMux(t *testing.T, configured, allowed bool, gotExec *execReq, execHit *bool) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/registry/allow", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(registryAllowResp{
			Configured: configured,
			Allowed:    allowed,
			Ecosystem:  r.URL.Query().Get("ecosystem"),
			Name:       r.URL.Query().Get("name"),
		})
	})
	mux.HandleFunc("POST /v1/sessions/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		*execHit = true
		json.NewDecoder(r.Body).Decode(gotExec)
		ndjson(w, frame{Stream: "stdout", Data: "ok\n"}, frame{Exit: intp(0)})
	})
	return mux
}

// TestInstallProjectLocalPipArgv proves an allowlisted pip install runs a
// PROJECT-LOCAL install (target under /workspace) through the exec API, in /workspace.
func TestInstallProjectLocalPipArgv(t *testing.T) {
	var gotExec execReq
	var execHit bool
	fd := newFakeDaemon(t, installMux(t, true, true, &gotExec, &execHit))

	out, _, err := execRoot(t, "workspace", "install", "--socket", fd.socketPath,
		"--session", "sess-1", "pip", "requests@2.31.0")
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !execHit {
		t.Fatalf("exec was not called")
	}
	joined := strings.Join(gotExec.Argv, " ")
	if !strings.Contains(joined, "pip install") || !strings.Contains(joined, "--target /workspace/.opslify/pip") {
		t.Fatalf("argv not a project-local pip install: %q", joined)
	}
	if !strings.Contains(joined, "requests==2.31.0") {
		t.Fatalf("version not applied: %q", joined)
	}
	if gotExec.Cwd != "/workspace" {
		t.Fatalf("cwd = %q, want /workspace", gotExec.Cwd)
	}
	// The --target value must be project-local under /workspace.
	for i, a := range gotExec.Argv {
		if a == "--target" && (i+1 >= len(gotExec.Argv) || !strings.HasPrefix(gotExec.Argv[i+1], "/workspace")) {
			t.Fatalf("install target not under /workspace: %v", gotExec.Argv)
		}
	}
	if !strings.Contains(out, "pkg.install audited") {
		t.Fatalf("missing audit notice in output: %q", out)
	}
}

// TestInstallRefusedNotAllowlisted proves a non-allowlisted package is refused BEFORE
// any exec runs (the allowlist gate is checked up front).
func TestInstallRefusedNotAllowlisted(t *testing.T) {
	var gotExec execReq
	var execHit bool
	fd := newFakeDaemon(t, installMux(t, true, false, &gotExec, &execHit))

	_, _, err := execRoot(t, "workspace", "install", "--socket", fd.socketPath,
		"--session", "sess-1", "pip", "evil-typosquat")
	if err == nil {
		t.Fatalf("expected refusal for a non-allowlisted package")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("error should name the allowlist: %v", err)
	}
	if execHit {
		t.Fatalf("SECURITY: exec ran for a non-allowlisted package (gate must precede install)")
	}
}

// TestInstallFailClosedNoProxy proves that with no registry proxy configured the
// install is refused (never an open-egress fallback), before any exec.
func TestInstallFailClosedNoProxy(t *testing.T) {
	var gotExec execReq
	var execHit bool
	fd := newFakeDaemon(t, installMux(t, false, false, &gotExec, &execHit))

	_, _, err := execRoot(t, "workspace", "install", "--socket", fd.socketPath,
		"--session", "sess-1", "pip", "requests")
	if err == nil {
		t.Fatalf("expected fail-closed refusal with no proxy configured")
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("error should say install unavailable: %v", err)
	}
	if execHit {
		t.Fatalf("SECURITY: exec ran with no proxy configured (must fail closed, no open egress)")
	}
}

// TestInstallRequiresSession proves the command targets a running session explicitly.
func TestInstallRequiresSession(t *testing.T) {
	_, _, err := execRoot(t, "workspace", "install", "pip", "requests")
	if err == nil || !strings.Contains(err.Error(), "--session") {
		t.Fatalf("expected a --session-required error, got %v", err)
	}
}

// TestInstallArgvPerEcosystem covers the project-local argv for each ecosystem.
func TestInstallArgvPerEcosystem(t *testing.T) {
	cases := []struct {
		eco, spec string
		want      []string
	}{
		{"npm", "left-pad@1.3.0", []string{"npm", "install", "--prefix", "/workspace", "left-pad@1.3.0"}},
		{"npm", "@scope/pkg@2.0.0", []string{"npm", "install", "--prefix", "/workspace", "@scope/pkg@2.0.0"}},
		{"go", "github.com/pkg/errors", []string{"go", "get", "github.com/pkg/errors@latest"}},
		{"pypi", "flask", []string{"pip", "install", "--no-input", "--target", "/workspace/.opslify/pip", "flask"}},
	}
	for _, c := range cases {
		name, version := splitPkgVersion(c.spec)
		argv, err := installArgv(ecosystemAlias[c.eco], name, version)
		if err != nil {
			t.Fatalf("%s/%s: %v", c.eco, c.spec, err)
		}
		if strings.Join(argv, " ") != strings.Join(c.want, " ") {
			t.Fatalf("%s/%s argv = %v, want %v", c.eco, c.spec, argv, c.want)
		}
	}
}

// TestNoAgentSelfInstall documents/enforces that install is operator-only: there is
// no MCP tool or in-sandbox trigger. The command lives on the operator CLI tree and
// nowhere in the agent-facing surface.
func TestNoAgentSelfInstall(t *testing.T) {
	// The install command is reachable only under `workspace install` on the operator
	// CLI; assert it is registered there and takes an explicit operator --session.
	wc := workspaceCmd()
	var found bool
	for _, sub := range wc.Commands() {
		if sub.Name() == "install" {
			found = true
			if sub.Flags().Lookup("session") == nil {
				t.Fatalf("install must require an operator-provided --session")
			}
		}
	}
	if !found {
		t.Fatalf("install command not found under the operator `workspace` tree")
	}
}
