package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// runPolicyCheck runs `opslify policy check <path>` capturing stdout+stderr and
// the exit code (0 on ok, 1 on validation failure).
func runPolicyCheck(t *testing.T, path string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := policyCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs([]string{"check", path})
	err := cmd.Execute()
	code = 0
	if err != nil {
		var ec *exitCodeError
		if !bytesAsExit(err, &ec) {
			t.Fatalf("unexpected non-exit error: %v", err)
		}
		code = ec.code
	}
	return out.String(), errb.String(), code
}

func bytesAsExit(err error, target **exitCodeError) bool {
	if e, ok := err.(*exitCodeError); ok {
		*target = e
		return true
	}
	return false
}

// AC (F4.1): `opslify policy check` returns ok + policy_hash for a valid file.
func TestPolicyCheckOK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "opslify.policy.yaml")
	src := "allow:\n  kubectl:\n    verbs: [get, list]\nstrict_exec: true\n"
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := runPolicyCheck(t, p)
	if code != 0 {
		t.Fatalf("valid policy exited %d; stdout=%q", code, stdout)
	}
	if !strings.Contains(stdout, "ok") || !strings.Contains(stdout, "policy_hash:") {
		t.Fatalf("missing ok/policy_hash: %q", stdout)
	}
	// The printed hash must equal the resolved hash of the same content.
	parsed, err := policy.Parse([]byte(src), "opslify.policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, policy.ResolveDefault(parsed).Hash) {
		t.Fatalf("printed hash mismatch: %q", stdout)
	}
}

// AC (F4.1): `opslify policy check` returns line-level errors + non-zero exit
// for an invalid file.
func TestPolicyCheckLineLevelErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "opslify.policy.yaml")
	src := "allow:\n  kubectl:\n    verbs: [get, destroy]\n"
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runPolicyCheck(t, p)
	if code != 1 {
		t.Fatalf("invalid policy exited %d, want 1", code)
	}
	if !strings.Contains(stderr, "opslify.policy.yaml:3:") || !strings.Contains(stderr, `unknown verb "destroy"`) {
		t.Fatalf("expected line-level error, got %q", stderr)
	}
}
