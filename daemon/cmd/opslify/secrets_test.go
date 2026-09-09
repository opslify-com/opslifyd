package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestSecretsAddFromStdin proves `secrets add` reads the value from STDIN (never
// argv) and sends it base64 to the daemon; the response echoes no value.
func TestSecretsAddFromStdin(t *testing.T) {
	var got addSecretReq
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(secretMeta{Ref: got.Ref, Provider: got.Provider})
	})
	fd := newFakeDaemon(t, mux)

	secret := "FAKE-cli-secret-abc"
	root := rootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetIn(strings.NewReader(secret + "\n")) // trailing newline is trimmed
	root.SetArgs([]string{"secrets", "add", "gh/token", "--provider", "github", "--socket", fd.socketPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v (%s)", err, errb.String())
	}
	// The value was carried base64 in the body, decoded back to exactly the secret.
	decoded, _ := base64.StdEncoding.DecodeString(got.ValueB64)
	if string(decoded) != secret {
		t.Fatalf("daemon received %q, want %q", decoded, secret)
	}
	if got.Ref != "gh/token" || got.Provider != "github" {
		t.Fatalf("bad request: %+v", got)
	}
	// The value must NOT appear in argv (it came from stdin) nor in stdout.
	if strings.Contains(out.String(), secret) {
		t.Fatal("SECURITY: secret value printed to stdout")
	}
}

// TestSecretsAddRejectsEmpty ensures a value cannot be passed as an argument (there
// is no value arg) and empty stdin is refused.
func TestSecretsAddRejectsEmpty(t *testing.T) {
	fd := newFakeDaemon(t, http.NewServeMux())
	root := rootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetIn(strings.NewReader(""))
	root.SetArgs([]string{"secrets", "add", "k", "--socket", fd.socketPath})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error on empty secret value")
	}
}

// TestSecretsLsNoValue ensures `secrets ls` renders metadata only.
func TestSecretsLsNoValue(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]secretMeta{
			{Ref: "aws/deploy", Provider: "aws", TTL: "15m", CreatedAt: "2026-08-18T00:00:00Z"},
		})
	})
	fd := newFakeDaemon(t, mux)
	root := rootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"secrets", "ls", "--socket", fd.socketPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "aws/deploy") || !strings.Contains(out.String(), "aws") {
		t.Fatalf("ls output missing metadata: %s", out.String())
	}
}

// --- F8.3 CLI surface --------------------------------------------------------

// recordedRequest captures what the CLI actually sent, so a test can assert over
// the request LINE (path + query), not just the body — that is where the D3 ref
// injection lived.
type recordedRequest struct {
	method, path, rawQuery string
	// escapedPath is the path AS SENT. r.URL.Path is already percent-decoded, so
	// "aws%2Fdeploy" and "aws/deploy" are indistinguishable there — asserting on
	// the decoded form cannot tell correct escaping from over-escaping.
	escapedPath string
	body        []byte
}

// newRecordingDaemon answers every secrets route and records the last request.
func newRecordingDaemon(t *testing.T, rec *recordedRequest, refs ...string) *fakeDaemon {
	t.Helper()
	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		rec.method, rec.path, rec.rawQuery = r.Method, r.URL.Path, r.URL.RawQuery
		rec.escapedPath = r.URL.EscapedPath()
		rec.body, _ = io.ReadAll(r.Body)
		if r.URL.Query().Get("force") != "true" && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"layer": "cred", "error": "broker: secret in use: used by 1 consumer(s)",
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	mux.HandleFunc("DELETE /v1/secrets/{ref...}", handler)
	mux.HandleFunc("PUT /v1/secrets/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		rec.method, rec.path, rec.rawQuery = r.Method, r.URL.Path, r.URL.RawQuery
		rec.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(secretMeta{Ref: "x"})
	})
	mux.HandleFunc("GET /v1/secrets/consumers", func(w http.ResponseWriter, r *http.Request) {
		rec.method, rec.path, rec.rawQuery = r.Method, r.URL.Path, r.URL.RawQuery
		// Written as literal JSON on purpose: this is the daemon's documented wire
		// shape (a BARE array of views). Encoding a Go value here would let the
		// test pass even if the two sides' shapes had drifted apart.
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[{"ref":"gitlab-token","provider":"gitlab","created_at":"2026-01-01T00:00:00Z",`+
			`"in_use":true,"consumers":[{"kind":"egress_inject","name":"gitlab.example.com"}]}]`)
	})
	return newFakeDaemon(t, mux)
}

func runCLI(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	root := rootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), errb.String(), err
}

// TestSecretsRmRefCannotForgeQueryString pins D3. A ref is concatenated into the
// request path; without escaping, `secrets rm 'gitlab-token?force=true'` rewrote
// the QUERY STRING and bypassed the daemon's in-use guard entirely — an
// unprivileged client-side bypass of a server-side control.
func TestSecretsRmRefCannotForgeQueryString(t *testing.T) {
	for _, ref := range []string{
		"gitlab-token?force=true",
		"gitlab-token?force=true&x=1",
		"gitlab-token#?force=true",
		"gitlab-token%3fforce=true",
	} {
		t.Run(ref, func(t *testing.T) {
			var rec recordedRequest
			fd := newRecordingDaemon(t, &rec)
			_, _, err := runCLI(t, "", "secrets", "rm", ref, "--socket", fd.socketPath)

			if rec.rawQuery != "" {
				t.Fatalf("SECURITY: ref %q forged query %q — the in-use guard is bypassable from the client", ref, rec.rawQuery)
			}
			if err == nil {
				t.Fatalf("the daemon refused this delete (409); the CLI must surface that as an error")
			}
		})
	}
}

// TestSecretsRmForceSendsForce is the other half of D3: --force must still work,
// and only --force may set it.
func TestSecretsRmForceSendsForce(t *testing.T) {
	var rec recordedRequest
	fd := newRecordingDaemon(t, &rec)
	if _, errb, err := runCLI(t, "", "secrets", "rm", "gitlab-token", "--force", "--socket", fd.socketPath); err != nil {
		t.Fatalf("rm --force: %v (%s)", err, errb)
	}
	if rec.rawQuery != "force=true" {
		t.Fatalf("--force sent query %q, want force=true", rec.rawQuery)
	}
}

// TestSecretsRmWithoutForceSurfacesTheRefusal proves the operator SEES what they
// would have broken, rather than the CLI swallowing a 409 as success.
func TestSecretsRmWithoutForceSurfacesTheRefusal(t *testing.T) {
	var rec recordedRequest
	fd := newRecordingDaemon(t, &rec)
	_, _, err := runCLI(t, "", "secrets", "rm", "gitlab-token", "--socket", fd.socketPath)
	if err == nil {
		t.Fatal("a 409 in-use refusal must be reported as an error, not swallowed")
	}
	if !strings.Contains(err.Error(), "in use") {
		t.Errorf("the refusal must say why; got %v", err)
	}
}

// TestSecretsRefsWithSlashesSurviveAsPathSegments guards against over-escaping:
// "aws/deploy" is a legitimate ref and must not become "aws%2Fdeploy".
func TestSecretsRefsWithSlashesSurviveAsPathSegments(t *testing.T) {
	var rec recordedRequest
	fd := newRecordingDaemon(t, &rec)
	if _, _, err := runCLI(t, "", "secrets", "rm", "aws/deploy", "--force", "--socket", fd.socketPath); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if rec.escapedPath != "/v1/secrets/aws/deploy" {
		t.Fatalf("escaped path = %q, want /v1/secrets/aws/deploy: a '/' in a ref is legitimate and must survive as path segments", rec.escapedPath)
	}
}

// TestSecretsRotateSendsValueFromStdin pins that rotation takes the value from
// stdin (never argv) and carries it base64.
func TestSecretsRotateSendsValueFromStdin(t *testing.T) {
	var rec recordedRequest
	fd := newRecordingDaemon(t, &rec)
	const secret = "FAKE-rotated-value-xyz"
	out, errb, err := runCLI(t, secret+"\n", "secrets", "rotate", "gitlab-token", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("rotate: %v (%s)", err, errb)
	}
	var body rotateSecretReq
	if err := json.Unmarshal(rec.body, &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(body.ValueB64)
	if string(decoded) != secret {
		t.Fatalf("daemon received %q, want %q", decoded, secret)
	}
	if rec.method != http.MethodPut {
		t.Errorf("rotate used %s, want PUT (rotation must not be able to create)", rec.method)
	}
	if strings.Contains(out+errb, secret) {
		t.Fatal("SECURITY: the rotated value was printed to the terminal")
	}
}

// TestSecretsConsumersPrintsNoValue: the consumers listing is the operator's
// "what would this break?" view, and must show refs and users only.
func TestSecretsConsumersPrintsNoValue(t *testing.T) {
	var rec recordedRequest
	fd := newRecordingDaemon(t, &rec)
	out, errb, err := runCLI(t, "", "secrets", "consumers", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("consumers: %v (%s)", err, errb)
	}
	for _, want := range []string{"gitlab-token", "gitlab.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("consumers output missing %q; got:\n%s", want, out)
		}
	}
}

// --- readSecretValue (D4) ----------------------------------------------------

// TestFromCommandNeverEchoesStderr pins D4. A manager CLI that writes the secret
// to stderr before failing had it echoed verbatim in the error — onto the
// operator's terminal, into shell scrollback, and into CI logs.
func TestFromCommandNeverEchoesStderr(t *testing.T) {
	const secret = "FAKE-leaked-via-stderr-9f2a"
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(""))

	_, err := readSecretValue(cmd, "", "printf %s "+secret+" 1>&2; exit 7")
	if err == nil {
		t.Fatal("a non-zero exit must fail the read")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("SECURITY: the secret leaked through the error message: %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 7") {
		t.Errorf("the error must still be diagnosable (exit status); got %v", err)
	}
}

// TestFromCommandTakesStdout is the happy path the leak fix must not break.
func TestFromCommandTakesStdout(t *testing.T) {
	const secret = "FAKE-from-manager-cli"
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(""))
	got, err := readSecretValue(cmd, "", "printf '%s\\n' "+secret)
	if err != nil {
		t.Fatalf("readSecretValue: %v", err)
	}
	if string(got) != secret {
		t.Fatalf("got %q, want %q (exactly one trailing newline is trimmed)", got, secret)
	}
}

// TestFromFileAndStdinPaths keep the non-command sources honest.
func TestFromFileAndStdinPaths(t *testing.T) {
	const secret = "FAKE-from-file-value"
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(""))
	got, err := readSecretValue(cmd, path, "")
	if err != nil || string(got) != secret {
		t.Fatalf("--from-file: got %q, err %v", got, err)
	}

	cmd2 := &cobra.Command{}
	cmd2.SetIn(strings.NewReader(secret + "\n"))
	got, err = readSecretValue(cmd2, "", "")
	if err != nil || string(got) != secret {
		t.Fatalf("stdin: got %q, err %v", got, err)
	}
}

// TestEmptyValueIsRefusedFromEverySource: an empty value must never be stored —
// a manager CLI that prints nothing on success would otherwise blank a
// credential during a routine sync.
func TestEmptyValueIsRefusedFromEverySource(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, file, command, stdin string }{
		{"stdin", "", "", ""},
		{"stdin-newline-only", "", "", "\n"},
		{"from-file", empty, "", ""},
		{"from-command", "", "true", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.SetIn(strings.NewReader(tc.stdin))
			if _, err := readSecretValue(cmd, tc.file, tc.command); err == nil {
				t.Fatal("an empty value must be refused, not stored")
			}
		})
	}
}
