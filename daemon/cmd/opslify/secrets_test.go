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

// TestSecretsRefCannotRetargetAnotherRoute pins F0, the exploitable half of the
// ref-injection class that percent-escaping alone did NOT close.
//
// url.PathEscape leaves "." and ".." intact, so a ref could walk out of its own
// route: `secrets rm '../../v1/sessions/live-1'` sent DELETE /v1/sessions/live-1
// — one request, exit code 0, "removed secret" printed, and a live session
// destroyed. Refs come from config files, CI variables and automation, not only
// from an operator's keyboard, and the daemon cannot defend against it because by
// then the request is for a different route entirely.
//
// The mux below carries the daemon's REAL route patterns, so a traversal that
// reaches another handler is observable as that handler firing.
func TestSecretsRefCannotRetargetAnotherRoute(t *testing.T) {
	traversals := []string{
		"../../v1/sessions/live-session-1",
		"../../v1/projects/prod",
		"../../v1/workspaces/prod",
		"a/../../../v1/projects/prod",
		"../secrets",
		"..",
		"../../../v1/sessions/live-session-1",
		"./../../v1/projects/prod",
		"/etc/passwd",
		"trailing/",
		"double//segment",
	}
	for _, ref := range traversals {
		t.Run(ref, func(t *testing.T) {
			var hit string
			mux := http.NewServeMux()
			// The daemon's actual patterns for every DELETE-able resource.
			for pattern, name := range map[string]string{
				"DELETE /v1/secrets/{ref...}":  "secrets",
				"DELETE /v1/sessions/{id}":     "sessions",
				"DELETE /v1/projects/{id}":     "projects",
				"DELETE /v1/workspaces/{name}": "workspaces",
				"PUT /v1/secrets/{ref...}":     "rotate",
			} {
				resource := name
				mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
					hit = resource + " " + r.URL.Path
					w.WriteHeader(http.StatusNoContent)
				})
			}
			fd := newFakeDaemon(t, mux)

			for _, args := range [][]string{
				{"secrets", "rm", ref, "--force"},
				{"secrets", "rm", ref},
				{"secrets", "rotate", ref},
			} {
				hit = ""
				_, _, err := runCLI(t, "value\n", append(args, "--socket", fd.socketPath)...)
				if err == nil {
					t.Fatalf("%v with ref %q must be refused before a request is built", args, ref)
				}
				if hit != "" {
					t.Fatalf("SECURITY: ref %q reached another route: %s", ref, hit)
				}
			}
		})
	}
}

// TestLegitimateRefsStillReachTheSecretsRoute keeps the validation from being a
// blanket refusal: a ref with '/', '@', '.', '_' and '-' is legal and must work.
func TestLegitimateRefsStillReachTheSecretsRoute(t *testing.T) {
	for _, ref := range []string{
		"gitlab-token", "aws/deploy", "a.b_c-d@e/f", "gh/token", "azure/sp.client-secret",
	} {
		t.Run(ref, func(t *testing.T) {
			var rec recordedRequest
			fd := newRecordingDaemon(t, &rec)
			if _, _, err := runCLI(t, "", "secrets", "rm", ref, "--force", "--socket", fd.socketPath); err != nil {
				t.Fatalf("legitimate ref %q was refused: %v", ref, err)
			}
			if rec.escapedPath != "/v1/secrets/"+ref {
				t.Errorf("path = %q, want /v1/secrets/%s", rec.escapedPath, ref)
			}
		})
	}
}

// --- secrets sync (F9) --------------------------------------------------------

// TestSecretsSyncFetchesFromManagerAndNeverPrintsTheValue exercises the
// documented Vault/Doppler/Secrets-Manager entry point, which had NO test at all
// — a mutant that appended the credential to its success line printed it to the
// operator's terminal, uncaught.
func TestSecretsSyncSendsValueAndNeverPrintsIt(t *testing.T) {
	const secret = "FAKE-from-vault-kv-get-abc123"
	var rec recordedRequest
	fd := newRecordingDaemon(t, &rec)

	out, errb, err := runCLI(t, "", "secrets", "sync", "gitlab-token",
		"--from-command", "printf '%s\\n' "+secret, "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("sync: %v (%s)", err, errb)
	}
	var body rotateSecretReq
	if err := json.Unmarshal(rec.body, &body); err != nil {
		t.Fatalf("unmarshal: %v (body %q)", err, rec.body)
	}
	decoded, _ := base64.StdEncoding.DecodeString(body.ValueB64)
	if string(decoded) != secret {
		t.Fatalf("daemon received %q, want %q", decoded, secret)
	}
	if rec.method != http.MethodPut {
		t.Errorf("sync used %s, want PUT (it is a rotation, and must not be able to create)", rec.method)
	}
	if strings.Contains(out+errb, secret) {
		t.Fatalf("SECURITY: sync printed the credential to the terminal:\nstdout=%q\nstderr=%q", out, errb)
	}
	if strings.Contains(out+errb, base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatal("SECURITY: sync printed the base64 credential to the terminal")
	}
}

// TestSecretsSyncFailureLeavesPreviousValueIntact: a failed fetch must never
// reach the vault. This is the property that makes an automated sync safe to run
// on a schedule.
func TestSecretsSyncFailureLeavesPreviousValueIntact(t *testing.T) {
	var rec recordedRequest
	fd := newRecordingDaemon(t, &rec)
	_, _, err := runCLI(t, "", "secrets", "sync", "gitlab-token",
		"--from-command", "exit 3", "--socket", fd.socketPath)
	if err == nil {
		t.Fatal("a failed --from-command must fail the sync")
	}
	if rec.method != "" {
		t.Fatalf("a failed fetch must not send a request; got %s %s", rec.method, rec.path)
	}
}

// TestSyncDoesNotFoldStderrIntoTheValue: a manager CLI that prints a deprecation
// warning to stderr must not have it stored as part of the credential. Using
// CombinedOutput here would silently corrupt every synced secret.
func TestSyncDoesNotFoldStderrIntoTheValue(t *testing.T) {
	const secret = "FAKE-real-credential"
	var rec recordedRequest
	fd := newRecordingDaemon(t, &rec)
	_, _, err := runCLI(t, "", "secrets", "sync", "gitlab-token",
		"--from-command", "printf 'WARNING: deprecated flag\\n' 1>&2; printf '%s\\n' "+secret,
		"--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	var body rotateSecretReq
	json.Unmarshal(rec.body, &body)
	decoded, _ := base64.StdEncoding.DecodeString(body.ValueB64)
	if string(decoded) != secret {
		t.Fatalf("stored value = %q, want exactly %q — stderr must not be folded in", decoded, secret)
	}
}

// TestReadSecretValueTakesStdoutOnly is the unit-level twin of the above.
func TestReadSecretValueTakesStdoutOnly(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(""))
	got, err := readSecretValue(cmd, "", "printf 'noise\\n' 1>&2; printf 'value'")
	if err != nil {
		t.Fatalf("readSecretValue: %v", err)
	}
	if string(got) != "value" {
		t.Fatalf("got %q, want %q — only stdout is the value", got, "value")
	}
}
