package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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

// TestSecretsRmRefCannotForgeQueryString pins D3, the client-side bypass of a
// server-side control. A ref is concatenated into the request URL; unescaped,
// `secrets rm 'gitlab-token?force=true'` rewrote the QUERY STRING and bypassed
// the daemon's in-use guard entirely.
//
// The assertion is about the FORCE parameter specifically, not about the query
// being empty: a ref that cannot be a path segment legitimately travels as an
// escaped ?ref= value (so a legacy secret stays deletable), and that is safe
// precisely because the escaping stops it from introducing new parameters.
func TestSecretsRmRefCannotForgeQueryString(t *testing.T) {
	for _, ref := range []string{
		"gitlab-token?force=true",
		"gitlab-token?force=true&x=1",
		"gitlab-token#?force=true",
		"gitlab-token%3fforce=true",
		"gitlab-token&force=true",
		"gitlab-token?FORCE=true",
	} {
		t.Run(ref, func(t *testing.T) {
			var rec recordedRequest
			fd := newRecordingDaemon(t, &rec)
			_, _, err := runCLI(t, "", "secrets", "rm", ref, "--socket", fd.socketPath)

			q := parseQuery(t, rec.rawQuery)
			if len(q["force"]) > 0 {
				t.Fatalf("SECURITY: ref %q forged force=%v without --force — the in-use guard is bypassable from the client", ref, q["force"])
			}
			for key := range q {
				if key != "ref" {
					t.Fatalf("SECURITY: ref %q introduced query parameter %q (%s)", ref, key, rec.rawQuery)
				}
			}
			// The daemon must see the ref VERBATIM, so it deletes the secret the
			// operator named and not some prefix of it.
			if got := q.Get("ref"); got != "" && got != ref {
				t.Errorf("daemon received ref %q, want %q", got, ref)
			}
			if err == nil {
				t.Errorf("the fake daemon refuses this delete (409); the CLI must surface that")
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
// destroyed.
//
// The invariant asserted here is the one that matters, and it is stronger than
// "the CLI errors": whatever the CLI does with a hostile ref, NO request may
// reach a route other than the secrets routes, and no query parameter other than
// ref/force may appear. Some of these refs are deliberately NOT refused — a
// secret stored under an older, looser rule has to stay deletable — and those
// travel as an escaped query value, which cannot retarget anything.
func TestSecretsRefCannotRetargetAnotherRoute(t *testing.T) {
	hostile := []string{
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
		"gitlab-token?force=true",
		"gitlab-token#frag",
	}
	for _, ref := range hostile {
		t.Run(ref, func(t *testing.T) {
			var reached []string
			var query string
			mux := http.NewServeMux()
			for pattern, name := range map[string]string{
				"DELETE /v1/secrets/{ref...}":  "secrets",
				"DELETE /v1/secrets":           "secrets-query",
				"PUT /v1/secrets/{ref...}":     "secrets-rotate",
				"DELETE /v1/sessions/{id}":     "sessions",
				"DELETE /v1/projects/{id}":     "projects",
				"DELETE /v1/workspaces/{name}": "workspaces",
			} {
				resource := name
				mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
					reached = append(reached, resource)
					query = r.URL.RawQuery
					w.WriteHeader(http.StatusNoContent)
				})
			}
			fd := newFakeDaemon(t, mux)

			for _, args := range [][]string{
				{"secrets", "rm", ref, "--force"},
				{"secrets", "rm", ref},
				{"secrets", "rotate", ref},
			} {
				reached, query = nil, ""
				_, _, _ = runCLI(t, "value\n", append(args, "--socket", fd.socketPath)...)

				for _, hit := range reached {
					if hit != "secrets" && hit != "secrets-query" && hit != "secrets-rotate" {
						t.Fatalf("SECURITY: %v with ref %q reached the %s route", args, ref, hit)
					}
				}
				// Only ref and force may ever appear. A forged parameter here is how
				// the in-use guard was bypassed from the client.
				for key := range parseQuery(t, query) {
					if key != "ref" && key != "force" {
						t.Fatalf("SECURITY: %v with ref %q forged query parameter %q (%s)", args, ref, key, query)
					}
				}
				// force must appear only when --force was passed.
				wantForce := args[len(args)-1] == "--force"
				if got := parseQuery(t, query)["force"]; !wantForce && len(got) > 0 {
					t.Fatalf("SECURITY: %v with ref %q set force=%v without --force", args, ref, got)
				}
			}
		})
	}
}

func parseQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("parse query %q: %v", raw, err)
	}
	return v
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

// TestNoVerbCanRetargetAnotherRouteViaPathTraversal is the general form of the
// ref-injection class, across EVERY verb that puts operator input in a URL.
//
// Guarding only the secrets verbs was not enough. Go's ServeMux 301-redirects an
// uncleaned path and the CLI's http.Client follows it, so a scoped verb reached
// the secrets route and took its query string with it:
//
//	opslify session kill '../secrets/gitlab-token?force=true'
//	  -> 301 -> DELETE /v1/secrets/gitlab-token?force=true -> 204
//
// One request, exit 0, and an in-use secret deleted past the 409 guard.
func TestNoVerbCanRetargetAnotherRouteViaPathTraversal(t *testing.T) {
	traversals := []string{
		"../secrets/gitlab-token?force=true",
		"../../v1/secrets/gitlab-token?force=true",
		"../projects/prod",
		"../workspaces/prod",
		"../../v1/sessions/live-1",
		"..",
		".",
		"a/../../b",
		"x/../../../v1/secrets/gitlab-token",
	}
	// Every verb that interpolates operator input into a path.
	verbs := [][]string{
		{"session", "kill"},
		{"session", "trace"},
		{"workspace", "rm"},
		{"project", "show"},
		{"env", "ls"},
	}
	for _, verb := range verbs {
		for _, bad := range traversals {
			t.Run(strings.Join(verb, "-")+"/"+bad, func(t *testing.T) {
				var hit string
				mux := http.NewServeMux()
				for pattern, name := range map[string]string{
					"DELETE /v1/secrets/{ref...}":        "secrets-delete",
					"PUT /v1/secrets/{ref...}":           "secrets-rotate",
					"DELETE /v1/sessions/{id}":           "sessions-delete",
					"GET /v1/sessions/{id}/trace":        "sessions-trace",
					"DELETE /v1/projects/{id}":           "projects-delete",
					"GET /v1/projects/{id}":              "projects-get",
					"GET /v1/projects/{id}/environments": "projects-envs",
					"DELETE /v1/workspaces/{name}":       "workspaces-delete",
					"POST /v1/sessions/{id}/exec":        "sessions-exec",
					"PUT /v1/sessions/{id}/files":        "sessions-files",
				} {
					resource := name
					mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
						// Record the FIRST handler reached and what it saw, including the
						// query — the force bypass rode in on the query string.
						if hit == "" {
							hit = resource + " " + r.URL.Path + "?" + r.URL.RawQuery
						}
						w.WriteHeader(http.StatusNoContent)
					})
				}
				fd := newFakeDaemon(t, mux)

				args := append(append([]string{}, verb...), bad, "--socket", fd.socketPath)
				_, _, err := runCLI(t, "", args...)
				if err == nil {
					t.Fatalf("%v %q must be refused before a request is built", verb, bad)
				}
				if hit != "" {
					t.Fatalf("SECURITY: %v %q reached %s", verb, bad, hit)
				}
			})
		}
	}
}

// TestLegitimateIdsStillWork keeps pathSeg from being a blanket refusal.
func TestLegitimateIdsStillWork(t *testing.T) {
	for _, id := range []string{"s1", "sess-abc123", "tripon", "prod", "a.b-c_d"} {
		t.Run(id, func(t *testing.T) {
			var reached bool
			mux := http.NewServeMux()
			mux.HandleFunc("DELETE /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
				reached = r.PathValue("id") == id
				w.WriteHeader(http.StatusNoContent)
			})
			fd := newFakeDaemon(t, mux)
			if _, _, err := runCLI(t, "", "session", "kill", id, "--socket", fd.socketPath); err != nil {
				t.Fatalf("legitimate id %q was refused: %v", id, err)
			}
			if !reached {
				t.Errorf("id %q did not arrive intact at the handler", id)
			}
		})
	}
}

// TestForceRmPrintsWhatItBreaks pins N13. The --force help promised "the
// consumers you are breaking are printed" and nothing was: a 204 carries no body,
// so the daemon cannot report them afterwards, and the only record was a daemon
// log line the operator never sees. Help text that describes output the tool
// cannot produce is worse than no help.
func TestForceRmPrintsWhatItBreaks(t *testing.T) {
	var rec recordedRequest
	fd := newRecordingDaemon(t, &rec)
	_, errb, err := runCLI(t, "", "secrets", "rm", "gitlab-token", "--force", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("rm --force: %v (%s)", err, errb)
	}
	for _, want := range []string{"breaking", "egress_inject", "gitlab.example.com"} {
		if !strings.Contains(errb, want) {
			t.Errorf("--force must report what it breaks (missing %q):\n%s", want, errb)
		}
	}
}

// TestForceRmProceedsWhenConsumersAreUnknowable: the report is a courtesy, not a
// gate. force already means "proceed", so a failure to read the consumer list
// must warn and continue — refusing would leave a leaked credential unrevocable.
func TestForceRmProceedsWhenConsumersAreUnknowable(t *testing.T) {
	var rec recordedRequest
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/secrets/consumers", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"layer":"cred","error":"policy store unavailable"}`, http.StatusInternalServerError)
	})
	mux.HandleFunc("DELETE /v1/secrets/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		rec.rawQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	})
	fd := newFakeDaemon(t, mux)

	out, errb, err := runCLI(t, "", "secrets", "rm", "leaked", "--force", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("a forced removal must proceed when consumers cannot be read: %v (%s)", err, errb)
	}
	if !strings.Contains(errb, "could not determine") {
		t.Errorf("the operator must be told the consumer list was unavailable:\n%s", errb)
	}
	if !strings.Contains(out, "removed secret leaked") {
		t.Errorf("the removal must still happen:\n%s", out)
	}
	if rec.rawQuery != "force=true" {
		t.Errorf("query = %q, want force=true", rec.rawQuery)
	}
}

// TestSecretsLsShowsRotationHygiene pins the CLI half of N14: the daemon began
// returning last_used/rotated_at, but the CLI's own wire type lacked the fields
// and `ls` never printed them, so the stated purpose stayed unmet.
func TestSecretsLsShowsRotationHygiene(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[
		  {"ref":"used","provider":"gitlab","created_at":"2026-01-01T00:00:00Z",
		   "last_used":"2026-09-01T10:00:00Z","rotated_at":"2026-08-01T10:00:00Z"},
		  {"ref":"fresh","provider":"azure","created_at":"2026-01-01T00:00:00Z"}
		]`)
	})
	fd := newFakeDaemon(t, mux)
	out, errb, err := runCLI(t, "", "secrets", "ls", "--socket", fd.socketPath)
	if err != nil {
		t.Fatalf("secrets ls: %v (%s)", err, errb)
	}
	for _, want := range []string{"LAST USED", "ROTATED", "2026-09-01", "2026-08-01"} {
		if !strings.Contains(out, want) {
			t.Errorf("secrets ls is missing %q:\n%s", want, out)
		}
	}
	// A secret never used must read as "never", not as year 1.
	if !strings.Contains(out, "never") {
		t.Errorf("a never-used secret must render as 'never', not a zero time:\n%s", out)
	}
	if strings.Contains(out, "0001-01-01") {
		t.Errorf("a zero time leaked into the listing:\n%s", out)
	}
}

// TestDeleteURLFormAndForceSeparator pins how a ref is addressed for deletion,
// including the query separator. Appending "?force=true" to a URL that already
// carried "?ref=" produced two "?" and a force the daemon never saw — so the
// removal came back 409 against an override the operator had explicitly asked
// for.
func TestDeleteURLFormAndForceSeparator(t *testing.T) {
	for _, tc := range []struct{ ref, wantPath, wantQuery string }{
		{"gitlab-token", "/v1/secrets/gitlab-token", "force=true"},
		{"aws/deploy", "/v1/secrets/aws/deploy", "force=true"},
		// Path-unaddressable shapes go to the query form, and force must ride on &.
		// Not storable under the current rule, so it goes to the query form — a
		// legacy secret must stay deletable even though it can no longer be created.
		{"trail/", "/v1/secrets", "ref=trail%2F&force=true"},
		{"/etc/passwd", "/v1/secrets", "ref=%2Fetc%2Fpasswd&force=true"},
		{"./tok", "/v1/secrets", "ref=.%2Ftok&force=true"},
		{"a//b", "/v1/secrets", "ref=a%2F%2Fb&force=true"},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			var rec recordedRequest
			mux := http.NewServeMux()
			h := func(w http.ResponseWriter, r *http.Request) {
				rec.path, rec.rawQuery = r.URL.Path, r.URL.RawQuery
				w.WriteHeader(http.StatusNoContent)
			}
			mux.HandleFunc("DELETE /v1/secrets/{ref...}", h)
			mux.HandleFunc("DELETE /v1/secrets", h)
			fd := newFakeDaemon(t, mux)

			if _, _, err := runCLI(t, "", "secrets", "rm", tc.ref, "--force", "--socket", fd.socketPath); err != nil {
				t.Fatalf("rm --force %q: %v", tc.ref, err)
			}
			if rec.path != tc.wantPath {
				t.Errorf("path = %q, want %q", rec.path, tc.wantPath)
			}
			if rec.rawQuery != tc.wantQuery {
				t.Errorf("query = %q, want %q", rec.rawQuery, tc.wantQuery)
			}
		})
	}
}
