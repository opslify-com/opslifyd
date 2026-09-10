package broker

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The key the daemon holds. It must appear nowhere the sandbox can see.
const sshPrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY-private-key-must-never-leave-the-daemon\n-----END OPENSSH PRIVATE KEY-----\n"

// fakeSSHRunner records what the kind asked the local tooling to do, so the tests
// assert over the DESTINATION CONSTRAINTS actually applied rather than trusting
// that ssh-add was called.
type fakeSSHRunner struct {
	mu           sync.Mutex
	major, minor int
	versionErr   error
	startErr     error
	addErr       error
	addedKey     []byte
	addedDests   []string
	addedKH      string
	sockPath     string
	agentStopped bool
	agentStarts  int
}

func (f *fakeSSHRunner) Version(context.Context) (int, int, error) {
	if f.versionErr != nil {
		return 0, 0, f.versionErr
	}
	return f.major, f.minor, nil
}

func (f *fakeSSHRunner) StartAgent(_ context.Context, sockPath string) (io.Closer, error) {
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.mu.Lock()
	f.sockPath = sockPath
	f.agentStarts++
	f.mu.Unlock()
	// A real agent creates the socket; the kind waits for it in production, and a
	// test that skipped this would not exercise the teardown path.
	if err := os.WriteFile(sockPath, nil, 0o600); err != nil {
		return nil, err
	}
	return closerFunc(func() error {
		f.mu.Lock()
		f.agentStopped = true
		f.mu.Unlock()
		return nil
	}), nil
}

func (f *fakeSSHRunner) AddKey(_ context.Context, sockPath string, key []byte, dests []string, kh string) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addedKey = append([]byte(nil), key...)
	f.addedDests = append([]string(nil), dests...)
	f.addedKH = kh
	return nil
}

func (f *fakeSSHRunner) stopped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.agentStopped
}

type closerFunc func() error

func (c closerFunc) Close() error { return c() }

// staticSecrets resolves one ref to one value, standing in for the vault.
type staticSecrets struct {
	ref, value string
	err        error
}

func (s staticSecrets) Get(_ context.Context, ref string) ([]byte, SecretMeta, error) {
	if s.err != nil {
		return nil, SecretMeta{}, s.err
	}
	if ref != s.ref {
		return nil, SecretMeta{}, fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	return []byte(s.value), SecretMeta{Ref: ref}, nil
}

func sshFixture(t *testing.T) (ConnectionSpec, SessionContext, string) {
	t.Helper()
	base := t.TempDir()
	ws := filepath.Join(base, "workspace")
	etc := filepath.Join(base, "etc")
	for _, d := range []string{ws, etc} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	kh := filepath.Join(etc, "known_hosts")
	if err := os.WriteFile(kh, []byte("prod-web-01 ssh-ed25519 AAAAC3Nz...\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := ConnectionSpec{
		Name:      "ops-fleet",
		Kind:      KindSSH,
		SecretRef: "ssh-ops-key",
		Hosts:     []string{"prod-web-01", "prod-web-02"},
		Config:    map[string]string{"known_hosts_path": kh},
	}
	return spec, SessionContext{SessionID: "s1", WorkspaceDir: ws}, kh
}

func sshRegistry(runner SSHRunner) *Registry {
	r := NewRegistry()
	r.Register(KindSSH, NewSSHConnection(runner))
	return r
}

func okRunner() *fakeSSHRunner { return &fakeSSHRunner{major: 9, minor: 6} }

// --- the AC: no key material in the sandbox -----------------------------------

// TestSSHSandboxGetsOnlyAnAgentSocket is the kind's one-line claim. The socket is
// the ONLY ssh artefact: no key, no ~/.ssh copy, no ProxyJump credential.
func TestSSHSandboxGetsOnlyAnAgentSocket(t *testing.T) {
	spec, sc, _ := sshFixture(t)
	runner := okRunner()
	c, err := sshRegistry(runner).Build(spec, staticSecrets{ref: "ssh-ops-key", value: sshPrivateKey})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	inj, closer, err := c.BuildForSession(context.Background(), sc)
	if err != nil {
		t.Fatalf("BuildForSession: %v", err)
	}
	defer closer.Close()

	if len(inj.Env) != 1 {
		t.Fatalf("the sandbox must get exactly one variable, got %v", inj.Env)
	}
	sock := inj.Env["SSH_AUTH_SOCK"]
	if sock == "" {
		t.Fatal("SSH_AUTH_SOCK must be set")
	}
	if len(inj.Files) != 0 {
		t.Fatalf("no files may be written into the sandbox, got %v", inj.Files)
	}
	// The key must not be anywhere the sandbox can read, in any encoding.
	for name, body := range map[string]string{"SSH_AUTH_SOCK": sock} {
		for enc, val := range map[string]string{
			"plaintext": sshPrivateKey,
			"base64":    base64.StdEncoding.EncodeToString([]byte(sshPrivateKey)),
			"canary":    "CANARY-private-key-must-never-leave-the-daemon",
		} {
			if strings.Contains(body, val) {
				t.Fatalf("%s carries key material as %s", name, enc)
			}
		}
	}
	// Nothing in the WORKSPACE either: an agent that could read the key off disk
	// would make the socket irrelevant.
	walkAssertNoKey(t, sc.WorkspaceDir)
	// And the ref itself must not be disclosed.
	if strings.Contains(sock, "ssh-ops-key") {
		t.Error("the secret ref leaked into the sandbox environment")
	}
}

// walkAssertNoKey fails if any file under root contains key material.
func walkAssertNoKey(t *testing.T, root string) {
	t.Helper()
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(b), "CANARY-private-key") {
			t.Fatalf("%s contains key material", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestSSHKeyIsLoadedWithDestinationConstraints: the constraints ARE the security
// control, so the test asserts they reached the tooling with exactly the
// connection's hosts — not that ssh-add was merely called.
func TestSSHKeyIsLoadedWithDestinationConstraints(t *testing.T) {
	spec, sc, kh := sshFixture(t)
	runner := okRunner()
	c, _ := sshRegistry(runner).Build(spec, staticSecrets{ref: "ssh-ops-key", value: sshPrivateKey})
	_, closer, err := c.BuildForSession(context.Background(), sc)
	if err != nil {
		t.Fatalf("BuildForSession: %v", err)
	}
	defer closer.Close()

	runner.mu.Lock()
	dests, gotKH, gotKey := runner.addedDests, runner.addedKH, string(runner.addedKey)
	runner.mu.Unlock()

	if len(dests) != 2 || dests[0] != "prod-web-01" || dests[1] != "prod-web-02" {
		t.Fatalf("destinations = %v, want exactly the connection's hosts", dests)
	}
	if gotKH != kh {
		t.Errorf("known_hosts = %q, want the daemon-side file %q", gotKH, kh)
	}
	// The key reached the tooling (on stdin, in production) but never the sandbox.
	if gotKey != sshPrivateKey {
		t.Errorf("the daemon must pass the real key to the agent")
	}
}

// --- fail-closed --------------------------------------------------------------

// TestSSHRefusesWithoutConstraintSupport is the BLOCKING QA item: a permissive
// fallback when constraints cannot be set would hand the sandbox an unrestricted
// signing oracle for every host the key reaches. No key is loaded at all.
func TestSSHRefusesWithoutConstraintSupport(t *testing.T) {
	for _, tc := range []struct{ major, minor int }{{8, 8}, {8, 0}, {7, 9}, {6, 7}} {
		spec, sc, _ := sshFixture(t)
		runner := &fakeSSHRunner{major: tc.major, minor: tc.minor}
		c, _ := sshRegistry(runner).Build(spec, staticSecrets{ref: "ssh-ops-key", value: sshPrivateKey})
		_, _, err := c.BuildForSession(context.Background(), sc)
		if !errors.Is(err, ErrDenied) {
			t.Errorf("OpenSSH %d.%d must be refused, got %v", tc.major, tc.minor, err)
		}
		runner.mu.Lock()
		added := runner.addedKey != nil
		runner.mu.Unlock()
		if added {
			t.Errorf("OpenSSH %d.%d: the key was loaded despite no constraint support", tc.major, tc.minor)
		}
	}
	// 8.9 and newer are accepted.
	for _, tc := range []struct{ major, minor int }{{8, 9}, {9, 0}, {10, 1}} {
		spec, sc, _ := sshFixture(t)
		runner := &fakeSSHRunner{major: tc.major, minor: tc.minor}
		c, _ := sshRegistry(runner).Build(spec, staticSecrets{ref: "ssh-ops-key", value: sshPrivateKey})
		_, closer, err := c.BuildForSession(context.Background(), sc)
		if err != nil {
			t.Errorf("OpenSSH %d.%d supports constraints and must be accepted: %v", tc.major, tc.minor, err)
			continue
		}
		closer.Close()
	}
}

// TestSSHRefusesWhenTheVersionCannotBeDetermined: an unparsed banner means we do
// not know whether constraints are supported, and guessing yes would load a key
// unconstrained on a host that silently ignores the flag.
func TestSSHRefusesWhenTheVersionCannotBeDetermined(t *testing.T) {
	spec, sc, _ := sshFixture(t)
	runner := &fakeSSHRunner{versionErr: errors.New("cannot parse banner")}
	c, _ := sshRegistry(runner).Build(spec, staticSecrets{ref: "ssh-ops-key", value: sshPrivateKey})
	if _, _, err := c.BuildForSession(context.Background(), sc); !errors.Is(err, ErrDenied) {
		t.Fatalf("an undeterminable version must be refused, got %v", err)
	}
}

// TestSSHRefusesAnEmptyHostList: for every other kind an empty list is merely
// useless; here it would turn a constrained agent into an unconstrained one.
func TestSSHRefusesAnEmptyHostList(t *testing.T) {
	spec, _, _ := sshFixture(t)
	spec.Hosts = nil
	if _, err := sshRegistry(okRunner()).Build(spec, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("an ssh connection with no destinations must be refused, got %v", err)
	}
}

// TestSSHRefusesWorkspaceSourcedKnownHosts: if known_hosts could be read from the
// workspace, an agent with write access there could add host keys and WIDEN its
// own destination constraint — quietly converting a scoped key into a general one.
func TestSSHRefusesWorkspaceSourcedKnownHosts(t *testing.T) {
	spec, sc, _ := sshFixture(t)
	planted := filepath.Join(sc.WorkspaceDir, "known_hosts")
	if err := os.WriteFile(planted, []byte("evil-host ssh-ed25519 AAAA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec.Config = map[string]string{"known_hosts_path": planted}
	runner := okRunner()
	c, err := sshRegistry(runner).Build(spec, staticSecrets{ref: "ssh-ops-key", value: sshPrivateKey})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	_, _, err = c.BuildForSession(context.Background(), sc)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("workspace-sourced known_hosts must be refused, got %v", err)
	}
	runner.mu.Lock()
	added := runner.addedKey != nil
	runner.mu.Unlock()
	if added {
		t.Error("the key was loaded against workspace-controlled host keys")
	}
}

// TestSSHRequiresKnownHosts: without host keys there is nothing to anchor the
// constraint to.
func TestSSHRequiresKnownHosts(t *testing.T) {
	spec, _, _ := sshFixture(t)
	spec.Config = nil
	if _, err := sshRegistry(okRunner()).Build(spec, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a missing known_hosts_path must be refused, got %v", err)
	}
	spec.Config = map[string]string{"known_hosts_path": "relative/known_hosts"}
	if _, err := sshRegistry(okRunner()).Build(spec, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a relative known_hosts_path must be refused, got %v", err)
	}
}

// TestSSHFailsClosedOnAnUnresolvableSecret: a connection whose secret is missing
// injects NOTHING. There is no fallback that lets the session proceed.
func TestSSHFailsClosedOnAnUnresolvableSecret(t *testing.T) {
	spec, sc, _ := sshFixture(t)
	runner := okRunner()
	c, _ := sshRegistry(runner).Build(spec, staticSecrets{err: errors.New("vault unreadable")})
	inj, closer, err := c.BuildForSession(context.Background(), sc)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("an unresolvable secret must be refused, got %v", err)
	}
	if closer != nil {
		t.Error("a refused build must not return a closer")
	}
	if len(inj.Env) != 0 || len(inj.Files) != 0 {
		t.Errorf("a refused build must inject nothing, got %+v", inj)
	}
	runner.mu.Lock()
	starts := runner.agentStarts
	runner.mu.Unlock()
	if starts != 0 {
		t.Error("no agent should be started before the secret resolves")
	}
}

// TestSSHTearsDownTheAgentAndSocket: nothing the kind allocated may outlive the
// session. A leftover socket is a live signing endpoint.
func TestSSHTearsDownTheAgentAndSocket(t *testing.T) {
	spec, sc, _ := sshFixture(t)
	runner := okRunner()
	c, _ := sshRegistry(runner).Build(spec, staticSecrets{ref: "ssh-ops-key", value: sshPrivateKey})
	inj, closer, err := c.BuildForSession(context.Background(), sc)
	if err != nil {
		t.Fatalf("BuildForSession: %v", err)
	}
	sock := inj.Env["SSH_AUTH_SOCK"]
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("the socket should exist while the session lives: %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !runner.stopped() {
		t.Error("the agent must be stopped")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("the socket must be removed at teardown; a leftover socket is a live signing endpoint (stat err = %v)", err)
	}
	if _, err := os.Stat(filepath.Dir(sock)); !os.IsNotExist(err) {
		t.Error("the socket directory must be removed too")
	}
}

// TestSSHCleansUpWhenAddKeyFails: a started agent must not be left running by a
// failure after it started.
func TestSSHCleansUpWhenAddKeyFails(t *testing.T) {
	spec, sc, _ := sshFixture(t)
	runner := okRunner()
	runner.addErr = errors.New("ssh-add refused the constraints")
	c, _ := sshRegistry(runner).Build(spec, staticSecrets{ref: "ssh-ops-key", value: sshPrivateKey})
	if _, _, err := c.BuildForSession(context.Background(), sc); !errors.Is(err, ErrDenied) {
		t.Fatalf("a failed key load must be refused, got %v", err)
	}
	if !runner.stopped() {
		t.Error("the agent must be stopped when the key cannot be loaded")
	}
	runner.mu.Lock()
	sock := runner.sockPath
	runner.mu.Unlock()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Error("the socket must be removed when the key cannot be loaded")
	}
}

// TestSSHProducesNoEgressRules: ssh is not HTTP; nothing is injected at the L7
// proxy for it.
func TestSSHProducesNoEgressRules(t *testing.T) {
	spec, _, _ := sshFixture(t)
	c, _ := sshRegistry(okRunner()).Build(spec, nil)
	if rules := c.EgressRules(); len(rules) != 0 {
		t.Errorf("ssh must contribute no egress rules, got %+v", rules)
	}
}

// TestRealRunnerRefusesAnUnconstrainedAdd is defence in code: the kind already
// refuses an empty host list, but AddKey must not be the place that quietly loads
// a key with no -h flag.
func TestRealRunnerRefusesAnUnconstrainedAdd(t *testing.T) {
	err := realSSHRunner{}.AddKey(context.Background(), "/tmp/nope.sock", []byte("key"), nil, "/etc/ssh/known_hosts")
	if err == nil {
		t.Fatal("AddKey with no destinations must refuse rather than load the key unconstrained")
	}
	if !strings.Contains(err.Error(), "destination constraint") {
		t.Errorf("the refusal must name the reason: %v", err)
	}
}
