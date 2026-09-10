package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/opslify-com/opslifyd/internal/install"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/project"
	"github.com/opslify-com/opslifyd/internal/session"
	"github.com/opslify-com/opslifyd/internal/session/egress"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// No toolchain digest configured => fail-closed DenyVerifier (never serves an
// unverified toolchain).
func TestBuildVerifierFailsClosedWithoutDigest(t *testing.T) {
	v, err := buildVerifier(install.Config{}, t.TempDir(), false)
	if err != nil {
		t.Fatalf("buildVerifier: %v", err)
	}
	if err := v.VerifyToolchain(context.Background()); err == nil {
		t.Fatal("expected DenyVerifier to refuse when no toolchain digest is configured")
	}
}

// --dev-skip-verify (skip=true) returns a pass verifier even with no digest,
// so a dev box without nix/cosign can serve. Fail-closed remains the default
// (skip=false), asserted by the tests above.
func TestBuildVerifierDevSkip(t *testing.T) {
	v, err := buildVerifier(install.Config{}, t.TempDir(), true)
	if err != nil {
		t.Fatalf("buildVerifier: %v", err)
	}
	if err := v.VerifyToolchain(context.Background()); err != nil {
		t.Fatalf("dev-skip-verify must pass, got: %v", err)
	}
}

// A configured digest with no matching attestation on disk => startup error
// (legible), not a silent pass.
func TestBuildVerifierMissingAttestation(t *testing.T) {
	cfg := install.Config{ToolchainDigest: "sha256:doesnotexist"}
	if _, err := buildVerifier(cfg, t.TempDir(), false); err == nil {
		t.Fatal("expected error locating a missing toolchain attestation")
	}
}

// sdNotifyReady is a no-op when NOTIFY_SOCKET is unset — must not panic or block.
func TestSdNotifyReadyNoSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	sdNotifyReady()
}

// F1.4 hardening: egress is fail-closed by default. The decision function maps
// (nft availability, insecure opt-out) to the wiring mode with no real nft/root.
func TestEgressDecision(t *testing.T) {
	unavailable := errors.New("nft not usable")

	// nft available => enforce, regardless of the insecure flag.
	if mode, _ := egressDecision(nil, false); mode != egressEnforce {
		t.Fatalf("available+no-flag: want enforce, got %v", mode)
	}
	if mode, _ := egressDecision(nil, true); mode != egressEnforce {
		t.Fatalf("available+flag: want enforce (flag must not weaken an enforceable host), got %v", mode)
	}

	// nft unavailable + no opt-out => FAIL CLOSED (daemon must refuse to start).
	if mode, err := egressDecision(unavailable, false); mode != egressFailClosed {
		t.Fatalf("unavailable+no-flag: want fail-closed, got %v", mode)
	} else if err == nil {
		t.Fatal("fail-closed must pass the availability error through for a legible fatal")
	}

	// nft unavailable + explicit opt-out => unenforced Noop (dev only).
	if mode, _ := egressDecision(unavailable, true); mode != egressInsecureNoop {
		t.Fatalf("unavailable+flag: want insecure-noop, got %v", mode)
	}
}

// buildEgress refuses to start (returns an error, nil controller) when nft is
// unavailable and the insecure opt-out is NOT set — the production default.
func TestBuildEgressFailsClosedByDefault(t *testing.T) {
	// Only meaningful where nft genuinely can't be programmed (the CI/dev norm:
	// no root/nft). Skip on a host that CAN enforce, so the test is deterministic.
	if (egress.NftRunner{}).Available() == nil {
		t.Skip("nft is enforceable here; fail-closed path not exercised")
	}
	cfg := install.Config{EgressAllowlist: []string{"example.com"}}
	ctl, stop, err := buildEgress(cfg, discardLog(), false)
	if err == nil {
		if stop != nil {
			stop()
		}
		t.Fatal("want fail-closed error when nft unavailable and no opt-out")
	}
	if ctl != nil {
		t.Fatalf("want nil controller on fail-closed, got %T", ctl)
	}
}

// --- F8.3 composition root ---------------------------------------------------
//
// These tests exist because the wiring itself was the untested part: unwiring
// SecretsSvc from the daemon's Options, or dropping the policy source from the
// consumer index, left the in-use delete guard inoperative IN PRODUCTION with a
// fully green suite. Unit tests over the service cannot see that.

func secretsWiringConfig() install.Config {
	return install.Config{
		EgressInject: []install.EgressInjectRule{
			{Host: "gitlab.example.com", SecretRef: "gitlab-token", HeaderName: "PRIVATE-TOKEN"},
		},
		RegistryProxy: install.RegistryProxyConfig{
			Upstreams: []install.RegistryUpstream{{Ecosystem: "npm", CredRef: "npm-token"}},
		},
	}
}

// TestSecretsServiceIndexesConfigAndPolicyConsumers pins that buildSecretsService
// registers BOTH sources. Dropping the policy source made every grant-only
// credential look unused, so a delete of a secret a running policy still grants
// was permitted without a warning.
func TestSecretsServiceIndexesConfigAndPolicyConsumers(t *testing.T) {
	base := policy.Policy{Creds: []policy.Cred{{Name: "grant-only-token", Provider: "azure"}}}
	svc := mustBuildSecretsService(t, secretsWiringConfig(), nil, newTestProjectService(t), base)

	for _, tc := range []struct {
		ref  string
		kind broker.ConsumerKind
		why  string
	}{
		{"gitlab-token", broker.ConsumerEgressInject, "an egress-inject rule"},
		{"npm-token", broker.ConsumerRegistryUpstream, "a registry upstream"},
		{"grant-only-token", broker.ConsumerPolicyGrant, "a policy grant"},
	} {
		cs, err := svc.Consumers(tc.ref)
		if err != nil {
			t.Fatalf("Consumers(%s): %v", tc.ref, err)
		}
		if len(cs) == 0 {
			t.Errorf("%s must be reported as a consumer of %q; the delete guard is blind to it otherwise", tc.why, tc.ref)
			continue
		}
		if cs[0].Kind != tc.kind {
			t.Errorf("Consumers(%s) kind = %q, want %q", tc.ref, cs[0].Kind, tc.kind)
		}
	}
}

// TestDaemonOptionsWireSecretsService pins that the binary's composition root
// actually hands the service to the daemon. Without SecretsSvc the route falls
// back to the unguarded delete path.
func TestDaemonOptionsWireSecretsService(t *testing.T) {
	cfg := secretsWiringConfig()
	svc := mustBuildSecretsService(t, cfg, nil, newTestProjectService(t), policy.Policy{})
	opts := daemonOptions(cfg, "/run/opslify/api.sock", "opslify", nil, nil, nil, nil, svc, nil, discardLog())

	if opts.SecretsSvc == nil {
		t.Fatal("daemon.Options.SecretsSvc is nil: the in-use delete guard is not wired into the running daemon")
	}
	if opts.SecretsSvc != svc {
		t.Error("daemon.Options.SecretsSvc must be the service built from live config and policy")
	}
}

// TestDaemonOptionsCarryEveryStatefulDependency guards the WHOLE literal. The
// first version of this test passed nil for mgr, projects and verifier, so it
// could not assert them — and dropping any of those three from daemonOptions
// survived the entire suite, silently disabling the project API, the session API
// or toolchain verification in production. Every dependency is now passed as a
// real non-nil value and asserted to arrive.
func TestDaemonOptionsCarryEveryStatefulDependency(t *testing.T) {
	cfg := secretsWiringConfig()
	vault := &noopSecretManager{}
	svc := mustBuildSecretsService(t, cfg, vault, newTestProjectService(t), policy.Policy{})
	projects := newTestProjectService(t)
	mgr := &session.Manager{}
	verifier := stubVerifier{}

	opts := daemonOptions(cfg, "/run/opslify/api.sock", "opslify", verifier, mgr, projects, vault, svc, nil, discardLog())

	if opts.SocketPath != "/run/opslify/api.sock" {
		t.Errorf("SocketPath = %q", opts.SocketPath)
	}
	if opts.SocketGroup != "opslify" {
		t.Errorf("SocketGroup = %q", opts.SocketGroup)
	}
	if opts.Secrets == nil {
		t.Error("Secrets (the narrow Put/List/Delete surface) must be wired")
	}
	if opts.SecretsSvc == nil {
		t.Error("SecretsSvc must be wired, or the in-use delete guard is inoperative")
	}
	if opts.Projects != projects {
		t.Error("Projects must be wired, or the F8.1 project/environment API is silently disabled")
	}
	if opts.Sessions != mgr {
		t.Error("Sessions must be wired, or the session API is silently disabled")
	}
	if opts.Verifier == nil {
		t.Error("Verifier must be wired, or the daemon serves an unverified toolchain")
	}
	if opts.Logger == nil {
		t.Error("Logger must be wired")
	}
	if opts.Ready == nil {
		t.Error("Ready must be wired, or systemd never sees the daemon come up")
	}
}

// newTestProjectService builds a real project.Service over a temp state dir, so
// the wiring tests exercise the actual type rather than nil.
func mustBuildSecretsService(t *testing.T, cfg install.Config, vault broker.SecretManager, projects *project.Service, base policy.Policy) *broker.SecretsService {
	t.Helper()
	svc, err := buildSecretsService(cfg, vault, projects, base, newTestConnService(t))
	if err != nil {
		t.Fatalf("buildSecretsService: %v", err)
	}
	return svc
}

// TestSecretsServiceRequiresProjectService: a nil project service limited the
// consumer index to the daemon baseline, so a credential a project or
// environment layer still granted reported zero consumers and its delete was
// permitted without a 409. The daemon always has one, so nil is a wiring bug and
// must fail loudly at startup rather than degrade the guard in silence.
func TestSecretsServiceRequiresProjectService(t *testing.T) {
	if _, err := buildSecretsService(secretsWiringConfig(), nil, nil, policy.Policy{}, newTestConnService(t)); err == nil {
		t.Fatal("a nil project service must be refused, not silently accepted")
	}
}

// newTestConnService builds a real ConnectionService over a temp store, so the
// wiring tests exercise the actual type.
func newTestConnService(t *testing.T) *broker.ConnectionService {
	t.Helper()
	store, err := broker.NewConnectionStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewConnectionStore: %v", err)
	}
	svc, err := broker.NewConnectionService(store, broker.DefaultRegistry(nil), nil)
	if err != nil {
		t.Fatalf("NewConnectionService: %v", err)
	}
	return svc
}

func newTestProjectService(t *testing.T) *project.Service {
	t.Helper()
	store, err := project.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	svc, err := project.NewService(project.Options{Store: store, Logger: discardLog()})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// TestSecretsServiceIndexesPerEnvironmentPolicyGrants covers the limb of
// buildSecretsService that enumerates projects and environments. It had ZERO
// coverage: passing projects=nil, or making a ResolveScope error `continue`,
// survived the whole suite.
//
// Note on semantics: an environment overlay CANNOT introduce a grant the daemon
// baseline lacks — policy.Resolve intersects creds, narrows-never-widens. So the
// property under test is not "a new grant appears" but "the per-environment
// layers are enumerated at all", which is observable in the consumer's SCOPE
// label. With the enumeration dropped, the same ref is still reported (via the
// baseline) but with no scope, and an operator can no longer tell WHICH
// environment a delete would break.
func TestSecretsServiceIndexesPerEnvironmentPolicyGrants(t *testing.T) {
	base := policy.Policy{Creds: []policy.Cred{
		{Name: "prod-token", Provider: "azure"},
		{Name: "staging-token", Provider: "azure"},
	}}
	// The overlay narrows prod to just prod-token.
	overlay := filepath.Join(t.TempDir(), "prod.policy.yaml")
	if err := os.WriteFile(overlay, []byte("creds:\n  - name: prod-token\n    provider: azure\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	projects := newTestProjectService(t)
	if _, _, err := projects.CreateProject(project.ProjectSpec{
		Name: "tripon",
		Environments: []project.EnvironmentSpec{
			{Name: "prod", PolicyOverlay: overlay, Production: true},
		},
	}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	svc := mustBuildSecretsService(t, secretsWiringConfig(), nil, projects, base)
	cs, err := svc.Consumers("prod-token")
	if err != nil {
		t.Fatalf("Consumers: %v", err)
	}
	var scopes []string
	for _, c := range cs {
		scopes = append(scopes, c.Scope)
	}
	if !slices.Contains(scopes, "tripon/prod") {
		t.Fatalf("the per-environment policy layers were not enumerated: consumer scopes = %v, want one naming tripon/prod", scopes)
	}
	for _, c := range cs {
		if c.Kind != broker.ConsumerPolicyGrant {
			t.Errorf("kind = %q, want %q", c.Kind, broker.ConsumerPolicyGrant)
		}
	}
}

// TestSecretsServiceFailsClosedOnUnresolvableScope: a scope that cannot resolve
// must make the whole index error, not silently drop its grants. Under-reporting
// is what lets a delete break a live grant.
func TestSecretsServiceFailsClosedOnUnresolvableScope(t *testing.T) {
	// A policy overlay path that does not exist: LoadLayer is fail-closed, so
	// ResolveScope errors for this environment.
	missing := filepath.Join(t.TempDir(), "gone.policy.yaml")
	projects := newTestProjectService(t)
	if _, _, err := projects.CreateProject(project.ProjectSpec{
		Name:         "tripon",
		Environments: []project.EnvironmentSpec{{Name: "prod", PolicyOverlay: missing}},
	}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	svc := mustBuildSecretsService(t, secretsWiringConfig(), nil, projects, policy.Policy{})
	if _, err := svc.Consumers("anything"); err == nil {
		t.Fatal("an unresolvable scope must fail the consumer index closed, not drop its grants")
	}
}

// stubVerifier stands in for the toolchain verifier: the wiring test only needs a
// non-nil value it can compare against.
type stubVerifier struct{}

func (stubVerifier) VerifyToolchain(context.Context) error { return nil }

type noopSecretManager struct{}

func (noopSecretManager) Put(context.Context, string, []byte, broker.PutMeta, bool) error { return nil }
func (noopSecretManager) List(context.Context) ([]broker.SecretMeta, error)               { return nil, nil }
func (noopSecretManager) Delete(context.Context, string) error                            { return nil }

// TestBuildDaemonOptionsWiresTheWholeSurface pins N4: the composition root's own
// arguments. Before this, run() passed basePolicy, vault and secretsSvc by hand,
// and three mutations there were SILENT — the daemon started normally with the
// delete guard degraded or the secrets surface absent entirely:
//
//	basePolicy -> policy.Policy{}  : baseline grants vanish from the consumer
//	                                 index, so deleting a granted secret gets no 409
//	secretsSvc -> nil              : no rotate route, unguarded delete
//	vault      -> nil              : secrets routes 404
func TestBuildDaemonOptionsWiresTheWholeSurface(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "opslify.policy.yaml")
	// A baseline grant: it must reach the consumer index through the composition
	// root, or a delete of this ref is permitted with no warning.
	if err := os.WriteFile(policyPath, []byte("creds:\n  - name: baseline-token\n    provider: azure\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := secretsWiringConfig()
	cfg.PolicyFile = policyPath

	vault := &noopSecretManager{}
	projects := newTestProjectService(t)
	mgr := &session.Manager{}

	opts, err := buildDaemonOptions(cfg, "/run/opslify/api.sock", "opslify", stubVerifier{}, mgr, projects, vault, newTestConnService(t), discardLog())
	if err != nil {
		t.Fatalf("buildDaemonOptions: %v", err)
	}
	if opts.SecretsSvc == nil {
		t.Fatal("SecretsSvc is nil: the in-use delete guard is absent from the running daemon")
	}
	if opts.Secrets == nil {
		t.Fatal("Secrets is nil: every secret route would 404")
	}
	if opts.Projects != projects || opts.Sessions != mgr || opts.Verifier == nil {
		t.Error("a dependency was dropped between run() and daemon.New")
	}
	// The DAEMON BASELINE's grants must be indexed. This is what catches the
	// baseline being replaced by an empty policy — the mutation that leaves every
	// baseline-granted credential looking unused.
	cs, err := opts.SecretsSvc.Consumers("baseline-token")
	if err != nil {
		t.Fatalf("Consumers: %v", err)
	}
	if len(cs) == 0 {
		t.Fatal("the daemon policy baseline was not indexed: a credential it grants reports zero consumers, so its delete is permitted with no 409")
	}
	if cs[0].Kind != broker.ConsumerPolicyGrant {
		t.Errorf("kind = %q, want %q", cs[0].Kind, broker.ConsumerPolicyGrant)
	}
	// And the config-derived consumers must still be there alongside them.
	if cs, err := opts.SecretsSvc.Consumers("gitlab-token"); err != nil || len(cs) == 0 {
		t.Errorf("the egress-inject consumer was lost: %v %v", cs, err)
	}
}

// TestBuildDaemonOptionsFailsClosedOnABadPolicy: a configured-but-invalid policy
// must abort startup, never fall back to the permissive built-in.
func TestBuildDaemonOptionsFailsClosedOnABadPolicy(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "opslify.policy.yaml")
	if err := os.WriteFile(bad, []byte("creds: [this is not a cred list\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := secretsWiringConfig()
	cfg.PolicyFile = bad
	if _, err := buildDaemonOptions(cfg, "/s", "g", stubVerifier{}, nil, newTestProjectService(t), &noopSecretManager{}, newTestConnService(t), discardLog()); err == nil {
		t.Fatal("an invalid daemon policy must abort startup, not fall back to a permissive default")
	}
}

// --- F8.2 composition root ---------------------------------------------------
//
// These exist because the composition root has been the weak spot on every
// feature so far: building a service correctly is worthless if nothing hands it
// to the thing that uses it, and an inlined literal makes that invisible to every
// test while the suite stays green.

// TestDaemonOptionsWireTheConnectionService: without it the connection routes are
// not registered at all, so `opslify connection add` fails against a daemon that
// otherwise looks healthy.
func TestDaemonOptionsWireTheConnectionService(t *testing.T) {
	conns := newTestConnService(t)
	opts, err := buildDaemonOptions(secretsWiringConfig(), "/run/opslify/api.sock", "opslify",
		stubVerifier{}, &session.Manager{}, newTestProjectService(t), &noopSecretManager{}, conns, discardLog())
	if err != nil {
		t.Fatalf("buildDaemonOptions: %v", err)
	}
	if opts.Connections == nil {
		t.Fatal("Connections is nil: the F8.2 routes are not registered, so every connection command fails")
	}
}

// TestSecretsServiceIndexesConnectionConsumers is the cross-feature guarantee.
// The F8.3 delete guard must be complete the moment a connection can exist — not
// retrofitted after an operator has deleted a credential that was in use.
func TestSecretsServiceIndexesConnectionConsumers(t *testing.T) {
	conns := newTestConnService(t)
	if err := conns.Add(broker.ConnectionSpec{
		Name: "gitlab", Kind: broker.KindHTTP, SecretRef: "gitlab-token",
		Hosts: []string{"gitlab.example.com"}, ProjectID: "tripon", EnvironmentID: "tripon.prod",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	svc, err := buildSecretsService(secretsWiringConfig(), nil, newTestProjectService(t), policy.Policy{}, conns)
	if err != nil {
		t.Fatalf("buildSecretsService: %v", err)
	}
	cs, err := svc.Consumers("gitlab-token")
	if err != nil {
		t.Fatalf("Consumers: %v", err)
	}
	var found bool
	for _, c := range cs {
		if c.Kind == broker.ConsumerConnection {
			found = true
			if c.Scope != "tripon.prod" {
				t.Errorf("the consumer must name which environment would break, got %q", c.Scope)
			}
		}
	}
	if !found {
		t.Fatalf("a connection's secret must be reported as in use; consumers = %+v", cs)
	}
}

// TestSecretsServiceRequiresTheConnectionService: a nil one silently drops every
// connection from the consumer index, so a credential a live connection depends
// on reports zero consumers and its delete is permitted without a 409.
func TestSecretsServiceRequiresTheConnectionService(t *testing.T) {
	_, err := buildSecretsService(secretsWiringConfig(), nil, newTestProjectService(t), policy.Policy{}, nil)
	if err == nil {
		t.Fatal("a nil connection service must be refused, not silently accepted")
	}
	if !strings.Contains(err.Error(), "connection") {
		t.Errorf("the refusal must name the missing dependency: %v", err)
	}
}

// TestSessionManagerRequiresAConnectionSource: without it every connection an
// operator defined is silently ignored, and the failure surfaces inside the
// agent's work rather than anywhere pointing at the cause.
func TestSessionManagerRequiresAConnectionSource(t *testing.T) {
	_, err := buildSessionManager(install.Config{}, discardLog(), nil, nil, nil, nil, nil, nil,
		newTestProjectService(t), nil)
	if err == nil {
		t.Fatal("a nil connection source must be refused at startup")
	}
	if !strings.Contains(err.Error(), "connection") {
		t.Errorf("the refusal must name the missing dependency: %v", err)
	}
}

// TestConnectionServiceUsesTheVaultAsAResolver: a kind resolves its credential
// daemon-side at build time. Without a resolver the ssh kind cannot load a key at
// all, and the failure would look like a broken connection rather than missing
// wiring.
func TestConnectionServiceUsesTheVaultAsAResolver(t *testing.T) {
	cfg := install.Config{WorkspaceDir: filepath.Join(t.TempDir(), "workspaces")}
	key := make([]byte, 32)
	v, err := broker.OpenVault(filepath.Join(t.TempDir(), "vault.db"), broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	svc, err := buildConnectionService(cfg, v, discardLog())
	if err != nil {
		t.Fatalf("buildConnectionService: %v", err)
	}
	if svc == nil {
		t.Fatal("nil service")
	}
	// A backend that cannot resolve is refused rather than accepted and later
	// mysterious.
	if _, err := buildConnectionService(cfg, &noopSecretManager{}, discardLog()); err == nil {
		t.Error("a backend with no resolve path must be refused: connection kinds need daemon-side resolution")
	}
}

// TestConnectionStoreLivesBesideTheProjectRecords: it names hosts and secret
// refs, which together describe an estate's shape, so it belongs in
// daemon-private state and not under the workspace the sandbox can reach.
func TestConnectionStoreLivesBesideTheProjectRecords(t *testing.T) {
	base := t.TempDir()
	cfg := install.Config{WorkspaceDir: filepath.Join(base, "workspaces")}
	key := make([]byte, 32)
	v, err := broker.OpenVault(filepath.Join(base, "vault.db"), broker.StaticKeySource(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildConnectionService(cfg, v, discardLog()); err != nil {
		t.Fatalf("buildConnectionService: %v", err)
	}
	dir := filepath.Join(base, "connections")
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("the connection store must be created outside the workspace: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("mode = %o, want 0700 (daemon-private)", info.Mode().Perm())
	}
	if strings.HasPrefix(dir, cfg.WorkspaceDir) {
		t.Error("the store must not live inside the workspace the sandbox can reach")
	}
}
