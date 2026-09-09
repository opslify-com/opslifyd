package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/install"
	"github.com/opslify-com/opslifyd/internal/policy"
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
	svc := buildSecretsService(secretsWiringConfig(), nil, nil, base)

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
	svc := buildSecretsService(cfg, nil, nil, policy.Policy{})
	opts := daemonOptions(cfg, "/run/opslify/api.sock", "opslify", nil, nil, nil, nil, svc, discardLog())

	if opts.SecretsSvc == nil {
		t.Fatal("daemon.Options.SecretsSvc is nil: the in-use delete guard is not wired into the running daemon")
	}
	if opts.SecretsSvc != svc {
		t.Error("daemon.Options.SecretsSvc must be the service built from live config and policy")
	}
}

// TestDaemonOptionsCarryEveryStatefulDependency guards the whole literal, not just
// the field this feature added: a dependency dropped here disables a subsystem
// silently at runtime.
func TestDaemonOptionsCarryEveryStatefulDependency(t *testing.T) {
	cfg := secretsWiringConfig()
	vault := &noopSecretManager{}
	svc := buildSecretsService(cfg, vault, nil, policy.Policy{})
	opts := daemonOptions(cfg, "/run/opslify/api.sock", "opslify", nil, nil, nil, vault, svc, discardLog())

	if opts.SocketPath != "/run/opslify/api.sock" {
		t.Errorf("SocketPath = %q", opts.SocketPath)
	}
	if opts.SocketGroup != "opslify" {
		t.Errorf("SocketGroup = %q", opts.SocketGroup)
	}
	if opts.Secrets == nil {
		t.Error("Secrets (the narrow Put/List/Delete surface) must be wired")
	}
	if opts.Logger == nil {
		t.Error("Logger must be wired")
	}
	if opts.Ready == nil {
		t.Error("Ready must be wired, or systemd never sees the daemon come up")
	}
}

type noopSecretManager struct{}

func (noopSecretManager) Put(context.Context, string, []byte, broker.PutMeta, bool) error { return nil }
func (noopSecretManager) List(context.Context) ([]broker.SecretMeta, error)               { return nil, nil }
func (noopSecretManager) Delete(context.Context, string) error                            { return nil }
