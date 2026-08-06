package main

import (
	"context"
	"testing"

	"github.com/opslify-com/opslifyd/internal/install"
)

// No toolchain digest configured => fail-closed DenyVerifier (never serves an
// unverified toolchain).
func TestBuildVerifierFailsClosedWithoutDigest(t *testing.T) {
	v, err := buildVerifier(install.Config{}, t.TempDir())
	if err != nil {
		t.Fatalf("buildVerifier: %v", err)
	}
	if err := v.VerifyToolchain(context.Background()); err == nil {
		t.Fatal("expected DenyVerifier to refuse when no toolchain digest is configured")
	}
}

// A configured digest with no matching attestation on disk => startup error
// (legible), not a silent pass.
func TestBuildVerifierMissingAttestation(t *testing.T) {
	cfg := install.Config{ToolchainDigest: "sha256:doesnotexist"}
	if _, err := buildVerifier(cfg, t.TempDir()); err == nil {
		t.Fatal("expected error locating a missing toolchain attestation")
	}
}

// sdNotifyReady is a no-op when NOTIFY_SOCKET is unset — must not panic or block.
func TestSdNotifyReadyNoSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	sdNotifyReady()
}
