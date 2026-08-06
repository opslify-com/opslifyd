// Command opslifyd is the Opslify daemon (F1.1). It loads /etc/opslify/config.yaml,
// verifies its signed toolchain before serving, and exposes the versioned REST
// API over a permissioned Unix socket, shutting down cleanly on SIGTERM.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/opslify-com/opslifyd/internal/env"
	"github.com/opslify-com/opslifyd/internal/install"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "opslifyd: fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", install.DefaultConfigPath, "daemon config path")
		socketPath  = flag.String("socket", daemon.DefaultSocketPath, "REST API Unix socket path")
		socketGroup = flag.String("socket-group", daemon.DefaultSocketGroup, "group that owns the socket (empty to skip chown)")
		envBaseDir  = flag.String("env-dir", env.DefaultBaseDir, "toolchain attestation/artifact root (F0.2)")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, err := install.LoadConfig(*configPath)
	if err != nil {
		return err
	}

	verifier, err := buildVerifier(cfg, *envBaseDir)
	if err != nil {
		return err
	}

	d, err := daemon.New(daemon.Options{
		Config:      cfg,
		SocketPath:  *socketPath,
		SocketGroup: *socketGroup,
		Verifier:    verifier,
		Ready:       sdNotifyReady,
		Version:     version,
		Logger:      log,
	})
	if err != nil {
		return err
	}

	// SIGTERM/SIGINT → cancel context → graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	return d.Run(ctx)
}

// buildVerifier wires the production verify-before-serve gate from F0.2. If the
// config carries no signed toolchain digest, it fails closed (DenyVerifier): the
// daemon must never serve an unverified toolchain. Otherwise it resolves the
// digest to its attestation and verifies via cosign (env.NewDefault) — which
// requires cosign on PATH, keeping the signed toolchain non-optional.
func buildVerifier(cfg install.Config, envBaseDir string) (daemon.ToolchainVerifier, error) {
	if cfg.ToolchainDigest == "" {
		return daemon.DenyVerifier("no signed toolchain digest in config (run `opslify init` to bake one)"), nil
	}
	store := env.NewStore(envBaseDir)
	att, err := store.FindAttestationByDigest(cfg.ToolchainDigest)
	if err != nil {
		return nil, fmt.Errorf("opslifyd: locate toolchain attestation: %w", err)
	}
	layer, err := att.SignedLayer()
	if err != nil {
		return nil, err
	}
	// The signer is the trust root; env.NewDefault requires cosign explicitly.
	builder, err := env.NewDefault(envBaseDir, "", "")
	if err != nil {
		return nil, fmt.Errorf("opslifyd: cannot build toolchain verifier: %w", err)
	}
	return daemon.NewEnvVerifier(builder, layer), nil
}

// sdNotifyReady sends systemd READY=1 if the daemon was socket/notify-activated.
// It is a no-op when NOTIFY_SOCKET is unset (interactive/test runs), so it adds
// no systemd dependency and never fails startup.
func sdNotifyReady() {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	// Abstract-namespace sockets start with '@'.
	name := addr
	if len(name) > 0 && name[0] == '@' {
		name = "\x00" + name[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("READY=1"))
}
