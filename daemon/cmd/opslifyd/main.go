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
	"path/filepath"
	"syscall"
	"time"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/opslify-com/opslifyd/internal/env"
	"github.com/opslify-com/opslifyd/internal/install"
	"github.com/opslify-com/opslifyd/internal/session"
	"github.com/opslify-com/opslifyd/internal/session/egress"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
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
		configPath       = flag.String("config", install.DefaultConfigPath, "daemon config path")
		socketPath       = flag.String("socket", daemon.DefaultSocketPath, "REST API Unix socket path")
		socketGroup      = flag.String("socket-group", daemon.DefaultSocketGroup, "group that owns the socket (empty to skip chown)")
		envBaseDir       = flag.String("env-dir", env.DefaultBaseDir, "toolchain attestation/artifact root (F0.2)")
		insecureNoEgress = flag.Bool("insecure-no-egress", false,
			"DEV/INSECURE: run with UNENFORCED egress (no default-deny) when nftables is unavailable. Never use in production.")
	)
	flag.Parse()

	// Env override for the insecure opt-out (e.g. container/CI dev), so the choice
	// can be set without editing the unit file; the CLI flag remains primary.
	insecure := *insecureNoEgress || os.Getenv("OPSLIFY_INSECURE_NO_EGRESS") == "1"

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

	// Wire F1.4 default-deny egress. The daemon FAILS CLOSED: if nftables can't be
	// programmed here, it refuses to start rather than silently serving sandboxes
	// with unconstrained network. `--insecure-no-egress` (or OPSLIFY_INSECURE_NO_EGRESS=1)
	// is the explicit dev opt-out that permits an UNENFORCED Noop, and it logs loudly.
	egressCtl, egressStop, err := buildEgress(cfg, log, insecure)
	if err != nil {
		return err
	}
	defer egressStop()

	mgr, err := buildSessionManager(cfg, log, egressCtl)
	if err != nil {
		return err
	}

	d, err := daemon.New(daemon.Options{
		Config:      cfg,
		SocketPath:  *socketPath,
		SocketGroup: *socketGroup,
		Verifier:    verifier,
		Sessions:    mgr,
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

	// Reap any sandboxes orphaned by a previous daemon lifetime before serving,
	// then run the TTL reaper for the duration; destroy live sessions on exit.
	if _, err := mgr.Reconcile(ctx); err != nil {
		return err
	}
	mgr.StartReaper(30 * time.Second)
	// Pre-warm the pool AFTER reconcile (so a restart's orphans are reaped first)
	// and before serving, so the first claim hits a warm container.
	mgr.StartWarmPool()
	defer mgr.Shutdown(context.Background())

	return d.Run(ctx)
}

// buildSessionManager wires the F1.2 session manager from config. It applies the
// hard-spec resource caps (pids 256, mem 2G, cpu 2) so no session is unbounded,
// derives the state dir alongside the workspace root (durable across restarts
// for orphan reconciliation), and parses the configured idle TTL.
func buildSessionManager(cfg install.Config, log *slog.Logger, egressCtl egress.Controller) (*session.Manager, error) {
	ttl, err := time.ParseDuration(orDefault(cfg.SessionTTL, install.DefaultSessionTTL))
	if err != nil {
		return nil, fmt.Errorf("opslifyd: invalid session_ttl %q: %w", cfg.SessionTTL, err)
	}
	stateDir := filepath.Join(filepath.Dir(cfg.WorkspaceDir), "sessions")
	return session.NewManager(session.Options{
		Config: session.ManagerConfig{
			Image:               cfg.Image,
			ToolchainDigest:     cfg.ToolchainDigest,
			WorkspaceRoot:       cfg.WorkspaceDir,
			StateDir:            stateDir,
			DefaultTier:         runtime.Tier(cfg.Tier),
			DefaultTTL:          ttl,
			Limits:              runtime.ResourceLimits{MemoryBytes: 2 << 30, CPUs: 2, PidsLimit: 256},
			WarmPoolSize:        cfg.WarmPoolSize,
			WarmPoolConcurrency: cfg.WarmPoolConcurrency,
		},
		Egress: egressCtl,
		Logger: log,
	})
}

// buildEgress wires the F1.4 egress controller from the configured allowlist. It
// FAILS CLOSED: if nftables cannot be programmed here, it returns an error and the
// daemon refuses to start — never silently serving sandboxes with unconstrained
// network. The `insecure` opt-out (from --insecure-no-egress) is the only way to
// run with an UNENFORCED egress.Noop, and that path warns loudly. Returns the
// Controller the Manager calls plus a stop func to run on shutdown.
func buildEgress(cfg install.Config, log *slog.Logger, insecure bool) (egress.Controller, func(), error) {
	ctl := egress.NewController(egress.Config{
		Allowlist: cfg.EgressAllowlist,
		Logger:    log,
	})
	decision, avail := egressDecision(ctl.Available(), insecure)
	switch decision {
	case egressInsecureNoop:
		log.Warn("EGRESS NOT ENFORCED: nftables unavailable; sandboxes will have UNCONSTRAINED network. Run the daemon as root with nft installed for default-deny egress.", "err", avail, "insecure_opt_out", true)
		return egress.Noop{}, func() {}, nil
	case egressFailClosed:
		return nil, func() {}, fmt.Errorf("opslifyd: egress: default-deny egress cannot be enforced (nftables unavailable): %w; run the daemon as root with nft installed, or pass --insecure-no-egress (OPSLIFY_INSECURE_NO_EGRESS=1) to run WITHOUT egress enforcement in dev", avail)
	}

	if err := ctl.Start(context.Background()); err != nil {
		return nil, func() {}, fmt.Errorf("opslifyd: egress: controller failed to start: %w", err)
	}
	log.Info("egress: default-deny enforcement active (nftables)", "allowlist_entries", len(cfg.EgressAllowlist))
	return ctl, ctl.Close, nil
}

// egressMode is the outcome of the egress wiring decision, factored out so the
// fail-closed-by-default / insecure-opt-out policy is unit-testable without a real
// nft binary or root.
type egressMode int

const (
	// egressEnforce: nftables is available → program real default-deny egress.
	egressEnforce egressMode = iota
	// egressFailClosed: unavailable and no opt-out → refuse to start.
	egressFailClosed
	// egressInsecureNoop: unavailable but the operator opted out → unenforced Noop.
	egressInsecureNoop
)

// egressDecision maps (availability, insecure-opt-out) to the wiring mode. When nft
// is available, enforcement wins regardless of the flag (the flag only lets an
// UNAVAILABLE host degrade instead of failing closed). It passes the availability
// error through so the caller can log/wrap it.
func egressDecision(availErr error, insecure bool) (egressMode, error) {
	if availErr == nil {
		return egressEnforce, nil
	}
	if insecure {
		return egressInsecureNoop, availErr
	}
	return egressFailClosed, availErr
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
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
