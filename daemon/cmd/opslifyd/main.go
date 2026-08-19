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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/opslify-com/opslifyd/internal/env"
	"github.com/opslify-com/opslifyd/internal/install"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/session"
	"github.com/opslify-com/opslifyd/internal/session/egress"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"github.com/opslify-com/opslifyd/internal/trace"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Subcommand dispatch: `opslifyd mcp` runs the F2.1 stdio MCP server (a client
	// of the daemon over its Unix socket), not the daemon itself. Everything else
	// is the daemon (default), preserving the existing flag-based entrypoint.
	if len(os.Args) > 1 && os.Args[1] == "mcp" {
		if err := runMCP(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "opslifyd mcp: fatal:", err)
			os.Exit(1)
		}
		return
	}
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
		devSkipVerify = flag.Bool("dev-skip-verify", false,
			"DEV/INSECURE: skip verify-before-serve (serve without a signed toolchain digest) for local testing without nix/cosign. Never use in production.")
	)
	flag.Parse()

	// Env override for the insecure opt-out (e.g. container/CI dev), so the choice
	// can be set without editing the unit file; the CLI flag remains primary.
	insecure := *insecureNoEgress || os.Getenv("OPSLIFY_INSECURE_NO_EGRESS") == "1"
	skipVerify := *devSkipVerify || os.Getenv("OPSLIFY_DEV_SKIP_VERIFY") == "1"

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, err := install.LoadConfig(*configPath)
	if err != nil {
		return err
	}

	verifier, err := buildVerifier(cfg, *envBaseDir, skipVerify)
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

	// Wire the F3.1 trace sink, signed by the daemon Ed25519 identity (F1.1). The
	// private key stays in-process; only the signature + fingerprint are recorded.
	// A signing-key load failure is fatal — a daemon that cannot seal its audit
	// trail must not serve (the trace is the evidentiary spine of P3).
	traceSink, traceStop, err := buildTraceSink(cfg, log)
	if err != nil {
		return err
	}
	defer traceStop()

	// Wire the F5.6 local encrypted vault (the default broker backend). It fails
	// CLOSED: a missing/short master key aborts startup rather than serving without a
	// vault. The vault is the value store; the broker gates + audits every resolve.
	vault, err := buildVault(cfg, log)
	if err != nil {
		return err
	}
	brk := broker.NewBroker(vault)

	// Wire the F5.1 executor-side credential injection: a loopback creds endpoint
	// (the fully credential-blind AWS container-credentials path) + the injector that
	// resolves granted creds and injects a scoped, TTL-bounded credential at exec.
	// The endpoint fails safe: if it cannot bind, the injector runs with no endpoint
	// and the AWS blind path fails closed (no raw-secret env fallback).
	credInjector, credStop := buildCredInjection(brk, log)
	defer credStop()

	// Wire the F5.4 Tier-2 OAuth2 adapter. Validate every per-service config
	// FAIL-CLOSED (a bad service aborts startup, never serves a broken adapter),
	// then register the single generic adapter for all configured services.
	if err := cfg.ValidateOAuth2(); err != nil {
		return err
	}
	if len(cfg.OAuth2) > 0 {
		credInjector.RegisterOAuth2Adapters(cfg.OAuth2, nil)
		log.Info("F5.4 oauth2 adapter active", "services", len(cfg.OAuth2))
	}

	mgr, err := buildSessionManager(cfg, log, egressCtl, traceSink, brk, credInjector)
	if err != nil {
		return err
	}

	d, err := daemon.New(daemon.Options{
		Config:      cfg,
		SocketPath:  *socketPath,
		SocketGroup: *socketGroup,
		Verifier:    verifier,
		Sessions:    mgr,
		Secrets:     vault, // narrow management surface (Put/List/Delete — no Get)
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
// buildTraceSink wires the F3.2 DURABLE trace sink: an append-only per-session log
// (the local source of truth, replayable across a daemon restart) plus the
// optional resumable cloud uploader. It seals with the daemon Ed25519 identity
// (F1.1); the private key stays in-process (fail-fast: absent / not-0600 refuses),
// so a seal is attributable to the daemon identity. It returns a stop func that
// halts the uploader and closes the log files on shutdown.
func buildTraceSink(cfg install.Config, log *slog.Logger) (trace.TraceSink, func(), error) {
	keyPath := cfg.IdentityKey
	if keyPath == "" {
		keyPath = install.DefaultIdentityKeyPath
	}
	priv, fp, err := install.LoadSigningKey(keyPath)
	if err != nil {
		return nil, func() {}, fmt.Errorf("opslifyd: load trace signing identity: %w", err)
	}
	slog.Info("trace signing identity loaded", "fingerprint", fp)

	traceDir := cfg.Trace.Dir
	if traceDir == "" {
		traceDir = install.DefaultTraceDir
	}
	sink, err := trace.NewFileSink(trace.FileSinkConfig{
		Dir:            traceDir,
		Fsync:          trace.FsyncPolicy(cfg.Trace.Fsync),
		RingBufferSize: cfg.Trace.RingBufferSize,
	}, trace.NewEd25519Signer(priv))
	if err != nil {
		return nil, func() {}, fmt.Errorf("opslifyd: build durable trace sink: %w", err)
	}
	log.Info("durable trace sink active", "dir", traceDir, "fsync", orDefault(cfg.Trace.Fsync, string(trace.FsyncBatch)))

	// Optional cloud push. With no URL configured NewUploader returns nil and
	// Start/Stop are no-ops — local persistence + SSE are entirely unaffected.
	up := trace.NewUploader(sink, trace.UploaderConfig{
		BackendURL: cfg.Trace.CloudURL,
		Dir:        traceDir,
		Logger:     log,
	})
	if up != nil {
		up.Start(context.Background())
		log.Info("trace cloud uploader active", "backend", cfg.Trace.CloudURL)
	}
	stop := func() {
		up.Stop()
		if err := sink.Close(); err != nil {
			log.Warn("trace sink close", "err", err)
		}
	}
	return sink, stop, nil
}

// buildVault opens the F5.6 local encrypted vault. It fails CLOSED: an absent or
// wrong-length master key (env OPSLIFY_VAULT_KEY / configured key_env), an
// insecure-perms vault file, or a malformed db aborts startup — the daemon never
// serves a broken or unencryptable vault. The master key is read from the env, so
// it is never written to config or to a plaintext file beside the db.
func buildVault(cfg install.Config, log *slog.Logger) (*broker.Vault, error) {
	path := cfg.Vault.Path
	if path == "" {
		path = broker.DefaultVaultPath
	}
	keyEnv := cfg.Vault.KeyEnv
	if keyEnv == "" {
		keyEnv = broker.DefaultVaultKeyEnv
	}
	v, err := broker.OpenVault(path, broker.EnvKeySource{Var: keyEnv})
	if err != nil {
		return nil, fmt.Errorf("opslifyd: open secret vault: %w (set %s to a 32-byte hex/base64 master key)", err, keyEnv)
	}
	log.Info("secret vault active", "path", path, "key_env", keyEnv)
	return v, nil
}

// buildCredInjection stands up the F5.1 loopback credential endpoint and injector.
// The endpoint serves each session a scoped, TTL-bounded credential body that the
// AWS CLI/SDK fetches unmodified via AWS_CONTAINER_CREDENTIALS_FULL_URI, so the raw
// secret is NEVER placed in the container env. It binds a pinned loopback address
// (never 0.0.0.0), so a host-network request cannot reach it; the in-sandbox→daemon
// network reachability (egress allowlist to the bridge gateway) is INTEGRATION-
// gated — the token/cross-session/expiry gates are unit-tested. If the listener
// cannot bind, injection runs WITHOUT an endpoint (the AWS blind path then fails
// closed), never falling back to a raw-secret env injection.
func buildCredInjection(brk *broker.Broker, log *slog.Logger) (*broker.Injector, func()) {
	server := broker.NewCredServer(time.Now)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Warn("F5.1 creds endpoint unavailable; AWS credential-blind path disabled (fail-closed, no env fallback)", "err", err)
		return broker.NewInjector(brk, nil, "", 0, time.Now), func() {}
	}
	baseURL := "http://" + ln.Addr().String()
	mux := http.NewServeMux()
	mux.Handle(broker.CredPath, server)
	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Warn("F5.1 creds endpoint serve stopped", "err", err)
		}
	}()
	log.Info("F5.1 creds endpoint active", "base_url", baseURL)
	injector := broker.NewInjector(brk, server, baseURL, 0, time.Now)
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
	return injector, stop
}

func buildSessionManager(cfg install.Config, log *slog.Logger, egressCtl egress.Controller, traceSink trace.TraceSink, brk *broker.Broker, credInjector *broker.Injector) (*session.Manager, error) {
	ttl, err := time.ParseDuration(orDefault(cfg.SessionTTL, install.DefaultSessionTTL))
	if err != nil {
		return nil, fmt.Errorf("opslifyd: invalid session_ttl %q: %w", cfg.SessionTTL, err)
	}
	approvalTTL, err := time.ParseDuration(orDefault(cfg.ApprovalTTL, install.DefaultApprovalTTL))
	if err != nil {
		return nil, fmt.Errorf("opslifyd: invalid approval_ttl %q: %w", cfg.ApprovalTTL, err)
	}
	stateDir := filepath.Join(filepath.Dir(cfg.WorkspaceDir), "sessions")
	// Load the daemon's trusted default policy (F4.1). Fail CLOSED: a configured
	// but invalid policy aborts startup rather than serving with a permissive one.
	defaultPolicy := policy.Default()
	if cfg.PolicyFile != "" {
		p, err := policy.Load(cfg.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("opslifyd: load default policy %q: %w", cfg.PolicyFile, err)
		}
		defaultPolicy = p
	}
	return session.NewManager(session.Options{
		Config: session.ManagerConfig{
			Image:               cfg.Image,
			ToolchainDigest:     cfg.ToolchainDigest,
			WorkspaceRoot:       cfg.WorkspaceDir,
			StateDir:            stateDir,
			DefaultTier:         runtime.Tier(cfg.Tier),
			DefaultTTL:          ttl,
			ApprovalTTL:         approvalTTL,
			Limits:              runtime.ResourceLimits{MemoryBytes: 2 << 30, CPUs: 2, PidsLimit: 256},
			WarmPoolSize:        cfg.WarmPoolSize,
			WarmPoolConcurrency: cfg.WarmPoolConcurrency,
			DefaultPolicy:       defaultPolicy,
			DryRun:              true, // F4.4: preview destructive ops before the approval pause
		},
		Egress:       egressCtl,
		Logger:       log,
		Trace:        traceSink,
		Redactor:     buildRedactor(cfg), // F3.3: config-driven secret scrubber
		Broker:       brk,                // F5.6: policy-gated, audited secret resolution
		CredInjector: credInjector,       // F5.1: executor-side credential injection
	})
}

// buildRedactor wires the F3.3 secret scrubber from config into the emit seam
// (Recorder runs it BEFORE the sink hashes, so the chain commits to redacted
// bytes). It fails SAFE: an absent/zero redaction section yields the code
// defaults with every pattern enabled — redaction is never off by omission.
func buildRedactor(cfg install.Config) trace.Redactor {
	return trace.NewPatternRedactor(trace.RedactorConfig{
		EntropyThreshold:   cfg.Redaction.EntropyThreshold,
		EntropyLengthFloor: cfg.Redaction.EntropyLengthFloor,
		DisabledPatterns:   cfg.Redaction.DisabledPatterns,
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
func buildVerifier(cfg install.Config, envBaseDir string, skipVerify bool) (daemon.ToolchainVerifier, error) {
	if skipVerify {
		slog.Warn("DEV/INSECURE: verify-before-serve DISABLED via --dev-skip-verify; serving an UNVERIFIED toolchain. Never use this in production.")
		return daemon.VerifierFunc(func(context.Context) error { return nil }), nil
	}
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
