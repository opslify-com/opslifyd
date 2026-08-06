package egress

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner is the privileged seam: it applies an nftables script and probes whether
// nft can run here at all. Every operation requiring root or the `nft` binary goes
// through it, so the rest of the package (ruleset generation, resolver, ordering)
// is unit-testable with a fake Runner and needs neither. Production uses NftRunner
// (shell to `nft -f -`); tests use an in-memory fake that records scripts.
type Runner interface {
	// Apply feeds an nft script (as produced by buildApplyScript /
	// buildTeardownScript) to the kernel atomically. An error is returned verbatim
	// for the caller to wrap with the egress layer tag.
	Apply(ctx context.Context, script string) error
	// Available reports, with a legible error, whether nft can be programmed here
	// (binary present + sufficient privilege). Callers use it to fall back to an
	// unenforced posture LOUDLY rather than failing every session create.
	Available() error
}

// NftRunner is the production Runner: it shells to `nft -f -`, piping the script on
// stdin so nft applies it as one atomic transaction. Shelling (rather than the
// google/nftables netlink library) keeps the generated ruleset human-auditable and
// the seam trivially fakeable — a deliberate simplicity choice for a security-
// critical path where reviewing the exact rules matters more than a marginal perf
// win, and it adds no new dependency.
type NftRunner struct {
	// Bin is the nft binary; empty => "nft" on PATH.
	Bin string
}

func (r NftRunner) bin() string {
	if r.Bin == "" {
		return "nft"
	}
	return r.Bin
}

// Apply runs `nft -f -` with the script on stdin.
func (r NftRunner) Apply(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, r.bin(), "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Never echo the script back (it is not secret, but stderr is the legible
		// signal); surface nft's own diagnostic.
		return fmt.Errorf("nft apply: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Available probes for the nft binary and privilege by listing the ruleset, which
// requires the same access programming does. A missing binary or lack of privilege
// is reported legibly so the daemon can degrade with a warning instead of dying.
func (r NftRunner) Available() error {
	if _, err := exec.LookPath(r.bin()); err != nil {
		return fmt.Errorf("nft binary not found (%s): %w", r.bin(), err)
	}
	cmd := exec.Command(r.bin(), "list", "ruleset")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft not usable (need root/CAP_NET_ADMIN): %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

var _ Runner = NftRunner{}
