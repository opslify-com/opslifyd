package broker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// realSSHRunner drives the local OpenSSH tooling.
type realSSHRunner struct{}

// sshVersionRe matches the version banner `ssh -V` writes to STDERR, e.g.
// "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13".
var sshVersionRe = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)

func (realSSHRunner) Version(ctx context.Context) (int, int, error) {
	cmd := exec.CommandContext(ctx, "ssh", "-V")
	var out bytes.Buffer
	// `ssh -V` writes to stderr, not stdout.
	cmd.Stderr = &out
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return 0, 0, fmt.Errorf("run ssh -V: %w", err)
	}
	m := sshVersionRe.FindStringSubmatch(out.String())
	if m == nil {
		// Refuse rather than assume. An unparsed banner means we do not know whether
		// destination constraints are supported, and guessing "yes" would load a key
		// unconstrained on a host that silently ignores the flag.
		return 0, 0, fmt.Errorf("cannot parse an OpenSSH version from %q", strings.TrimSpace(out.String()))
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major, minor, nil
}

func (realSSHRunner) StartAgent(ctx context.Context, sockPath string) (io.Closer, error) {
	// -D keeps the agent in the foreground so its lifetime is ours to manage: a
	// daemonised agent would outlive the session unless we tracked its pid, and a
	// leaked agent is a live signing endpoint.
	cmd := exec.Command("ssh-agent", "-D", "-a", sockPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ssh-agent: %w", err)
	}
	// Wait for the socket to appear before the key is added, or ssh-add races the
	// agent's bind and fails intermittently.
	if err := waitForSocket(ctx, sockPath); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, err
	}
	return &processCloser{cmd: cmd}, nil
}

func (realSSHRunner) AddKey(ctx context.Context, sockPath string, key []byte, destinations []string, knownHostsPath string) error {
	if len(destinations) == 0 {
		// Defence in code. The kind already refuses this, but ssh-add with no -h
		// would load the key UNCONSTRAINED, and this function must not be the place
		// that quietly does so.
		return fmt.Errorf("refusing to add a key with no destination constraint")
	}
	args := []string{"-H", knownHostsPath}
	for _, d := range destinations {
		args = append(args, "-h", d)
	}
	// "-" reads the key from STDIN. It never touches disk: a private key in a temp
	// file is recoverable afterwards and survives a crash, which defeats the point
	// of the daemon holding it.
	args = append(args, "-")

	cmd := exec.CommandContext(ctx, "ssh-add", args...)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sockPath)
	cmd.Stdin = bytes.NewReader(key)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// ssh-add's stderr can echo key material in some failure modes, so it is
		// summarised rather than passed through — the same reasoning as the F8.3
		// --from-command fix.
		return fmt.Errorf("ssh-add failed: %w (stderr suppressed: it may echo key material)", err)
	}
	return nil
}

// agentStopTimeout bounds how long a graceful agent stop may take before it is
// killed. A stuck agent must not delay session teardown, because the socket is a
// live signing endpoint until it is gone.
const agentStopTimeout = 3 * time.Second

// waitForSocket blocks until the agent's socket exists, or the context ends.
func waitForSocket(ctx context.Context, path string) error {
	deadline := time.Now().Add(agentStartTimeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ssh-agent did not create %s within %s", path, agentStartTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// agentStartTimeout bounds waiting for the agent to bind its socket.
const agentStartTimeout = 5 * time.Second

func timeAfter(d time.Duration) <-chan time.Time { return time.After(d) }

// processCloser stops a child process and reaps it.
type processCloser struct{ cmd *exec.Cmd }

func (p *processCloser) Close() error {
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	// SIGTERM first so the agent can remove its own socket, then reap. An
	// unreaped agent is a zombie holding a key for the daemon's lifetime.
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_, _ = p.cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-timeAfter(agentStopTimeout):
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
	return nil
}
