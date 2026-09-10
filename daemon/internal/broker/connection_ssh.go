package broker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// sshConnection forwards a daemon-held agent socket with destination-constrained
// keys.
//
// What the sandbox receives: AN AGENT SOCKET. Signatures only. The agent protocol
// has no export operation, so the key cannot cross it — and the classic
// agent-forwarding risk, a hostile client using the socket as an unrestricted
// signing oracle, is exactly this threat model. Destination constraints are the
// mitigation: the binding is anchored by session-bind@openssh.com, which carries
// the target's signature over the session identifier using its host key, so a
// compromised sandbox cannot forge which host it is authenticating to.
//
// Constrained forwarding is preferred over minting certificates for v1: nothing
// bearer-shaped enters the sandbox, revocation is removing the key or the socket,
// and there is one audit record per authentication rather than one per issuance.
type sshConnection struct {
	spec    ConnectionSpec
	secrets SecretResolver
	runner  SSHRunner
}

// SSHRunner is the seam over the local OpenSSH tooling, so the kind is testable
// without a real agent and so a host without new-enough OpenSSH is a detectable
// condition rather than a mysterious failure.
type SSHRunner interface {
	// Version reports the local OpenSSH version. Destination constraints need
	// 8.9 or newer.
	Version(ctx context.Context) (major, minor int, err error)
	// StartAgent starts an agent listening on sockPath and returns a closer that
	// stops it and removes the socket.
	StartAgent(ctx context.Context, sockPath string) (io.Closer, error)
	// AddKey loads a private key into the agent WITH destination constraints.
	//
	// key is passed on stdin, never written to disk: a private key in a temp file
	// is recoverable after the fact and survives a crash, which defeats the point
	// of the daemon holding it.
	AddKey(ctx context.Context, sockPath string, key []byte, destinations []string, knownHostsPath string) error
}

// minSSHMajor/minSSHMinor is the first OpenSSH with `ssh-add -h` destination
// constraints.
const (
	minSSHMajor = 8
	minSSHMinor = 9
)

// NewSSHConnection builds the ssh kind. runner is the OpenSSH seam; nil uses the
// real local tooling.
func NewSSHConnection(runner SSHRunner) Builder {
	return func(spec ConnectionSpec, secrets SecretResolver) (Connection, error) {
		r := runner
		if r == nil {
			r = realSSHRunner{}
		}
		return &sshConnection{spec: spec, secrets: secrets, runner: r}, nil
	}
}

func (c *sshConnection) Kind() Kind           { return KindSSH }
func (c *sshConnection) Name() string         { return c.spec.Name }
func (c *sshConnection) SecretRefs() []string { return []string{c.spec.SecretRef} }

// knownHostsPath is the DAEMON-side file supplying host keys for the destination
// constraint.
func (c *sshConnection) knownHostsPath() string { return c.spec.Config["known_hosts_path"] }

func (c *sshConnection) Validate() error {
	if err := c.spec.ValidateSpec(); err != nil {
		return err
	}
	if len(c.spec.Hosts) == 0 {
		// An empty host list must NEVER mean "any host". For every other kind that
		// would merely be useless; here it would turn a constrained agent into an
		// unconstrained signing oracle, which is the single thing this kind exists
		// to prevent.
		return fmt.Errorf("%w: ssh connection %q needs at least one destination — an empty list must never mean any host",
			ErrInvalidInput, c.spec.Name)
	}
	kh := c.knownHostsPath()
	// Without host keys there is nothing to anchor the constraint to. Redundant
	// with the absolute-path check below (an empty path is not absolute), but kept
	// because it names the actual omission — "needs known_hosts_path" is a better
	// message than "must be absolute" for an operator who simply left it out.
	if kh == "" {
		return fmt.Errorf("%w: ssh connection %q needs known_hosts_path — destination constraints are looked up against it",
			ErrInvalidInput, c.spec.Name)
	}
	if !filepath.IsAbs(kh) {
		return fmt.Errorf("%w: ssh connection %q known_hosts_path %q must be absolute (it is a daemon-side file)",
			ErrInvalidInput, c.spec.Name, kh)
	}
	return nil
}

// EgressRules: none. SSH is not HTTP, so nothing is injected at the L7 proxy.
func (c *sshConnection) EgressRules() []HeaderInjectRule { return nil }

// BuildForSession starts a per-session agent, loads the key under destination
// constraints, and forwards ONLY the socket.
//
// Every failure path here refuses rather than degrading. In particular a local
// OpenSSH too old for `ssh-add -h` means NO KEY IS LOADED — loading it
// unconstrained would hand the sandbox an unrestricted signing oracle for every
// host the key reaches, which is worse than the connection simply not working.
func (c *sshConnection) BuildForSession(ctx context.Context, sc SessionContext) (ConnectionInjection, io.Closer, error) {
	if sc.WorkspaceDir == "" {
		return ConnectionInjection{}, nil, fmt.Errorf("%w: ssh connection %q needs a workspace to place the agent socket",
			ErrInvalidInput, c.spec.Name)
	}
	// The known_hosts file must be DAEMON-side. If it could be read from the
	// workspace, an agent with write access there could add host keys and widen
	// its own destination constraint — quietly converting a scoped key into a
	// general one.
	kh := c.knownHostsPath()
	if inside, err := pathInside(sc.WorkspaceDir, kh); err != nil {
		return ConnectionInjection{}, nil, err
	} else if inside {
		return ConnectionInjection{}, nil, fmt.Errorf(
			"%w: ssh connection %q known_hosts_path %q is inside the workspace; the sandbox could then widen its own destination constraint",
			ErrDenied, c.spec.Name, kh)
	}
	if _, err := os.Stat(kh); err != nil {
		return ConnectionInjection{}, nil, fmt.Errorf("%w: ssh connection %q known_hosts_path %q is unreadable: %v",
			ErrDenied, c.spec.Name, kh, err)
	}

	major, minor, err := c.runner.Version(ctx)
	if err != nil {
		return ConnectionInjection{}, nil, fmt.Errorf("%w: ssh connection %q: cannot determine the local OpenSSH version: %v",
			ErrDenied, c.spec.Name, err)
	}
	if major < minSSHMajor || (major == minSSHMajor && minor < minSSHMinor) {
		return ConnectionInjection{}, nil, fmt.Errorf(
			"%w: ssh connection %q needs OpenSSH %d.%d+ for destination constraints (found %d.%d); refusing to load the key unconstrained",
			ErrDenied, c.spec.Name, minSSHMajor, minSSHMinor, major, minor)
	}

	if c.secrets == nil {
		return ConnectionInjection{}, nil, fmt.Errorf("%w: ssh connection %q has no secret resolver", ErrInvalidInput, c.spec.Name)
	}
	key, _, err := c.secrets.Get(ctx, c.spec.SecretRef)
	if err != nil {
		// FAIL CLOSED: a connection whose secret is missing or unreadable injects
		// nothing. There is no fallback that would let the session proceed with a
		// different credential path.
		return ConnectionInjection{}, nil, fmt.Errorf("%w: ssh connection %q: resolve %s: %v",
			ErrDenied, c.spec.Name, c.spec.SecretRef, err)
	}
	defer Zeroize(key)

	// The socket lives in a daemon-created directory beside the workspace, not in
	// it: the sandbox needs to reach the socket, not to be able to replace it.
	sockDir, err := os.MkdirTemp("", "opslify-ssh-"+sc.SessionID+"-")
	if err != nil {
		return ConnectionInjection{}, nil, fmt.Errorf("broker: create agent socket dir: %w", err)
	}
	if err := os.Chmod(sockDir, 0o700); err != nil {
		_ = os.RemoveAll(sockDir)
		return ConnectionInjection{}, nil, fmt.Errorf("broker: secure agent socket dir: %w", err)
	}
	sockPath := filepath.Join(sockDir, "agent.sock")

	agentCloser, err := c.runner.StartAgent(ctx, sockPath)
	if err != nil {
		_ = os.RemoveAll(sockDir)
		return ConnectionInjection{}, nil, fmt.Errorf("%w: ssh connection %q: start agent: %v", ErrDenied, c.spec.Name, err)
	}
	cleanup := &sshCleanup{agent: agentCloser, dir: sockDir}

	if err := c.runner.AddKey(ctx, sockPath, key, c.spec.Hosts, kh); err != nil {
		_ = cleanup.Close()
		return ConnectionInjection{}, nil, fmt.Errorf("%w: ssh connection %q: load key with destination constraints: %v",
			ErrDenied, c.spec.Name, err)
	}

	inj := ConnectionInjection{
		Env: map[string]string{
			// The ONLY ssh artefact the sandbox gets. No key, no ~/.ssh copy, no
			// ProxyJump credential.
			"SSH_AUTH_SOCK": sockPath,
		},
		ExcludeRefs: []string{c.spec.SecretRef},
	}
	if err := inj.Validate(); err != nil {
		_ = cleanup.Close()
		return ConnectionInjection{}, nil, err
	}
	return inj, cleanup, nil
}

// sshCleanup stops the agent and removes its socket directory. Nothing the kind
// allocated may outlive the session.
type sshCleanup struct {
	agent io.Closer
	dir   string
}

func (s *sshCleanup) Close() error {
	var firstErr error
	if s.agent != nil {
		if err := s.agent.Close(); err != nil {
			firstErr = err
		}
	}
	// Remove the directory even if stopping the agent failed: a leftover socket is
	// a live signing endpoint, so it is the more urgent of the two.
	if err := os.RemoveAll(s.dir); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// pathInside reports whether path resolves inside root.
func pathInside(root, path string) (bool, error) {
	if root == "" || path == "" {
		return false, nil
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%w: resolve %s: %v", ErrInvalidInput, root, err)
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			// A path that does not exist yet cannot be resolved; compare lexically so
			// an obvious escape is still caught.
			realPath = filepath.Clean(path)
		} else {
			return false, fmt.Errorf("%w: resolve %s: %v", ErrInvalidInput, path, err)
		}
	}
	rel, err := filepath.Rel(realRoot, realPath)
	if err != nil {
		return false, nil
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}
