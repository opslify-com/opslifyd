package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// DefaultSeccompProfile is the path the hardened base points podman at for its
// seccomp profile. It is emitted unconditionally so the syscall filter can
// never be silently dropped by an impl (defense in code, not assumption). The
// operator provisions the profile at this path; F1.2's escape suite asserts it
// is enforced at runtime.
const DefaultSeccompProfile = "/etc/opslify/seccomp.json"

// workspaceMountRemap returns the podman volume option that makes the writable
// /workspace bind mount owner-correct under the sandbox user namespace. Under
// `--userns=auto` + `--user=1000:1000` the sandbox process is a remapped subuid
// that does not own the host dir, so a plain rw bind mount is read-only-by-
// accident. `U` chowns the source into the CURRENT container's mapping at each
// start — re-applied every run, so it stays correct even though `--userns=auto`
// may pick a different range each time. (`idmap` was tried but maps without
// chowning, leaving the dir owned by in-container root and thus unwritable by
// the --user 1000 process; it also needs privilege rootless runc lacks.)
// OPSLIFY_WORKSPACE_REMAP overrides the value for experimentation.
func workspaceMountRemap() string {
	if v := os.Getenv("OPSLIFY_WORKSPACE_REMAP"); v == "idmap" || v == "U" {
		return v
	}
	return "U"
}

// seccompProfilePath returns the seccomp profile to emit. It defaults to
// DefaultSeccompProfile but can be overridden by OPSLIFY_SECCOMP_PROFILE so an
// operator (or a rootless dev box that can't write /etc/opslify) can point at a
// profile elsewhere — e.g. podman's shipped /usr/share/containers/seccomp.json.
// The profile is still emitted unconditionally; only its path is configurable.
func seccompProfilePath() string {
	if p := os.Getenv("OPSLIFY_SECCOMP_PROFILE"); p != "" {
		return p
	}
	return DefaultSeccompProfile
}

// SandboxUser is the non-root uid:gid the sandbox process runs as. Combined
// with --userns=auto (host uid remap) the in-container root is never host root.
const SandboxUser = "1000:1000"

// commandRunner is the seam over the Podman CLI. Isolating command construction
// behind it lets the argv/flag assembly and tier resolution be unit-tested with
// no Podman/runsc installed (the valuable, testable core of F0.3); the real
// impl is execRunner. Missing binaries surface as legible errors, never build
// breaks.
type commandRunner interface {
	// run executes name with args and returns stdout. stderr is folded into the
	// error (never a log sink) so failures name the failing binary without
	// leaking output. No secrets are ever passed as args by this package.
	run(ctx context.Context, name string, args ...string) ([]byte, error)
	// stream starts name with args and returns its stdout and stderr as LIVE,
	// separate readers plus a wait closure that reaps the process and yields its
	// real exit code. It is the streaming counterpart to run: it never buffers the
	// full output, so a hostile command cannot OOM the daemon (the consumer bounds
	// each reader). The caller MUST drain both readers to EOF before calling wait
	// (os/exec pipe contract). No secrets are ever passed as args by this package.
	stream(ctx context.Context, name string, args ...string) (streamResult, error)
	// lookup reports whether a binary is available, with a legible error if not.
	lookup(name string) error
}

// streamResult is a started command's two live output readers plus a wait
// closure. wait reaps the process (after both readers hit EOF) and returns the
// real exit code — a non-zero exit is (code, nil); only a failure to reap the
// process is a non-nil error.
type streamResult struct {
	stdout io.Reader
	stderr io.Reader
	wait   func() (int, error)
}

// execRunner is the production commandRunner: it shells out to the real binary.
type execRunner struct{}

func (execRunner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("runtime: %s failed: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// stream starts the command with piped stdout/stderr and returns the live
// readers plus a wait closure. exec.CommandContext kills the process if ctx is
// cancelled, which EOFs the pipes so the consumer's pumps unwind; cmd.Wait then
// reaps it. Wait also closes both pipes, so there is no fd/goroutine leak
// provided the caller honors the contract (drain both readers, then wait) —
// which the F1.2 consumer does.
//
// D3 fix — kill the whole process TREE, not just the direct child. The command
// we launch is typically a shell (`sh -c ...` inside `podman exec`, or a
// real DevOps script) that forks worker children/grandchildren (terraform, a
// backgrounded `yes`, a subshell). Go's default CommandContext cancel sends
// SIGKILL to ONLY the direct child; on shells that exec-through vs. fork this
// leaves grandchildren alive holding the stdout pipe's write end open, so
// drainReader never hits EOF and Wait never reaps — a process-tree-level
// re-introduction of the D1/D2 hang. We put the child in its OWN process group
// (Setpgid, pgid == child PID) and override cmd.Cancel to SIGKILL the negative
// PGID, so cancel tears down every descendant and closes all pipe write-ends.
func (execRunner) stream(ctx context.Context, name string, args ...string) (streamResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// New process group rooted at the child so cancel can signal the whole tree.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Override the default single-process kill: signal the negative PGID (==child
	// PID) to SIGKILL the entire group, reaping every forked descendant.
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return streamResult{}, fmt.Errorf("runtime: %s stdout pipe: %w", name, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return streamResult{}, fmt.Errorf("runtime: %s stderr pipe: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return streamResult{}, fmt.Errorf("runtime: %s start: %w", name, err)
	}
	wait := func() (int, error) {
		err := cmd.Wait()
		if err == nil {
			return 0, nil
		}
		// A non-zero process exit is NOT a runner failure: surface the real code
		// so the daemon reports the command's true success/failure.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		// A genuine failure to run/reap the process (ExitCode() is -1 here).
		return -1, fmt.Errorf("runtime: %s wait: %w", name, err)
	}
	return streamResult{stdout: stdout, stderr: stderr, wait: wait}, nil
}

func (execRunner) lookup(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("runtime: %q not found on PATH: %w", name, err)
	}
	return nil
}

// podmanRuntime is the shared base for every local rung. RuncRuntime and
// GvisorRuntime are thin configs over it — they differ ONLY in runtimeFlag
// (runc vs runsc) and runtimeBinary (the extra binary Available() must probe).
// All lifecycle logic (Create/Exec/Destroy/Snapshot) and, crucially, all
// hardening lives here exactly once, so no impl can drift or forget a flag.
type podmanRuntime struct {
	// runtimeFlag is passed as `--runtime <flag>` to podman (runc | runsc).
	runtimeFlag string
	// runtimeBinary is the OCI-runtime binary Available() must probe in
	// addition to podman. Empty means "bundled with podman, no extra probe"
	// (runc). "runsc" for the gVisor rung.
	runtimeBinary string
	// tier records which rung this base serves (stamped onto handles).
	tier Tier
	// seccompProfile is the seccomp profile path emitted in the hardening set.
	seccompProfile string
	// runner is the command seam (execRunner in production; a fake in tests).
	runner commandRunner
}

// hardeningFlags is the single source of truth for the sandbox hardening set.
// Both local impls inherit it verbatim (see podmanRuntime.createArgs), so the
// security posture can never be forgotten or weakened by one rung. It enforces,
// in code (not by relying on engine defaults):
//   - --cap-drop=ALL                     : drop every Linux capability
//   - --security-opt=no-new-privileges   : no setuid/privilege escalation
//   - --userns=auto                      : host uid remap (in-container root
//     is an unprivileged host uid)
//   - --user=1000:1000                   : run as non-root inside the container
//   - --read-only                        : read-only rootfs (writable paths are
//     explicit tmpfs/volumes only)
//   - --security-opt=seccomp=<profile>   : explicit syscall filter
//   - --pid=private                      : a private PID namespace, so the
//     sandbox owns its own PID 1 and can neither see nor signal host/parent
//     processes, nor reach a host rootfs via /proc/<host-pid>/root. Podman's
//     default is already a private PID ns, but we set it EXPLICITLY so the
//     boundary can never be silently downgraded by a config/default change
//     (defense in code). This completes the F1.2-deferred /proc + PID-namespace
//     isolation and is what the escape suite's pid-namespace-isolation probe
//     verifies at runtime. (Sensitive /proc paths — /proc/kcore, /proc/sys, … —
//     are masked by podman's default OCI spec and re-implemented harmlessly by
//     gVisor, so no extra --security-opt=mask is required to close this.)
func hardeningFlags(seccompProfile string) []string {
	return []string{
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--userns=auto",
		"--user=" + SandboxUser,
		"--read-only",
		"--pid=private",
		"--security-opt=seccomp=" + seccompProfile,
	}
}

// limitFlags renders resource limits to podman flags. Zero fields are omitted
// (engine default). Kept separate from hardening so limits can vary per session
// while the hardening set stays fixed.
func limitFlags(l ResourceLimits) []string {
	var args []string
	if l.MemoryBytes > 0 {
		args = append(args, "--memory", strconv.FormatInt(l.MemoryBytes, 10))
	}
	if l.CPUs > 0 {
		args = append(args, "--cpus", strconv.FormatFloat(l.CPUs, 'f', -1, 64))
	}
	if l.PidsLimit > 0 {
		args = append(args, "--pids-limit", strconv.FormatInt(l.PidsLimit, 10))
	}
	return args
}

// createArgs assembles the full `podman create` argv for a spec. This is the
// security-critical assembly the unit tests pin: the runtime flag, the complete
// hardening set, limits, mounts, image, and entrypoint — in a stable order.
func (r *podmanRuntime) createArgs(spec SessionSpec) []string {
	args := []string{"create", "--runtime", r.runtimeFlag}
	args = append(args, hardeningFlags(r.seccompProfile)...)
	args = append(args, limitFlags(spec.Limits)...)
	if spec.Name != "" {
		args = append(args, "--name", spec.Name)
	}
	if spec.ToolchainDigest != "" {
		// Signed F0.2 toolchain, mounted read-only. Never writable.
		// podman --mount type=image expresses read-only as rw=false (it does NOT
		// accept ro=true — that errors "ro: invalid mount option"). Image mounts
		// are read-only by default; rw=false is explicit and unambiguous.
		args = append(args, "--mount",
			"type=image,source="+spec.ToolchainDigest+",destination=/opt/toolchain,rw=false")
	}
	if spec.Workspace != "" {
		// The one writable persistent path. See workspaceMountRemap: `U` chowns the
		// host source into the sandbox user-namespace mapping at each start, so the
		// --user 1000 process can write even though --userns=auto remapped it to a
		// subuid. Re-applied every run, so it stays correct across the different
		// ranges auto may pick.
		args = append(args, "--volume", spec.Workspace+":/workspace:rw,"+workspaceMountRemap())
	}
	args = append(args, spec.Image)
	args = append(args, spec.Entrypoint...)
	return args
}

// Create realises a container from the spec via `podman create`. It returns a
// handle stamping the tier + OCI runtime actually used (for tracing). Full
// lifecycle wiring (start, warm-pool claim) is F1.2; F0.3 provides the create
// seam its tests pin.
func (r *podmanRuntime) Create(ctx context.Context, spec SessionSpec) (ContainerHandle, error) {
	out, err := r.runner.run(ctx, "podman", r.createArgs(spec)...)
	if err != nil {
		return ContainerHandle{}, fmt.Errorf("runtime: create container: %w", err)
	}
	id := strings.TrimSpace(string(out))
	if id == "" {
		return ContainerHandle{}, fmt.Errorf("runtime: create container: engine returned empty id")
	}
	return ContainerHandle{ID: id, Tier: r.tier, Runtime: r.runtimeFlag}, nil
}

// execArgs assembles the `podman exec` argv for a request.
func (r *podmanRuntime) execArgs(h ContainerHandle, req ExecRequest) []string {
	args := []string{"exec"}
	if req.Workdir != "" {
		args = append(args, "--workdir", req.Workdir)
	}
	for _, e := range req.Env {
		args = append(args, "--env", e)
	}
	args = append(args, h.ID)
	args = append(args, req.Argv...)
	return args
}

// Exec runs a command inside a created container and STREAMS its output. It
// wires the podman-exec process's stdout and stderr as two separate live
// readers into the returned ExecStream (so F1.2's concurrent pumps stream
// incrementally — the runtime never buffers full output, closing the OOM risk)
// and delivers the process's REAL exit code via ExecStream.Wait, called by the
// consumer after both streams are drained (non-zero on command failure — no more
// hardcoded success). Cancellation is via ctx (CommandContext kills the process,
// EOFing the pipes and unwinding the pumps).
func (r *podmanRuntime) Exec(ctx context.Context, h ContainerHandle, req ExecRequest) (ExecStream, error) {
	if h.ID == "" {
		return ExecStream{}, fmt.Errorf("runtime: exec: empty container handle")
	}
	if len(req.Argv) == 0 {
		return ExecStream{}, fmt.Errorf("runtime: exec: empty argv")
	}
	// Derive a per-exec cancelable context so the consumer can KILL the process on
	// truncation/early-return (CommandContext kills on cancel). This is what makes
	// the output cap enforceable against a hostile occupant: without it, a process
	// that keeps writing past the cap would fill the pipe buffer, block in write(),
	// and wedge Wait forever. Cancel is idempotent; the consumer also defers it to
	// release context resources on the clean path.
	ectx, cancel := context.WithCancel(ctx)
	sr, err := r.runner.stream(ectx, "podman", r.execArgs(h, req)...)
	if err != nil {
		cancel()
		return ExecStream{}, fmt.Errorf("runtime: exec in %s: %w", h.ID, err)
	}
	return ExecStream{
		Stdout: sr.stdout,
		Stderr: sr.stderr,
		Wait:   sr.wait,
		Cancel: cancel,
	}, nil
}

// Destroy removes a container and its anonymous volumes.
func (r *podmanRuntime) Destroy(ctx context.Context, h ContainerHandle) error {
	if h.ID == "" {
		return fmt.Errorf("runtime: destroy: empty container handle")
	}
	if _, err := r.runner.run(ctx, "podman", "rm", "--force", "--volumes", h.ID); err != nil {
		return fmt.Errorf("runtime: destroy container %s: %w", h.ID, err)
	}
	return nil
}

// Snapshot commits a container's filesystem to a named image (workspace mode).
func (r *podmanRuntime) Snapshot(ctx context.Context, h ContainerHandle, name string) (ImageRef, error) {
	if h.ID == "" {
		return ImageRef{}, fmt.Errorf("runtime: snapshot: empty container handle")
	}
	if name == "" {
		return ImageRef{}, fmt.Errorf("runtime: snapshot: empty image name")
	}
	out, err := r.runner.run(ctx, "podman", "commit", h.ID, name)
	if err != nil {
		return ImageRef{}, fmt.Errorf("runtime: snapshot container %s: %w", h.ID, err)
	}
	return ImageRef{Name: name, Digest: strings.TrimSpace(string(out))}, nil
}

// Available probes whether this runtime can actually run here: the podman
// engine, plus (for the hardened rung) the extra OCI-runtime binary. Errors are
// layer-tagged and actionable so callers can fall back down the ladder.
func (r *podmanRuntime) Available() error {
	if err := r.runner.lookup("podman"); err != nil {
		return fmt.Errorf("runtime: podman engine unavailable: %w", err)
	}
	if r.runtimeBinary != "" {
		if err := r.runner.lookup(r.runtimeBinary); err != nil {
			return fmt.Errorf("runtime: OCI runtime %q unavailable "+
				"(install gVisor/runsc, or fall back to tier local-docker): %w",
				r.runtimeBinary, err)
		}
	}
	return nil
}
