package escape

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// This file holds the GATED real-engine escape suite. It drives the REAL F0.3
// runtime (GvisorRuntime / RuncRuntime → podman create/start/exec/rm with the
// fixed hardening set) to build a hardened sandbox and run every in-sandbox
// probe inside it, asserting each is BLOCKED. It is gated on a real engine so
// `go test ./...` on a dev laptop skips cleanly; where podman(+runsc) exists it
// MUST run and pass.
//
// The teeth test (TestEscapeSuiteHasTeeth) proves the suite is honest: with
// hardening removed (raw podman, caps kept, writable rootfs, root user, mounted
// socket, runc where gVisor is claimed) the relevant probe flips to ALLOWED —
// i.e. a real escape turns the suite RED.

// escapeImage is the base rootfs the probes run in. Needs a POSIX sh + coreutils
// (id, grep, uname, touch, cat, sleep) — Alpine/busybox suffice.
func escapeImage() string {
	if v := os.Getenv("OPSLIFY_ESCAPE_IMAGE"); v != "" {
		return v
	}
	return "docker.io/library/alpine:3.20"
}

// gatingReason returns "" if the real-engine suite may run, else a skip reason.
// The suite runs only when explicitly opted in (OPSLIFY_ESCAPE=1) AND podman is
// present and functional — belt-and-suspenders so a bare CI never runs it by
// accident, and a dev laptop never fails on a missing engine.
func requirePodman(t *testing.T) {
	t.Helper()
	if os.Getenv("OPSLIFY_ESCAPE") != "1" {
		t.Skip("escape suite gated: set OPSLIFY_ESCAPE=1 on a podman(+runsc) host to run")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not installed: escape suite requires a real engine (unit coverage in matrix_test.go)")
	}
	if err := runtime.NewRuncRuntime().Available(); err != nil {
		t.Skipf("podman present but not functional: %v", err)
	}
}

func hasRunsc() bool {
	return runtime.NewGvisorRuntime().Available() == nil
}

// tiersToRun returns the runtimes to exercise: always runc; gVisor when runsc is
// present. Each is paired with its tier and a lifecycle handle.
func tiersToRun(t *testing.T) []struct {
	tier runtime.Tier
	rt   lifecycle
} {
	out := []struct {
		tier runtime.Tier
		rt   lifecycle
	}{{runtime.TierLocalDocker, runtime.NewRuncRuntime()}}
	if hasRunsc() {
		out = append(out, struct {
			tier runtime.Tier
			rt   lifecycle
		}{runtime.TierLocalHardened, runtime.NewGvisorRuntime()})
	} else {
		t.Log("runsc absent: gVisor tier (kernel-identity + hardened checks) not exercised here")
	}
	return out
}

func TestEscapeSuiteRealEngine(t *testing.T) {
	requirePodman(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Pre-pull the image once so per-tier create isn't racing a pull.
	if out, err := exec.CommandContext(ctx, "podman", "pull", escapeImage()).CombinedOutput(); err != nil {
		t.Fatalf("podman pull %s: %v\n%s", escapeImage(), err, out)
	}

	probes := InSandboxProbes()
	sb := SandboxSpec{
		Image:           escapeImage(),
		ToolchainDigest: escapeImage(), // mount the image read-only at /opt/toolchain to exercise toolchain-readonly
		Workspace:       buildPtraceHelperDir(t),
	}

	byTier := map[runtime.Tier]map[string]Outcome{}
	sawGvisor := false
	for _, tr := range tiersToRun(t) {
		if tr.tier == runtime.TierLocalHardened {
			sawGvisor = true
		}
		res, err := RunInSandbox(ctx, tr.rt, tr.tier, sb, probes)
		if err != nil {
			t.Fatalf("tier %s: %v", tr.tier, err)
		}
		byTier[tr.tier] = res
	}

	m := NewMatrix(probes, byTier, "podman+runsc")
	// Emit the public results-matrix artifact (human + machine readable).
	t.Logf("\n%s", m.Table())
	if out := os.Getenv("OPSLIFY_ESCAPE_MATRIX_OUT"); out != "" {
		writeArtifact(t, out, m)
	}

	if !m.AllSecure() {
		for _, c := range m.Failures() {
			t.Errorf("ESCAPE NOT BLOCKED: probe %q on tier %s → %s", c.Probe, c.Tier, c.Outcome)
		}
	}
	// The gVisor kernel-identity claim is the crown jewel — assert it explicitly
	// when the hardened tier ran.
	if sawGvisor {
		if got := byTier[runtime.TierLocalHardened]["gvisor-kernel-identity"]; got != OutcomeBlocked {
			t.Errorf("gvisor-kernel-identity on local-hardened = %s, want blocked (uname must show gVisor)", got)
		}
	}
}

// buildPtraceHelperDir compiles the static ptrace helper (CGO-free) into a
// world-readable+executable temp dir and returns that dir, to be bind-mounted at
// /workspace so the ptrace-attach probe can exec PtraceHelperPath. The dir/file
// are chmod 0755 because the sandbox runs as an unprivileged, userns-remapped uid
// that must be able to traverse+exec them. Skips (not fails) if the toolchain
// can't build the helper, keeping the gated path honest.
func buildPtraceHelperDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "opslify-ptrace-*")
	if err != nil {
		t.Fatalf("mkdir helper dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	bin := dir + "/ptrace_probe"
	cmd := exec.Command("go", "build", "-o", bin, "./ptracehelper")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build ptrace helper (toolchain unavailable): %v\n%s", err, out)
	}
	// World rx so the remapped sandbox uid can traverse the dir and exec the file.
	_ = os.Chmod(dir, 0o755)
	_ = os.Chmod(bin, 0o755)
	return dir
}

func writeArtifact(t *testing.T, path string, m Matrix) {
	t.Helper()
	if err := os.WriteFile(path+".json", []byte(m.JSON()), 0o644); err != nil {
		t.Logf("warning: could not write matrix JSON artifact: %v", err)
	}
	if err := os.WriteFile(path+".txt", []byte(m.Table()), 0o644); err != nil {
		t.Logf("warning: could not write matrix table artifact: %v", err)
	}
}

// --- TEETH: a weakened config must make the relevant probe go RED. -----------

// rawPodman runs a raw `podman run -d ... sleep 3600` with the given extra flags
// (NOT the hardened runtime), execs a probe script, and returns the observation.
// This is how the teeth test proves each probe distinguishes a hardened sandbox
// from a compromised one — no production code is weakened.
func rawPodman(t *testing.T, ctx context.Context, extraFlags []string, script string) ExecResult {
	t.Helper()
	args := append([]string{"run", "-d", "--rm"}, extraFlags...)
	args = append(args, escapeImage(), "sleep", "3600")
	out, err := exec.CommandContext(ctx, "podman", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("raw podman run: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	defer func() { _ = exec.Command("podman", "rm", "-f", id).Run() }()

	eout, _ := exec.CommandContext(ctx, "podman", "exec", id, "sh", "-c", script).CombinedOutput()
	return ExecResult{ExitCode: 0, Stdout: string(eout)}
}

func TestEscapeSuiteHasTeeth(t *testing.T) {
	requirePodman(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "podman", "pull", escapeImage()).CombinedOutput(); err != nil {
		t.Fatalf("podman pull: %v\n%s", err, out)
	}

	byName := map[string]Probe{}
	for _, p := range InSandboxProbes() {
		byName[p.Name] = p
	}

	// The ptrace teeth case needs the compiled helper mounted at /workspace, and a
	// config where ptrace is PERMITTED (CAP_SYS_PTRACE back + seccomp unconfined).
	helperDir := buildPtraceHelperDir(t)

	// Each case: a probe + a DELIBERATELY WEAKENED podman config that should make
	// that probe's Secure predicate return FALSE (escape NOT blocked). If a probe
	// still reports "blocked" under the weakened config, it has no teeth — fail.
	cases := []struct {
		probe string
		flags []string
	}{
		// caps NOT dropped → CapEff is non-zero → caps-dropped must go RED.
		{"caps-dropped", []string{"--privileged"}},
		// writable rootfs (no --read-only) → the write succeeds → rootfs-write RED.
		{"rootfs-write", nil},
		// running as root (default) → id -u == 0 → root-escalation RED.
		{"root-escalation", nil},
		// toolchain mounted READ-WRITE → the write succeeds → toolchain-readonly RED.
		{"toolchain-readonly", []string{"-v", "/tmp:/opt/toolchain:rw"}},
		// SHARED host PID namespace (--pid=host) → /proc/1 is the HOST init, whose
		// /root is not our own hostname (denied / different) → pid-namespace-
		// isolation must go RED (a genuine host-PID escape the probe now catches).
		{"pid-namespace-isolation", []string{"--pid=host"}},
		// CAP_SYS_PTRACE restored + seccomp unconfined → the PTRACE_ATTACH on PID 1
		// SUCCEEDS → ptrace-attach must go RED (proves the probe catches a real
		// ptrace escape, not an always-deny).
		{"ptrace-attach", []string{
			"-v", helperDir + ":/workspace:rw",
			"--cap-add=SYS_PTRACE", "--security-opt=seccomp=unconfined",
		}},
	}
	for _, c := range cases {
		p := byName[c.probe]
		res := rawPodman(t, ctx, c.flags, p.Script)
		if classify(p, res) != OutcomeAllowed {
			t.Errorf("TEETH FAILURE: probe %q under weakened config classified %s, want allowed "+
				"(output %q) — the probe would not catch a real escape",
				c.probe, classify(p, res), strings.TrimSpace(res.out()))
		} else {
			t.Logf("teeth OK: %q correctly turns RED (allowed) under weakened config", c.probe)
		}
	}

	// gVisor kernel-identity teeth: on the runc rung the kernel is the HOST
	// kernel, not gVisor, so the identity probe must NOT be secure there.
	kid := byName["gvisor-kernel-identity"]
	res := rawPodman(t, ctx, []string{"--runtime", "runc"}, kid.Script)
	if kid.Secure(res) {
		t.Errorf("TEETH FAILURE: gvisor-kernel-identity reported gVisor on the runc rung (uname=%q) — false positive",
			strings.TrimSpace(res.Stdout))
	} else {
		t.Logf("teeth OK: gvisor-kernel-identity correctly RED on runc (host kernel %q, not gVisor)", strings.TrimSpace(res.Stdout))
	}
}
