package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// fakeRunner is the test double for the Podman CLI seam. It records the argv of
// the last run and returns canned output, so argv/flag assembly is verifiable
// with no Podman installed. missing lists binaries lookup should report absent.
type fakeRunner struct {
	out      []byte
	runErr   error
	missing  map[string]bool
	lastName string
	lastArgs []string

	// Streaming seam doubles: stdout defaults to `out` so existing callers keep
	// working; streamStderr/streamExit/streamWaitErr drive the streaming tests.
	streamStderr   []byte
	streamExit     int
	streamWaitErr  error
	streamStartErr error
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.lastName = name
	f.lastArgs = args
	if f.runErr != nil {
		return nil, f.runErr
	}
	return f.out, nil
}

func (f *fakeRunner) stream(_ context.Context, name string, args ...string) (streamResult, error) {
	f.lastName = name
	f.lastArgs = args
	if f.streamStartErr != nil {
		return streamResult{}, f.streamStartErr
	}
	return streamResult{
		stdout: bytes.NewReader(f.out),
		stderr: bytes.NewReader(f.streamStderr),
		wait:   func() (int, error) { return f.streamExit, f.streamWaitErr },
	}, nil
}

func (f *fakeRunner) lookup(name string) error {
	if f.missing[name] {
		return errors.New("runtime: " + name + " not found on PATH")
	}
	return nil
}

// hasFlag reports whether the exact token is present in args.
func hasFlag(args []string, token string) bool {
	for _, a := range args {
		if a == token {
			return true
		}
	}
	return false
}

// expectedHardening is the security-critical flag set both local rungs MUST
// emit. Pinning it here means a future edit that drops one fails the test.
var expectedHardening = []string{
	"--cap-drop=ALL",
	"--security-opt=no-new-privileges",
	"--userns=auto",
	"--user=" + SandboxUser,
	"--read-only",
	"--security-opt=seccomp=" + DefaultSeccompProfile,
}

// --- Acceptance: interface compiles & impls satisfy it (compile-time in
// runtimes.go; asserted again here for clarity). ------------------------------

func TestImplsSatisfyRuntime(t *testing.T) {
	var _ Runtime = newRuncRuntime(&fakeRunner{})
	var _ Runtime = newGvisorRuntime(&fakeRunner{})
	var _ Runtime = NewRemoteRuntime()
}

// --- Acceptance: hardening lives in the shared base, emitted by BOTH impls. ---

func TestBothImplsEmitFullHardeningSet(t *testing.T) {
	spec := SessionSpec{Image: "img@sha256:abc"}
	cases := map[string][]string{
		"runc":   newRuncRuntime(&fakeRunner{}).createArgs(spec),
		"gvisor": newGvisorRuntime(&fakeRunner{}).createArgs(spec),
	}
	for name, args := range cases {
		for _, want := range expectedHardening {
			if !hasFlag(args, want) {
				t.Errorf("%s createArgs missing hardening flag %q; got %v", name, want, args)
			}
		}
	}
}

// --- Acceptance: only difference is the --runtime flag (runc vs runsc). -------

func TestRuntimeFlagIsTheOnlyDifference(t *testing.T) {
	spec := SessionSpec{Image: "img@sha256:abc"}
	runc := newRuncRuntime(&fakeRunner{}).createArgs(spec)
	gvisor := newGvisorRuntime(&fakeRunner{}).createArgs(spec)

	if !hasFlag(runc, "runc") || hasFlag(runc, "runsc") {
		t.Errorf("runc rung must carry --runtime runc, not runsc: %v", runc)
	}
	if !hasFlag(gvisor, "runsc") || hasFlag(gvisor, "runc") {
		t.Errorf("gvisor rung must carry --runtime runsc, not runc: %v", gvisor)
	}

	// Everything except the runtime token must be identical — proving the two
	// share one base and neither drifts. Replace the differing token and
	// compare.
	normalize := func(args []string) string {
		s := strings.Join(args, " ")
		s = strings.ReplaceAll(s, "--runtime runsc", "--runtime X")
		return strings.ReplaceAll(s, "--runtime runc", "--runtime X")
	}
	if normalize(runc) != normalize(gvisor) {
		t.Errorf("rungs differ beyond the runtime flag:\n runc:   %v\n gvisor: %v", runc, gvisor)
	}
}

// --- createArgs: mounts, limits, order. --------------------------------------

func TestCreateArgsMountsAndLimits(t *testing.T) {
	spec := SessionSpec{
		Image:           "base@sha256:deadbeef",
		ToolchainDigest: "tool@sha256:cafe",
		Workspace:       "/host/ws",
		Name:            "sess-1",
		Limits:          ResourceLimits{MemoryBytes: 1 << 30, CPUs: 1.5, PidsLimit: 128},
		Entrypoint:      []string{"/bin/sleep", "inf"},
	}
	args := newGvisorRuntime(&fakeRunner{}).createArgs(spec)

	for _, want := range []string{"--memory", "1073741824", "--cpus", "1.5", "--pids-limit", "128", "--name", "sess-1"} {
		if !hasFlag(args, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
	if !hasFlag(args, "type=image,source=tool@sha256:cafe,destination=/opt/toolchain,ro=true") {
		t.Errorf("toolchain must be mounted read-only: %v", args)
	}
	if !hasFlag(args, "/host/ws:/workspace:rw") {
		t.Errorf("workspace must be bind-mounted rw: %v", args)
	}
	// Image precedes the entrypoint, and both trail the flags.
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "base@sha256:deadbeef /bin/sleep inf") {
		t.Errorf("image must precede entrypoint at the end of argv: %v", args)
	}
	if args[0] != "create" {
		t.Errorf("first arg must be 'create': %v", args)
	}
}

func TestCreateArgsOmitsZeroLimits(t *testing.T) {
	args := newRuncRuntime(&fakeRunner{}).createArgs(SessionSpec{Image: "img"})
	for _, tok := range []string{"--memory", "--cpus", "--pids-limit"} {
		if hasFlag(args, tok) {
			t.Errorf("zero limits must be omitted, found %q: %v", tok, args)
		}
	}
}

// --- Acceptance: ResolveRuntime tier/location dispatch. ----------------------

func TestResolveRuntime(t *testing.T) {
	cases := []struct {
		tier    Tier
		loc     Location
		want    string // reflect-free type tag
		wantErr error
	}{
		{TierLocalHardened, LocationLocal, "*runtime.GvisorRuntime", nil},
		{TierLocalDocker, LocationLocal, "*runtime.RuncRuntime", nil},
		{TierCloudMicroVM, LocationLocal, "*runtime.RemoteRuntime", nil},
		{TierLocalHardened, LocationRemote, "*runtime.RemoteRuntime", nil}, // remote seam wins
		{TierLocalHardened, "", "*runtime.GvisorRuntime", nil},             // empty loc = local
		{"bogus-tier", LocationLocal, "", ErrUnknownTier},
		{TierLocalHardened, "bogus-loc", "", ErrUnknownLocation},
	}
	for _, c := range cases {
		got, err := ResolveRuntime(c.tier, c.loc)
		if c.wantErr != nil {
			if !errors.Is(err, c.wantErr) {
				t.Errorf("ResolveRuntime(%q,%q) err = %v, want %v", c.tier, c.loc, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveRuntime(%q,%q) unexpected err %v", c.tier, c.loc, err)
			continue
		}
		if tag := typeTag(got); tag != c.want {
			t.Errorf("ResolveRuntime(%q,%q) = %s, want %s", c.tier, c.loc, tag, c.want)
		}
	}
}

func typeTag(v any) string {
	switch v.(type) {
	case *GvisorRuntime:
		return "*runtime.GvisorRuntime"
	case *RuncRuntime:
		return "*runtime.RuncRuntime"
	case *RemoteRuntime:
		return "*runtime.RemoteRuntime"
	default:
		return "unknown"
	}
}

// --- Acceptance: cloud stub returns ErrNotImplemented from every method. ------

func TestRemoteRuntimeStub(t *testing.T) {
	r := NewRemoteRuntime()
	ctx := context.Background()
	_, cErr := r.Create(ctx, SessionSpec{})
	_, eErr := r.Exec(ctx, ContainerHandle{}, ExecRequest{})
	dErr := r.Destroy(ctx, ContainerHandle{})
	_, sErr := r.Snapshot(ctx, ContainerHandle{}, "x")
	aErr := r.Available()
	for _, err := range []error{cErr, eErr, dErr, sErr, aErr} {
		if !errors.Is(err, ErrNotImplemented) {
			t.Errorf("remote stub must return ErrNotImplemented, got %v", err)
		}
	}
}

// --- Acceptance: Available() reports legibly when runsc is absent. -----------

func TestAvailable(t *testing.T) {
	// gVisor rung: podman present, runsc absent → legible error naming runsc.
	gv := newGvisorRuntime(&fakeRunner{missing: map[string]bool{"runsc": true}})
	err := gv.Available()
	if err == nil || !strings.Contains(err.Error(), "runsc") {
		t.Errorf("gvisor Available with runsc absent must name runsc, got %v", err)
	}
	if !strings.Contains(err.Error(), "local-docker") {
		t.Errorf("gvisor Available should suggest falling back to local-docker, got %v", err)
	}

	// gVisor rung with everything present → nil.
	if err := newGvisorRuntime(&fakeRunner{}).Available(); err != nil {
		t.Errorf("gvisor Available with all present = %v, want nil", err)
	}

	// runc rung only needs podman; runsc absence is irrelevant.
	rc := newRuncRuntime(&fakeRunner{missing: map[string]bool{"runsc": true}})
	if err := rc.Available(); err != nil {
		t.Errorf("runc Available should ignore runsc, got %v", err)
	}

	// podman absent → both rungs report the engine is unavailable.
	noPodman := &fakeRunner{missing: map[string]bool{"podman": true}}
	if err := newRuncRuntime(noPodman).Available(); err == nil || !strings.Contains(err.Error(), "podman") {
		t.Errorf("runc Available with podman absent must name podman, got %v", err)
	}
}

// --- Lifecycle over the seam (no real Podman): handle & argv wiring. ---------

func TestCreateParsesHandle(t *testing.T) {
	f := &fakeRunner{out: []byte("  container-abc123\n")}
	h, err := newGvisorRuntime(f).Create(context.Background(), SessionSpec{Image: "img"})
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != "container-abc123" {
		t.Errorf("handle ID = %q, want trimmed container-abc123", h.ID)
	}
	if h.Runtime != "runsc" || h.Tier != TierLocalHardened {
		t.Errorf("handle should stamp runtime/tier, got %+v", h)
	}
	if f.lastName != "podman" || f.lastArgs[0] != "create" {
		t.Errorf("Create must invoke podman create, got %s %v", f.lastName, f.lastArgs)
	}
}

func TestCreateEmptyIDIsError(t *testing.T) {
	_, err := newRuncRuntime(&fakeRunner{out: []byte("  \n")}).Create(context.Background(), SessionSpec{Image: "img"})
	if err == nil || !strings.Contains(err.Error(), "empty id") {
		t.Errorf("empty engine output must error, got %v", err)
	}
}

func TestExecArgsAndValidation(t *testing.T) {
	f := &fakeRunner{out: []byte("hello")}
	r := newRuncRuntime(f)
	h := ContainerHandle{ID: "c1"}

	if _, err := r.Exec(context.Background(), ContainerHandle{}, ExecRequest{Argv: []string{"ls"}}); err == nil {
		t.Error("exec with empty handle must error")
	}
	if _, err := r.Exec(context.Background(), h, ExecRequest{}); err == nil {
		t.Error("exec with empty argv must error")
	}

	stream, err := r.Exec(context.Background(), h, ExecRequest{
		Argv:    []string{"echo", "hi"},
		Env:     []string{"FOO=bar"},
		Workdir: "/workspace",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.lastArgs, " ")
	for _, want := range []string{"exec", "--workdir /workspace", "--env FOO=bar", "c1", "echo hi"} {
		if !strings.Contains(got, want) {
			t.Errorf("exec argv missing %q: %v", want, f.lastArgs)
		}
	}
	body, _ := io.ReadAll(stream.Stdout)
	if string(body) != "hello" {
		t.Errorf("stream stdout = %q, want hello", body)
	}
}

// --- FIX #1: Exec streams stdout+stderr separately and returns the real exit. -

// stdout and stderr are delivered as DISTINCT readers (not folded together), and
// Wait surfaces the process's real, non-zero exit code — proving the false-
// success bug is gone and output is streamed, not buffered into one blob.
func TestExecStreamsSeparateAndPropagatesExit(t *testing.T) {
	f := &fakeRunner{
		out:          []byte("OUT-DATA"),
		streamStderr: []byte("ERR-DATA"),
		streamExit:   42,
	}
	r := newGvisorRuntime(f)
	es, err := r.Exec(context.Background(), ContainerHandle{ID: "c1"}, ExecRequest{Argv: []string{"false"}})
	if err != nil {
		t.Fatal(err)
	}

	// Separate streams: each reader carries only its own stream's bytes.
	so, _ := io.ReadAll(es.Stdout)
	se, _ := io.ReadAll(es.Stderr)
	if string(so) != "OUT-DATA" {
		t.Errorf("stdout = %q, want OUT-DATA", so)
	}
	if string(se) != "ERR-DATA" {
		t.Errorf("stderr = %q, want ERR-DATA (must be a distinct reader, not empty/folded)", se)
	}

	// Real exit code delivered via Wait (called after streams are drained).
	if es.Wait == nil {
		t.Fatal("streaming Exec must set Wait for lazy exit-code delivery")
	}
	code, werr := es.Wait()
	if werr != nil {
		t.Fatalf("Wait err = %v, want nil (non-zero exit is not a wait failure)", werr)
	}
	if code != 42 {
		t.Errorf("exit code = %d, want 42 (real code must propagate, not hardcoded 0)", code)
	}
}

// A start failure from the seam surfaces legibly (no panic, layer-tagged).
func TestExecStreamStartError(t *testing.T) {
	f := &fakeRunner{streamStartErr: errors.New("boom")}
	_, err := newRuncRuntime(f).Exec(context.Background(), ContainerHandle{ID: "c1"}, ExecRequest{Argv: []string{"ls"}})
	if err == nil || !strings.Contains(err.Error(), "exec in c1") {
		t.Errorf("stream start error must surface as an exec error, got %v", err)
	}
}

// BLOCKING-D1 (gated, no podman): the REAL execRunner.stream must let a caller
// kill a still-writing process via ctx-cancel and then reap it via wait without
// hanging — the production kill-then-drain path end-to-end. Uses `sh -c "yes"`
// (an infinite writer) behind an sh-availability skip, so it is a no-op on hosts
// without sh; the deterministic seam test in the session package is the primary.
func TestExecRunnerStreamKillReapGated(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not installed: skipping real kill/reap smoke (seam test covers the logic)")
	}
	ctx, cancel := context.WithCancel(context.Background())
	sr, err := execRunner{}.stream(ctx, "sh", "-c", "yes ABCDEFGH")
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	// Read a bit (well past any single pipe buffer), then stop and kill.
	buf := make([]byte, 256*1024)
	if _, err := io.ReadFull(sr.stdout, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	cancel() // kill the process (mirrors truncation-triggered cancel)

	done := make(chan struct{})
	go func() {
		drainReader(sr.stdout) // drain to EOF so Wait can reap
		drainReader(sr.stderr)
		_, _ = sr.wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK: killed process was not reaped within 3s")
	}
}

func drainReader(r io.Reader) { _, _ = io.Copy(io.Discard, r) }

// --- FIX #2: Start seam issues `podman start` and validates the handle. -------

func TestStartArgsAndValidation(t *testing.T) {
	f := &fakeRunner{}
	r := newGvisorRuntime(f)

	if err := r.Start(context.Background(), ContainerHandle{}); err == nil {
		t.Error("start with empty handle must error")
	}
	if err := r.Start(context.Background(), ContainerHandle{ID: "c9"}); err != nil {
		t.Fatal(err)
	}
	if f.lastName != "podman" || strings.Join(f.lastArgs, " ") != "start c9" {
		t.Errorf("start must invoke `podman start c9`, got %s %v", f.lastName, f.lastArgs)
	}

	// Both local rungs implement the optional Starter capability.
	var _ Starter = newRuncRuntime(&fakeRunner{})
	var _ Starter = newGvisorRuntime(&fakeRunner{})
}

func TestDestroyAndSnapshotArgs(t *testing.T) {
	f := &fakeRunner{out: []byte("sha256:committed\n")}
	r := newGvisorRuntime(f)
	h := ContainerHandle{ID: "c1"}

	if err := r.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.lastArgs, " ") != "rm --force --volumes c1" {
		t.Errorf("destroy argv = %v", f.lastArgs)
	}

	ref, err := r.Snapshot(context.Background(), h, "img:snap")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Name != "img:snap" || ref.Digest != "sha256:committed" {
		t.Errorf("snapshot ref = %+v", ref)
	}
	if strings.Join(f.lastArgs, " ") != "commit c1 img:snap" {
		t.Errorf("snapshot argv = %v", f.lastArgs)
	}

	if err := r.Destroy(context.Background(), ContainerHandle{}); err == nil {
		t.Error("destroy empty handle must error")
	}
	if _, err := r.Snapshot(context.Background(), h, ""); err == nil {
		t.Error("snapshot empty name must error")
	}
}

// --- Gated real-Podman smoke test: skipped when podman/runsc absent. ---------

func TestRealPodmanAvailableGated(t *testing.T) {
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not installed: skipping real-runtime probe (unit coverage via fakeRunner)")
	}
	if err := NewRuncRuntime().Available(); err != nil {
		t.Skipf("podman present but not functional: %v", err)
	}
	if _, err := exec.LookPath("runsc"); err != nil {
		t.Skip("runsc not installed: gVisor rung unverifiable here (expected on dev laptops)")
	}
	if err := NewGvisorRuntime().Available(); err != nil {
		t.Errorf("gVisor Available with podman+runsc present = %v, want nil", err)
	}
}
