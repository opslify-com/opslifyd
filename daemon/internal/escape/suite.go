package escape

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// Outcome is a probe's verdict in one cell of the matrix.
type Outcome string

const (
	// OutcomeBlocked: the escape/exfil was BLOCKED, or the required identity held
	// (the SECURE posture). This is the only PASS.
	OutcomeBlocked Outcome = "blocked"
	// OutcomeAllowed: the escape SUCCEEDED / the property did NOT hold. A real
	// failure — the suite must go red.
	OutcomeAllowed Outcome = "allowed"
	// OutcomeNA: the probe is not meaningful on this tier (e.g. gVisor kernel
	// identity on runc).
	OutcomeNA Outcome = "n/a"
	// OutcomeError: the probe could not be executed (harness/engine error) —
	// inconclusive, never counted as a pass.
	OutcomeError Outcome = "error"
)

// Secure reports whether an outcome is the secure posture. N/A is secure-by-
// vacuity (the probe does not apply); only Allowed and Error are non-green, and
// Error is treated as a hard failure by the suite so a broken harness cannot pass.
func (o Outcome) Secure() bool { return o == OutcomeBlocked || o == OutcomeNA }

// SandboxSpec parameterises the sandbox the runner builds. It mirrors the fields
// the escape suite needs from runtime.SessionSpec plus the base image.
type SandboxSpec struct {
	Image           string
	ToolchainDigest string // mounted read-only at /opt/toolchain; enables the toolchain probe
	SeccompUnused   bool   // documentation only; hardening is fixed in the runtime
}

// lifecycle is the subset of the runtime a sandbox needs: create, start, exec,
// destroy. The real *GvisorRuntime / *RuncRuntime satisfy it (Start via the
// Starter capability).
type lifecycle interface {
	runtime.Runtime
	runtime.Starter
}

// RunInSandbox creates a hardened sandbox with rt, starts it, runs every probe
// in probes that applies to tier, and tears it down. It drives the REAL runtime
// end-to-end: podman create (with the fixed hardening set) → start → exec →
// rm. The returned map is probe-name → Outcome.
func RunInSandbox(ctx context.Context, rt lifecycle, tier runtime.Tier, sb SandboxSpec, probes []Probe) (map[string]Outcome, error) {
	spec := runtime.SessionSpec{
		Tier:            tier,
		Location:        runtime.LocationLocal,
		Image:           sb.Image,
		ToolchainDigest: sb.ToolchainDigest,
		// Idle entrypoint so the container stays up for exec probing.
		Entrypoint: []string{"sleep", "3600"},
	}
	h, err := rt.Create(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("escape: create sandbox: %w", err)
	}
	defer func() {
		dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = rt.Destroy(dctx, h)
	}()
	if err := rt.Start(ctx, h); err != nil {
		return nil, fmt.Errorf("escape: start sandbox: %w", err)
	}

	results := make(map[string]Outcome, len(probes))
	for _, p := range probes {
		if p.Script == "" {
			continue // exfil probes are handled by the egress harness
		}
		if !p.appliesTo(tier) {
			results[p.Name] = OutcomeNA
			continue
		}
		res := execProbe(ctx, rt, h, p)
		results[p.Name] = classify(p, res)
	}
	return results, nil
}

// execProbe runs one probe's script inside the sandbox via `sh -c` and collects
// the full result. It honours the streaming ExecStream contract: drain both
// readers to EOF, then Wait for the real exit code.
func execProbe(ctx context.Context, rt lifecycle, h runtime.ContainerHandle, p Probe) ExecResult {
	ectx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stream, err := rt.Exec(ectx, h, runtime.ExecRequest{Argv: []string{"sh", "-c", p.Script}})
	if err != nil {
		return ExecResult{HarnessErr: fmt.Errorf("exec %q: %w", p.Name, err)}
	}
	if stream.Cancel != nil {
		defer stream.Cancel()
	}
	outB, errB := readAll(stream.Stdout), readAll(stream.Stderr)
	code := stream.ExitCode
	if stream.Wait != nil {
		c, werr := stream.Wait()
		if werr != nil {
			return ExecResult{Stdout: outB, Stderr: errB, HarnessErr: fmt.Errorf("wait %q: %w", p.Name, werr)}
		}
		code = c
	}
	return ExecResult{ExitCode: code, Stdout: outB, Stderr: errB}
}

func readAll(r io.Reader) string {
	if r == nil {
		return ""
	}
	b, _ := io.ReadAll(r)
	return string(b)
}

// classify turns a raw ExecResult into an Outcome using the probe's honest
// Secure predicate. A harness error is Error (inconclusive), never a pass.
func classify(p Probe, res ExecResult) Outcome {
	if res.HarnessErr != nil {
		return OutcomeError
	}
	if p.Secure(res) {
		return OutcomeBlocked
	}
	return OutcomeAllowed
}
