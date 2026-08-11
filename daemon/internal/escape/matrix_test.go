package escape

import (
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// These are pure, no-engine unit tests for the honest-classification and matrix
// logic. They run everywhere (including a dev laptop with no podman/runsc/nft),
// so `go test ./...` stays green; the real-engine probing lives in the gated
// integration tests (isolation_test.go, egress_test.go).

func TestProbeSecurePredicatesAreHonest(t *testing.T) {
	byName := map[string]Probe{}
	for _, p := range InSandboxProbes() {
		byName[p.Name] = p
	}

	cases := []struct {
		probe     string
		secureOut ExecResult // the SECURE observation → must classify blocked
		escapeOut ExecResult // a REAL escape observation → must classify allowed
	}{
		{"docker-socket", ExecResult{Stdout: "BLOCKED\n"}, ExecResult{Stdout: "LEAK\n"}},
		{"caps-dropped", ExecResult{Stdout: "CapEff:\t0000000000000000\n"}, ExecResult{Stdout: "CapEff:\t000001ffffffffff\n"}},
		{"root-escalation", ExecResult{Stdout: "1000\n"}, ExecResult{Stdout: "0\n"}},
		{"rootfs-write", ExecResult{Stdout: "READONLY\n"}, ExecResult{Stdout: "WROTE\n"}},
		{"proc-other-pid-mem", ExecResult{Stdout: "DENIED\n"}, ExecResult{Stdout: "READ\n"}},
		{"pid-namespace-isolation", ExecResult{Stdout: "PRIVATE_PIDNS\n"}, ExecResult{Stdout: "HOST_PIDNS\n"}},
		{"ptrace-attach", ExecResult{Stdout: "PTRACE_DENIED errno=1\n"}, ExecResult{Stdout: "PTRACE_ATTACHED pid=1\n"}},
		{"gvisor-kernel-identity", ExecResult{Stdout: "4.19.0-gvisor\n"}, ExecResult{Stdout: "7.1.5-arch1-2\n"}},
		{"toolchain-readonly", ExecResult{Stdout: "READONLY\n"}, ExecResult{Stdout: "WROTE\n"}},
	}
	for _, c := range cases {
		p, ok := byName[c.probe]
		if !ok {
			t.Fatalf("probe %q missing from catalog", c.probe)
		}
		if classify(p, c.secureOut) != OutcomeBlocked {
			t.Errorf("%s: secure observation must classify blocked, got %s", c.probe, classify(p, c.secureOut))
		}
		if classify(p, c.escapeOut) != OutcomeAllowed {
			t.Errorf("%s: ESCAPE observation must classify allowed (suite has teeth), got %s", c.probe, classify(p, c.escapeOut))
		}
	}
}

func TestHarnessErrorIsNeverGreen(t *testing.T) {
	p := InSandboxProbes()[0]
	if got := classify(p, ExecResult{HarnessErr: errFake}); got != OutcomeError {
		t.Fatalf("harness error must be OutcomeError, got %s", got)
	}
	if OutcomeError.Secure() {
		t.Fatal("OutcomeError must NOT count as secure")
	}
}

var errFake = &fakeErr{}

type fakeErr struct{}

func (*fakeErr) Error() string { return "fake" }

func TestMatrixNAandMissing(t *testing.T) {
	probes := InSandboxProbes()
	byTier := map[runtime.Tier]map[string]Outcome{
		runtime.TierLocalHardened: {}, // deliberately empty
	}
	// Fill hardened with blocked for all applicable probes except one missing.
	for _, p := range probes {
		if p.appliesTo(runtime.TierLocalHardened) && p.Name != "caps-dropped" {
			byTier[runtime.TierLocalHardened][p.Name] = OutcomeBlocked
		}
	}
	m := NewMatrix(probes, byTier, "unit")

	var sawMissingError, sawNA bool
	for _, c := range m.Cells {
		if c.Probe == "caps-dropped" && c.Outcome == OutcomeError {
			sawMissingError = true // applies but no result → error, never green
		}
		if c.Probe == "gvisor-kernel-identity" && c.Tier == string(runtime.TierLocalHardened) {
			// applies to hardened; recorded blocked above? no — it's not in map, so error.
		}
	}
	// A probe that does NOT apply to hardened would be N/A; all in-sandbox probes
	// except identity apply to hardened, so construct N/A via runc tier.
	byTier[runtime.TierLocalDocker] = map[string]Outcome{}
	m2 := NewMatrix(probes, byTier, "unit")
	for _, c := range m2.Cells {
		if c.Probe == "gvisor-kernel-identity" && c.Tier == string(runtime.TierLocalDocker) && c.Outcome == OutcomeNA {
			sawNA = true
		}
	}
	if !sawMissingError {
		t.Error("a probe that applies but has no result must be OutcomeError, not silently green")
	}
	if !sawNA {
		t.Error("gvisor identity on runc tier must be N/A")
	}
	if m.AllSecure() {
		t.Error("matrix with an error cell must not be AllSecure")
	}
}

func TestMatrixTableRendersVerdict(t *testing.T) {
	byTier := map[runtime.Tier]map[string]Outcome{
		runtime.TierLocalHardened: {"docker-socket": OutcomeBlocked},
	}
	m := NewMatrix([]Probe{InSandboxProbes()[0]}, byTier, "podman+runsc")
	tbl := m.Table()
	if !strings.Contains(tbl, "VERDICT: PASS") {
		t.Errorf("all-blocked matrix must render PASS verdict:\n%s", tbl)
	}
	if !strings.Contains(m.JSON(), `"outcome": "blocked"`) {
		t.Errorf("JSON artifact must carry the outcome:\n%s", m.JSON())
	}

	byTier[runtime.TierLocalHardened]["docker-socket"] = OutcomeAllowed
	m2 := NewMatrix([]Probe{InSandboxProbes()[0]}, byTier, "podman+runsc")
	if !strings.Contains(m2.Table(), "VERDICT: FAIL") {
		t.Error("an allowed cell must render FAIL verdict")
	}
}
