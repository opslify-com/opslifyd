// Package escape implements F1.5's public escape/exfil test suite — the
// trust-defining artifact that backs every security claim opslify makes
// ("verify our claims yourself").
//
// It is a matrix of adversarial probes run INSIDE a real hardened sandbox
// (driven through the REAL F0.3 runtime — GvisorRuntime / RuncRuntime — and the
// REAL F1.4 nftables egress ruleset), each expected to be BLOCKED. The suite is
// deliberately HONEST: a probe's Secure predicate reports the SECURE posture, so
// a genuine escape (a leaked docker socket, an undropped capability, a writable
// rootfs, a host kernel where gVisor is claimed, a reachable resolver) flips the
// cell RED. The teeth tests prove exactly that — with hardening removed the
// relevant probe is NOT blocked.
//
// Nothing in this package weakens the sandbox: the probes only OBSERVE. The
// weakened configurations used to prove teeth live entirely in the gated tests
// and never touch the production runtime.
package escape

import (
	"strings"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// Category groups probes for the results matrix.
type Category string

const (
	CatContainerEscape Category = "container-escape"
	CatKernelIdentity  Category = "kernel-identity"
	CatExfil           Category = "exfil"
	CatToolchain       Category = "toolchain-integrity"
)

// ExecResult is what a probe observed: the in-sandbox command's exit code and
// captured output, plus any harness-level error (a failure to exec at all,
// distinct from the command running and reporting an escape).
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	// HarnessErr is non-nil only when the probe could not be executed (engine
	// error). It is NOT a security signal — it means "inconclusive", surfaced as
	// Outcome "error" in the matrix so a broken harness can never masquerade as a
	// green result.
	HarnessErr error
}

func (r ExecResult) out() string { return r.Stdout + "\n" + r.Stderr }

// Probe is one adversarial check. Script is a POSIX-sh program run inside the
// sandbox (via `sh -c`). Secure reports whether the observed result represents
// the SECURE posture (escape blocked / identity correct). It must be written so
// that a REAL escape makes it return false — never soften it to force green.
type Probe struct {
	Name     string
	Category Category
	Desc     string
	// Script is the in-sandbox POSIX-sh program. Empty for probes that are not
	// run via the in-sandbox exec harness (the egress probes run from the network
	// namespace side — see egress_test.go).
	Script string
	// Tiers lists the isolation tiers on which this probe is MEANINGFUL. A probe
	// absent from a tier is reported N/A there (e.g. the gVisor kernel-identity
	// check is meaningless on the runc rung).
	Tiers []runtime.Tier
	// Secure evaluates the observed result. Only called when HarnessErr == nil.
	Secure func(ExecResult) bool
}

func (p Probe) appliesTo(t runtime.Tier) bool {
	for _, tt := range p.Tiers {
		if tt == t {
			return true
		}
	}
	return false
}

// bothLocalTiers is the common case: a probe meaningful on both local rungs.
var bothLocalTiers = []runtime.Tier{runtime.TierLocalHardened, runtime.TierLocalDocker}

// InSandboxProbes is the catalog of probes executed INSIDE the sandbox through
// the real runtime. Each Secure predicate is deterministic and honest: the token
// a probe prints on the SECURE path is only reachable when the escape is blocked.
func InSandboxProbes() []Probe {
	return []Probe{
		{
			Name:     "docker-socket",
			Category: CatContainerEscape,
			Desc:     "the container runtime's docker/podman socket must not be reachable inside the sandbox",
			Script:   `if [ -S /var/run/docker.sock ] || [ -S /run/docker.sock ] || [ -S /run/podman/podman.sock ]; then echo LEAK; else echo BLOCKED; fi`,
			Tiers:    bothLocalTiers,
			Secure: func(r ExecResult) bool {
				return strings.Contains(r.Stdout, "BLOCKED") && !strings.Contains(r.Stdout, "LEAK")
			},
		},
		{
			Name:     "caps-dropped",
			Category: CatContainerEscape,
			Desc:     "all Linux capabilities must be dropped (CapEff == 0) — no CAP_SYS_ADMIN escape surface",
			Script:   `grep '^CapEff:' /proc/self/status`,
			Tiers:    bothLocalTiers,
			Secure: func(r ExecResult) bool {
				// CapEff is a 16-hex-digit bitmask; the secure posture is all zero.
				f := strings.Fields(r.Stdout)
				if len(f) != 2 {
					return false
				}
				return strings.Trim(f[1], "0") == ""
			},
		},
		{
			Name:     "root-escalation",
			Category: CatContainerEscape,
			Desc:     "the sandbox process must run as an unprivileged uid, not root (no in-container uid 0)",
			Script:   `id -u`,
			Tiers:    bothLocalTiers,
			Secure: func(r ExecResult) bool {
				return strings.TrimSpace(r.Stdout) != "0" && strings.TrimSpace(r.Stdout) != ""
			},
		},
		{
			Name:     "rootfs-write",
			Category: CatContainerEscape,
			Desc:     "the root filesystem must be read-only outside /workspace (no persistence / no binary tampering)",
			Script:   `if touch /etc/opslify_escape_probe 2>/dev/null; then rm -f /etc/opslify_escape_probe; echo WROTE; else echo READONLY; fi`,
			Tiers:    bothLocalTiers,
			Secure: func(r ExecResult) bool {
				return strings.Contains(r.Stdout, "READONLY") && !strings.Contains(r.Stdout, "WROTE")
			},
		},
		{
			Name:     "proc-other-pid-mem",
			Category: CatContainerEscape,
			Desc:     "reading another process's memory via /proc/<pid>/mem must be denied (no cross-process spying)",
			Script:   `sleep 5 & pid=$!; if cat /proc/$pid/mem >/dev/null 2>&1; then echo READ; else echo DENIED; fi; kill $pid 2>/dev/null`,
			Tiers:    bothLocalTiers,
			Secure: func(r ExecResult) bool {
				return strings.Contains(r.Stdout, "DENIED") && !strings.Contains(r.Stdout, "READ")
			},
		},
		{
			Name:     "pid-namespace-isolation",
			Category: CatContainerEscape,
			Desc:     "the sandbox must own its own PID namespace — it cannot see host/parent processes, so /proc/1 is its OWN init and no host rootfs is reachable via /proc/<host-pid>/root",
			// Honest calibration (see the F1.5 QA note): under a PRIVATE PID
			// namespace /proc/1 IS the sandbox's own init, so reading
			// /proc/1/root/etc/hostname simply returns the sandbox's OWN hostname
			// (benign — reading your own rootfs is not an escape). The real escape
			// this guards is a SHARED host PID namespace (--pid=host): then /proc/1
			// is the HOST init, its /root belongs to the host (permission-denied to
			// our unprivileged uid, or a DIFFERENT hostname), and host processes are
			// visible. So the secure signal is "we own PID 1": /proc/1/root/etc/
			// hostname equals our own /etc/hostname. This PASSES under correct
			// isolation and turns RED only under a genuine host-PID escape.
			Script: `h1=$(cat /proc/1/root/etc/hostname 2>/dev/null || echo __DENIED__); h2=$(cat /etc/hostname); if [ "$h1" = "$h2" ]; then echo PRIVATE_PIDNS; else echo HOST_PIDNS; fi`,
			Tiers:  bothLocalTiers,
			Secure: func(r ExecResult) bool {
				return strings.Contains(r.Stdout, "PRIVATE_PIDNS") && !strings.Contains(r.Stdout, "HOST_PIDNS")
			},
		},
		{
			Name:     "gvisor-kernel-identity",
			Category: CatKernelIdentity,
			Desc:     "on local-hardened the kernel must be gVisor's, NOT the host kernel — the isolation boundary is real",
			Script:   `uname -r`,
			// gVisor-only: meaningless on the runc rung (which shares the host kernel).
			Tiers: []runtime.Tier{runtime.TierLocalHardened},
			Secure: func(r ExecResult) bool {
				return strings.Contains(strings.ToLower(r.Stdout), "gvisor")
			},
		},
		{
			Name:     "toolchain-readonly",
			Category: CatToolchain,
			Desc:     "the mounted toolchain must be read-only — no in-sandbox install/modify of signed tools",
			Script:   `if touch /opt/toolchain/opslify_escape_probe 2>/dev/null; then rm -f /opt/toolchain/opslify_escape_probe; echo WROTE; else echo READONLY; fi`,
			Tiers:    bothLocalTiers,
			Secure: func(r ExecResult) bool {
				return strings.Contains(r.Stdout, "READONLY") && !strings.Contains(r.Stdout, "WROTE")
			},
		},
	}
}

// ExfilProbes are the egress/exfil probes. They are NOT run through the
// in-sandbox exec harness (that governs the process, not the network); they are
// executed from inside the sandbox's network namespace against the REAL F1.4
// nftables ruleset — see egress_test.go. They are catalogued here so the results
// matrix has a single, complete probe registry.
func ExfilProbes() []Probe {
	return []Probe{
		{
			Name:     "direct-dns",
			Category: CatExfil,
			Desc:     "direct DNS (udp/tcp port 53 to any resolver) must be dropped — the DNS-exfil channel is closed",
			Tiers:    []runtime.Tier{runtime.TierLocalHardened, runtime.TierLocalDocker},
		},
		{
			Name:     "non-allowlisted-egress",
			Category: CatExfil,
			Desc:     "outbound to a non-allowlisted address must be dropped (default-deny egress)",
			Tiers:    []runtime.Tier{runtime.TierLocalHardened, runtime.TierLocalDocker},
		},
	}
}
