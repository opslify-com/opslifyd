package escape

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/egress"
	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// This file holds the GATED real-nft exfil suite. It builds a real Linux network
// namespace attached to the opslify0 bridge (exactly the F0.3 attachment model),
// then programs the REAL F1.4 egress ruleset (egress.NftController →
// buildApplyScript, forward + input hooks, port-53 drop, default-deny with a
// pinned allowlist) and runs the exfil probes FROM the namespace against it.
//
// It is honest by construction: it first proves the path WORKS with no opslify
// rules (baseline connectivity), then applies the ruleset and proves the exfil
// channels are DROPPED — so a "blocked" result is the ruleset acting, never mere
// lack of connectivity. That baseline is the built-in teeth for the egress half.
//
// Gated on OPSLIFY_ESCAPE_EGRESS=1 + root + nft + ip, so `go test ./...` on a dev
// laptop skips cleanly.

const (
	escBridge  = egress.DefaultBridge // "opslify0"
	escNS      = "opslify_esc"
	escHostIP  = "10.201.0.1"
	escSandIP  = "10.201.0.2"
	escCIDR    = "10.201.0.0/24"
	allowedIP  = "1.1.1.1" // allowlisted host with tcp/443 open (baseline reachability)
	deniedIP   = "1.0.0.1" // NOT allowlisted, tcp/443 open → must be dropped
	dnsProbeIP = "1.1.1.1" // direct DNS target; blocked even though the IP is allowlisted (port-53 drop sits above)
)

func requireEgressEngine(t *testing.T) {
	t.Helper()
	if os.Getenv("OPSLIFY_ESCAPE_EGRESS") != "1" {
		t.Skip("egress exfil suite gated: set OPSLIFY_ESCAPE_EGRESS=1 on a root host with nft+ip to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("egress exfil suite requires root (netns + nft CAP_NET_ADMIN)")
	}
	for _, bin := range []string{"nft", "ip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed: egress exfil suite needs it", bin)
		}
	}
	if err := (egress.NewController(egress.Config{})).Available(); err != nil {
		t.Skipf("nft not usable here: %v", err)
	}
}

// sh runs a command, failing the test on error with combined output.
func mustSh(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func trySh(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// nsRun runs argv inside the sandbox netns and reports whether it SUCCEEDED
// (exit 0) within the timeout. Used to distinguish reachable (true) from
// dropped/blocked (false).
func nsReachable(timeout time.Duration, argv ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{"netns", "exec", escNS}, argv...)
	return exec.CommandContext(ctx, "ip", full...).Run() == nil
}

func setupNetns(t *testing.T) {
	t.Helper()
	teardownNetns() // clean any prior run
	mustSh(t, "ip", "link", "add", escBridge, "type", "bridge")
	mustSh(t, "ip", "addr", "add", escHostIP+"/24", "dev", escBridge)
	mustSh(t, "ip", "link", "set", escBridge, "up")
	mustSh(t, "ip", "netns", "add", escNS)
	mustSh(t, "ip", "link", "add", "hesc0", "type", "veth", "peer", "name", "esc0")
	mustSh(t, "ip", "link", "set", "hesc0", "master", escBridge)
	mustSh(t, "ip", "link", "set", "hesc0", "up")
	mustSh(t, "ip", "link", "set", "esc0", "netns", escNS)
	mustSh(t, "ip", "netns", "exec", escNS, "ip", "addr", "add", escSandIP+"/24", "dev", "esc0")
	mustSh(t, "ip", "netns", "exec", escNS, "ip", "link", "set", "esc0", "up")
	mustSh(t, "ip", "netns", "exec", escNS, "ip", "link", "set", "lo", "up")
	mustSh(t, "ip", "netns", "exec", escNS, "ip", "route", "add", "default", "via", escHostIP)
	// Host-side forwarding + NAT so the baseline path actually reaches the internet
	// (this is what makes a later "blocked" attributable to the ruleset, not to a
	// missing route). Use a dedicated masquerade table we tear down with the rest.
	mustSh(t, "sysctl", "-w", "net.ipv4.ip_forward=1")
	mustSh(t, "nft", "-f", "-", nftMasqScript())
}

func nftMasqScript() string {
	return "add table ip opslify_esc_nat\n" +
		"delete table ip opslify_esc_nat\n" +
		"table ip opslify_esc_nat {\n" +
		"  chain post {\n" +
		"    type nat hook postrouting priority srcnat; policy accept;\n" +
		"    ip saddr " + escCIDR + " masquerade\n" +
		"  }\n" +
		"}\n"
}

func teardownNetns() {
	_ = trySh("ip", "netns", "del", escNS)
	_ = trySh("ip", "link", "del", escBridge)
	_ = trySh("nft", "delete", "table", "ip", "opslify_esc_nat")
}

func TestExfilSuiteRealNft(t *testing.T) {
	requireEgressEngine(t)
	setupNetns(t)
	t.Cleanup(teardownNetns)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// dig/nc availability inside the netns (the host binaries are used via ip netns
	// exec, so they only need to exist on the host).
	digArgs := []string{"dig", "+time=2", "+tries=1", "@" + dnsProbeIP, "example.com"}
	ncDenied := []string{"nc", "-w", "3", "-z", deniedIP, "443"}
	ncAllowed := []string{"nc", "-w", "3", "-z", allowedIP, "443"}
	if _, err := exec.LookPath("dig"); err != nil {
		t.Skip("dig not installed on host: needed for the direct-dns probe")
	}
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("nc not installed on host: needed for the egress-connect probes")
	}

	// --- BASELINE (no opslify rules): the path must WORK, else a later "blocked"
	// is meaningless. This is the egress half's built-in teeth. ---
	if !nsReachable(6*time.Second, digArgs...) {
		t.Skip("baseline: direct DNS did not work without rules (no outbound internet in this env) — egress suite inconclusive here")
	}
	if !nsReachable(6*time.Second, ncDenied...) {
		t.Skip("baseline: tcp/443 to " + deniedIP + " did not work without rules — egress suite inconclusive here")
	}
	t.Log("baseline OK: direct DNS and arbitrary egress WORK with no opslify rules (teeth for the egress half)")

	// --- Apply the REAL F1.4 egress ruleset for one session. ---
	ctrl := egress.NewController(egress.Config{
		Allowlist: []string{allowedIP}, // only this IP is permitted
		Bridge:    escBridge,
	})
	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("egress controller start (allowlist resolve): %v", err)
	}
	defer ctrl.Close()
	net := egress.SessionNet{SessionID: "escape_exfil_sess", SandboxIP: escSandIP, Bridge: escBridge}
	if err := ctrl.SetupSession(ctx, net); err != nil {
		t.Fatalf("program egress ruleset: %v", err)
	}
	defer func() { _ = ctrl.TeardownSession(context.Background(), net.SessionID) }()

	byName := map[string]Probe{}
	for _, p := range ExfilProbes() {
		byName[p.Name] = p
	}
	results := map[string]Outcome{}

	// direct-dns: must be DROPPED (port-53 drop sits above the allowlist, so even
	// DNS to the allowlisted IP is blocked — no self-resolution channel).
	if nsReachable(6*time.Second, digArgs...) {
		results["direct-dns"] = OutcomeAllowed
		t.Error("EXFIL NOT BLOCKED: direct DNS to " + dnsProbeIP + ":53 succeeded under the egress ruleset")
	} else {
		results["direct-dns"] = OutcomeBlocked
		t.Log("blocked: direct DNS dropped by the port-53 rule")
	}

	// non-allowlisted-egress: tcp/443 to a NON-allowlisted IP must be DROPPED.
	if nsReachable(6*time.Second, ncDenied...) {
		results["non-allowlisted-egress"] = OutcomeAllowed
		t.Error("EXFIL NOT BLOCKED: tcp/443 to non-allowlisted " + deniedIP + " succeeded under the egress ruleset")
	} else {
		results["non-allowlisted-egress"] = OutcomeBlocked
		t.Log("blocked: non-allowlisted egress dropped by default-deny")
	}

	// Sanity: the ALLOWLISTED IP must still be reachable — proves default-deny is
	// scoped, not a blanket network cut (an honest allowlist, not "block all").
	if !nsReachable(6*time.Second, ncAllowed...) {
		t.Errorf("allowlisted egress to %s:443 was blocked — the ruleset is over-broad (not an allowlist)", allowedIP)
	} else {
		t.Logf("allowlisted egress to %s:443 works — default-deny is correctly scoped", allowedIP)
	}

	// Emit / merge the exfil half of the results matrix. Both local tiers share the
	// same egress boundary (nft on the host bridge), so record both.
	byTier := map[runtime.Tier]map[string]Outcome{
		runtime.TierLocalHardened: results,
		runtime.TierLocalDocker:   results,
	}
	m := NewMatrix(ExfilProbes(), byTier, "netns+nft")
	t.Logf("\n%s", m.Table())
	if out := os.Getenv("OPSLIFY_ESCAPE_EGRESS_MATRIX_OUT"); out != "" {
		writeArtifact(t, out, m)
	}
}
