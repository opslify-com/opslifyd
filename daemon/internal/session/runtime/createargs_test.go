package runtime

import (
	"strings"
	"testing"
)

// F5.9: SessionSpec.Network threads to `podman create --network <name>`, so a sandbox
// can attach to an operator-provisioned bridge (opslify0) that has a routable gateway
// the credential-blind listeners can bind. Empty Network omits the flag (legacy default).
func TestCreateArgs_NetworkFlag(t *testing.T) {
	r := &podmanRuntime{runtimeFlag: "runc", seccompProfile: "/x.json"}

	with := strings.Join(r.createArgs(SessionSpec{Image: "img@sha256:a", Network: "opslify-net"}), " ")
	if !strings.Contains(with, "--network opslify-net") {
		t.Fatalf("want --network opslify-net in args, got:\n%s", with)
	}

	without := strings.Join(r.createArgs(SessionSpec{Image: "img@sha256:a"}), " ")
	if strings.Contains(without, "--network") {
		t.Fatalf("empty Network must omit --network, got:\n%s", without)
	}
}

// TestCreateArgs_OperatorOwnedWorkspaceIsNotChowned.
//
// The `U` mount option chowns the bind source into the container's user-namespace
// mapping at every start. For a daemon-managed workspace that is what makes it
// writable at all. For a directory the OPERATOR owns it is the damage: their
// files are recursively taken away from them, every session, and their editor
// stops being able to save.
//
// This pairs with the keep-id flag — either one alone leaves the directory
// broken, so both are asserted here against the real argv.
func TestCreateArgs_OperatorOwnedWorkspaceIsNotChowned(t *testing.T) {
	r := &podmanRuntime{runtimeFlag: "runc", seccompProfile: "/x.json"}

	daemonOwned := strings.Join(r.createArgs(SessionSpec{
		Image: "img@sha256:a", Workspace: "/var/lib/opslify/workspaces/ws-x",
	}), " ")
	if !strings.Contains(daemonOwned, "/workspace:rw,U") {
		t.Errorf("a daemon-managed workspace must keep the U remap, or it is "+
			"read-only-by-accident under --userns=auto:\n%s", daemonOwned)
	}
	if !strings.Contains(daemonOwned, "--userns=auto") {
		t.Errorf("the default namespace changed:\n%s", daemonOwned)
	}

	operatorOwned := strings.Join(r.createArgs(SessionSpec{
		Image: "img@sha256:a", Workspace: "/home/op/opslify-workspace/thing",
		WorkspaceIsOperatorOwned: true,
	}), " ")
	if strings.Contains(operatorOwned, ":rw,U") {
		t.Errorf("an operator-owned workspace is being chowned; their files will stop "+
			"being theirs after the first session:\n%s", operatorOwned)
	}
	if !strings.Contains(operatorOwned, "/home/op/opslify-workspace/thing:/workspace:rw") {
		t.Errorf("the operator's directory is not mounted rw at /workspace:\n%s", operatorOwned)
	}
	if !strings.Contains(operatorOwned, "--userns=keep-id") {
		t.Errorf("keep-id is missing, so the mount would be unwritable by the sandbox:\n%s", operatorOwned)
	}
}
