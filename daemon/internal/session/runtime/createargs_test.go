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
