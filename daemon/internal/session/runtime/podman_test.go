package runtime

import "testing"

// TestOperatorOwnedWorkspaceChangesTheUserNamespace.
//
// `--userns=auto` chowns the mounted workspace into a fresh subuid range on every
// start. For a directory only the daemon touches that is correct. For one the
// OPERATOR owns and opens in an editor it is ruinous: their files are taken away
// from them, recursively, every session.
//
// The flag is therefore not cosmetic, and neither is the mount option: `U` is
// what performs the chown.
func TestOperatorOwnedWorkspaceChangesTheUserNamespace(t *testing.T) {
	daemonOwned := hardeningFlagsFor("/seccomp.json", false)
	operatorOwned := hardeningFlagsFor("/seccomp.json", true)

	if !containsFlag(daemonOwned, "--userns=auto") {
		t.Error("the default is no longer --userns=auto; each sandbox should get its own subuid range")
	}
	if !containsFlag(operatorOwned, "--userns=keep-id") {
		t.Error("an operator-owned workspace must use --userns=keep-id, or the chown " +
			"takes the operator's own files away from them on every session")
	}
	if containsFlag(operatorOwned, "--userns=auto") {
		t.Error("both namespaces were passed")
	}
	// Everything else must be identical: this switch trades ONE property and must
	// not quietly relax the rest.
	for _, must := range []string{
		"--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--read-only", "--pid=private", "--security-opt=seccomp=/seccomp.json",
	} {
		if !containsFlag(operatorOwned, must) {
			t.Errorf("%s is missing from an operator-owned sandbox; only the user "+
				"namespace changes", must)
		}
	}
}

func containsFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
