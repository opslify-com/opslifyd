package daemon

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// setUmask sets the process umask and returns the previous value.
func setUmask(mask int) int { return syscall.Umask(mask) }

func TestListenUnixPerms(t *testing.T) {
	// Deliberately tighten the umask so we prove Chmod widens back to 0660
	// rather than inheriting a coincidentally-correct mode.
	old := setUmask(0o077)
	defer setUmask(old)

	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := listenUnix(path, "")
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != SocketPerm {
		t.Fatalf("perm = %#o, want %#o", perm, SocketPerm)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatal("not a socket")
	}
}

func TestListenUnixRemovesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	ln1, err := listenUnix(path, "")
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	// Leak ln1's socket file: close the listener's fd path handling by removing
	// via a second bind. Simulate an unclean shutdown by NOT closing ln1 and
	// re-listening on the same path.
	ln2, err := listenUnix(path, "")
	if err != nil {
		ln1.Close()
		t.Fatalf("re-listen over stale socket should succeed: %v", err)
	}
	ln1.Close()
	ln2.Close()
}

func TestListenUnixRefusesNonSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regular.file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := listenUnix(path, ""); err == nil {
		t.Fatal("expected refusal to clobber a non-socket file")
	}
}

func TestListenUnixUnknownGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	_, err := listenUnix(path, "definitely-no-such-group-xyz")
	if err == nil {
		t.Fatal("expected error resolving an unknown socket group")
	}
}
