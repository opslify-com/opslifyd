package daemon

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// SocketPerm is the required permission on the daemon's Unix socket: owner +
// group read/write, no world access. The socket is the entire trust boundary
// for local callers (only members of the socket's group may talk to the
// daemon), so these bits are load-bearing and asserted after creation.
const SocketPerm os.FileMode = 0o660

// listenUnix creates the daemon's Unix-domain listener at path with SocketPerm,
// optionally chowning it to group (by name). It removes a stale socket first,
// creates the parent dir 0750, and re-asserts the mode after listening (net
// applies the process umask, which we must override). When group is empty the
// chown is skipped — that is what tests use so they need neither root nor the
// real `opslify` group.
func listenUnix(path, group string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("daemon: create socket dir %s: %w", dir, err)
	}
	// Remove a stale socket from an unclean shutdown; refuse if the path exists
	// as something other than a socket (don't clobber a real file).
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("daemon: refusing to replace non-socket %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("daemon: remove stale socket %s: %w", path, err)
		}
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("daemon: listen on %s: %w", path, err)
	}

	// net.Listen honours the umask, so the socket may be tighter than SocketPerm.
	// Set it explicitly so the group can reach it (the whole point of the group).
	if err := os.Chmod(path, SocketPerm); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("daemon: chmod socket %s: %w", path, err)
	}

	if group != "" {
		gid, err := lookupGID(group)
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		if err := os.Chown(path, -1, gid); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("daemon: chown socket %s to group %s: %w", path, group, err)
		}
	}

	return ln, nil
}

// lookupGID resolves a group name to its GID, tolerating a numeric group.
func lookupGID(group string) (int, error) {
	g, err := user.LookupGroup(group)
	if err == nil {
		gid, convErr := strconv.Atoi(g.Gid)
		if convErr != nil {
			return 0, fmt.Errorf("daemon: group %s has non-numeric gid %q: %w", group, g.Gid, convErr)
		}
		return gid, nil
	}
	if gid, convErr := strconv.Atoi(group); convErr == nil {
		return gid, nil
	}
	return 0, fmt.Errorf("daemon: resolve socket group %q: %w", group, err)
}
