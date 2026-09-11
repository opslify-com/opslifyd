package daemon

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/user"
	"strconv"
	"syscall"
)

// peerKey is the context key under which a connection's peer identity is stored.
type peerKeyType struct{}

var peerKey peerKeyType

// peerIdentity returns who is on the other end of this request's connection.
//
// It is read from the SOCKET, never from the request body. An approval names who
// accepted a blast radius, and a self-declared identity would make that record
// worthless — anyone could approve as anyone. SO_PEERCRED is supplied by the
// kernel and cannot be forged by the connecting process.
//
// It returns "" when the peer cannot be determined — a non-unix listener, or a
// test harness. Empty is deliberately NOT rendered as "unknown": a caller that
// requires attribution must be able to tell "nobody could be identified" from a
// user literally named unknown, and refuse rather than record a placeholder as
// though it were a person.
func (d *Daemon) peerIdentity(r *http.Request) string {
	if v, ok := r.Context().Value(peerKey).(string); ok {
		return v
	}
	return ""
}

// withPeerIdentity injects a peer identity. Used by tests, which have no unix
// socket to read credentials from.
func withPeerIdentity(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, peerKey, id)
}

// connContext stashes the peer identity on every accepted connection.
//
// Done once per CONNECTION rather than per request: the credentials are a
// property of the socket, and re-reading them per request would be the same
// syscall for the same answer.
func connContext(ctx context.Context, c net.Conn) context.Context {
	id := peerFromConn(c)
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, peerKey, id)
}

// peerFromConn reads SO_PEERCRED and renders it as a human-readable identity.
func peerFromConn(c net.Conn) string {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ""
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ""
	}
	var (
		cred    *syscall.Ucred
		credErr error
	)
	if ctrlErr := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); ctrlErr != nil || credErr != nil {
		return ""
	}
	if cred == nil {
		return ""
	}
	return renderPeer(cred.Uid, cred.Pid)
}

// renderPeer prefers a username, falling back to the numeric uid.
//
// The uid is included either way: a username can be ambiguous across a container
// boundary, and the number is what an auditor can actually correlate with the
// host's records.
func renderPeer(uid uint32, pid int32) string {
	name := ""
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = u.Username
	}
	if name != "" {
		return fmt.Sprintf("%s (uid %d, pid %d)", name, uid, pid)
	}
	return fmt.Sprintf("uid %d (pid %d)", uid, pid)
}
