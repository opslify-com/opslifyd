package sshagent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- wire helpers (test-side encoder, so the tests drive REAL frames) --------

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}

func frame(msg []byte) []byte {
	out := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint32(out[:4], uint32(len(msg)))
	copy(out[4:], msg)
	return out
}

// keyBlob builds a plausible public-key blob: type string then opaque body.
func keyBlob(typ, body string) []byte {
	return append(sshString([]byte(typ)), sshString([]byte(body))...)
}

func signRequest(key []byte, data string, flags uint32) []byte {
	msg := []byte{MsgSignRequest}
	msg = append(msg, sshString(key)...)
	msg = append(msg, sshString([]byte(data))...)
	var f [4]byte
	binary.BigEndian.PutUint32(f[:], flags)
	return append(msg, f[:]...)
}

func sessionBind(hostKey []byte, sessionID, sig string, forwarding bool) []byte {
	msg := []byte{MsgExtension}
	msg = append(msg, sshString([]byte(SessionBindExtension))...)
	msg = append(msg, sshString(hostKey)...)
	msg = append(msg, sshString([]byte(sessionID))...)
	msg = append(msg, sshString([]byte(sig))...)
	b := byte(0)
	if forwarding {
		b = 1
	}
	return append(msg, b)
}

// fakeAgent stands in for the daemon's real ssh-agent. It records what reached it
// — which is how the tests prove a refused message was never forwarded.
//
// Access is mutex-guarded because the recording goroutine and the test read it
// concurrently. It also matters that assertions are ORDERED after the proxy has
// finished handling a message: reading the refusal reply does not by itself mean
// the proxy has stopped, so `sawType` is used after a synchronising round-trip
// rather than immediately. An unsynchronised check let a mutation that forwarded
// refused signatures survive.
type fakeAgent struct {
	mu   sync.Mutex
	got  [][]byte
	conn net.Conn
}

func (a *fakeAgent) record(msg []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, append([]byte(nil), msg...))
}

// sawType reports whether a message of this type ever reached the agent.
func (a *fakeAgent) sawType(typ byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, m := range a.got {
		if len(m) > 0 && m[0] == typ {
			return true
		}
	}
	return false
}

func (a *fakeAgent) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.got)
}

// syncPoint sends a message that IS forwarded and waits for its reply. Because
// the proxy handles one connection's messages sequentially, a completed
// round-trip proves every earlier message has been fully handled — so a
// subsequent sawType assertion is deterministic rather than a race.
func syncPoint(t *testing.T, c net.Conn) {
	t.Helper()
	if reply := writeAndRead(t, c, []byte{MsgRequestIdentities}); reply[0] != MsgSuccess {
		t.Fatalf("sync round-trip failed: reply %d", reply[0])
	}
}

func newProxyPair(t *testing.T, opts Options) (client net.Conn, agent *fakeAgent, done chan error) {
	t.Helper()
	agentClient, agentServer := net.Pipe()
	agent = &fakeAgent{conn: agentServer}
	go func() {
		for {
			msg, err := readMessage(agentServer)
			if err != nil {
				return
			}
			agent.record(msg)
			// A generic success reply; the proxy only relays it.
			_ = writeMessage(agentServer, []byte{MsgSuccess})
		}
	}()

	opts.Upstream = func() (net.Conn, error) { return agentClient, nil }
	p, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sandbox, proxySide := net.Pipe()
	done = make(chan error, 1)
	go func() { done <- p.Serve(proxySide) }()
	t.Cleanup(func() {
		_ = sandbox.Close()
		_ = agentClient.Close()
		_ = agentServer.Close()
	})
	return sandbox, agent, done
}

func writeAndRead(t *testing.T, c net.Conn, msg []byte) []byte {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(frame(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply, err := readMessage(c)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return reply
}

// --- the audit record ---------------------------------------------------------

// TestSignatureIsAuditedWithTheTargetHostKey is the F8.2 acceptance criterion:
// every signature emits an event carrying the TARGET's fingerprint, the key id
// and the decision. Without the target, the record says only "a signature
// happened" — which is the unrestricted signing oracle forwarded agents are
// notorious for.
func TestSignatureIsAuditedWithTheTargetHostKey(t *testing.T) {
	var events []SignEvent
	host := keyBlob("ssh-ed25519", "prod-web-01-host-key")
	key := keyBlob("ssh-ed25519", "ops-fleet-key")

	client, agent, _ := newProxyPair(t, Options{Audit: func(e SignEvent) { events = append(events, e) }})

	// Bind first, as OpenSSH does on a forwarded agent.
	if reply := writeAndRead(t, client, sessionBind(host, "session-id-1", "host-signature", true)); reply[0] != MsgSuccess {
		t.Fatalf("session-bind reply = %d", reply[0])
	}
	if reply := writeAndRead(t, client, signRequest(key, "data-to-sign", 0)); reply[0] != MsgSuccess {
		t.Fatalf("sign reply = %d, want success", reply[0])
	}

	if len(events) != 1 {
		t.Fatalf("want one audit event, got %d", len(events))
	}
	ev := events[0]
	if !ev.Allowed {
		t.Errorf("the signature should have been allowed: %s", ev.Reason)
	}
	if ev.HostKeyFingerprint == "" || !strings.HasPrefix(ev.HostKeyFingerprint, "SHA256:") {
		t.Errorf("the event must name the target host key: %+v", ev)
	}
	if ev.HostKeyFingerprint == ev.KeyFingerprint {
		t.Error("the target host key and the signing key must be distinguished")
	}
	if ev.HostKeyType != "ssh-ed25519" {
		t.Errorf("host key type = %q", ev.HostKeyType)
	}
	// The signed DATA must not be in the record: it is protocol material, and a
	// permanent log of it buys nothing.
	if strings.Contains(ev.Reason, "data-to-sign") {
		t.Error("the signed data must not reach the audit record")
	}
	// And the sign request DID reach the real agent.
	if !agent.sawType(MsgSignRequest) {
		t.Error("an allowed signature must reach the upstream agent")
	}
}

// TestUnboundSignatureIsRefusedAndRecorded: with no session-bind there is no
// evidence of the target, so the signature is refused. A refused attempt is the
// more interesting audit record of the two and must never be dropped.
func TestUnboundSignatureIsRefusedAndRecorded(t *testing.T) {
	var events []SignEvent
	client, agent, _ := newProxyPair(t, Options{Audit: func(e SignEvent) { events = append(events, e) }})

	reply := writeAndRead(t, client, signRequest(keyBlob("ssh-ed25519", "k"), "data", 0))
	if reply[0] != MsgFailure {
		t.Fatalf("an unbound signature must be refused, got reply %d", reply[0])
	}
	if len(events) != 1 || events[0].Allowed {
		t.Fatalf("the refusal must be recorded: %+v", events)
	}
	if !strings.Contains(events[0].Reason, "session-bind") {
		t.Errorf("the reason must say what was missing: %q", events[0].Reason)
	}
	// And it must NEVER have reached the agent holding the key. Ordered after a
	// sync round-trip so this cannot pass merely because the proxy had not got
	// around to forwarding yet.
	syncPoint(t, client)
	if agent.sawType(MsgSignRequest) {
		t.Fatal("a refused signature reached the upstream agent")
	}
}

// TestPolicyCanRefuseASignature: a second line of defence over what the client
// disclosed. The primary control is OpenSSH destination constraints.
func TestPolicyCanRefuseASignature(t *testing.T) {
	var events []SignEvent
	host := keyBlob("ssh-ed25519", "db-01-host-key")
	client, agent, _ := newProxyPair(t, Options{
		Audit:  func(e SignEvent) { events = append(events, e) },
		Policy: func(e SignEvent) string { return "db-01 is out of scope for this session" },
	})
	writeAndRead(t, client, sessionBind(host, "sid", "sig", true))
	reply := writeAndRead(t, client, signRequest(keyBlob("ssh-ed25519", "k"), "d", 0))
	if reply[0] != MsgFailure {
		t.Fatalf("a policy-refused signature must fail, got %d", reply[0])
	}
	if len(events) != 1 || events[0].Allowed || !strings.Contains(events[0].Reason, "out of scope") {
		t.Fatalf("the policy reason must reach the audit record: %+v", events)
	}
	syncPoint(t, client)
	if agent.sawType(MsgSignRequest) {
		t.Fatal("a policy-refused signature reached the agent")
	}
}

// --- the allowlist -------------------------------------------------------------

// TestOnlyAllowlistedMessagesReachTheAgent. The protocol grows, and a message
// type added upstream must not be silently forwarded to a component holding a
// private key. Notably refused: add/remove identity (a sandbox must not change
// what the agent holds) and lock/unlock (a sandbox must not disable the agent for
// every other session using it).
func TestOnlyAllowlistedMessagesReachTheAgent(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  byte
	}{
		{"add-identity", MsgAddIdentity},
		{"add-identity-constrained", MsgAddIDConstrained},
		{"remove-identity", MsgRemoveIdentity},
		{"remove-all-identities", MsgRemoveAllIdentities},
		{"lock", MsgLock},
		{"unlock", MsgUnlock},
		{"add-smartcard", MsgAddSmartcardKey},
		{"unknown-future-type", 99},
		{"unknown-future-type-2", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, agent, _ := newProxyPair(t, Options{})
			reply := writeAndRead(t, client, []byte{tc.typ, 0, 0, 0, 0})
			if reply[0] != MsgFailure {
				t.Fatalf("%s must be refused, got reply %d", tc.name, reply[0])
			}
			syncPoint(t, client)
			if agent.sawType(tc.typ) {
				t.Fatalf("%s reached the upstream agent", tc.name)
			}
		})
	}
}

// TestRequestIdentitiesIsForwarded: listing public keys is how a client knows
// which key to ask for, and it discloses nothing secret.
func TestRequestIdentitiesIsForwarded(t *testing.T) {
	client, agent, _ := newProxyPair(t, Options{})
	if reply := writeAndRead(t, client, []byte{MsgRequestIdentities}); reply[0] != MsgSuccess {
		t.Fatalf("request-identities reply = %d", reply[0])
	}
	if !agent.sawType(MsgRequestIdentities) || agent.count() != 1 {
		t.Fatalf("request-identities must be forwarded exactly once, saw %d messages", agent.count())
	}
}

// --- malformed input ----------------------------------------------------------

// TestMalformedSessionBindIsRefusedNotIgnored: ignoring it would let a client
// suppress the binding and then sign with no target recorded — turning the audit
// into a claim by the sandbox rather than evidence from the host.
func TestMalformedSessionBindIsRefusedNotIgnored(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  []byte
	}{
		{"truncated", append([]byte{MsgExtension}, sshString([]byte(SessionBindExtension))...)},
		{"no host key", func() []byte {
			return sessionBind(nil, "sid", "sig", true)
		}()},
		{"no signature", func() []byte {
			return sessionBind(keyBlob("ssh-ed25519", "h"), "sid", "", true)
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []SignEvent
			client, agent, _ := newProxyPair(t, Options{Audit: func(e SignEvent) { events = append(events, e) }})
			reply := writeAndRead(t, client, tc.msg)
			if reply[0] != MsgFailure {
				t.Fatalf("a malformed session-bind must be refused, got %d", reply[0])
			}
			// A signature afterwards must still be refused: no valid binding exists.
			reply = writeAndRead(t, client, signRequest(keyBlob("ssh-ed25519", "k"), "d", 0))
			if reply[0] != MsgFailure {
				t.Fatal("a signature after a refused bind must also be refused")
			}
			syncPoint(t, client)
			if agent.sawType(MsgSignRequest) {
				t.Fatal("a signature with no valid binding reached the agent")
			}
		})
	}
}

// TestOversizedMessageIsRefused: an unbounded length prefix from a hostile
// sandbox is a memory-exhaustion primitive.
func TestOversizedMessageIsRefused(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 1<<30)
	if _, err := readMessage(bytes.NewReader(hdr[:])); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a 1 GiB length prefix must be refused, got %v", err)
	}
	binary.BigEndian.PutUint32(hdr[:], 0)
	if _, err := readMessage(bytes.NewReader(hdr[:])); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a zero-length message must be refused, got %v", err)
	}
}

// TestStringReaderRefusesOverlongLengths: a length prefix claiming more than the
// buffer holds must not slice out of range.
func TestStringReaderRefusesOverlongLengths(t *testing.T) {
	r := &reader{b: []byte{0xff, 0xff, 0xff, 0xff, 'a'}}
	if _, err := r.readString(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
	r = &reader{b: []byte{0, 0}}
	if _, err := r.readString(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed on a truncated prefix, got %v", err)
	}
}

// TestNoUpstreamDialerIsRefused: a proxy with nowhere to forward would accept
// sandbox connections and answer nothing.
func TestNoUpstreamDialerIsRefused(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("a proxy with no upstream dialer must be refused")
	}
}

// TestClientCloseEndsServeCleanly: a sandbox disconnecting is normal, not an error.
func TestClientCloseEndsServeCleanly(t *testing.T) {
	client, _, done := newProxyPair(t, Options{})
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("a client close must end Serve cleanly, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the client closed")
	}
}
