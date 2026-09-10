package sshagent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
)

// SignEvent is one authentication attempt, as recorded in the audit trail.
//
// It carries fingerprints and a decision — never key material, never the signed
// data. The signed payload contains protocol material and nothing an operator
// could act on, so retaining it in a permanent log would be cost without benefit.
type SignEvent struct {
	// KeyFingerprint is the key the sandbox asked to sign with.
	KeyFingerprint string
	// HostKeyFingerprint is the TARGET, learned from the session-bind extension
	// that preceded this request. Empty when the client never bound — see Allowed.
	HostKeyFingerprint string
	// HostKeyType is the target host key's algorithm.
	HostKeyType string
	// Allowed reports the proxy's decision.
	Allowed bool
	// Reason explains a refusal, and is empty when allowed.
	Reason string
}

// Auditor receives one event per signature attempt, allowed or refused. A refused
// attempt is the more interesting record of the two, so it is never dropped.
type Auditor func(SignEvent)

// Policy decides whether a signature may proceed, given the target host learned
// from session-bind. Returning a non-empty reason refuses it.
//
// This is a SECOND line of defence, not the primary one. OpenSSH's destination
// constraints are the enforcement point, because they are anchored by the
// target's own host-key signature. A policy here can only act on what the client
// chose to disclose, so it is used to refuse the clearly-wrong rather than to
// establish the right.
type Policy func(SignEvent) (reason string)

// Proxy sits between a sandbox's SSH_AUTH_SOCK and the daemon's real agent.
type Proxy struct {
	// upstream dials the daemon-held agent socket.
	upstream func() (net.Conn, error)
	audit    Auditor
	policy   Policy
	log      *slog.Logger
}

// Options wires a Proxy.
type Options struct {
	// Upstream dials the real agent. Required.
	Upstream func() (net.Conn, error)
	// Audit receives one event per signature attempt. nil => events are dropped,
	// which is only acceptable in tests: the audit record is half the reason this
	// proxy exists.
	Audit Auditor
	// Policy may refuse a signature. nil => allow whatever the destination
	// constraints already permit.
	Policy Policy
	Logger *slog.Logger
}

// New builds a Proxy.
func New(opts Options) (*Proxy, error) {
	if opts.Upstream == nil {
		return nil, errors.New("sshagent: an upstream dialer is required")
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Proxy{upstream: opts.Upstream, audit: opts.Audit, policy: opts.Policy, log: log}, nil
}

// forwardable is the ALLOWLIST of message types a sandbox may send through.
//
// An allowlist rather than a denylist, because the protocol grows: a message type
// added to OpenSSH after this code was written must not be silently forwarded to
// a component holding a private key. The cost of the allowlist is that a new
// legitimate capability needs a deliberate change here; that is the intended
// trade.
//
// Notably ABSENT and therefore refused: add/remove identity (a sandbox must not
// be able to change what the daemon's agent holds), lock/unlock (a sandbox must
// not be able to disable the agent for every other session sharing it), and
// smartcard operations.
var forwardable = map[byte]string{
	MsgRequestIdentities: "request-identities",
	MsgSignRequest:       "sign",
	MsgExtension:         "extension",
}

// Serve handles one sandbox connection until it closes.
func (p *Proxy) Serve(client net.Conn) error {
	defer client.Close()
	up, err := p.upstream()
	if err != nil {
		return fmt.Errorf("sshagent: dial upstream agent: %w", err)
	}
	defer up.Close()

	// boundHost is the target learned from the most recent session-bind on THIS
	// connection. It is per-connection state on purpose: a binding from one
	// sandbox connection must not describe a signature made on another.
	var (
		mu        sync.Mutex
		boundHost SessionBind
		haveBound bool
	)

	for {
		msg, err := readMessage(client)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(msg) == 0 {
			return fmt.Errorf("%w: empty message", ErrMalformed)
		}
		typ, body := msg[0], msg[1:]

		if _, ok := forwardable[typ]; !ok {
			// Refuse without forwarding. The sandbox gets a protocol-level failure,
			// which every SSH client already handles.
			p.log.Warn("sshagent: refused an agent message type not on the allowlist",
				"type", typ)
			if err := writeMessage(client, []byte{MsgFailure}); err != nil {
				return err
			}
			continue
		}

		switch typ {
		case MsgExtension:
			name, rest, perr := ExtensionName(body)
			if perr != nil {
				return perr
			}
			if name == SessionBindExtension {
				bind, berr := ParseSessionBind(rest)
				if berr != nil {
					// A malformed bind is refused rather than ignored: ignoring it would
					// let a client suppress the binding and then sign with no target
					// recorded.
					p.log.Warn("sshagent: refused a malformed session-bind", "err", berr)
					if err := writeMessage(client, []byte{MsgFailure}); err != nil {
						return err
					}
					continue
				}
				mu.Lock()
				boundHost, haveBound = bind, true
				mu.Unlock()
			}

		case MsgSignRequest:
			req, perr := ParseSignRequest(body)
			if perr != nil {
				return perr
			}
			mu.Lock()
			bind, bound := boundHost, haveBound
			mu.Unlock()

			ev := SignEvent{KeyFingerprint: req.KeyFingerprint(), Allowed: true}
			if bound {
				ev.HostKeyFingerprint = bind.HostKeyFingerprint()
				ev.HostKeyType = bind.HostKeyType()
			}
			if !bound {
				// No binding means no evidence of what is being authenticated to. The
				// audit record would be "a signature happened, target unknown", which
				// is exactly the unrestricted signing oracle that forwarded agents are
				// notorious for. Refuse.
				ev.Allowed, ev.Reason = false, "no session-bind: the target host is unknown, so this signature cannot be attributed"
			} else if p.policy != nil {
				if reason := p.policy(ev); reason != "" {
					ev.Allowed, ev.Reason = false, reason
				}
			}
			if p.audit != nil {
				p.audit(ev)
			}
			if !ev.Allowed {
				if err := writeMessage(client, []byte{MsgFailure}); err != nil {
					return err
				}
				continue
			}
		}

		// Forward the allowed message and relay exactly one reply.
		if err := writeMessage(up, msg); err != nil {
			return fmt.Errorf("sshagent: forward to upstream: %w", err)
		}
		reply, err := readMessage(up)
		if err != nil {
			return fmt.Errorf("sshagent: read upstream reply: %w", err)
		}
		if err := writeMessage(client, reply); err != nil {
			return err
		}
	}
}

// readMessage reads one length-prefixed agent message.
func readMessage(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, fmt.Errorf("%w: zero-length message", ErrMalformed)
	}
	if n > maxMessage {
		// An unbounded length prefix from a hostile sandbox is a memory-exhaustion
		// primitive. No legitimate agent message approaches this size.
		return nil, fmt.Errorf("%w: message of %d bytes exceeds the %d-byte limit", ErrMalformed, n, maxMessage)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeMessage writes one length-prefixed agent message.
func writeMessage(w io.Writer, msg []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(msg)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}
