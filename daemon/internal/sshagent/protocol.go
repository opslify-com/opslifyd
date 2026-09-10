// Package sshagent implements just enough of the SSH agent protocol to sit
// between a sandbox and a daemon-held agent: forward what is allowed, refuse
// everything else, and record one audit event per signature.
//
// WHY A PROXY AT ALL. The agent protocol has no export operation — add, remove,
// list, sign, lock, unlock — so key material genuinely cannot cross the socket.
// That is the security property, and it comes from the protocol, not from this
// code. What this code adds is the two things the protocol does not give us:
//
//  1. AUDIT. One record per authentication, naming the host key the sandbox is
//     authenticating to. Without a proxy the daemon sees a socket being used and
//     nothing about what for.
//  2. AN ALLOWLIST. The protocol will grow message types, and a future agent may
//     answer ones we never considered. Forwarding only what we understand means a
//     capability added upstream is not silently granted to a sandbox we treat as
//     hostile.
//
// The ENFORCEMENT of which hosts a key may be used against is OpenSSH's
// destination constraints, not this proxy — see the ssh connection kind. This
// proxy cannot be the enforcement point on its own, because it can only see what
// the client chooses to tell it.
package sshagent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// Agent protocol message numbers (RFC draft-miller-ssh-agent).
const (
	MsgFailure             = 5
	MsgSuccess             = 6
	MsgRequestIdentities   = 11
	MsgIdentitiesAnswer    = 12
	MsgSignRequest         = 13
	MsgSignResponse        = 14
	MsgAddIdentity         = 17
	MsgRemoveIdentity      = 18
	MsgRemoveAllIdentities = 19
	MsgAddIDConstrained    = 25
	MsgAddSmartcardKey     = 20
	MsgLock                = 22
	MsgUnlock              = 23
	MsgExtension           = 27
)

// SessionBindExtension is the extension name OpenSSH uses to bind a forwarded
// agent to one session and one target host key.
//
// It is what makes the audit trustworthy rather than advisory: the message
// carries the TARGET's host key plus a signature by that host key over the
// session identifier. A compromised sandbox therefore cannot forge which host it
// is authenticating to — it would need the target's private host key to produce
// a matching signature.
const SessionBindExtension = "session-bind@openssh.com"

// maxMessage bounds one agent message. The real protocol has no explicit cap, but
// an unbounded length prefix from a hostile sandbox is a trivial memory
// exhaustion primitive, and no legitimate message comes close to this.
const maxMessage = 256 * 1024

// ErrMalformed marks a message this proxy will not forward because it could not
// be parsed. Refusing is the only safe response: forwarding bytes we do not
// understand to a component holding a private key is precisely what a proxy is
// for preventing.
var ErrMalformed = fmt.Errorf("sshagent: malformed message")

// reader walks an SSH-encoded byte string.
type reader struct {
	b []byte
}

// readString reads a uint32-length-prefixed byte string.
func (r *reader) readString() ([]byte, error) {
	if len(r.b) < 4 {
		return nil, fmt.Errorf("%w: truncated length prefix", ErrMalformed)
	}
	n := binary.BigEndian.Uint32(r.b[:4])
	if uint64(n) > uint64(len(r.b)-4) {
		return nil, fmt.Errorf("%w: string length %d exceeds remaining %d", ErrMalformed, n, len(r.b)-4)
	}
	out := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return out, nil
}

func (r *reader) readUint32() (uint32, error) {
	if len(r.b) < 4 {
		return 0, fmt.Errorf("%w: truncated uint32", ErrMalformed)
	}
	v := binary.BigEndian.Uint32(r.b[:4])
	r.b = r.b[4:]
	return v, nil
}

func (r *reader) readBool() (bool, error) {
	if len(r.b) < 1 {
		return false, fmt.Errorf("%w: truncated bool", ErrMalformed)
	}
	v := r.b[0] != 0
	r.b = r.b[1:]
	return v, nil
}

// SignRequest is a parsed SSH_AGENTC_SIGN_REQUEST.
type SignRequest struct {
	// KeyBlob is the public key the signature is requested under.
	KeyBlob []byte
	// Data is what would be signed. It is NOT retained in the audit record: it
	// contains the session identifier and other protocol material, and recording
	// it would put bytes in a permanent log for no diagnostic gain.
	Data  []byte
	Flags uint32
}

// KeyFingerprint is the standard SHA256 fingerprint of the key the signature is
// requested under, in the form ssh-keygen prints.
func (s SignRequest) KeyFingerprint() string { return fingerprint(s.KeyBlob) }

// ParseSignRequest parses the body of a sign request (type byte already consumed).
func ParseSignRequest(body []byte) (SignRequest, error) {
	r := &reader{b: body}
	key, err := r.readString()
	if err != nil {
		return SignRequest{}, err
	}
	data, err := r.readString()
	if err != nil {
		return SignRequest{}, err
	}
	flags, err := r.readUint32()
	if err != nil {
		return SignRequest{}, err
	}
	return SignRequest{KeyBlob: key, Data: data, Flags: flags}, nil
}

// SessionBind is a parsed session-bind@openssh.com extension message.
type SessionBind struct {
	// HostKeyBlob is the TARGET host's public key. This is the field that makes
	// the audit meaningful: it names what the sandbox is authenticating to.
	HostKeyBlob []byte
	// SessionID is the SSH session identifier the target signed.
	SessionID []byte
	// Signature is the target's signature over the session identifier, made with
	// its host key. Its presence is why a sandbox cannot lie about the target.
	Signature []byte
	// IsForwarding distinguishes binding for a forwarded hop from the first hop.
	IsForwarding bool
}

// HostKeyFingerprint is the target host key's SHA256 fingerprint.
func (s SessionBind) HostKeyFingerprint() string { return fingerprint(s.HostKeyBlob) }

// HostKeyType is the key algorithm, read from the blob's first field.
func (s SessionBind) HostKeyType() string {
	r := &reader{b: s.HostKeyBlob}
	t, err := r.readString()
	if err != nil {
		return ""
	}
	return string(t)
}

// ParseSessionBind parses a session-bind extension body (extension name already
// consumed).
func ParseSessionBind(body []byte) (SessionBind, error) {
	r := &reader{b: body}
	hostKey, err := r.readString()
	if err != nil {
		return SessionBind{}, err
	}
	sessionID, err := r.readString()
	if err != nil {
		return SessionBind{}, err
	}
	sig, err := r.readString()
	if err != nil {
		return SessionBind{}, err
	}
	fwd, err := r.readBool()
	if err != nil {
		return SessionBind{}, err
	}
	if len(hostKey) == 0 {
		return SessionBind{}, fmt.Errorf("%w: session-bind carries no host key", ErrMalformed)
	}
	if len(sig) == 0 {
		// A bind with no signature proves nothing about the target. Treating it as
		// valid would make the audit record a claim by the sandbox rather than
		// evidence from the host.
		return SessionBind{}, fmt.Errorf("%w: session-bind carries no host signature", ErrMalformed)
	}
	return SessionBind{HostKeyBlob: hostKey, SessionID: sessionID, Signature: sig, IsForwarding: fwd}, nil
}

// ExtensionName reads the extension type from an SSH_AGENTC_EXTENSION body.
func ExtensionName(body []byte) (string, []byte, error) {
	r := &reader{b: body}
	name, err := r.readString()
	if err != nil {
		return "", nil, err
	}
	return string(name), r.b, nil
}

// fingerprint renders a key blob as ssh-keygen does: SHA256:<base64, unpadded>.
func fingerprint(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
