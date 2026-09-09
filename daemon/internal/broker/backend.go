// Package broker implements F5.6 — the SecretBackend interface, a local
// encrypted vault (the default battery), policy-`creds` gated resolution, and the
// `cred.resolve` audit event. It is the storage + management + gating + audit
// foundation of the P5 credential broker.
//
// SECURITY POSTURE (read before touching this package):
//   - A secret VALUE never leaves the daemon. Get is DAEMON-INTERNAL: it is used
//     by the future F5.1 injection path and is never wired to any CLI/API/UI
//     route. Only metadata (ref/provider/scope/ttl/created) is ever returned to a
//     caller outside the daemon.
//   - Values are write-only from outside: `opslify secrets add` puts a value in
//     (via stdin/file, never argv); nothing reads one back out.
//   - On disk the value is encrypted at rest (envelope encryption, see vault.go);
//     the master key never sits in a plaintext file beside the db.
//   - Resolution is DENY-BY-DEFAULT and gated on the F4.1 resolved policy `creds`
//     grants. An ungranted resolve is denied, audited, and returns NO value. Any
//     error fails closed (no value).
//
// HONEST CAVEAT: this feature does NOT yet make the agent credential-blind.
// Storing + gating + auditing a secret is the foundation; the agent still never
// receiving the value is the executor-side injection work of F5.1/F5.2. Do not
// overstate: a stored secret is not an injected-and-hidden secret.
package broker

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors. Callers use errors.Is; the daemon maps them to layer-tagged
// HTTP statuses (always with layer "cred" — failure legibility, shared-eng §6).
var (
	// ErrNotFound is returned when no secret exists for a ref (List/Delete/Get).
	ErrNotFound = errors.New("broker: secret not found")
	// ErrDenied is returned by Resolve when the session's policy does not grant the
	// ref (deny-by-default). No value is ever returned alongside it.
	ErrDenied = errors.New("broker: credential resolve denied by policy")
	// ErrInvalidInput is a bad ref/provider/value at the trust boundary.
	ErrInvalidInput = errors.New("broker: invalid input")
	// ErrExists is returned by Put when the ref already exists and overwrite was
	// not requested (add is not silently a replace).
	ErrExists = errors.New("broker: secret already exists")
)

// SecretMeta is the metadata face of a secret — everything about a secret EXCEPT
// its value. It is the only shape that ever crosses the daemon boundary (List, and
// the metadata half of an internal Get). It deliberately carries NO value and no
// value length (a length can narrow a brute force), only descriptive fields.
type SecretMeta struct {
	// Ref is the stable name a policy `creds` grant and a resolve address it by.
	Ref string `json:"ref"`
	// Provider is the backing credential provider (e.g. "aws", "github"); it is the
	// same vocabulary as policy.Cred.Provider, so a grant can pin name+provider.
	Provider string `json:"provider,omitempty"`
	// Scope is an opaque provider-specific scope string (e.g. an OAuth scope set or
	// an IAM scope-down hint), surfaced for audit; never secret.
	Scope string `json:"scope,omitempty"`
	// TTL is the requested lifetime hint for a minted/injected token (a Go duration
	// string). It bounds F5.1 injection later; here it is stored + audited only.
	TTL string `json:"ttl,omitempty"`
	// CreatedAt is when the secret was stored (audit/rotation hygiene).
	CreatedAt time.Time `json:"created_at"`
	// LastUsed is when a resolve last read this secret; zero means never. It is
	// metadata only — knowing WHEN a secret was used reveals nothing about it, and
	// "nothing has used this in 90 days" is the signal that retires a stale grant.
	LastUsed time.Time `json:"last_used,omitempty"`
	// RotatedAt is when the value was last replaced in place under the same ref.
	RotatedAt time.Time `json:"rotated_at,omitempty"`
}

// PutMeta is the metadata a caller supplies when storing a secret. Created is
// stamped by the backend, so it is not part of the input.
type PutMeta struct {
	Provider string
	Scope    string
	TTL      string
}

// SecretBackend is the pluggable storage battery (the F5.6 seam). The local
// encrypted vault is the default impl; a HashiCorp Vault / OpenBao / AWS Secrets
// Manager impl swaps in WITHOUT changing any caller. Callers depend on this
// interface, never a concrete store.
//
// Get is DAEMON-INTERNAL by contract: it returns a plaintext value and therefore
// must never be reachable from a CLI/API/UI route. Only the daemon's internal
// resolve/injection path calls it. The daemon's management surface is given a
// NARROWER interface (SecretManager, without Get) so a value read is not even
// expressible there.
type SecretBackend interface {
	// Put stores value under ref with meta, encrypting at rest. It returns ErrExists
	// if ref is present and overwrite is false. value is the caller's buffer; the
	// backend does not retain it past the call.
	Put(ctx context.Context, ref string, value []byte, meta PutMeta, overwrite bool) error
	// Get returns the decrypted value + metadata for ref. DAEMON-INTERNAL ONLY. The
	// returned value is a fresh buffer the caller SHOULD Zeroize after use.
	Get(ctx context.Context, ref string) (value []byte, meta SecretMeta, err error)
	// List returns metadata for every stored secret — NEVER a value. Sorted by ref.
	List(ctx context.Context) ([]SecretMeta, error)
	// Delete removes ref. ErrNotFound if absent.
	Delete(ctx context.Context, ref string) error
}

// SecretManager is the NARROW management surface exposed to the daemon's REST
// layer: put (write-only), list (metadata), delete. It deliberately OMITS Get, so
// no management route can even express a value read — the value-never-leaks
// invariant is enforced by the type, not just by discipline. The concrete Vault
// satisfies both SecretBackend and SecretManager; the daemon holds only this.
type SecretManager interface {
	Put(ctx context.Context, ref string, value []byte, meta PutMeta, overwrite bool) error
	List(ctx context.Context) ([]SecretMeta, error)
	Delete(ctx context.Context, ref string) error
}

// Zeroize best-effort scrubs a plaintext byte slice. Go gives a WEAKER guarantee
// than the plan's Rust target (`zeroize`/`secrecy`): the GC may have already
// copied the backing array during growth, the compiler could in principle elide a
// write to a slice that is never read again (it does not today for a range-set
// loop over a slice that escapes), and there is no memory locking. It is
// defence-in-depth — the primary control is that values are decrypted only in the
// daemon, held briefly, and never logged/traced. Callers zero decrypted buffers
// (and the vault zeroes every intermediate data key) as soon as they are done.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
