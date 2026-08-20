package broker

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultVaultPath is the production vault database path. It sits under the
// daemon state root, 0600, daemon-user — the sandbox has no path to it.
const DefaultVaultPath = "/var/lib/opslify/vault.db"

// masterKeyLen is the AES-256 key length (bytes) for both the master key (KEK)
// and each per-secret data key (DEK).
const masterKeyLen = 32

// vaultFormatVersion is the on-disk schema version of the vault file. It is
// recorded so a future migration can detect the format.
const vaultFormatVersion = 1

// KeySource yields the 32-byte master key (KEK) that wraps every per-secret data
// key. It is an interface so the master key can come from an env var / passphrase
// (headless v1) or a future OS-keyring impl WITHOUT changing the vault. The KEK is
// NEVER persisted to the vault file — only wrapped data keys are.
type KeySource interface {
	// MasterKey returns the 32-byte KEK. It must not return a key derived from a
	// plaintext file living beside the vault db (that would defeat at-rest
	// encryption). An error fails vault construction closed.
	MasterKey() ([]byte, error)
}

// EnvKeySource reads the KEK from an environment variable (headless / CI). The
// value is 32 raw bytes encoded as hex (64 chars) or standard/raw base64. This is
// the documented v1 fallback; an OS-keyring source is the preferred production
// path and slots in behind the same interface.
type EnvKeySource struct {
	// Var is the environment variable name (e.g. "OPSLIFY_VAULT_KEY").
	Var string
}

// DefaultVaultKeyEnv is the env var the daemon reads the master key from when no
// other key source is configured.
const DefaultVaultKeyEnv = "OPSLIFY_VAULT_KEY"

func (e EnvKeySource) MasterKey() ([]byte, error) {
	name := e.Var
	if name == "" {
		name = DefaultVaultKeyEnv
	}
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, fmt.Errorf("%w: vault master key env %s is unset (set it to 32 bytes as hex or base64)", ErrInvalidInput, name)
	}
	key, err := decodeKey(raw)
	if err != nil {
		return nil, fmt.Errorf("broker: vault master key env %s: %w", name, err)
	}
	return key, nil
}

// StaticKeySource is a fixed in-memory KEK, used by tests and by a caller that
// derived the key elsewhere (e.g. a keyring lookup at startup). It never touches
// disk.
type StaticKeySource []byte

func (s StaticKeySource) MasterKey() ([]byte, error) {
	if len(s) != masterKeyLen {
		return nil, fmt.Errorf("%w: master key must be %d bytes, got %d", ErrInvalidInput, masterKeyLen, len(s))
	}
	out := make([]byte, len(s))
	copy(out, s)
	return out, nil
}

// decodeKey parses a 32-byte key from hex or base64.
func decodeKey(raw string) ([]byte, error) {
	if k, err := hex.DecodeString(raw); err == nil && len(k) == masterKeyLen {
		return k, nil
	}
	for _, dec := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := dec.DecodeString(raw); err == nil && len(k) == masterKeyLen {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w: expected 32 bytes as hex (64 chars) or base64", ErrInvalidInput)
}

// record is one on-disk secret. It holds only CIPHERTEXT + metadata — never a
// plaintext value and never the KEK. WrappedDEK is the data key encrypted under
// the KEK; Value is the secret encrypted under that data key. Both blobs are
// nonce||ciphertext (AES-256-GCM), base64-encoded for JSON.
type record struct {
	Ref        string    `json:"ref"`
	Provider   string    `json:"provider,omitempty"`
	Scope      string    `json:"scope,omitempty"`
	TTL        string    `json:"ttl,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	WrappedDEK string    `json:"wrapped_dek"` // base64(nonce||GCM(KEK, DEK))
	Value      string    `json:"value"`       // base64(nonce||GCM(DEK, plaintext))
}

// vaultFile is the whole on-disk document.
type vaultFile struct {
	Version int               `json:"version"`
	Secrets map[string]record `json:"secrets"`
}

// Vault is the local encrypted SecretBackend (the F5.6 default battery). Each
// value is sealed with a fresh random data key (DEK) which is itself wrapped by
// the master key (KEK) — envelope encryption, so the KEK can be rotated by
// re-wrapping the small DEKs without re-encrypting a single value. The whole file
// is persisted 0600, atomically. All operations are serialized by mu.
type Vault struct {
	path string
	mu   sync.Mutex
	kek  []byte
	data vaultFile
}

var _ SecretBackend = (*Vault)(nil)
var _ SecretManager = (*Vault)(nil)

// OpenVault opens (or initializes) the vault at path, loading the KEK from ks. It
// fails CLOSED: an unreadable KEK, a wrong-length key, a malformed file, or a
// vault file with looser-than-0600 perms is an error, never a silent empty vault.
func OpenVault(path string, ks KeySource) (*Vault, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: vault path is required", ErrInvalidInput)
	}
	kek, err := ks.MasterKey()
	if err != nil {
		return nil, err
	}
	if len(kek) != masterKeyLen {
		return nil, fmt.Errorf("%w: master key must be %d bytes", ErrInvalidInput, masterKeyLen)
	}
	v := &Vault{path: path, kek: kek, data: vaultFile{Version: vaultFormatVersion, Secrets: map[string]record{}}}
	if err := v.load(); err != nil {
		return nil, err
	}
	return v, nil
}

// load reads and parses the vault file if it exists. A missing file is a fresh
// (empty) vault. An existing file MUST be 0600 (no group/other bits) — a looser
// mode is a refuse-to-serve error, since the vault is a high-value target.
func (v *Vault) load() error {
	info, err := os.Stat(v.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // fresh vault
		}
		return fmt.Errorf("broker: stat vault %s: %w", v.path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("broker: vault %s has insecure perms %o (must be 0600)", v.path, perm)
	}
	b, err := os.ReadFile(v.path)
	if err != nil {
		return fmt.Errorf("broker: read vault %s: %w", v.path, err)
	}
	if len(b) == 0 {
		return nil
	}
	var f vaultFile
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("broker: parse vault %s: %w", v.path, err)
	}
	if f.Secrets == nil {
		f.Secrets = map[string]record{}
	}
	v.data = f
	return nil
}

// persist writes the vault file atomically at 0600 (temp file in the same dir,
// fsync, rename). The parent dir is created 0700 if absent.
func (v *Vault) persist() error {
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return fmt.Errorf("broker: create vault dir: %w", err)
	}
	b, err := json.MarshalIndent(v.data, "", "  ")
	if err != nil {
		return fmt.Errorf("broker: marshal vault: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(v.path), ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("broker: create vault temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("broker: chmod vault temp: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("broker: write vault temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("broker: fsync vault temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("broker: close vault temp: %w", err)
	}
	if err := os.Rename(tmpName, v.path); err != nil {
		return fmt.Errorf("broker: replace vault: %w", err)
	}
	return nil
}

// validRef bounds a ref to a safe, non-empty identifier so it can never be a path
// or an injection vector in a log/audit line.
func validRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("%w: ref is empty", ErrInvalidInput)
	}
	if len(ref) > 256 {
		return fmt.Errorf("%w: ref too long", ErrInvalidInput)
	}
	for _, r := range ref {
		ok := r == '-' || r == '_' || r == '.' || r == '/' || r == '@' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("%w: ref %q has an invalid character (allowed: alnum . _ - / @)", ErrInvalidInput, ref)
		}
	}
	if strings.Contains(ref, "..") {
		return fmt.Errorf("%w: ref %q contains ..", ErrInvalidInput, ref)
	}
	return nil
}

// Put stores value under ref (envelope-encrypted). See SecretBackend.Put.
func (v *Vault) Put(_ context.Context, ref string, value []byte, meta PutMeta, overwrite bool) error {
	if err := validRef(ref); err != nil {
		return err
	}
	if len(value) == 0 {
		return fmt.Errorf("%w: secret value is empty", ErrInvalidInput)
	}
	if meta.TTL != "" {
		if _, err := time.ParseDuration(meta.TTL); err != nil {
			return fmt.Errorf("%w: ttl %q: %v", ErrInvalidInput, meta.TTL, err)
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.data.Secrets[ref]; ok && !overwrite {
		return fmt.Errorf("%w: %s", ErrExists, ref)
	}

	// Fresh per-secret data key; sealed value under it; DEK wrapped under the KEK.
	dek := make([]byte, masterKeyLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return fmt.Errorf("broker: generate data key: %w", err)
	}
	defer Zeroize(dek)
	valueBlob, err := gcmSeal(dek, value)
	if err != nil {
		return err
	}
	wrapped, err := gcmSeal(v.kek, dek)
	if err != nil {
		return err
	}

	rec := record{
		Ref:        ref,
		Provider:   meta.Provider,
		Scope:      meta.Scope,
		TTL:        meta.TTL,
		CreatedAt:  time.Now().UTC(),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
		Value:      base64.StdEncoding.EncodeToString(valueBlob),
	}
	if existing, ok := v.data.Secrets[ref]; ok {
		rec.CreatedAt = existing.CreatedAt // preserve original creation on overwrite
	}
	v.data.Secrets[ref] = rec
	return v.persist()
}

// Get decrypts and returns the value + metadata for ref. DAEMON-INTERNAL ONLY.
func (v *Vault) Get(_ context.Context, ref string) ([]byte, SecretMeta, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	rec, ok := v.data.Secrets[ref]
	if !ok {
		return nil, SecretMeta{}, fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	dek, value, err := v.decrypt(rec)
	if err != nil {
		return nil, SecretMeta{}, err
	}
	Zeroize(dek)
	return value, metaOf(rec), nil
}

// decrypt unwraps the DEK under the KEK and opens the value under the DEK. The
// caller owns zeroing the returned dek; the value is returned to the caller.
func (v *Vault) decrypt(rec record) (dek, value []byte, err error) {
	wrapped, err := base64.StdEncoding.DecodeString(rec.WrappedDEK)
	if err != nil {
		return nil, nil, fmt.Errorf("broker: decode wrapped key for %s: %w", rec.Ref, err)
	}
	dek, err = gcmOpen(v.kek, wrapped)
	if err != nil {
		return nil, nil, fmt.Errorf("broker: unwrap data key for %s: %w", rec.Ref, err)
	}
	blob, err := base64.StdEncoding.DecodeString(rec.Value)
	if err != nil {
		Zeroize(dek)
		return nil, nil, fmt.Errorf("broker: decode value for %s: %w", rec.Ref, err)
	}
	value, err = gcmOpen(dek, blob)
	if err != nil {
		Zeroize(dek)
		return nil, nil, fmt.Errorf("broker: decrypt value for %s: %w", rec.Ref, err)
	}
	return dek, value, nil
}

// List returns metadata for every secret, sorted by ref. NEVER a value.
func (v *Vault) List(_ context.Context) ([]SecretMeta, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]SecretMeta, 0, len(v.data.Secrets))
	for _, rec := range v.data.Secrets {
		out = append(out, metaOf(rec))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, nil
}

// Delete removes ref.
func (v *Vault) Delete(_ context.Context, ref string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.data.Secrets[ref]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	delete(v.data.Secrets, ref)
	return v.persist()
}

// RotateMasterKey re-wraps every data key under newKEK WITHOUT re-encrypting any
// value (envelope encryption's whole point). It updates the in-use KEK on success
// and persists. On any failure the vault's KEK/state is left unchanged (the
// re-wrap is computed into a new map before it is committed), so a rotation is
// all-or-nothing. This is the primitive a scheduled key rotation is built on.
func (v *Vault) RotateMasterKey(newKEK []byte) error {
	if len(newKEK) != masterKeyLen {
		return fmt.Errorf("%w: new master key must be %d bytes", ErrInvalidInput, masterKeyLen)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	rewrapped := make(map[string]record, len(v.data.Secrets))
	for ref, rec := range v.data.Secrets {
		wrapped, err := base64.StdEncoding.DecodeString(rec.WrappedDEK)
		if err != nil {
			return fmt.Errorf("broker: rotate: decode wrapped key for %s: %w", ref, err)
		}
		dek, err := gcmOpen(v.kek, wrapped)
		if err != nil {
			return fmt.Errorf("broker: rotate: unwrap data key for %s: %w", ref, err)
		}
		newWrapped, err := gcmSeal(newKEK, dek)
		Zeroize(dek)
		if err != nil {
			return fmt.Errorf("broker: rotate: re-wrap data key for %s: %w", ref, err)
		}
		rec.WrappedDEK = base64.StdEncoding.EncodeToString(newWrapped)
		// rec.Value is UNTOUCHED — no value is re-encrypted.
		rewrapped[ref] = rec
	}
	prevKEK := v.kek
	v.data.Secrets = rewrapped
	v.kek = append([]byte(nil), newKEK...)
	if err := v.persist(); err != nil {
		v.kek = prevKEK // roll back the in-memory KEK if the write failed
		return err
	}
	Zeroize(prevKEK)
	return nil
}

func metaOf(rec record) SecretMeta {
	return SecretMeta{
		Ref:       rec.Ref,
		Provider:  rec.Provider,
		Scope:     rec.Scope,
		TTL:       rec.TTL,
		CreatedAt: rec.CreatedAt,
	}
}

// gcmSeal encrypts plaintext with key (AES-256-GCM) and returns nonce||ciphertext.
func gcmSeal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("broker: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// gcmOpen reverses gcmSeal: it splits nonce||ciphertext and authenticates+decrypts.
func gcmOpen(key, blob []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrInvalidInput)
	}
	nonce, ct := blob[:ns], blob[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("broker: gcm open (auth failed): %w", err)
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("broker: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("broker: gcm: %w", err)
	}
	return gcm, nil
}
