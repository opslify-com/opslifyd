package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// ErrInUse is returned when a secret cannot be removed because something still
// addresses its ref. It fails CLOSED: silently deleting a ref that a policy grant
// or an egress rule still names would not surface until the next session tried to
// resolve it — in production, at the worst moment.
var ErrInUse = errors.New("broker: secret in use")

// SecretsService is the operator-facing surface over the vault: listing with
// consumers, rotation, and a delete that refuses while a ref is still addressed.
//
// It deliberately has NO read path. The manager interface it holds (SecretManager)
// omits Get by construction, so a value cannot be returned from here even by
// mistake — the write-only property is enforced by the type, not by discipline.
type SecretsService struct {
	secrets SecretManager
	index   *ConsumerIndex
	now     func() time.Time
	// log receives the administrative audit record for a rotation or a delete.
	//
	// HONEST SCOPE: this is a structured LOG line, not a tamper-evident chain
	// entry. The F3.1 chain is per-SESSION (rooted at session.start) and a secret
	// rotation happens outside any session, so there is no chain to append to. A
	// daemon-level administrative chain is a documented follow-up; until it lands
	// these records are as trustworthy as the daemon's log, and no more.
	log *slog.Logger
}

// NewSecretsService wires the service. index may be nil, in which case nothing is
// reported as a consumer and deletes are unguarded — acceptable only in tests.
func NewSecretsService(secrets SecretManager, index *ConsumerIndex) *SecretsService {
	return &SecretsService{secrets: secrets, index: index, now: time.Now, log: slog.Default()}
}

// WithLogger sets the audit logger (tests inject a capturing handler).
func (s *SecretsService) WithLogger(l *slog.Logger) *SecretsService {
	if l != nil {
		s.log = l
	}
	return s
}

// audit records an administrative action by REFERENCE. It takes metadata only —
// there is deliberately no parameter that could carry a value.
func (s *SecretsService) audit(action, ref, provider string, consumers int) {
	s.logger().Info("secret."+action,
		"audit", true,
		"ref", ref,
		"provider", provider,
		"consumers", consumers,
		"at", s.now().UTC().Format(time.RFC3339))
}

// SecretUpdater is the ATOMIC rotation path: it replaces the value under a ref
// only if the ref still exists at the moment of the write. A backend that does not
// implement it falls back to check-then-Put, which has a window in which a delete
// concurrent with a rotation is undone by the rotation's write.
type SecretUpdater interface {
	Update(ctx context.Context, ref string, value []byte, meta PutMeta) error
}

// logger returns the audit/diagnostic logger, defaulting when unset so a
// zero-value service cannot panic on a nil logger.
func (s *SecretsService) logger() *slog.Logger {
	if s.log == nil {
		return slog.Default()
	}
	return s.log
}

// SecretUpserter stores a value whether or not the ref exists, reporting the
// stored metadata and whether it REPLACED an existing record. One call, so a
// create and a rotation cannot end up sharing a plaintext buffer.
type SecretUpserter interface {
	Upsert(ctx context.Context, ref string, value []byte, meta PutMeta) (SecretMeta, bool, error)
}

// SecretView is a secret's metadata plus who uses it. It carries no value and no
// way to obtain one.
type SecretView struct {
	SecretMeta
	Consumers []Consumer `json:"consumers,omitempty"`
	// InUse is a convenience for a UI that does not want to count.
	InUse bool `json:"in_use"`
}

// List returns every secret with its consumers.
func (s *SecretsService) List(ctx context.Context) ([]SecretView, error) {
	metas, err := s.secrets.List(ctx)
	if err != nil {
		return nil, err
	}
	var byRef map[string][]Consumer
	if s.index != nil {
		if byRef, err = s.index.All(); err != nil {
			return nil, err
		}
	}
	out := make([]SecretView, 0, len(metas))
	for _, m := range metas {
		cs := byRef[m.Ref]
		out = append(out, SecretView{SecretMeta: m, Consumers: cs, InUse: len(cs) > 0})
	}
	return out, nil
}

// Consumers returns who addresses one ref.
func (s *SecretsService) Consumers(ref string) ([]Consumer, error) {
	if s.index == nil {
		return nil, nil
	}
	return s.index.Of(ref)
}

// Rotate replaces the value under an EXISTING ref, keeping the ref and its
// metadata so every consumer keeps working without an edit. It refuses to create
// a ref (that is `add`), because a typo'd rotate that silently created a new
// secret would leave the real one un-rotated and the operator believing otherwise.
//
// The write is atomic in the vault, so a resolve concurrent with a rotation sees
// either the old value or the new one, never a partial.
func (s *SecretsService) Rotate(ctx context.Context, ref string, value []byte, meta PutMeta) error {
	defer Zeroize(value)
	// No existence pre-check and no manual metadata carry-forward here. Both used
	// to live in this function and both were dead weight that merely LOOKED like
	// checks: Update re-tests existence under the mutex it writes under (so a
	// pre-check's answer is stale by the time it matters), and the write path
	// carries forward provider/scope/TTL from the record itself. A mutation making
	// the old lookup match by prefix changed nothing observable — the clearest
	// possible signal that it was not the control it appeared to be.
	//
	// The atomic path is REQUIRED, not preferred. The old fallback to
	// Put(overwrite=true) let a Delete landing mid-rotation be silently undone (the
	// ref came back holding the value the operator believed they had removed), and
	// let a rotation CREATE a ref — leaving the real credential un-rotated while
	// the operator believed otherwise. A backend that cannot rotate atomically
	// cannot offer this operation safely, and saying so beats doing it unsafely.
	u, ok := s.secrets.(SecretUpdater)
	if !ok {
		return fmt.Errorf("%w: this secret backend does not support atomic rotation", ErrDenied)
	}
	if err := u.Update(ctx, ref, value, meta); err != nil {
		return err
	}
	stored, err := s.find(ctx, ref)
	if err != nil {
		// The rotation succeeded; only the audit detail is unavailable.
		stored = SecretMeta{Ref: ref, Provider: meta.Provider}
	}
	cs, _ := s.Consumers(ref) // best-effort: the rotation already succeeded
	s.audit("rotate", ref, stored.Provider, len(cs))
	return nil
}

// Upsert stores a value under ref, creating or replacing it, and returns the
// stored metadata plus whether it replaced an existing record. A replacement is
// audited as a rotation, because that is what it is — `secrets add --overwrite`
// replaces a live credential just as `rotate` does, and one operation must not
// have two audit stories depending on which verb reached it.
//
// This is deliberately ONE backend call rather than a rotate-then-create pair.
// The pair corrupted data: Rotate zeroizes the caller's plaintext (correct
// hygiene), so the create that followed on ErrNotFound wrote an all-zero value
// and reported success. It also had a race the single call does not — two
// concurrent --overwrite requests on a fresh ref could make one of them lose to
// ErrExists.
func (s *SecretsService) Upsert(ctx context.Context, ref string, value []byte, meta PutMeta) (SecretMeta, bool, error) {
	defer Zeroize(value)
	u, ok := s.secrets.(SecretUpserter)
	if !ok {
		return SecretMeta{}, false, fmt.Errorf("%w: this secret backend does not support atomic upsert", ErrDenied)
	}
	stored, replaced, err := u.Upsert(ctx, ref, value, meta)
	if err != nil {
		return SecretMeta{}, false, err
	}
	action := "create"
	if replaced {
		action = "rotate"
	}
	cs, _ := s.Consumers(ref) // best-effort: the write already succeeded
	s.audit(action, ref, stored.Provider, len(cs))
	return stored, replaced, nil
}

// Delete removes a ref. It REFUSES while anything still addresses it unless force
// is set, in which case the caller is told exactly what it is breaking.
func (s *SecretsService) Delete(ctx context.Context, ref string, force bool) ([]Consumer, error) {
	if _, err := s.find(ctx, ref); err != nil {
		return nil, err
	}
	cs, err := s.Consumers(ref)
	if err != nil {
		if !force {
			// Unforced: fail CLOSED. Permitting a delete while the index cannot answer
			// "who uses this?" would break a running grant exactly when the daemon has
			// lost the ability to warn about it.
			return nil, err
		}
		// Forced: PROCEED. force already means "I accept breaking consumers", and
		// refusing here left an operator unable to revoke a leaked credential while
		// the project store was corrupt or a scope would not resolve — no escape
		// hatch at the moment one is most needed. The unknown consumer set is
		// surfaced rather than silently treated as empty.
		s.logger().Warn("broker: deleting a secret while its consumers are unknowable; forced",
			"ref", ref, "err", err)
		cs = nil
	}
	if len(cs) > 0 && !force {
		return cs, fmt.Errorf("%w: %q is used by %d consumer(s): %s (use force to remove anyway)",
			ErrInUse, ref, len(cs), FormatConsumers(cs))
	}
	if err := s.secrets.Delete(ctx, ref); err != nil {
		return cs, err
	}
	s.audit("delete", ref, "", len(cs))
	return cs, nil
}

// find returns a secret's metadata, or ErrNotFound. It reads the LISTING, never a
// value — there is no code path here that could decrypt one.
func (s *SecretsService) find(ctx context.Context, ref string) (SecretMeta, error) {
	metas, err := s.secrets.List(ctx)
	if err != nil {
		return SecretMeta{}, err
	}
	for _, m := range metas {
		if m.Ref == ref {
			return m, nil
		}
	}
	return SecretMeta{}, fmt.Errorf("%w: %s", ErrNotFound, ref)
}
