package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
)

func mustPut(t *testing.T, v *Vault, ref, val, provider string) {
	t.Helper()
	if err := v.Put(context.Background(), ref, []byte(val), PutMeta{Provider: provider}, false); err != nil {
		t.Fatalf("Put %s: %v", ref, err)
	}
}

// --- the load-bearing property: there is no read path ------------------------

// SecretsService holds a SecretManager, which omits Get BY CONSTRUCTION. This is
// a compile-time proof that no method here can return a value, and it is the
// whole reason a ref is safe to write in a config file or hand to an agent.
func TestSecretsServiceHasNoReadPath(t *testing.T) {
	// The property is about the INTERFACE's method set, not about whatever
	// concrete type happens to satisfy it: SecretsService holds a SecretManager,
	// so if that interface has no Get, no method on the service can return a
	// value however it is implemented. This is a structural guarantee, not a
	// convention someone has to remember.
	mgr := reflect.TypeOf((*SecretManager)(nil)).Elem()
	for i := 0; i < mgr.NumMethod(); i++ {
		if mgr.Method(i).Name == "Get" {
			t.Fatal("SecretManager gained a Get — a read path here defeats the entire feature")
		}
	}

	// And no method on the service itself may hand back raw bytes.
	svcT := reflect.TypeOf(&SecretsService{})
	for i := 0; i < svcT.NumMethod(); i++ {
		m := svcT.Method(i)
		for r := 0; r < m.Type.NumOut(); r++ {
			out := m.Type.Out(r)
			if out.Kind() == reflect.Slice && out.Elem().Kind() == reflect.Uint8 {
				t.Fatalf("SecretsService.%s returns []byte — that is a value read path", m.Name)
			}
		}
	}

	// The service must genuinely be typed on the narrow interface.
	if got := reflect.TypeOf(SecretsService{}).Field(0).Type; got != mgr {
		t.Fatalf("SecretsService holds %v, want the Get-less SecretManager", got)
	}
}

// A listing carries metadata and consumers only. If a value ever leaked into a
// view it would reach every UI and API response that renders one.
func TestListNeverCarriesAValue(t *testing.T) {
	v, _ := newTestVault(t)
	const secret = "s3cr3t-canary-value"
	mustPut(t, v, "gitlab-token", secret, "gitlab")

	svc := NewSecretsService(v, NewConsumerIndex())
	views, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("want 1 view, got %d", len(views))
	}
	if strings.Contains(dump(t, views), secret) {
		t.Fatal("a secret VALUE appeared in a listing")
	}
}

// --- consumer index ----------------------------------------------------------

func TestConsumerIndexFindsEveryKindOfConsumer(t *testing.T) {
	idx := NewConsumerIndex(
		ConfigConsumers(
			[]EgressInjectRef{{Host: "gitlab.example.com", SecretRef: "gitlab-token"}},
			[]RegistryUpstreamRef{{Ecosystem: "pypi", CredRef: "pypi-token"}},
		),
		PolicyConsumers([]PolicyScope{{
			Scope:  "tripon/staging",
			Policy: policy.Policy{Creds: []policy.Cred{{Name: "gitlab-token", Provider: "gitlab"}}},
		}}),
	)
	all, err := idx.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	// One ref, two different kinds of consumer — the case that makes rotation one
	// action instead of an edit in several places.
	if got := len(all["gitlab-token"]); got != 2 {
		t.Fatalf("gitlab-token consumers = %d, want 2 (%v)", got, all["gitlab-token"])
	}
	if got := len(all["pypi-token"]); got != 1 {
		t.Fatalf("pypi-token consumers = %d, want 1", got)
	}
	var kinds []string
	for _, c := range all["gitlab-token"] {
		kinds = append(kinds, string(c.Kind))
	}
	for _, want := range []string{string(ConsumerEgressInject), string(ConsumerPolicyGrant)} {
		if !containsStr(kinds, want) {
			t.Errorf("missing consumer kind %q in %v", want, kinds)
		}
	}
}

// A source that errors must fail the whole index CLOSED: under-reporting
// consumers is what lets a delete break a live grant.
func TestConsumerIndexFailsClosedOnSourceError(t *testing.T) {
	idx := NewConsumerIndex(ConsumerSourceFunc(func() (map[string][]Consumer, error) {
		return nil, errors.New("boom")
	}))
	if _, err := idx.All(); err == nil {
		t.Fatal("a failing consumer source must fail the index, not be skipped")
	}
}

// --- delete guard ------------------------------------------------------------

func TestDeleteRefusesWhileInUseAndForceReports(t *testing.T) {
	v, _ := newTestVault(t)
	mustPut(t, v, "gitlab-token", "v", "gitlab")
	idx := NewConsumerIndex(ConfigConsumers(
		[]EgressInjectRef{{Host: "gitlab.example.com", SecretRef: "gitlab-token"}}, nil))
	svc := NewSecretsService(v, idx)
	ctx := context.Background()

	cs, err := svc.Delete(ctx, "gitlab-token", false)
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("delete of an in-use ref: got %v, want ErrInUse", err)
	}
	if len(cs) != 1 {
		t.Fatalf("the refusal must name the consumers, got %v", cs)
	}
	if metas, _ := v.List(ctx); len(metas) != 1 {
		t.Fatal("a refused delete must leave the secret intact")
	}

	// force proceeds AND reports what it broke.
	cs, err = svc.Delete(ctx, "gitlab-token", true)
	if err != nil {
		t.Fatalf("forced delete: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("a forced delete must report what it broke, got %v", cs)
	}
	if metas, _ := v.List(ctx); len(metas) != 0 {
		t.Fatal("a forced delete must remove the secret")
	}
}

func TestDeleteUnusedSecretSucceeds(t *testing.T) {
	v, _ := newTestVault(t)
	mustPut(t, v, "orphan", "v", "")
	svc := NewSecretsService(v, NewConsumerIndex())
	if _, err := svc.Delete(context.Background(), "orphan", false); err != nil {
		t.Fatalf("deleting an unused secret must succeed: %v", err)
	}
}

// --- rotation ----------------------------------------------------------------

// Rotation keeps the ref and its metadata, so consumers that address the ref keep
// working with no edit anywhere.
func TestRotateKeepsRefAndConsumersAndCarriesMetadata(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Put(context.Background(), "gitlab-token", []byte("old"),
		PutMeta{Provider: "gitlab", TTL: "15m", Scope: "api"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	before, _ := v.List(context.Background())
	svc := NewSecretsService(v, NewConsumerIndex())

	if err := svc.Rotate(context.Background(), "gitlab-token", []byte("new"), PutMeta{}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	after, _ := v.List(context.Background())
	if len(after) != 1 || after[0].Ref != "gitlab-token" {
		t.Fatalf("rotation must keep exactly the same ref, got %v", after)
	}
	// Metadata the caller did not restate must survive, or a rotation silently
	// drops a TTL bound or a provider pin.
	if after[0].Provider != "gitlab" || after[0].TTL != "15m" || after[0].Scope != "api" {
		t.Fatalf("rotation dropped metadata: %+v", after[0])
	}
	if !after[0].CreatedAt.Equal(before[0].CreatedAt) {
		t.Fatal("rotation must preserve CreatedAt — it is the same secret identity")
	}
	if after[0].RotatedAt.IsZero() {
		t.Fatal("rotation must stamp RotatedAt; nothing downstream can otherwise tell the value changed")
	}
	// And the NEW value is what resolves.
	got, _, err := v.Get(context.Background(), "gitlab-token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("resolve after rotation = %q, want the new value", got)
	}
}

// Rotate must not CREATE a ref: a typo would otherwise leave the real secret
// un-rotated while the operator believed it had been replaced.
func TestRotateRefusesUnknownRef(t *testing.T) {
	vv, _ := newTestVault(t)
	svc := NewSecretsService(vv, NewConsumerIndex())
	if err := svc.Rotate(context.Background(), "never-stored", []byte("v"), PutMeta{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotating an unknown ref: got %v, want ErrNotFound", err)
	}
}

// A failed rotation leaves the previous value intact — the sync path relies on
// this, since a manager fetch can fail midway.
func TestFailedRotationLeavesPreviousValueIntact(t *testing.T) {
	v, _ := newTestVault(t)
	mustPut(t, v, "gitlab-token", "old", "gitlab")
	svc := NewSecretsService(v, NewConsumerIndex())

	// An empty value is refused by the vault, standing in for a failed fetch.
	if err := svc.Rotate(context.Background(), "gitlab-token", []byte(""), PutMeta{}); err == nil {
		t.Fatal("rotating to an empty value must be refused")
	}
	got, _, err := v.Get(context.Background(), "gitlab-token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "old" {
		t.Fatalf("a failed rotation changed the stored value to %q", got)
	}
}

// --- last-used ---------------------------------------------------------------

func TestResolveStampsLastUsed(t *testing.T) {
	v, path := newTestVault(t)
	mustPut(t, v, "gitlab-token", "v", "gitlab")
	before, _ := v.List(context.Background())
	if !before[0].LastUsed.IsZero() {
		t.Fatal("a never-resolved secret must have a zero LastUsed")
	}
	if _, _, err := v.Get(context.Background(), "gitlab-token"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	after, _ := v.List(context.Background())
	if after[0].LastUsed.IsZero() {
		t.Fatal("a resolve must stamp LastUsed — it is the signal that retires a stale grant")
	}
	// The stamp must reach DISK, not just memory: it is read back after a restart
	// to retire stale grants. The old assertion here only checked that an accessor
	// returned nil, which it did even when nothing was ever written.
	reopened, err := OpenVault(path, StaticKeySource(testKey()))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	persisted, _ := reopened.List(context.Background())
	if persisted[0].LastUsed.IsZero() {
		t.Fatal("the first resolve of a ref must flush its last-used stamp to disk")
	}
}

// TestLastUsedWritesAreThrottled pins D7: a resolve used to rewrite the WHOLE
// vault file, so a hot ref turned every credential injection into a full-file
// write. The stamp must stay exact in memory while the writes are throttled.
func TestLastUsedWritesAreThrottled(t *testing.T) {
	v, path := newTestVault(t)
	mustPut(t, v, "hot", "v", "gitlab")
	ctx := context.Background()

	writes := func() int64 {
		t.Helper()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		return fi.ModTime().UnixNano()
	}
	if _, _, err := v.Get(ctx, "hot"); err != nil { // first resolve flushes
		t.Fatalf("Get: %v", err)
	}
	afterFirst := writes()

	for i := 0; i < 50; i++ {
		if _, _, err := v.Get(ctx, "hot"); err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
	}
	if writes() != afterFirst {
		t.Error("50 resolves inside one flush interval must not rewrite the vault file")
	}
	// In-memory freshness is NOT sacrificed by the throttle.
	metas, _ := v.List(ctx)
	if time.Since(metas[0].LastUsed) > time.Minute {
		t.Error("the in-memory last-used stamp must stay exact regardless of flushing")
	}

	// Once the interval has elapsed, the next resolve does flush.
	v.mu.Lock()
	v.lastUsedFlushed["hot"] = time.Now().UTC().Add(-2 * lastUsedFlushInterval)
	v.mu.Unlock()
	if _, _, err := v.Get(ctx, "hot"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if writes() == afterFirst {
		t.Error("a resolve after the flush interval must persist the stamp")
	}
}

// TestResolveSurvivesUnpersistableLastUsed pins D6: the resolve must succeed and
// the failure must be VISIBLE. Previously it was recorded in a field nothing read.
func TestResolveSurvivesUnpersistableLastUsed(t *testing.T) {
	v, path := newTestVault(t)
	const value = "SECRET-VALUE-must-not-be-logged"
	mustPut(t, v, "gitlab-token", value, "gitlab")

	var buf bytes.Buffer
	v.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	// Make persist fail: the vault writes via a temp file in the same directory.
	if err := os.Chmod(filepath.Dir(path), 0o500); err != nil {
		t.Skipf("cannot make dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	got, _, err := v.Get(context.Background(), "gitlab-token")
	if err != nil {
		t.Fatalf("a resolve must SUCCEED through a last-used persist failure: %v", err)
	}
	if string(got) != value {
		t.Fatalf("value = %q", got)
	}
	if !strings.Contains(buf.String(), "last-used") {
		t.Errorf("the persist failure must be logged, not swallowed; log = %q", buf.String())
	}
	if strings.Contains(buf.String(), value) {
		t.Errorf("the log must never carry the value; log = %q", buf.String())
	}
}

// TestRotateCannotResurrectDeletedRef pins D8. Rotation used to check existence
// and then write; a delete in between was undone by the write, bringing a
// credential the operator had removed back to life with a fresh value.
func TestRotateCannotResurrectDeletedRef(t *testing.T) {
	v, _ := newTestVault(t)
	mustPut(t, v, "doomed", "old", "gitlab")
	ctx := context.Background()

	if err := v.Delete(ctx, "doomed"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Simulates the rotation resuming after the delete landed: the service has
	// already passed its existence check and is now performing the write.
	err := v.Update(ctx, "doomed", []byte("new"), PutMeta{Provider: "gitlab"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update of a concurrently-deleted ref must fail with ErrNotFound, got %v", err)
	}
	metas, _ := v.List(ctx)
	for _, m := range metas {
		if m.Ref == "doomed" {
			t.Fatal("a deleted ref was resurrected by a concurrent rotation")
		}
	}
}

// TestRotateUsesAtomicPath makes sure the service actually TAKES the atomic path.
// Without this, dropping the SecretUpdater branch leaves every other test green.
func TestRotateUsesAtomicPath(t *testing.T) {
	v, _ := newTestVault(t)
	mustPut(t, v, "gitlab-token", "old", "gitlab")
	spy := &updaterSpy{Vault: v}
	svc := NewSecretsService(spy, nil)
	if err := svc.Rotate(context.Background(), "gitlab-token", []byte("new"), PutMeta{}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !spy.updateCalled() {
		t.Fatal("Rotate must go through the atomic Update path, not find-then-Put")
	}
}

// updaterSpy records whether the atomic path was taken.
type updaterSpy struct {
	*Vault
	called bool
	mu     sync.Mutex
}

func (u *updaterSpy) Update(ctx context.Context, ref string, value []byte, meta PutMeta) error {
	u.mu.Lock()
	u.called = true
	u.mu.Unlock()
	return u.Vault.Update(ctx, ref, value, meta)
}

func (u *updaterSpy) updateCalled() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.called
}

// --- ref validation ----------------------------------------------------------

func TestUnsafeRefsRefused(t *testing.T) {
	v, _ := newTestVault(t)
	for _, ref := range []string{"", "../escape", "a b", "tab\there", "nul\x00byte", strings.Repeat("x", 300)} {
		if err := v.Put(context.Background(), ref, []byte("v"), PutMeta{}, false); err == nil {
			t.Errorf("Put(%q) must be refused", ref)
		}
	}
}

// dump renders a value for a leak check. A secret must not appear in ANY
// rendering of a view, so the assertion is deliberately over the whole struct.
func dump(t *testing.T, v any) string {
	t.Helper()
	return fmt.Sprintf("%+v", v)
}

func containsStr(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// --- administrative audit (D2) -----------------------------------------------

// TestRotateAndDeleteAreAudited pins that an administrative change to a
// credential leaves a record naming the ref — and that the record can never carry
// the value. Without this, a rotation or a delete was completely invisible.
func TestRotateAndDeleteAreAudited(t *testing.T) {
	const value = "SECRET-VALUE-must-not-be-audited"
	ctx := context.Background()

	for _, tc := range []struct {
		name, want string
		act        func(*SecretsService) error
	}{
		{"rotate", "secret.rotate", func(s *SecretsService) error {
			return s.Rotate(ctx, "gitlab-token", []byte(value), PutMeta{})
		}},
		{"delete", "secret.delete", func(s *SecretsService) error {
			_, err := s.Delete(ctx, "gitlab-token", false)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := newTestVault(t)
			mustPut(t, v, "gitlab-token", value, "gitlab")
			var buf bytes.Buffer
			svc := NewSecretsService(v, nil).
				WithLogger(slog.New(slog.NewTextHandler(&buf, nil)))

			if err := tc.act(svc); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			log := buf.String()
			if !strings.Contains(log, tc.want) {
				t.Errorf("%s must leave an audit record; log = %q", tc.name, log)
			}
			if !strings.Contains(log, "gitlab-token") {
				t.Errorf("the audit record must name the ref; log = %q", log)
			}
			if strings.Contains(log, value) {
				t.Errorf("the audit record must NEVER carry the value; log = %q", log)
			}
		})
	}
}

// TestAuditRecordCarriesConsumerCount proves the record says what a rotation
// affected, so an operator can tell a no-op rotation from one that changed a
// credential five things depend on.
func TestAuditRecordCarriesConsumerCount(t *testing.T) {
	v, _ := newTestVault(t)
	mustPut(t, v, "gitlab-token", "old", "gitlab")
	idx := &ConsumerIndex{}
	idx.Register(ConsumerSourceFunc(func() (map[string][]Consumer, error) {
		return map[string][]Consumer{"gitlab-token": {
			{Kind: ConsumerEgressInject, Name: "gitlab.tripon.io"},
			{Kind: ConsumerPolicyGrant, Name: "prod"},
		}}, nil
	}))
	var buf bytes.Buffer
	svc := NewSecretsService(v, idx).WithLogger(slog.New(slog.NewTextHandler(&buf, nil)))

	if err := svc.Rotate(context.Background(), "gitlab-token", []byte("new"), PutMeta{}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !strings.Contains(buf.String(), "consumers=2") {
		t.Errorf("audit record must carry the consumer count; log = %q", buf.String())
	}
}

// --- ref validation, exhaustively (F10) --------------------------------------

// TestValidateRefRefusesInjectionCharacters pins the ALLOWLIST, which was
// previously unconstrained: widening it to admit '?', '#' or '%' survived the
// whole suite, and those are precisely the characters that let a ref rewrite a
// URL. validRef's own doc calls it the guard that stops a ref being "a path or
// an injection vector", so the allowlist is a security boundary, not a style
// choice.
func TestValidateRefRefusesInjectionCharacters(t *testing.T) {
	for _, ref := range []string{
		// URL structure
		"tok?force=true", "tok#frag", "tok%2f", "tok%00", "tok&x=1", "tok=v",
		"tok:1", "tok;x", "tok|x", "tok\\x", "tok<x", "tok>x", "tok\"x", "tok'x",
		"http://evil/tok", "//evil/tok", "tok?", "tok#",
		// path shape
		"/leading", "trailing/", "double//seg", "..", "../tok", "tok/..",
		"a/../../b", "./tok", "/", "//",
		// whitespace and control
		"tok tok", "tok\ttok", "tok\ntok", "tok\rtok", "tok\x00",
		// non-ASCII lookalikes for '/'
		"tok⁄x", "tok／x",
		// empty and over-long
		"", strings.Repeat("x", 257),
	} {
		if err := ValidateRef(ref); err == nil {
			t.Errorf("ValidateRef(%q) must be refused — a ref reaches a URL path and a filesystem-shaped key", ref)
		}
	}
}

// TestValidateRefAcceptsLegitimateRefs keeps the allowlist from being a blanket
// refusal. These shapes are documented and in use.
func TestValidateRefAcceptsLegitimateRefs(t *testing.T) {
	for _, ref := range []string{
		"gitlab-token", "aws/deploy", "gh/token", "a.b_c-d@e/f",
		"azure/sp.client-secret", "npm_token", "k8s/prod/kubeconfig",
		"user@example.com", "v1.2.3", strings.Repeat("x", 256),
	} {
		if err := ValidateRef(ref); err != nil {
			t.Errorf("ValidateRef(%q) is legitimate but was refused: %v", ref, err)
		}
	}
}

// --- find() (F8) --------------------------------------------------------------

// TestRotateRefusesUnknownRefInAPopulatedVault pins that a rotation of an absent
// ref is refused even when the vault HOLDS other secrets — an empty vault would
// have nothing to match against, so the earlier version of this test proved
// nothing about matching.
//
// The refusal comes from the atomic write path (Update re-tests existence under
// the mutex it writes under), not from a pre-check. That is deliberate: a
// pre-check's answer is stale by the time the write happens.
func TestRotateRefusesUnknownRefInAPopulatedVault(t *testing.T) {
	v, _ := newTestVault(t)
	mustPut(t, v, "real-token", "real-value", "gitlab")
	mustPut(t, v, "other-token", "other-value", "azure")
	svc := NewSecretsService(v, nil)

	err := svc.Rotate(context.Background(), "typo-token", []byte("new"), PutMeta{})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotating an unknown ref must be ErrNotFound, got %v", err)
	}
	metas, _ := v.List(context.Background())
	if len(metas) != 2 {
		t.Fatalf("a refused rotation must not create a ref: %d secrets", len(metas))
	}
	for _, m := range metas {
		if !m.RotatedAt.IsZero() {
			t.Errorf("a refused rotation must not stamp RotatedAt on %q", m.Ref)
		}
	}
}

// TestRotateCarriesForwardTheCorrectSecretsMetadata: the carry-forward must come
// from the ref being rotated, not from whichever record happened to match first.
func TestRotateCarriesForwardTheCorrectSecretsMetadata(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if err := v.Put(ctx, "first", []byte("v1"), PutMeta{Provider: "azure", Scope: "prod", TTL: "1h"}, false); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, "second", []byte("v2"), PutMeta{Provider: "gitlab", Scope: "staging", TTL: "2h"}, false); err != nil {
		t.Fatal(err)
	}
	svc := NewSecretsService(v, nil)
	// Rotate the SECOND one, restating nothing.
	if err := svc.Rotate(ctx, "second", []byte("v2-new"), PutMeta{}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	metas, _ := v.List(ctx)
	for _, m := range metas {
		if m.Ref != "second" {
			continue
		}
		if m.Provider != "gitlab" || m.Scope != "staging" || m.TTL != "2h" {
			t.Fatalf("rotation inherited the wrong record's metadata: %+v", m)
		}
	}
}

// TestRotateRequiresAnAtomicBackend: a backend that cannot rotate atomically
// must be refused rather than served by the old find-then-Put fallback, which
// could both resurrect a deleted ref and create a new one.
func TestRotateRequiresAnAtomicBackend(t *testing.T) {
	svc := NewSecretsService(&nonAtomicBackend{secrets: map[string]bool{"tok": true}}, nil)
	err := svc.Rotate(context.Background(), "tok", []byte("new"), PutMeta{})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("a backend without atomic Update must be refused, got %v", err)
	}
}

// nonAtomicBackend implements SecretManager but NOT SecretUpdater.
type nonAtomicBackend struct{ secrets map[string]bool }

func (b *nonAtomicBackend) Put(_ context.Context, ref string, _ []byte, _ PutMeta, _ bool) error {
	b.secrets[ref] = true
	return nil
}

func (b *nonAtomicBackend) List(context.Context) ([]SecretMeta, error) {
	out := make([]SecretMeta, 0, len(b.secrets))
	for ref := range b.secrets {
		out = append(out, SecretMeta{Ref: ref})
	}
	return out, nil
}

func (b *nonAtomicBackend) Delete(_ context.Context, ref string) error {
	delete(b.secrets, ref)
	return nil
}

// --- metadata bounds (F7) -----------------------------------------------------

// TestProviderAndScopeAreBounded: both are written to the audit log and stored in
// the vault file (read whole at startup, rewritten whole on every write). Only
// ref and TTL were validated, so a 100 KB provider was accepted, and a newline
// in one forged a second audit line under a text log handler.
func TestProviderAndScopeAreBounded(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	for _, tc := range []struct{ name, provider, scope string }{
		{"long provider", strings.Repeat("p", 129), ""},
		{"long scope", "", strings.Repeat("s", 129)},
		{"newline in provider", "x\nlevel=INFO msg=secret.delete audit=true ref=other", ""},
		{"newline in scope", "", "prod\nforged"},
		{"carriage return", "x\ry", ""},
		{"NUL", "x\x00y", ""},
		{"escape", "x\x1b[2Jy", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Put(ctx, "tok-"+strings.ReplaceAll(tc.name, " ", "-"), []byte("v"),
				PutMeta{Provider: tc.provider, Scope: tc.scope}, false)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("provider/scope %q/%q must be refused, got %v", tc.provider, tc.scope, err)
			}
		})
	}
	// Legitimate values still work.
	if err := v.Put(ctx, "ok", []byte("v"), PutMeta{Provider: "gitlab", Scope: "tripon/prod"}, false); err != nil {
		t.Errorf("a legitimate provider/scope was refused: %v", err)
	}
}

// TestAuditRecordCannotBeForgedThroughProvider is the end-to-end of F7: even
// with a text handler (the worst case), no second audit line can be forged.
func TestAuditRecordCannotBeForgedThroughProvider(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	mustPut(t, v, "tok", "v", "gitlab")
	var buf bytes.Buffer
	svc := NewSecretsService(v, nil).WithLogger(slog.New(slog.NewTextHandler(&buf, nil)))

	err := svc.Rotate(ctx, "tok", []byte("new"),
		PutMeta{Provider: "x\nlevel=INFO msg=secret.delete audit=true ref=victim provider=forged"})
	if err == nil {
		t.Fatal("a provider with a newline must be refused")
	}
	if strings.Contains(buf.String(), "ref=victim") {
		t.Fatalf("an audit line was forged through the provider field:\n%s", buf.String())
	}
}

// --- force past a broken index (F5) -------------------------------------------

// TestForceDeleteSurvivesABrokenConsumerIndex. Fail-closed is right for the
// UNFORCED path, but force means "I accept breaking consumers" — refusing it too
// left an operator unable to revoke a LEAKED credential while the project store
// was corrupt, with no escape hatch at the moment one is most needed.
func TestForceDeleteSurvivesABrokenConsumerIndex(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	mustPut(t, v, "leaked-token", "v", "gitlab")
	idx := NewConsumerIndex(ConsumerSourceFunc(func() (map[string][]Consumer, error) {
		return nil, errors.New("project store corrupt")
	}))
	svc := NewSecretsService(v, idx)

	// Unforced: must refuse.
	if _, err := svc.Delete(ctx, "leaked-token", false); err == nil {
		t.Fatal("an unforced delete must fail closed while consumers are unknowable")
	}
	if metas, _ := v.List(ctx); len(metas) != 1 {
		t.Fatal("the refused delete removed the secret anyway")
	}
	// Forced: must proceed, so a leaked credential can always be revoked.
	if _, err := svc.Delete(ctx, "leaked-token", true); err != nil {
		t.Fatalf("a FORCED delete must proceed past a broken index: %v", err)
	}
	if metas, _ := v.List(ctx); len(metas) != 0 {
		t.Fatal("the forced delete did not remove the secret")
	}
}

// --- flush-marker lifecycle (F4) ----------------------------------------------

// TestRotationMakesTheNextUseVisibleOnDisk pins F4. A rotation left the flush
// marker in place, so the FIRST resolve of the newly rotated value did not flush
// — on disk last_used predated rotated_at, and an operator asking "has the new
// credential been used since I rotated it?" was told no.
func TestRotationMakesTheNextUseVisibleOnDisk(t *testing.T) {
	v, path := newTestVault(t)
	ctx := context.Background()
	mustPut(t, v, "tok", "old", "gitlab")

	if _, _, err := v.Get(ctx, "tok"); err != nil { // first use: flushes
		t.Fatalf("Get: %v", err)
	}
	svc := NewSecretsService(v, nil)
	if err := svc.Rotate(ctx, "tok", []byte("new"), PutMeta{}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, _, err := v.Get(ctx, "tok"); err != nil { // first use of the NEW value
		t.Fatalf("Get after rotate: %v", err)
	}

	reopened, err := OpenVault(path, StaticKeySource(testKey()))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	metas, _ := reopened.List(ctx)
	if len(metas) != 1 {
		t.Fatalf("want 1 secret, got %d", len(metas))
	}
	m := metas[0]
	if m.RotatedAt.IsZero() {
		t.Fatal("the rotation was not persisted")
	}
	if m.LastUsed.Before(m.RotatedAt) {
		t.Fatalf("on disk last_used (%s) predates rotated_at (%s): use of the rotated credential is invisible, so 'has the new credential been used?' answers wrongly",
			m.LastUsed.Format(time.RFC3339Nano), m.RotatedAt.Format(time.RFC3339Nano))
	}
}

// TestDeleteClearsTheFlushMarker: a ref that is removed and later re-added must
// flush on its first use, rather than inheriting the old ref's marker and going
// unrecorded on disk.
func TestDeleteClearsTheFlushMarker(t *testing.T) {
	v, path := newTestVault(t)
	ctx := context.Background()
	mustPut(t, v, "tok", "v1", "gitlab")
	if _, _, err := v.Get(ctx, "tok"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := v.Delete(ctx, "tok"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	mustPut(t, v, "tok", "v2", "gitlab")
	if _, _, err := v.Get(ctx, "tok"); err != nil {
		t.Fatalf("Get after re-add: %v", err)
	}

	reopened, err := OpenVault(path, StaticKeySource(testKey()))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	metas, _ := reopened.List(ctx)
	if len(metas) != 1 || metas[0].LastUsed.IsZero() {
		t.Fatal("a re-added ref must flush its last-used stamp on first use")
	}
}

// --- legacy refs stay removable (N5) -----------------------------------------

// TestLegacyRefRemainsDeletable pins the escape hatch. The ref rule was tightened
// after these could be stored, and for a while the delete route re-applied the
// new rule and 400'd before consulting the vault — leaving a secret that was
// listed, live, resolvable and permanently UN-DELETABLE, removable only by hand-
// editing an encrypted file. Enforcement belongs on the WRITE path.
func TestLegacyRefRemainsDeletable(t *testing.T) {
	ctx := context.Background()
	for _, legacy := range []string{"/etc/passwd", "a//b", "trail/", "./tok", "x/../y"} {
		t.Run(legacy, func(t *testing.T) {
			v, path := newTestVault(t)
			// The current rule must refuse to STORE it...
			if err := v.Put(ctx, legacy, []byte("v"), PutMeta{}, false); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("the write path must refuse %q, got %v", legacy, err)
			}
			// ...but one already on disk must still resolve and still be removable.
			plantLegacyRef(t, v, path, legacy)

			if _, _, err := v.Get(ctx, legacy); err != nil {
				t.Errorf("a legacy ref must keep resolving — breaking a live injection to enforce a naming rule is a self-inflicted outage: %v", err)
			}
			svc := NewSecretsService(v, nil)
			if _, err := svc.Delete(ctx, legacy, false); err != nil {
				t.Fatalf("a legacy ref must be deletable: %v", err)
			}
			metas, _ := v.List(ctx)
			for _, m := range metas {
				if m.Ref == legacy {
					t.Fatal("the legacy ref survived deletion")
				}
			}
		})
	}
}

// plantLegacyRef writes a record under a ref the current rule refuses, by reusing
// the vault's own sealing path under a temporarily-relaxed name. It exercises the
// real on-disk format rather than a hand-rolled fixture, so the test cannot pass
// against a shape the loader would reject.
func plantLegacyRef(t *testing.T, v *Vault, path, legacy string) {
	t.Helper()
	ctx := context.Background()
	const stand = "legacy-stand-in"
	if err := v.Put(ctx, stand, []byte("v"), PutMeta{Provider: "gitlab"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v.mu.Lock()
	rec := v.data.Secrets[stand]
	delete(v.data.Secrets, stand)
	rec.Ref = legacy
	v.data.Secrets[legacy] = rec
	err := v.persist()
	v.mu.Unlock()
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	// Prove it survives a reload, i.e. that this is a real on-disk state and not
	// just an in-memory contrivance.
	reopened, err := OpenVault(path, StaticKeySource(testKey()))
	if err != nil {
		t.Fatalf("reopen with a legacy ref must work: %v", err)
	}
	metas, _ := reopened.List(ctx)
	var found bool
	for _, m := range metas {
		if m.Ref == legacy {
			found = true
		}
	}
	if !found {
		t.Fatalf("the planted legacy ref %q did not survive a reload", legacy)
	}
}

// TestLegacyRefIsWarnedAboutAtStartup: an operator must learn about it at load
// time, not at the moment a rotation fails.
func TestLegacyRefIsWarnedAboutAtStartup(t *testing.T) {
	v, path := newTestVault(t)
	plantLegacyRef(t, v, path, "trail/")

	var buf bytes.Buffer
	reopened, err := OpenVault(path, StaticKeySource(testKey()))
	if err != nil {
		t.Fatal(err)
	}
	reopened.log = slog.New(slog.NewTextHandler(&buf, nil))
	reopened.warnLegacyRefs()
	if !strings.Contains(buf.String(), "trail/") {
		t.Errorf("startup must warn about a ref the current rule refuses; log:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "cannot be rotated") {
		t.Errorf("the warning must say what is actually broken; log:\n%s", buf.String())
	}
}

// TestOverwriteCarriesMetadataForward pins that an overwrite which restates only
// the value keeps the provider, scope and TTL. Blanking them would relax a
// constraint nobody chose to relax — a dropped TTL bound in particular turns a
// short-lived credential into a permanent one, silently.
func TestOverwriteCarriesMetadataForward(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"Put-overwrite", "Upsert", "Rotate"} {
		t.Run(name, func(t *testing.T) {
			v, _ := newTestVault(t)
			if err := v.Put(ctx, "tok", []byte("v1"),
				PutMeta{Provider: "gitlab", Scope: "tripon/prod", TTL: "1h"}, false); err != nil {
				t.Fatal(err)
			}
			var err error
			switch name {
			case "Put-overwrite":
				err = v.Put(ctx, "tok", []byte("v2"), PutMeta{}, true)
			case "Upsert":
				_, _, err = v.Upsert(ctx, "tok", []byte("v2"), PutMeta{})
			case "Rotate":
				err = NewSecretsService(v, nil).Rotate(ctx, "tok", []byte("v2"), PutMeta{})
			}
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			metas, _ := v.List(ctx)
			if len(metas) != 1 {
				t.Fatalf("want 1 secret, got %d", len(metas))
			}
			m := metas[0]
			if m.Provider != "gitlab" || m.Scope != "tripon/prod" || m.TTL != "1h" {
				t.Errorf("%s blanked metadata: provider=%q scope=%q ttl=%q", name, m.Provider, m.Scope, m.TTL)
			}
			if m.RotatedAt.IsZero() {
				t.Errorf("%s must stamp RotatedAt", name)
			}
			// A restated value must still win, or carry-forward would make metadata
			// unchangeable.
			if name == "Upsert" {
				if _, _, err := v.Upsert(ctx, "tok", []byte("v3"), PutMeta{Provider: "azure"}); err != nil {
					t.Fatal(err)
				}
				metas, _ = v.List(ctx)
				if metas[0].Provider != "azure" {
					t.Errorf("a restated provider must win, got %q", metas[0].Provider)
				}
				if metas[0].TTL != "1h" {
					t.Errorf("an unrestated TTL must still carry forward, got %q", metas[0].TTL)
				}
			}
		})
	}
}

// TestRefLookupIsExactNotPrefix: a ref that is a PREFIX of a stored ref must not
// match it. Prefix matching would let `secrets rm gitlab` report success against
// `gitlab-token`, or attribute a rotation's audit record to the wrong credential.
func TestRefLookupIsExactNotPrefix(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	mustPut(t, v, "gitlab-token", "v", "gitlab")
	mustPut(t, v, "gitlab-token-staging", "v", "gitlab")
	svc := NewSecretsService(v, nil)

	for _, probe := range []string{"gitlab", "gitlab-", "gitlab-tok", "g"} {
		if _, err := svc.Delete(ctx, probe, false); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete(%q) must be ErrNotFound — it is only a prefix of a stored ref, got %v", probe, err)
		}
	}
	// Nothing may have been removed.
	metas, _ := v.List(ctx)
	if len(metas) != 2 {
		t.Fatalf("a prefix probe removed a secret: %d remain", len(metas))
	}
	// The audit record for a rotation must name the ref that was rotated, with its
	// OWN provider, not a prefix-matched neighbour's.
	var buf bytes.Buffer
	svc = NewSecretsService(v, nil).WithLogger(slog.New(slog.NewTextHandler(&buf, nil)))
	if err := v.Put(ctx, "gitlab-token-staging", []byte("v"), PutMeta{Provider: "gitlab-staging"}, true); err != nil {
		t.Fatal(err)
	}
	if err := svc.Rotate(ctx, "gitlab-token-staging", []byte("new"), PutMeta{}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !strings.Contains(buf.String(), "provider=gitlab-staging") {
		t.Errorf("the audit record attributed the wrong provider; log:\n%s", buf.String())
	}
}

// TestWritePathFlagMatrix pins every combination across the three write verbs,
// which now share one validate+write path. A shared path is worth having only if
// the flags that distinguish the verbs still hold: a Put that could overwrite, or
// an Update that could create, would each be a silent data-loss bug.
func TestWritePathFlagMatrix(t *testing.T) {
	ctx := context.Background()

	t.Run("Put refuses to overwrite when not asked", func(t *testing.T) {
		v, _ := newTestVault(t)
		mustPut(t, v, "tok", "v1", "gitlab")
		if err := v.Put(ctx, "tok", []byte("v2"), PutMeta{}, false); !errors.Is(err, ErrExists) {
			t.Fatalf("want ErrExists, got %v", err)
		}
		got, _, _ := v.Get(ctx, "tok")
		if string(got) != "v1" {
			t.Fatalf("the refused write changed the value to %q", got)
		}
	})

	t.Run("Update refuses to create", func(t *testing.T) {
		v, _ := newTestVault(t)
		if err := v.Update(ctx, "absent", []byte("v"), PutMeta{}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
		if metas, _ := v.List(ctx); len(metas) != 0 {
			t.Fatal("Update created a ref")
		}
	})

	t.Run("Upsert reports create vs replace accurately", func(t *testing.T) {
		v, _ := newTestVault(t)
		if _, replaced, err := v.Upsert(ctx, "a", []byte("v"), PutMeta{}); err != nil || replaced {
			t.Fatalf("first Upsert: replaced=%v err=%v — a new ref is a create", replaced, err)
		}
		if _, replaced, err := v.Upsert(ctx, "a", []byte("v2"), PutMeta{}); err != nil || !replaced {
			t.Fatalf("second Upsert: replaced=%v err=%v — an existing ref is a replace", replaced, err)
		}
	})

	t.Run("a bound can be tightened but not silently cleared", func(t *testing.T) {
		v, _ := newTestVault(t)
		if err := v.Put(ctx, "tok", []byte("v"), PutMeta{TTL: "1h", Scope: "prod"}, false); err != nil {
			t.Fatal(err)
		}
		// Restating nothing keeps the bound.
		if _, _, err := v.Upsert(ctx, "tok", []byte("v2"), PutMeta{}); err != nil {
			t.Fatal(err)
		}
		if m, _ := v.List(ctx); m[0].TTL != "1h" || m[0].Scope != "prod" {
			t.Fatalf("an unrestated bound was dropped: %+v", m[0])
		}
		// Tightening works.
		if _, _, err := v.Upsert(ctx, "tok", []byte("v3"), PutMeta{TTL: "5m"}); err != nil {
			t.Fatal(err)
		}
		if m, _ := v.List(ctx); m[0].TTL != "5m" {
			t.Fatalf("TTL = %q, want the tightened 5m", m[0].TTL)
		}
		// Clearing requires an explicit delete + re-add. Documented in `secrets add
		// --help`: a rotation must never silently relax a bound.
		if err := v.Delete(ctx, "tok"); err != nil {
			t.Fatal(err)
		}
		if err := v.Put(ctx, "tok", []byte("v4"), PutMeta{}, false); err != nil {
			t.Fatal(err)
		}
		if m, _ := v.List(ctx); m[0].TTL != "" {
			t.Fatalf("delete + re-add must clear the bound, got TTL %q", m[0].TTL)
		}
	})
}

// TestConcurrentWritesAndDeletesStayConsistent races every write verb against
// Delete and Get. The three verbs now share one write path, so a locking mistake
// there would corrupt every one of them at once.
func TestConcurrentWritesAndDeletesStayConsistent(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	mustPut(t, v, "tok", "seed", "gitlab")
	svc := NewSecretsService(v, nil)

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			_, _, _ = v.Upsert(ctx, "tok", []byte("upserted"), PutMeta{Provider: "gitlab"})
		}()
		go func() { defer wg.Done(); _ = svc.Rotate(ctx, "tok", []byte("rotated"), PutMeta{}) }()
		go func() { defer wg.Done(); _, _ = svc.Delete(ctx, "tok", true) }()
		go func() {
			defer wg.Done()
			if val, _, err := v.Get(ctx, "tok"); err == nil {
				// A resolve must never see a partial or zeroed value.
				if len(val) == 0 {
					t.Error("a resolve returned an empty value")
					return
				}
				for _, b := range val {
					if b != 0 {
						return
					}
				}
				t.Errorf("a resolve returned an all-zero value: the plaintext buffer was reused after being wiped")
			}
		}()
	}
	wg.Wait()

	// Whatever the interleaving, the vault must be readable and internally
	// consistent — never a ref that lists but cannot be resolved.
	metas, err := v.List(ctx)
	if err != nil {
		t.Fatalf("List after the race: %v", err)
	}
	for _, m := range metas {
		if _, _, err := v.Get(ctx, m.Ref); err != nil {
			t.Errorf("%s lists but cannot be resolved: %v", m.Ref, err)
		}
	}
}
