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
