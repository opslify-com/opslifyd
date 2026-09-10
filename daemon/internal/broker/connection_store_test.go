package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newConnService(t *testing.T) (*ConnectionService, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewConnectionStore(dir)
	if err != nil {
		t.Fatalf("NewConnectionStore: %v", err)
	}
	svc, err := NewConnectionService(store, DefaultRegistry(&fakeSSHRunner{major: 9, minor: 6}), nil)
	if err != nil {
		t.Fatalf("NewConnectionService: %v", err)
	}
	return svc, dir
}

// --- records hold refs, never values -----------------------------------------

// TestStoredRecordHoldsNoValue: a record that could hold a value would put
// credentials in a file an operator edits and commits, which is the habit the
// whole system exists to break.
func TestStoredRecordHoldsNoValue(t *testing.T) {
	svc, dir := newConnService(t)
	spec := httpSpec()
	spec.ProjectID, spec.EnvironmentID = "tripon", "tripon.prod"
	if err := svc.Add(spec); err != nil {
		t.Fatalf("Add: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want one record, got %d", len(entries))
	}
	body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	// The REF must be present; nothing that looks like a value may be.
	if !strings.Contains(string(body), "gitlab-token") {
		t.Errorf("the record must carry the secret ref: %s", body)
	}
	for _, forbidden := range []string{"value", "secret_value", "token_value", "BEGIN OPENSSH"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("the record contains %q, which suggests a value field: %s", forbidden, body)
		}
	}
	// 0600: the record names hosts and refs, which together describe an estate's
	// shape.
	info, err := os.Stat(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
}

// --- validation at create time ------------------------------------------------

// TestAddValidatesByBuilding: a spec that cannot produce a working connection is
// rejected where the operator is watching, rather than at session start where it
// surfaces as an agent mysteriously lacking access.
func TestAddValidatesByBuilding(t *testing.T) {
	svc, dir := newConnService(t)
	for _, tc := range []struct {
		name string
		spec ConnectionSpec
	}{
		{"unknown kind", ConnectionSpec{Name: "c", Kind: "database", SecretRef: "r"}},
		{"http with no hosts", ConnectionSpec{Name: "c", Kind: KindHTTP, SecretRef: "r"}},
		{"k8s with two hosts", ConnectionSpec{Name: "c", Kind: KindKubernetes, SecretRef: "r", Hosts: []string{"a.example.com", "b.example.com"}}},
		{"k8s with a user-supplied server", ConnectionSpec{Name: "c", Kind: KindKubernetes, SecretRef: "r", Hosts: []string{"a.example.com"}, Config: map[string]string{"server": "https://evil"}}},
		{"ssh with no destinations", ConnectionSpec{Name: "c", Kind: KindSSH, SecretRef: "r", Config: map[string]string{"known_hosts_path": "/etc/ssh/known_hosts"}}},
		{"ssh with no known_hosts", ConnectionSpec{Name: "c", Kind: KindSSH, SecretRef: "r", Hosts: []string{"h"}}},
		{"bad name", ConnectionSpec{Name: "../evil", Kind: KindHTTP, SecretRef: "r", Hosts: []string{"a.example.com"}}},
		{"inline-looking ref", ConnectionSpec{Name: "c", Kind: KindHTTP, SecretRef: "tok?force=true", Hosts: []string{"a.example.com"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := svc.Add(tc.spec); err == nil {
				t.Fatal("an unusable spec must be refused at create time")
			}
		})
	}
	// Nothing may have been written by any refusal.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("refused specs wrote %d record(s)", len(entries))
	}
}

// TestAddRefusesADuplicateInTheSameScope: silently overwriting would change what
// a session does with no record of why.
func TestAddRefusesADuplicateInTheSameScope(t *testing.T) {
	svc, _ := newConnService(t)
	spec := httpSpec()
	spec.ProjectID = "tripon"
	if err := svc.Add(spec); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := svc.Add(spec); !errors.Is(err, ErrExists) {
		t.Fatalf("a duplicate must be refused, got %v", err)
	}
	// The same NAME in a different scope is fine — that is what scoping is for.
	other := spec
	other.ProjectID = "other-project"
	if err := svc.Add(other); err != nil {
		t.Errorf("the same name in a different scope must be allowed: %v", err)
	}
	// Replace is the explicit way to change one.
	if err := svc.Replace(spec); err != nil {
		t.Errorf("Replace must overwrite: %v", err)
	}
}

// --- scoping ------------------------------------------------------------------

// TestForScopeAppliesAtOrBelow: a daemon-wide connection must not have to be
// repeated per project, and an environment-scoped one must not leak to a sibling.
func TestForScopeAppliesAtOrBelow(t *testing.T) {
	svc, _ := newConnService(t)
	mk := func(name, proj, env string) ConnectionSpec {
		s := httpSpec()
		s.Name, s.ProjectID, s.EnvironmentID = name, proj, env
		return s
	}
	for _, spec := range []ConnectionSpec{
		mk("daemon-wide", "", ""),
		mk("tripon-any", "tripon", ""),
		mk("tripon-prod", "tripon", "tripon.prod"),
		mk("tripon-staging", "tripon", "tripon.staging"),
		mk("other-any", "other", ""),
	} {
		if err := svc.Add(spec); err != nil {
			t.Fatalf("Add %s: %v", spec.Name, err)
		}
	}
	names := func(conns []Connection) []string {
		out := make([]string, 0, len(conns))
		for _, c := range conns {
			out = append(out, c.Name())
		}
		return out
	}
	got, err := svc.ForScope("tripon", "tripon.prod")
	if err != nil {
		t.Fatalf("ForScope: %v", err)
	}
	want := map[string]bool{"daemon-wide": true, "tripon-any": true, "tripon-prod": true}
	if len(got) != len(want) {
		t.Fatalf("prod scope = %v, want %v", names(got), want)
	}
	for _, c := range got {
		if !want[c.Name()] {
			t.Errorf("connection %q must not apply to tripon.prod", c.Name())
		}
	}
	// A sibling environment must not see prod's connection.
	staging, _ := svc.ForScope("tripon", "tripon.staging")
	for _, c := range staging {
		if c.Name() == "tripon-prod" {
			t.Error("an environment-scoped connection leaked to a sibling environment")
		}
	}
	// An unrelated project sees only the daemon-wide one.
	unrelated, _ := svc.ForScope("nothing", "nothing.dev")
	if len(unrelated) != 1 || unrelated[0].Name() != "daemon-wide" {
		t.Errorf("unrelated scope = %v, want just daemon-wide", names(unrelated))
	}
}

// TestForScopeFailsClosedOnAnUnusableStoredSpec: a spec that was valid when
// stored can become unusable (a known_hosts file removed, a tightened rule). A
// session must refuse rather than run without it.
func TestForScopeFailsClosedOnAnUnusableStoredSpec(t *testing.T) {
	dir := t.TempDir()
	store, err := NewConnectionStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Write a record that bypasses Add's validation, as an older release or a
	// hand-edit could have.
	bad := ConnectionSpec{Name: "stale", Kind: KindKubernetes, SecretRef: "r",
		Hosts: []string{"a.example.com", "b.example.com"}} // two hosts: now invalid
	if err := store.Save(bad); err != nil {
		t.Fatalf("Save: %v", err)
	}
	svc, err := NewConnectionService(store, DefaultRegistry(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ForScope("p", "p.e"); err == nil {
		t.Fatal("an unusable stored spec must fail the scope resolution closed")
	} else if !strings.Contains(err.Error(), "stale") {
		t.Errorf("the error should name the connection: %v", err)
	}
}

// --- removal -------------------------------------------------------------------

func TestRemoveConnection(t *testing.T) {
	svc, _ := newConnService(t)
	spec := httpSpec()
	spec.ProjectID = "tripon"
	if err := svc.Add(spec); err != nil {
		t.Fatal(err)
	}
	if err := svc.Remove("tripon", "", "gitlab"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	list, _ := svc.List()
	if len(list) != 0 {
		t.Fatalf("the connection survived removal: %v", list)
	}
	// Removing something absent is an explicit not-found, not a silent success:
	// an operator typing the wrong name must learn that nothing was removed.
	if err := svc.Remove("tripon", "", "gitlab"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing an absent connection must report not-found, got %v", err)
	}
}

// --- path safety ---------------------------------------------------------------

// TestStoreRefusesTraversalIds is the last line of defence: a name that reached
// filepath.Join unvalidated would be an arbitrary-file write running as the
// daemon user.
func TestStoreRefusesTraversalIds(t *testing.T) {
	dir := t.TempDir()
	store, err := NewConnectionStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Plant a file at the traversal target, so the assertion is that the write was
	// REFUSED rather than merely that an error came back for some other reason.
	victim := filepath.Join(filepath.Dir(dir), "victim.json")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every one of these must be refused on WRITE, by the spec's own name rule.
	for _, name := range []string{"../victim", "../../victim", "a/b", "..", ".", "with space", "UPPER"} {
		spec := ConnectionSpec{Name: name, Kind: KindHTTP, SecretRef: "r", Hosts: []string{"a.example.com"}}
		if err := store.Save(spec); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("name %q must be refused with ErrInvalidInput, got %v", name, err)
		}
	}
	// On READ the picture is different, and worth pinning because it explains why
	// records are prefixed with their scope at all. A name is never the whole
	// filename: "_daemon__" + ".." is the harmless literal "_daemon__..", so a
	// dot-name cannot escape and simply does not exist. Only a name carrying a
	// PATH SEPARATOR could still traverse, and that is what the last-line-of-
	// defence check refuses.
	for _, name := range []string{"..", "."} {
		if _, found, err := store.Load("_daemon", name); err != nil || found {
			t.Errorf("Load(%q) should be a harmless miss (the scope prefix neutralises it), got found=%v err=%v", name, found, err)
		}
	}
	for _, name := range []string{"a/b", "../victim", `x\y`} {
		if _, _, err := store.Load("_daemon", name); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Load(%q) carries a separator and must be refused, got %v", name, err)
		}
	}
	// A scope key carrying a separator must be refused too — it is the other half
	// of the filename.
	if _, _, err := store.Load("../escape", "gitlab"); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("a traversal scope key must be refused, got %v", err)
	}
	body, _ := os.ReadFile(victim)
	if string(body) != "original" {
		t.Fatal("a traversal name overwrote a file outside the store")
	}
}

// TestCorruptRecordIsSkippedAndSurfaced: one bad file must not make every other
// connection unreachable, but it must not vanish silently either.
func TestCorruptRecordIsSkippedAndSurfaced(t *testing.T) {
	svc, dir := newConnService(t)
	good := httpSpec()
	good.ProjectID = "tripon"
	if err := svc.Add(good); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "_daemon__broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := svc.List()
	if err != nil {
		t.Fatalf("a corrupt record must not fail the whole listing: %v", err)
	}
	if len(list) != 1 || list[0].Name != "gitlab" {
		t.Fatalf("the good record must still list: %v", list)
	}
}

// --- F8.3 integration ----------------------------------------------------------

// TestStoredConnectionsGuardTheirSecrets: the delete guard must be complete the
// moment a connection exists, not retrofitted after an operator has removed
// something in use.
func TestStoredConnectionsGuardTheirSecrets(t *testing.T) {
	svc, _ := newConnService(t)
	spec := httpSpec()
	spec.ProjectID, spec.EnvironmentID = "tripon", "tripon.prod"
	if err := svc.Add(spec); err != nil {
		t.Fatal(err)
	}
	v, _ := newTestVault(t)
	mustPut(t, v, "gitlab-token", "value", "gitlab")
	idx := NewConsumerIndex(ConsumerSourceFunc(svc.Consumers))
	secrets := NewSecretsService(v, idx)

	_, err := secrets.Delete(context.Background(), "gitlab-token", false)
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("deleting a secret a stored connection uses must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "tripon.prod") {
		t.Errorf("the refusal must name which environment would break: %v", err)
	}
	// Once the connection is gone the secret is removable.
	if err := svc.Remove("tripon", "tripon.prod", "gitlab"); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.Delete(context.Background(), "gitlab-token", false); err != nil {
		t.Fatalf("with the connection removed the secret must be deletable: %v", err)
	}
}
