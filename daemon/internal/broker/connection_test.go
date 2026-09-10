package broker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func httpSpec() ConnectionSpec {
	return ConnectionSpec{
		Name:      "gitlab",
		Kind:      KindHTTP,
		SecretRef: "gitlab-token",
		Hosts:     []string{"gitlab.example.com"},
		Config:    map[string]string{"header_name": "PRIVATE-TOKEN"},
	}
}

func testRegistry() *Registry {
	r := NewRegistry()
	r.Register(KindHTTP, NewHTTPConnection)
	return r
}

// --- the invariant every kind must satisfy -----------------------------------

// TestHTTPConnectionGivesTheSandboxNothing is the http kind's one-line answer to
// "what does the sandbox actually receive?" — nothing. The header is added to the
// upstream clone inside the daemon, so there is no env var, no file, and nothing
// to steal from the sandbox side.
func TestHTTPConnectionGivesTheSandboxNothing(t *testing.T) {
	c, err := testRegistry().Build(httpSpec(), nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	inj, closer, err := c.BuildForSession(context.Background(), SessionContext{SessionID: "s1"})
	if err != nil {
		t.Fatalf("BuildForSession: %v", err)
	}
	if closer != nil {
		t.Error("the http kind allocates nothing per session and needs no closer")
	}
	if len(inj.Env) != 0 {
		t.Errorf("the sandbox must receive no environment from an http connection: %v", inj.Env)
	}
	if len(inj.Files) != 0 {
		t.Errorf("the sandbox must receive no files from an http connection: %v", inj.Files)
	}
	// What it DOES produce: an upstream rule (phase one, before the proxy exists)
	// and the exclusion that keeps the same secret out of the sandbox environment.
	rules := c.EgressRules()
	if len(rules) != 1 || rules[0].Host != "gitlab.example.com" {
		t.Fatalf("EgressRules = %+v", rules)
	}
	if rules[0].HeaderName != "PRIVATE-TOKEN" {
		t.Errorf("header name = %q", rules[0].HeaderName)
	}
	if rules[0].SecretRef != "gitlab-token" {
		t.Errorf("rule must name the ref, not a value: %+v", rules[0])
	}
}

// TestHTTPConnectionExcludesItsSecretFromEnvInjection pins the load-bearing half.
// Without the exclusion the SAME credential resolved at the proxy boundary would
// also be resolved into the sandbox environment by the F5.1 injector — placing in
// the sandbox exactly the value the connection exists to keep out of it.
func TestHTTPConnectionExcludesItsSecretFromEnvInjection(t *testing.T) {
	c, _ := testRegistry().Build(httpSpec(), nil)
	inj, _, err := c.BuildForSession(context.Background(), SessionContext{SessionID: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, ref := range inj.ExcludeRefs {
		if ref == "gitlab-token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the connection's secret must be excluded from env injection; ExcludeRefs = %v", inj.ExcludeRefs)
	}
}

// --- spec validation ----------------------------------------------------------

// TestConnectionSpecRefusesInlineValuesAndBadRefs: a connection references a
// secret BY REF, never a value. A record that could hold a value would put
// credentials in a file the operator edits and commits.
func TestConnectionSpecRefusesInlineValuesAndBadRefs(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec ConnectionSpec
	}{
		{"no ref", ConnectionSpec{Name: "c", Kind: KindHTTP}},
		{"unsafe ref", ConnectionSpec{Name: "c", Kind: KindHTTP, SecretRef: "../../etc/passwd"}},
		{"ref with query", ConnectionSpec{Name: "c", Kind: KindHTTP, SecretRef: "tok?force=true"}},
		{"no kind", ConnectionSpec{Name: "c", SecretRef: "tok"}},
		{"bad name", ConnectionSpec{Name: "Bad Name", Kind: KindHTTP, SecretRef: "tok"}},
		{"traversal name", ConnectionSpec{Name: "../evil", Kind: KindHTTP, SecretRef: "tok"}},
		{"empty name", ConnectionSpec{Kind: KindHTTP, SecretRef: "tok"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.spec.ValidateSpec(); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("spec must be refused, got %v", err)
			}
		})
	}
}

// TestConnectionHostsAreBounded: a host list is matched against, so a permissive
// entry silently widens what a connection covers.
func TestConnectionHostsAreBounded(t *testing.T) {
	for _, host := range []string{
		"", "*", "*.example.com", "https://example.com", "example.com/path",
		"user@example.com", "example.com?x=1", "exa mple.com", "example.com\x00",
		"a" + strings.Repeat("b", 300),
	} {
		spec := httpSpec()
		spec.Hosts = []string{host}
		if err := spec.ValidateSpec(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("host %q must be refused, got %v", host, err)
		}
	}
	for _, host := range []string{"example.com", "gitlab.example.com", "example.com:8443", "10.0.0.5", "10.0.0.5:6443"} {
		spec := httpSpec()
		spec.Hosts = []string{host}
		if err := spec.ValidateSpec(); err != nil {
			t.Errorf("host %q is legitimate but was refused: %v", host, err)
		}
	}
}

// TestHTTPConnectionRefusesAnEmptyHostList: injecting on nothing is useless, and
// a future reader "fixing" it by treating empty as a wildcard would inject a
// credential on every host the sandbox reaches. Requiring a host makes that
// unreachable.
func TestHTTPConnectionRefusesAnEmptyHostList(t *testing.T) {
	spec := httpSpec()
	spec.Hosts = nil
	if _, err := testRegistry().Build(spec, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("an http connection with no hosts must be refused, got %v", err)
	}
}

// TestHTTPHeaderFormatMustCarryExactlyOneVerb: a format with no %s produces a
// header that authenticates nothing while looking like it does; one with two
// puts the secret somewhere unintended.
func TestHTTPHeaderFormatMustCarryExactlyOneVerb(t *testing.T) {
	for _, format := range []string{"Bearer", "Bearer %s %s", "%s %s", "Bearer %d", "%v", "Bearer %s\r\nX-Evil: 1"} {
		spec := httpSpec()
		spec.Config = map[string]string{"header_format": format}
		if _, err := testRegistry().Build(spec, nil); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("header_format %q must be refused, got %v", format, err)
		}
	}
	for _, format := range []string{"", "Bearer %s", "token %s"} {
		spec := httpSpec()
		spec.Config = map[string]string{"header_format": format}
		if _, err := testRegistry().Build(spec, nil); err != nil {
			t.Errorf("header_format %q is legitimate but was refused: %v", format, err)
		}
	}
}

// TestHeaderNameCannotInjectAHeader: a name carrying CRLF or a colon would split
// the upstream request.
func TestHeaderNameCannotInjectAHeader(t *testing.T) {
	for _, name := range []string{"X-Bad\r\nX-Evil: 1", "X: Y", "with space", "nul\x00"} {
		spec := httpSpec()
		spec.Config = map[string]string{"header_name": name}
		if _, err := testRegistry().Build(spec, nil); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("header_name %q must be refused, got %v", name, err)
		}
	}
	// An UNSET header name is not an error — it means the default. In a
	// map[string]string an explicit "" is indistinguishable from absent, so
	// refusing it would break the default rather than catch a mistake.
	spec := httpSpec()
	spec.Config = nil
	c, err := testRegistry().Build(spec, nil)
	if err != nil {
		t.Fatalf("an unset header name must fall back to the default: %v", err)
	}
	if got := c.EgressRules()[0].HeaderName; got != "Authorization" {
		t.Errorf("default header = %q, want Authorization", got)
	}
}

// --- registry -----------------------------------------------------------------

// TestUnknownKindIsAnErrorNotANoOp: a connection an operator created and believes
// is in force, silently doing nothing, is the worst of both worlds.
func TestUnknownKindIsAnErrorNotANoOp(t *testing.T) {
	spec := httpSpec()
	spec.Kind = "database"
	_, err := testRegistry().Build(spec, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("an unregistered kind must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "http") {
		t.Errorf("the error should name the kinds that ARE known: %v", err)
	}
}

// TestRegisteringAKindTwicePanics: two builders for one kind means one of them
// silently never runs.
func TestRegisteringAKindTwicePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registering a kind twice must panic at startup, not silently take one")
		}
	}()
	r := NewRegistry()
	r.Register(KindHTTP, NewHTTPConnection)
	r.Register(KindHTTP, NewHTTPConnection)
}

// --- injection hygiene ---------------------------------------------------------

// TestInjectedPathsCannotEscapeTheWorkspace: a file written outside the session's
// own directory would land in the daemon's filesystem with the daemon's
// privileges.
func TestInjectedPathsCannotEscapeTheWorkspace(t *testing.T) {
	for _, p := range []string{
		"/etc/passwd", "../escape", "a/../../b", "./x", "", "a//b", "a/../b", "nul\x00",
	} {
		inj := ConnectionInjection{Files: []InjectedFile{{Path: p}}}
		if err := inj.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("injected path %q must be refused, got %v", p, err)
		}
	}
	ok := ConnectionInjection{Files: []InjectedFile{{Path: ".kube/config"}, {Path: "a/b/c.yaml"}}}
	if err := ok.Validate(); err != nil {
		t.Errorf("a legitimate injected path was refused: %v", err)
	}
}

// TestMergeRefusesConflicts: one connection silently overwriting another's
// variable or file would make which credential is in force depend on map order.
func TestMergeRefusesConflicts(t *testing.T) {
	a := ConnectionInjection{Env: map[string]string{"KUBECONFIG": "/workspace/.kube/one"}}
	b := ConnectionInjection{Env: map[string]string{"KUBECONFIG": "/workspace/.kube/two"}}
	if err := a.Merge(b); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting env must be refused, got %v", err)
	}
	f1 := ConnectionInjection{Files: []InjectedFile{{Path: ".kube/config"}}}
	f2 := ConnectionInjection{Files: []InjectedFile{{Path: ".kube/config"}}}
	if err := f1.Merge(f2); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting files must be refused, got %v", err)
	}
	// Identical values are not a conflict — two connections may agree.
	same := ConnectionInjection{Env: map[string]string{"X": "1"}}
	if err := same.Merge(ConnectionInjection{Env: map[string]string{"X": "1"}}); err != nil {
		t.Errorf("identical values must merge cleanly: %v", err)
	}
	// Exclusions accumulate rather than conflict: two connections may each need a
	// different ref kept out of the sandbox environment.
	acc := ConnectionInjection{ExcludeRefs: []string{"r1"}}
	if err := acc.Merge(ConnectionInjection{ExcludeRefs: []string{"r2"}}); err != nil {
		t.Fatal(err)
	}
	if len(acc.ExcludeRefs) != 2 {
		t.Errorf("exclusions must accumulate: %+v", acc)
	}
}

// --- F8.3 integration ----------------------------------------------------------

// TestConnectionsRegisterAsSecretConsumers: the F8.3 delete guard must refuse to
// remove a credential a live connection depends on. The guard has to be complete
// on the day the first connection is created, not retrofitted after an operator
// has deleted something in use.
func TestConnectionsRegisterAsSecretConsumers(t *testing.T) {
	idx := NewConsumerIndex(ConnectionConsumers([]ConnectionSpec{
		{Name: "gitlab", Kind: KindHTTP, SecretRef: "gitlab-token", ProjectID: "tripon", EnvironmentID: "tripon.prod"},
		{Name: "cluster", Kind: KindKubernetes, SecretRef: "k8s-token", ProjectID: "tripon"},
	}))
	cs, err := idx.Of("gitlab-token")
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("consumers = %+v", cs)
	}
	if cs[0].Kind != ConsumerConnection {
		t.Errorf("kind = %q, want %q", cs[0].Kind, ConsumerConnection)
	}
	if !strings.Contains(cs[0].Name, "gitlab") || !strings.Contains(cs[0].Name, "http") {
		t.Errorf("the consumer must name the connection and its kind, got %q", cs[0].Name)
	}
	if cs[0].Scope != "tripon.prod" {
		t.Errorf("scope = %q — the refusal must say WHICH environment would break", cs[0].Scope)
	}

	// And a delete of that ref must now be refused.
	v, _ := newTestVault(t)
	mustPut(t, v, "gitlab-token", "v", "gitlab")
	svc := NewSecretsService(v, idx)
	if _, err := svc.Delete(context.Background(), "gitlab-token", false); !errors.Is(err, ErrInUse) {
		t.Fatalf("deleting a secret a connection uses must be refused, got %v", err)
	}
}
