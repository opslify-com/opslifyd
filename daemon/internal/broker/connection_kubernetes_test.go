package broker

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const k8sToken = "CANARY-k8s-bearer-token-must-never-be-in-the-sandbox"

func k8sSpec() ConnectionSpec {
	return ConnectionSpec{
		Name:      "prod-cluster",
		Kind:      KindKubernetes,
		SecretRef: "k8s-token",
		Hosts:     []string{"api.k8s.example.com:6443"},
	}
}

func k8sRegistry() *Registry {
	r := NewRegistry()
	r.Register(KindKubernetes, NewKubernetesConnection)
	return r
}

func k8sSessionContext() SessionContext {
	return SessionContext{
		SessionID:  "s1",
		ProxyAddr:  "172.17.0.1:41234",
		ProxyCAPEM: []byte("-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n"),
	}
}

// buildK8s returns the injection for a valid kubernetes connection.
func buildK8s(t *testing.T) ConnectionInjection {
	t.Helper()
	c, err := k8sRegistry().Build(k8sSpec(), nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	inj, closer, err := c.BuildForSession(context.Background(), k8sSessionContext())
	if err != nil {
		t.Fatalf("BuildForSession: %v", err)
	}
	if closer != nil {
		t.Error("the kubernetes kind allocates nothing of its own and needs no closer")
	}
	return inj
}

// --- the AC: the kubeconfig contains no credential ----------------------------

// TestKubeconfigContainsNoCredential is the kind's one-line claim, asserted by
// PARSING the generated file rather than reasoning about it. If a token could
// reach the sandbox here, the kind would be no better than handing over the
// credential and calling it a connection.
func TestKubeconfigContainsNoCredential(t *testing.T) {
	inj := buildK8s(t)
	if len(inj.Files) != 1 {
		t.Fatalf("want exactly one injected file, got %d", len(inj.Files))
	}
	body := string(inj.Files[0].Content)

	// Parsed, not grepped: the structural claim is that the user block is empty.
	var parsed struct {
		Clusters []struct {
			Name    string `yaml:"name"`
			Cluster struct {
				Server                string `yaml:"server"`
				CAData                string `yaml:"certificate-authority-data"`
				InsecureSkipTLSVerify bool   `yaml:"insecure-skip-tls-verify"`
			} `yaml:"cluster"`
		} `yaml:"clusters"`
		Users []struct {
			Name string         `yaml:"name"`
			User map[string]any `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("the generated kubeconfig must be valid YAML: %v\n%s", err, body)
	}
	if len(parsed.Users) != 1 {
		t.Fatalf("want one user entry (kubectl requires the context's user to exist), got %d", len(parsed.Users))
	}
	if len(parsed.Users[0].User) != 0 {
		t.Fatalf("the user block MUST be empty; got %v", parsed.Users[0].User)
	}
	// The server must be the session proxy, never the real cluster.
	if got := parsed.Clusters[0].Cluster.Server; got != "https://172.17.0.1:41234" {
		t.Fatalf("server = %q, want the session proxy", got)
	}
	if strings.Contains(body, "api.k8s.example.com") {
		t.Error("the kubeconfig must not point at the real cluster API")
	}
	// TLS verification must be ON, against the per-session CA.
	if parsed.Clusters[0].Cluster.InsecureSkipTLSVerify {
		t.Fatal("insecure-skip-tls-verify would make the sandbox accept ANY certificate, not merely ours")
	}
	ca, err := base64.StdEncoding.DecodeString(parsed.Clusters[0].Cluster.CAData)
	if err != nil || !strings.Contains(string(ca), "BEGIN CERTIFICATE") {
		t.Errorf("the per-session CA must be embedded so kubectl can verify the proxy: %v", err)
	}
}

// TestKubernetesSandboxSurfaceCarriesNoToken greps every surface the sandbox can
// actually see for the credential, in the encodings it could travel in. The
// kind's whole justification is this absence.
func TestKubernetesSandboxSurfaceCarriesNoToken(t *testing.T) {
	inj := buildK8s(t)

	surfaces := map[string]string{}
	for k, v := range inj.Env {
		surfaces["env "+k] = v
	}
	for _, f := range inj.Files {
		surfaces["file "+f.Path] = string(f.Content)
	}
	for name, body := range surfaces {
		for enc, val := range map[string]string{
			"plaintext":     k8sToken,
			"base64":        base64.StdEncoding.EncodeToString([]byte(k8sToken)),
			"base64-raw":    base64.RawStdEncoding.EncodeToString([]byte(k8sToken)),
			"bearer-header": "Bearer " + k8sToken,
		} {
			if strings.Contains(body, val) {
				t.Fatalf("%s carries the token as %s", name, enc)
			}
		}
	}
	// The ref must not travel either: a sandbox that learns the ref learns which
	// vault entry to ask a confused-deputy path for.
	for name, body := range surfaces {
		if strings.Contains(body, "k8s-token") {
			t.Errorf("%s leaks the secret REF: %s", name, body)
		}
	}
	// KUBECONFIG must point inside the workspace, at our generated file.
	if got := inj.Env["KUBECONFIG"]; got != "/workspace/.opslify/kubeconfig" {
		t.Errorf("KUBECONFIG = %q", got)
	}
}

// TestKubernetesInjectsTheTokenOnlyUpstream: the credential reaches the cluster
// via the proxy rule, on the REAL api host — the one the kubeconfig deliberately
// does not name.
func TestKubernetesInjectsTheTokenOnlyUpstream(t *testing.T) {
	c, err := k8sRegistry().Build(k8sSpec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := c.EgressRules()
	if len(rules) != 1 {
		t.Fatalf("want one upstream rule, got %+v", rules)
	}
	r := rules[0]
	if r.Host != "api.k8s.example.com:6443" {
		t.Errorf("the rule must target the real cluster API, got %q", r.Host)
	}
	if r.SecretRef != "k8s-token" {
		t.Errorf("the rule must carry the REF, not a value: %+v", r)
	}
	if r.HeaderName != "Authorization" || r.HeaderFormat != "Bearer %s" {
		t.Errorf("kubernetes must inject a bearer token: %+v", r)
	}
	// And the same ref must be excluded from environment injection, or the token
	// the proxy adds upstream would ALSO be placed in the sandbox env.
	inj, _, err := c.BuildForSession(context.Background(), k8sSessionContext())
	if err != nil {
		t.Fatal(err)
	}
	var excluded bool
	for _, ref := range inj.ExcludeRefs {
		if ref == "k8s-token" {
			excluded = true
		}
	}
	if !excluded {
		t.Fatalf("the token must be excluded from env injection; ExcludeRefs = %v", inj.ExcludeRefs)
	}
}

// --- the generated config cannot be pointed elsewhere -------------------------

// TestKubernetesRefusesUserSuppliedServerAndAuth is the QA checklist item: a
// generated kubeconfig must not be pointable at anything but the session proxy,
// and no operator-supplied auth may reach it. Allowing `server` would let a
// connection aim the sandbox straight at the cluster, which then needs the
// credential the whole design keeps away from it.
func TestKubernetesRefusesUserSuppliedServerAndAuth(t *testing.T) {
	for _, key := range []string{"server", "insecure-skip-tls-verify", "token", "client-certificate-data", "client-key-data"} {
		spec := k8sSpec()
		spec.Config = map[string]string{key: "anything"}
		if _, err := k8sRegistry().Build(spec, nil); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("config key %q must be refused, got %v", key, err)
		}
	}
}

// TestKubernetesRefusesWithoutAProxy: generating a kubeconfig aimed at the real
// cluster would hand the sandbox a direct path that only works with the
// credential it must never hold. Refuse instead.
func TestKubernetesRefusesWithoutAProxy(t *testing.T) {
	c, err := k8sRegistry().Build(k8sSpec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sc := k8sSessionContext()
	sc.ProxyAddr = ""
	if _, _, err := c.BuildForSession(context.Background(), sc); !errors.Is(err, ErrDenied) {
		t.Fatalf("no proxy address must be refused, got %v", err)
	}
	// And with no CA: the only way to make that work inside the sandbox is
	// disabling verification, which accepts ANY certificate.
	sc = k8sSessionContext()
	sc.ProxyCAPEM = nil
	if _, _, err := c.BuildForSession(context.Background(), sc); !errors.Is(err, ErrDenied) {
		t.Fatalf("no proxy CA must be refused, got %v", err)
	}
}

// TestKubernetesRefusesAMalformedProxyAddress: an address carrying a path or
// userinfo would change what the sandbox actually connects to.
func TestKubernetesRefusesAMalformedProxyAddress(t *testing.T) {
	c, _ := k8sRegistry().Build(k8sSpec(), nil)
	for _, addr := range []string{
		"172.17.0.1", "172.17.0.1:41234/evil", "evil@172.17.0.1:41234",
		"172.17.0.1:41234/../x", "not a host", "",
	} {
		sc := k8sSessionContext()
		sc.ProxyAddr = addr
		if _, _, err := c.BuildForSession(context.Background(), sc); err == nil {
			t.Errorf("proxy address %q must be refused", addr)
		}
	}
}

// TestKubernetesRequiresExactlyOneHost: a kubeconfig names one server, and
// silently using the first of several would make which cluster the agent talks
// to depend on list order.
func TestKubernetesRequiresExactlyOneHost(t *testing.T) {
	for _, hosts := range [][]string{nil, {}, {"a.example.com", "b.example.com"}} {
		spec := k8sSpec()
		spec.Hosts = hosts
		if _, err := k8sRegistry().Build(spec, nil); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("hosts %v must be refused, got %v", hosts, err)
		}
	}
}

// TestKubernetesNamespaceAndClusterAreBounded: both land in a generated YAML
// document, so an unbounded value could break the file's structure.
func TestKubernetesNamespaceAndClusterAreBounded(t *testing.T) {
	for _, key := range []string{"namespace", "cluster"} {
		for _, bad := range []string{"Bad Name", "with/slash", "-leading", "trailing-", strings.Repeat("x", 64), "quote\"", "nl\nx"} {
			spec := k8sSpec()
			spec.Config = map[string]string{key: bad}
			if _, err := k8sRegistry().Build(spec, nil); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("%s %q must be refused, got %v", key, bad, err)
			}
		}
	}
	spec := k8sSpec()
	spec.Config = map[string]string{"namespace": "kube-system", "cluster": "prod-eu"}
	c, err := k8sRegistry().Build(spec, nil)
	if err != nil {
		t.Fatalf("legitimate namespace/cluster refused: %v", err)
	}
	inj, _, err := c.BuildForSession(context.Background(), k8sSessionContext())
	if err != nil {
		t.Fatal(err)
	}
	body := string(inj.Files[0].Content)
	if !strings.Contains(body, "kube-system") || !strings.Contains(body, "prod-eu") {
		t.Errorf("the namespace and cluster must reach the kubeconfig:\n%s", body)
	}
}

// TestKubeconfigIsWrittenInsideTheWorkspace: a file outside the session's own
// directory would land in the daemon's filesystem with the daemon's privileges.
func TestKubeconfigIsWrittenInsideTheWorkspace(t *testing.T) {
	inj := buildK8s(t)
	if err := inj.Validate(); err != nil {
		t.Fatalf("the injection must pass path validation: %v", err)
	}
	if strings.HasPrefix(inj.Files[0].Path, "/") {
		t.Error("the injected path must be workspace-relative")
	}
	if inj.Files[0].Mode != 0o600 {
		t.Errorf("mode = %o, want 0600", inj.Files[0].Mode)
	}
}

// TestKubeconfigSaysWhatItIs: an operator who finds this file needs to know it is
// generated, scoped to one session, and worth nothing if copied.
func TestKubeconfigSaysWhatItIs(t *testing.T) {
	body := string(buildK8s(t).Files[0].Content)
	for _, want := range []string{"opslifyd", "NO credential", "session"} {
		if !strings.Contains(body, want) {
			t.Errorf("the kubeconfig header should mention %q:\n%s", want, body)
		}
	}
}
