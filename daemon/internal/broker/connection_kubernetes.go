package broker

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"

	"gopkg.in/yaml.v3"
)

// kubeconfigPath is where the generated kubeconfig lands, relative to the
// workspace. Under .opslify/ rather than the conventional ~/.kube/config so it
// is unmistakably daemon-generated and lands inside the directory the session
// owns.
const kubeconfigPath = ".opslify/kubeconfig"

// kubernetesConnection hands the sandbox a kubeconfig with NO credential in it.
//
// What the sandbox receives: a kubeconfig whose `server:` is the per-session
// proxy and whose user block is empty. The proxy terminates TLS with the
// per-session CA and adds the real bearer token to the upstream request. The
// token never enters the sandbox's environment, its filesystem, or the trace.
//
// The kubeconfig is useless off this host by construction: it points at a
// loopback/gateway address bound for one session and source-scoped to one
// container, and it carries nothing to authenticate with.
type kubernetesConnection struct {
	spec ConnectionSpec
}

// NewKubernetesConnection builds the kubernetes kind from a spec.
func NewKubernetesConnection(spec ConnectionSpec, _ SecretResolver) (Connection, error) {
	return &kubernetesConnection{spec: spec}, nil
}

func (c *kubernetesConnection) Kind() Kind           { return KindKubernetes }
func (c *kubernetesConnection) Name() string         { return c.spec.Name }
func (c *kubernetesConnection) SecretRefs() []string { return []string{c.spec.SecretRef} }

// apiHost is the cluster's real API host — the upstream the proxy injects for.
func (c *kubernetesConnection) apiHost() string { return c.spec.Hosts[0] }

// clusterName names the cluster in the generated kubeconfig.
func (c *kubernetesConnection) clusterName() string {
	if n := c.spec.Config["cluster"]; n != "" {
		return n
	}
	return c.spec.Name
}

func (c *kubernetesConnection) namespace() string {
	if ns := c.spec.Config["namespace"]; ns != "" {
		return ns
	}
	return "default"
}

func (c *kubernetesConnection) Validate() error {
	if err := c.spec.ValidateSpec(); err != nil {
		return err
	}
	if len(c.spec.Hosts) != 1 {
		// Exactly one: a kubeconfig names one server, and silently using the first
		// of several would make which cluster the agent talks to depend on list
		// order.
		return fmt.Errorf("%w: kubernetes connection %q needs exactly one host (the cluster API), got %d",
			ErrInvalidInput, c.spec.Name, len(c.spec.Hosts))
	}
	// A user-supplied server: must never reach the generated kubeconfig — the
	// whole point is that it can only be pointed at the session proxy.
	for _, banned := range []string{"server", "insecure-skip-tls-verify", "token", "client-certificate-data", "client-key-data"} {
		if _, present := c.spec.Config[banned]; present {
			return fmt.Errorf("%w: kubernetes connection %q may not set %q — the server is always the session proxy and the user block is always empty",
				ErrInvalidInput, c.spec.Name, banned)
		}
	}
	if ns := c.spec.Config["namespace"]; ns != "" && !isDNSLabel(ns) {
		return fmt.Errorf("%w: kubernetes connection %q namespace %q is not a valid DNS label", ErrInvalidInput, c.spec.Name, ns)
	}
	if cl := c.spec.Config["cluster"]; cl != "" && !isDNSLabel(cl) {
		return fmt.Errorf("%w: kubernetes connection %q cluster name %q is not a valid DNS label", ErrInvalidInput, c.spec.Name, cl)
	}
	return nil
}

// EgressRules injects the bearer token on the cluster API host, upstream.
//
// This is the same mechanism as the http kind — which is the point of having
// built http first. The kubernetes kind adds the kubeconfig, not a second
// credential path.
func (c *kubernetesConnection) EgressRules() []HeaderInjectRule {
	return []HeaderInjectRule{{
		Host:         c.apiHost(),
		SecretRef:    c.spec.SecretRef,
		HeaderName:   "Authorization",
		HeaderFormat: "Bearer %s",
	}}
}

// BuildForSession writes the credential-free kubeconfig and points KUBECONFIG at
// it. It requires the proxy address: without one there is nothing to point the
// sandbox at, and generating a kubeconfig aimed at the real cluster would hand
// the sandbox a direct path that needs the credential it must never have.
func (c *kubernetesConnection) BuildForSession(_ context.Context, sc SessionContext) (ConnectionInjection, io.Closer, error) {
	if sc.ProxyAddr == "" {
		return ConnectionInjection{}, nil, fmt.Errorf(
			"%w: kubernetes connection %q needs the session proxy address; refusing to generate a kubeconfig that would bypass it",
			ErrDenied, c.spec.Name)
	}
	if len(sc.ProxyCAPEM) == 0 {
		// Without the CA the sandbox's kubectl cannot verify the proxy, and the only
		// way to "fix" that inside the sandbox is insecure-skip-tls-verify — which
		// would make it accept ANY certificate, not merely ours.
		return ConnectionInjection{}, nil, fmt.Errorf(
			"%w: kubernetes connection %q needs the per-session proxy CA; refusing to produce a kubeconfig that could only work with verification disabled",
			ErrDenied, c.spec.Name)
	}
	cfg, err := c.renderKubeconfig(sc)
	if err != nil {
		return ConnectionInjection{}, nil, err
	}
	inj := ConnectionInjection{
		Env: map[string]string{
			// An absolute in-sandbox path: the workspace is mounted at /workspace.
			"KUBECONFIG": "/workspace/" + kubeconfigPath,
		},
		Files: []InjectedFile{{
			Path: kubeconfigPath,
			// 0600: the file carries no credential, but it does carry the CA and the
			// proxy address, and a world-readable config in a shared workspace is a
			// habit worth not teaching.
			Mode:    0o600,
			Content: cfg,
		}},
		ExcludeRefs: []string{c.spec.SecretRef},
	}
	if err := inj.Validate(); err != nil {
		return ConnectionInjection{}, nil, err
	}
	return inj, nil, nil
}

// kubeconfig mirrors the subset of the kubeconfig schema we generate. It is a
// typed struct rather than a string template so the output cannot be malformed
// by an unescaped value, and so the ABSENCE of credential fields is structural:
// there is no field here that could hold a token.
type kubeconfig struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Clusters   []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server string `yaml:"server"`
			CAData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	// Users carries a named user with an EMPTY auth block. kubectl requires the
	// user referenced by the context to exist; it does not require it to hold
	// anything. The proxy supplies the credential upstream.
	Users []struct {
		Name string   `yaml:"name"`
		User struct{} `yaml:"user"`
	} `yaml:"users"`
}

// renderKubeconfig produces the YAML written into the sandbox.
func (c *kubernetesConnection) renderKubeconfig(sc SessionContext) ([]byte, error) {
	server := "https://" + sc.ProxyAddr
	// Parse-check what we generate rather than trusting the address we were handed:
	// a malformed server silently makes every kubectl call fail with a confusing
	// error, and an address carrying a path or userinfo would change what the
	// sandbox connects to.
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || u.Path != "" || u.User != nil {
		return nil, fmt.Errorf("%w: kubernetes connection %q: proxy address %q is not a bare host:port",
			ErrInvalidInput, c.spec.Name, sc.ProxyAddr)
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return nil, fmt.Errorf("%w: kubernetes connection %q: proxy address %q needs host:port",
			ErrInvalidInput, c.spec.Name, sc.ProxyAddr)
	}

	var kc kubeconfig
	kc.APIVersion = "v1"
	kc.Kind = "Config"
	cluster := c.clusterName()
	user := cluster + "-via-opslify"
	ctxName := cluster

	kc.Clusters = append(kc.Clusters, struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server string `yaml:"server"`
			CAData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	}{Name: cluster})
	kc.Clusters[0].Cluster.Server = server
	kc.Clusters[0].Cluster.CAData = base64.StdEncoding.EncodeToString(sc.ProxyCAPEM)

	kc.Contexts = append(kc.Contexts, struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	}{Name: ctxName})
	kc.Contexts[0].Context.Cluster = cluster
	kc.Contexts[0].Context.User = user
	kc.Contexts[0].Context.Namespace = c.namespace()

	kc.CurrentContext = ctxName
	kc.Users = append(kc.Users, struct {
		Name string   `yaml:"name"`
		User struct{} `yaml:"user"`
	}{Name: user})

	out, err := yaml.Marshal(kc)
	if err != nil {
		return nil, fmt.Errorf("broker: render kubeconfig for %q: %w", c.spec.Name, err)
	}
	header := "# Generated by opslifyd for one session. It contains NO credential:\n" +
		"# the server is this session's proxy, which adds the real token upstream.\n" +
		"# Copying this file elsewhere gains nothing.\n"
	return append([]byte(header), out...), nil
}

// isDNSLabel checks a kubeconfig cluster/namespace name.
func isDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i != 0 && i != len(s)-1:
		default:
			return false
		}
	}
	return true
}
