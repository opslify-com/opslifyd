package broker

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
)

// A Connection is how a credential reaches an upstream WITHOUT the sandbox ever
// holding it.
//
// The abstraction exists to generalise what P5 already proves for HTTP. Every
// kind must be able to answer, in one line, what the sandbox actually receives —
// and that thing must be useless off this host:
//
//	http        nothing (the proxy adds the header on the upstream leg)
//	kubernetes  a kubeconfig with no credential in it
//	ssh         an agent socket — signatures only, never key material
//	cloud       short-lived scoped credentials
//
// A kind whose honest answer is "the credential" does not ship. That rule is the
// whole point of the interface: it makes the question unavoidable at the moment
// someone adds a kind, rather than a property people believe the system has.
type Connection interface {
	// Kind identifies the mechanism.
	Kind() Kind
	// Name is the operator-facing connection name, unique within a scope.
	Name() string
	// SecretRefs are the vault refs this connection resolves. They are REFS, never
	// values — the F8.3 consumer index reads them to refuse a delete that would
	// break a live connection.
	SecretRefs() []string
	// Validate checks the connection is usable before it is stored, so a broken
	// definition is a create-time error rather than a session-time surprise.
	Validate() error
	// BuildForSession produces the injection for one session and a Closer that
	// tears down everything the kind allocated (listeners, agents, sockets).
	//
	// It must FAIL CLOSED: a connection whose secret is missing or unreadable
	// returns an error and injects nothing. There is no partial mode and no
	// fallback to handing the value over directly.
	BuildForSession(ctx context.Context, sc SessionContext) (ConnectionInjection, io.Closer, error)
}

// Kind names a connection mechanism.
type Kind string

const (
	// KindHTTP injects an auth header at the L7 egress proxy (F5.2/F5.7).
	KindHTTP Kind = "http"
	// KindKubernetes hands the sandbox a credential-free kubeconfig pointed at the
	// per-session proxy, which adds the real token upstream.
	KindKubernetes Kind = "kubernetes"
	// KindSSH forwards a daemon-held agent socket with destination-constrained
	// keys. The agent protocol has no export operation, so key material genuinely
	// cannot cross the socket.
	KindSSH Kind = "ssh"
	// KindCloud mints short-lived scoped credentials (F5.3).
	KindCloud Kind = "cloud"
)

// SessionContext is what a kind is given to build an injection.
type SessionContext struct {
	SessionID string
	// Listen binds a listener for a kind that needs one. Supplied by the session
	// layer so binding stays subject to the F5.9 gateway rules — a kind never
	// chooses its own bind address, because a routable bind on a
	// credential-injecting listener is a blocking defect.
	Listen func() (net.Listener, error)
	// AdvertiseHost is the container-reachable address the sandbox should use.
	// Empty means the listener address is already reachable.
	AdvertiseHost string
	// SourceIP scopes the listener to the owning container. Empty means unscoped,
	// which is only correct where the runtime exposes no container IP.
	SourceIP string
	// WorkspaceDir is where injected files are written. Daemon-controlled.
	WorkspaceDir string
}

// InjectedFile is a file a kind writes for the sandbox to use.
//
// It carries no credential by construction of each kind — a kubeconfig with an
// empty user block, a known_hosts file. The test for every kind greps these files
// for the credential rather than reasoning about them.
type InjectedFile struct {
	// Path is relative to the workspace root. Absolute paths and traversal are
	// refused: a kind must not be able to write outside the directory the session
	// owns.
	Path    string
	Mode    os.FileMode
	Content []byte
}

// HeaderInjectRule is a host→secret→header mapping for the HTTP egress proxy.
//
// It is declared here rather than reusing the egress proxy's own type because
// that package already imports this one; a neutral shape keeps the dependency
// pointing one way and keeps kinds from depending on proxy internals.
type HeaderInjectRule struct {
	Host         string
	SecretRef    string
	HeaderName   string
	HeaderFormat string
}

// ConnectionInjection is a kind's contribution to a session.
//
// Named distinctly from the F5.1 Injection, which is a single resolved
// credential's contribution to one spawned PROCESS. This one is a whole
// connection's contribution to a whole SESSION, and conflating them would make
// the credential-blindness argument harder to follow, not easier.
type ConnectionInjection struct {
	// Env are environment variables for the sandbox. A kind must never place a
	// credential here; the tests assert it.
	Env map[string]string
	// Files are written into the workspace before the sandbox starts.
	Files []InjectedFile
	// EgressRules are header injections for the L7 proxy. Only the http kind
	// produces these today.
	EgressRules []HeaderInjectRule
	// ExcludeRefs are secret refs that must NOT be resolved into the sandbox
	// environment by the F5.1 env injector, because this connection resolves them
	// at a boundary instead. Getting this wrong would place in the sandbox exactly
	// the value the connection exists to keep out of it.
	ExcludeRefs []string
}

// Merge folds another injection into this one, refusing conflicts rather than
// letting one connection silently overwrite another's variable or file.
func (i *ConnectionInjection) Merge(other ConnectionInjection) error {
	for k, v := range other.Env {
		if existing, ok := i.Env[k]; ok && existing != v {
			return fmt.Errorf("%w: two connections both set %s", ErrConflict, k)
		}
		if i.Env == nil {
			i.Env = map[string]string{}
		}
		i.Env[k] = v
	}
	seen := map[string]bool{}
	for _, f := range i.Files {
		seen[f.Path] = true
	}
	for _, f := range other.Files {
		if seen[f.Path] {
			return fmt.Errorf("%w: two connections both write %s", ErrConflict, f.Path)
		}
		i.Files = append(i.Files, f)
	}
	i.EgressRules = append(i.EgressRules, other.EgressRules...)
	i.ExcludeRefs = append(i.ExcludeRefs, other.ExcludeRefs...)
	return nil
}

// ErrConflict marks two connections that cannot coexist in one session.
var ErrConflict = fmt.Errorf("broker: connection conflict")

// validateInjectedPath refuses a path that could escape the workspace.
//
// A kind is daemon code, not workspace input — but a kind reading a
// connection record built from operator input is one indirection away from it,
// and a file written outside the session's own directory would land in the
// daemon's filesystem with the daemon's privileges.
func validateInjectedPath(p string) error {
	if p == "" {
		return fmt.Errorf("%w: injected file needs a path", ErrInvalidInput)
	}
	// Redundant with the empty-segment check below (an absolute path splits to a
	// leading ""), but kept: it names the actual mistake in the error, and the two
	// together mean neither can be removed without the other noticing.
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: injected path %q must be relative to the workspace", ErrInvalidInput, p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." || seg == "" {
			return fmt.Errorf("%w: injected path %q must not contain %q", ErrInvalidInput, p, seg)
		}
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("%w: injected path %q contains NUL", ErrInvalidInput, p)
	}
	return nil
}

// Validate checks every file path in an injection.
func (i ConnectionInjection) Validate() error {
	for _, f := range i.Files {
		if err := validateInjectedPath(f.Path); err != nil {
			return err
		}
	}
	for k := range i.Env {
		if k == "" || strings.ContainsAny(k, "=\x00") {
			return fmt.Errorf("%w: invalid environment variable name %q", ErrInvalidInput, k)
		}
	}
	return nil
}

// --- registry ----------------------------------------------------------------

// Builder constructs a Connection from a stored spec. Registered per kind, so
// adding a kind touches no session code.
type Builder func(spec ConnectionSpec, secrets SecretResolver) (Connection, error)

// SecretResolver is the narrow view a kind gets of the vault: resolve by ref, at
// build time, inside the daemon. Kinds never see the manager and so cannot list,
// enumerate or delete.
type SecretResolver interface {
	Get(ctx context.Context, ref string) ([]byte, SecretMeta, error)
}

// registry maps a kind to its builder.
type registry struct {
	builders map[Kind]Builder
}

// Registry holds the known kinds.
type Registry struct{ r registry }

// NewRegistry returns a registry with no kinds. The daemon registers the kinds
// it ships; a test registers a fake.
func NewRegistry() *Registry {
	return &Registry{r: registry{builders: map[Kind]Builder{}}}
}

// Register adds a builder for a kind. Registering twice is a programming error
// and panics at startup rather than silently taking one of the two.
func (reg *Registry) Register(k Kind, b Builder) {
	if _, dup := reg.r.builders[k]; dup {
		panic(fmt.Sprintf("broker: connection kind %q registered twice", k))
	}
	reg.r.builders[k] = b
}

// Build constructs a Connection from a spec, or reports an unknown kind.
//
// An unknown kind is an ERROR, never a no-op: a connection an operator created
// and believes is in force, silently doing nothing, is the worst of both worlds.
func (reg *Registry) Build(spec ConnectionSpec, secrets SecretResolver) (Connection, error) {
	b, ok := reg.r.builders[spec.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: unknown connection kind %q (known: %s)",
			ErrInvalidInput, spec.Kind, strings.Join(reg.Kinds(), ", "))
	}
	c, err := b(spec, secrets)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Kinds lists the registered kinds, sorted.
func (reg *Registry) Kinds() []string {
	out := make([]string, 0, len(reg.r.builders))
	for k := range reg.r.builders {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}

// ConnectionSpec is the stored, operator-facing definition of a connection.
//
// It is project/environment SCOPED (F8.1) and references a secret BY REF (F8.3) —
// never an inline value. A record that could hold a value would put credentials
// in a file the operator edits and commits, which is the habit the whole system
// exists to break.
type ConnectionSpec struct {
	// Name is unique within a scope.
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	// ProjectID and EnvironmentID scope the connection. Empty means daemon-wide.
	ProjectID     string `json:"project_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
	// SecretRef is the vault ref this connection resolves. Never a value.
	SecretRef string `json:"secret_ref"`
	// Hosts are the upstreams this connection is for: the HTTP host to inject on,
	// the SSH destinations a key may be used against, the cluster API host. For ssh
	// this list IS the destination constraint, so an empty list must never mean
	// "any host".
	Hosts []string `json:"hosts,omitempty"`
	// Config holds kind-specific settings (header name and format, cluster CA,
	// namespace). Kind-specific rather than a union type so a new kind adds no
	// fields here.
	Config map[string]string `json:"config,omitempty"`
}

// connectionNameRe bounds a connection name to one safe path/identifier segment,
// for the same reason project and environment names are bounded: it is stored as
// a record id and shown in audit output.
var connectionNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// ValidateSpec checks the operator-supplied parts of a spec, independent of kind.
// Kind-specific validation happens in the kind's own Validate.
func (s ConnectionSpec) ValidateSpec() error {
	if !connectionNameRe.MatchString(s.Name) {
		return fmt.Errorf("%w: connection name %q must be lowercase alphanumeric with dashes (1-40 chars)", ErrInvalidInput, s.Name)
	}
	if s.Kind == "" {
		return fmt.Errorf("%w: connection %q needs a kind", ErrInvalidInput, s.Name)
	}
	if s.SecretRef == "" {
		return fmt.Errorf("%w: connection %q needs a secret ref (a connection never holds a value)", ErrInvalidInput, s.Name)
	}
	if err := ValidateRef(s.SecretRef); err != nil {
		return err
	}
	for _, h := range s.Hosts {
		if err := validateHost(h); err != nil {
			return fmt.Errorf("%w: connection %q: %v", ErrInvalidInput, s.Name, err)
		}
	}
	return nil
}

// validateHost bounds a declared upstream host. It refuses anything with a
// scheme, path, credentials or wildcard: a host list is matched against, and a
// permissive entry silently widens what a connection covers.
func validateHost(h string) error {
	if h == "" {
		return fmt.Errorf("empty host")
	}
	if len(h) > 253 {
		return fmt.Errorf("host %q is too long", h)
	}
	if strings.ContainsAny(h, "/\\ \t\x00?#@*") {
		return fmt.Errorf("host %q must be a bare host or host:port", h)
	}
	if strings.Contains(h, "://") {
		return fmt.Errorf("host %q must not carry a scheme", h)
	}
	host := h
	if hh, _, err := net.SplitHostPort(h); err == nil {
		host = hh
	}
	if host == "" {
		return fmt.Errorf("host %q has no host part", h)
	}
	return nil
}
