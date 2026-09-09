package broker

import (
	"fmt"
	"sort"
	"strings"
)

// A secret is a VALUE; a consumer is something that reaches an upstream with it.
// One secret commonly backs several consumers — which is why rotating a key is
// one action here rather than an edit in six config files, and why deleting a ref
// has to be refused while anything still addresses it.

// ConsumerKind names the sort of thing that uses a secret ref.
type ConsumerKind string

const (
	// ConsumerPolicyGrant is a `creds` grant in a resolved policy layer: a session
	// in that scope may resolve the ref.
	ConsumerPolicyGrant ConsumerKind = "policy-grant"
	// ConsumerEgressInject is an F5.7 egress_inject rule: the L7 proxy injects the
	// secret as a header for one upstream host.
	ConsumerEgressInject ConsumerKind = "egress-inject"
	// ConsumerRegistryUpstream is an F5.5 registry upstream's cred_ref.
	ConsumerRegistryUpstream ConsumerKind = "registry-upstream"
	// ConsumerConnection is reserved for F8.2 connections. Declared now so the
	// index has a stable vocabulary before the objects exist.
	ConsumerConnection ConsumerKind = "connection"
)

// Consumer is one thing that addresses a secret ref. It carries NO value and no
// path to one — a consumer listing is safe to render anywhere the ref itself is.
type Consumer struct {
	Kind ConsumerKind `json:"kind"`
	// Name identifies the consumer within its kind (a host, an upstream, a
	// connection id, or the granting policy layer).
	Name string `json:"name"`
	// Scope is the project/environment the consumer belongs to, where that is
	// meaningful. Empty means daemon-wide.
	Scope string `json:"scope,omitempty"`
}

func (c Consumer) String() string {
	if c.Scope == "" {
		return fmt.Sprintf("%s %s", c.Kind, c.Name)
	}
	return fmt.Sprintf("%s %s (%s)", c.Kind, c.Name, c.Scope)
}

// ConsumerSource reports which secret refs one subsystem addresses. It is the
// extension seam: F8.2 registers connections as another source WITHOUT changing
// any caller, and a subsystem that forgets to register simply reports nothing
// rather than breaking the index.
type ConsumerSource interface {
	// Consumers returns every (ref -> consumers) pair this source knows about.
	Consumers() (map[string][]Consumer, error)
}

// ConsumerSourceFunc adapts a plain function to ConsumerSource.
type ConsumerSourceFunc func() (map[string][]Consumer, error)

func (f ConsumerSourceFunc) Consumers() (map[string][]Consumer, error) { return f() }

// ConsumerIndex aggregates every registered source. It is queried on demand
// rather than cached: config and policy layers change under a running daemon, and
// a stale index would refuse a legitimate delete or — far worse — permit one that
// breaks a live grant.
type ConsumerIndex struct {
	sources []ConsumerSource
}

// NewConsumerIndex builds an index over sources. A nil source is ignored so a
// caller can pass an optional subsystem without a nil check.
func NewConsumerIndex(sources ...ConsumerSource) *ConsumerIndex {
	out := make([]ConsumerSource, 0, len(sources))
	for _, s := range sources {
		if s != nil {
			out = append(out, s)
		}
	}
	return &ConsumerIndex{sources: out}
}

// Register adds a source after construction (F8.2 wiring, mutual references).
func (ci *ConsumerIndex) Register(s ConsumerSource) {
	if s != nil {
		ci.sources = append(ci.sources, s)
	}
}

// All returns every ref that is addressed, mapped to its consumers, sorted and
// de-duplicated so the output is stable for a UI and a test alike.
func (ci *ConsumerIndex) All() (map[string][]Consumer, error) {
	merged := map[string][]Consumer{}
	for _, src := range ci.sources {
		got, err := src.Consumers()
		if err != nil {
			// Fail CLOSED: an index that silently drops a source would under-report
			// consumers, and under-reporting is what lets a delete break a live grant.
			return nil, fmt.Errorf("broker: consumer source: %w", err)
		}
		for ref, cs := range got {
			merged[ref] = append(merged[ref], cs...)
		}
	}
	for ref, cs := range merged {
		merged[ref] = dedupeConsumers(cs)
	}
	return merged, nil
}

// Of returns the consumers of one ref.
func (ci *ConsumerIndex) Of(ref string) ([]Consumer, error) {
	all, err := ci.All()
	if err != nil {
		return nil, err
	}
	return all[ref], nil
}

func dedupeConsumers(in []Consumer) []Consumer {
	seen := make(map[Consumer]struct{}, len(in))
	out := make([]Consumer, 0, len(in))
	for _, c := range in {
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Scope < out[j].Scope
	})
	return out
}

// FormatConsumers renders consumers for an error message or a terminal.
func FormatConsumers(cs []Consumer) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, ", ")
}
