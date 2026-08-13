// Package policy implements F4.1 — the declarative, schema-validated
// opslify.policy.yaml that governs a session.
//
// A policy file has five sections — session (ttl/tier/image), allow (kubectl,
// terraform, generic exec regexes), approval_required (command patterns),
// egress (domains) and creds (refs/providers, parsed now, enforced in P5) —
// plus two flags (strict_exec, and deny-by-default creds).
//
// This package is PURE POLICY DATA + resolution: it loads and validates a file
// with LINE-LEVEL errors, RESOLVES a workspace policy over the daemon default
// under the hard invariant that a workspace may only NARROW (never WIDEN) the
// daemon policy, and computes a deterministic policy_hash over the RESOLVED
// model. It contains NO enforcement — the classifier/decision engine is F4.2,
// which consumes the exported Resolved model WITHOUT re-parsing.
//
// Security posture: the workspace is agent-controlled and therefore untrusted.
// The narrows-not-widens merge (see resolve.go) is the security teeth: a
// workspace file can never grant itself a capability the daemon did not already
// allow. Loading is fail-closed: an invalid/unparseable policy is an error the
// caller treats as refuse-to-serve, never a silent permissive default.
package policy

import (
	"sort"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// Policy is the typed, in-memory model of an opslify.policy.yaml. It is used
// both for a parsed file and, once merged, for the resolved model (embedded in
// Resolved). All slice fields are normalised (sorted + de-duplicated) by
// normalize() before hashing so the model has ONE canonical form.
type Policy struct {
	Session          Session  `json:"session" yaml:"session"`
	Allow            Allow    `json:"allow" yaml:"allow"`
	ApprovalRequired []string `json:"approval_required" yaml:"approval_required"`
	Egress           Egress   `json:"egress" yaml:"egress"`
	Creds            []Cred   `json:"creds" yaml:"creds"`
	// StrictExec makes exec allowlist-only (F4.2 consumes it). Default false =
	// allow-with-approval_required. Narrowing can only turn it ON, never OFF.
	StrictExec bool `json:"strict_exec" yaml:"strict_exec"`
}

// Session carries per-session limits.
type Session struct {
	// TTL is a Go duration string ("30m"); empty means "inherit the daemon
	// default". A workspace may only SHORTEN the ttl, never lengthen it.
	TTL string `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// Tier is an isolation rung (runtime.Tier). A workspace may only choose a
	// tier at least as isolated as the daemon's, never a weaker one.
	Tier string `json:"tier,omitempty" yaml:"tier,omitempty"`
	// Image is a digest-pinned base image. A workspace may not change a
	// daemon-pinned image (that would be a widening); a differing value clamps
	// back to the daemon's with a recorded reason.
	Image string `json:"image,omitempty" yaml:"image,omitempty"`
}

// Allow enumerates positively-permitted operations. Narrowing intersects each
// set with the daemon's, so a workspace can only ever SHRINK what is allowed.
type Allow struct {
	Kubectl   Kubectl   `json:"kubectl" yaml:"kubectl"`
	Terraform Terraform `json:"terraform" yaml:"terraform"`
	// Exec is a set of generic argv regexes (matched by F4.2). It is an allow
	// set: narrowing keeps only patterns also present in the daemon policy.
	Exec []string `json:"exec" yaml:"exec"`
}

// Kubectl bounds kubectl to a set of namespaces and verbs.
type Kubectl struct {
	Namespaces []string `json:"namespaces" yaml:"namespaces"`
	Verbs      []string `json:"verbs" yaml:"verbs"`
}

// Terraform bounds terraform to a set of subcommands.
type Terraform struct {
	Commands []string `json:"commands" yaml:"commands"`
}

// Egress is the allowlist of destination domains (reconciles with F1.4).
type Egress struct {
	Domains []string `json:"domains" yaml:"domains"`
}

// Cred is a requested credential grant. Parsed + validated now; ENFORCED in P5
// (the broker). Creds are deny-by-default: nothing is granted unless listed,
// and a workspace may only request creds the daemon already allows.
type Cred struct {
	Name     string `json:"name" yaml:"name"`
	Provider string `json:"provider" yaml:"provider"`
}

// tierRank orders the isolation ladder from least (0) to most isolated. A higher
// rank is MORE isolated. Narrowing requires the resolved tier rank >= the
// daemon's; a workspace picking a lower rank is a widening and is clamped.
var tierRank = map[string]int{
	string(runtime.TierLocalDocker):   0,
	string(runtime.TierLocalHardened): 1,
	string(runtime.TierCloudMicroVM):  2,
}

// knownTiers is the set of accepted session.tier values.
func knownTier(t string) bool {
	_, ok := tierRank[t]
	return ok
}

// knownKubectlVerbs is the accepted verb vocabulary for allow.kubectl.verbs. An
// unknown verb is a line-level validation error (fail-closed: a typo does not
// silently become an unbounded grant).
var knownKubectlVerbs = map[string]bool{
	"get": true, "list": true, "watch": true, "describe": true, "explain": true,
	"logs": true, "top": true, "apply": true, "create": true, "delete": true,
	"patch": true, "edit": true, "replace": true, "scale": true, "rollout": true,
	"exec": true, "cp": true, "port-forward": true, "annotate": true, "label": true,
	"cordon": true, "drain": true, "uncordon": true, "taint": true, "expose": true,
	"set": true, "wait": true, "diff": true,
}

// knownTerraformCommands is the accepted subcommand vocabulary for
// allow.terraform.commands.
var knownTerraformCommands = map[string]bool{
	"init": true, "validate": true, "plan": true, "apply": true, "destroy": true,
	"fmt": true, "output": true, "show": true, "state": true, "import": true,
	"refresh": true, "workspace": true, "providers": true, "version": true,
	"graph": true, "taint": true, "untaint": true, "console": true, "get": true,
}

// Default is the documented default policy used when NO policy file is present:
// no allow grants, no approval requirements, no egress domains, deny-by-default
// creds (empty), strict_exec off (exec default-allow). Its resolved form has a
// stable, well-known policy_hash (see DefaultHash / policy_test.go).
func Default() Policy {
	return Policy{}
}

// normalize sorts and de-duplicates every set-valued field IN PLACE and returns
// the receiver, so a Policy has exactly one canonical shape regardless of the
// order things appeared in the file. It is the basis of the deterministic
// policy_hash: two policies with the same logical content normalise identically.
func (p Policy) normalize() Policy {
	p.ApprovalRequired = sortedSet(p.ApprovalRequired)
	p.Allow.Exec = sortedSet(p.Allow.Exec)
	p.Allow.Kubectl.Namespaces = sortedSet(p.Allow.Kubectl.Namespaces)
	p.Allow.Kubectl.Verbs = sortedSet(p.Allow.Kubectl.Verbs)
	p.Allow.Terraform.Commands = sortedSet(p.Allow.Terraform.Commands)
	p.Egress.Domains = sortedSet(p.Egress.Domains)
	p.Creds = sortedCreds(p.Creds)
	return p
}

// sortedSet returns a new sorted, de-duplicated copy of in. A nil/empty input
// yields nil, so an absent section and an empty section canonicalise the same.
func sortedSet(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// sortedCreds returns creds sorted by (name, provider) with exact duplicates
// removed, so the resolved model is order-independent.
func sortedCreds(in []Cred) []Cred {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[Cred]struct{}, len(in))
	out := make([]Cred, 0, len(in))
	for _, c := range in {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}
