package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultFileName is the policy file looked up at the workspace repo root (the
// mounted /workspace) and accepted by `opslify policy check`.
const DefaultFileName = "opslify.policy.yaml"

// maxTTL bounds session.ttl. A ttl beyond this is an out-of-range validation
// error (a policy cannot pin an unboundedly long-lived session).
const maxTTL = 24 * time.Hour

// LineError is a single validation problem tied to a source line. Line 0 means
// "no position available" (e.g. a whole-file parse failure).
type LineError struct {
	Line int
	Msg  string
}

// ValidationError aggregates every line-level problem found in one policy file.
// It renders as one `file:line: reason` per line so `opslify policy check` can
// print them all. It is the fail-closed signal: any caller that receives it must
// refuse to serve the session rather than fall back to a permissive default.
type ValidationError struct {
	File   string
	Errors []LineError
}

func (e *ValidationError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("%s: invalid policy", e.File)
	}
	lines := make([]string, len(e.Errors))
	for i, le := range e.Errors {
		if le.Line > 0 {
			lines[i] = fmt.Sprintf("%s:%d: %s", e.File, le.Line, le.Msg)
		} else {
			lines[i] = fmt.Sprintf("%s: %s", e.File, le.Msg)
		}
	}
	return strings.Join(lines, "\n")
}

// yamlLineRe extracts the "line N" a yaml.v3 decode error reports so a low-level
// syntax/type/unknown-key error still surfaces as a `file:line: reason`.
var yamlLineRe = regexp.MustCompile(`line (\d+):`)

// Load reads and validates a policy file at path, returning the typed model.
// A missing file is reported via os.IsNotExist so callers can distinguish
// "absent → use default" from "present but invalid → refuse to serve". Any
// syntax, unknown-key, wrong-type, or semantic problem returns a
// *ValidationError with line-level detail; the model is NEVER returned partial.
func Load(path string) (Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	return Parse(b, filepath.Base(path))
}

// Parse validates policy bytes labelled as file (for error messages). It is the
// testable core of Load. Validation proceeds in three stages, each fail-closed:
//  1. parse into a position-preserving yaml.Node (syntax errors → line-level);
//  2. strict-decode into the typed model with KnownFields(true) (unknown keys +
//     wrong types → line-level, via the yaml error's own line number);
//  3. semantic checks (unknown tier/verb/command, bad duration, uncompilable
//     regex, malformed egress/cred) with line numbers looked up in the node tree.
func Parse(b []byte, file string) (Policy, error) {
	if file == "" {
		file = DefaultFileName
	}
	verr := &ValidationError{File: file}

	// Stage 1: position-preserving parse. A syntax error carries a line number.
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		verr.Errors = append(verr.Errors, lineErrorFromYAML(err, "syntax error"))
		return Policy{}, verr
	}

	// Stage 2: strict decode. KnownFields(true) rejects unknown keys; type
	// mismatches also surface here. Both carry a line number in the yaml error.
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		// A yaml.TypeError can hold several messages; split so each becomes one
		// line-level entry.
		for _, msg := range splitYAMLErrors(err) {
			verr.Errors = append(verr.Errors, lineErrorFromMsg(msg))
		}
		if len(verr.Errors) > 0 {
			sortErrors(verr)
			return Policy{}, verr
		}
	}

	// Stage 3: semantic validation with node-tree line lookups.
	mapNode := documentMapping(&root)
	validateSemantics(mapNode, p, verr)
	if len(verr.Errors) > 0 {
		sortErrors(verr)
		return Policy{}, verr
	}
	return p, nil
}

// validateSemantics runs every content check that a schema/type decode cannot,
// attributing each failure to the line of the offending node.
func validateSemantics(m *yaml.Node, p Policy, verr *ValidationError) {
	// session.tier
	if p.Session.Tier != "" && !knownTier(p.Session.Tier) {
		verr.add(lineOf(m, "session", "tier"), fmt.Sprintf("unknown tier %q in session.tier", p.Session.Tier))
	}
	// session.ttl
	if p.Session.TTL != "" {
		if d, err := time.ParseDuration(p.Session.TTL); err != nil {
			verr.add(lineOf(m, "session", "ttl"), fmt.Sprintf("invalid duration %q in session.ttl", p.Session.TTL))
		} else if d <= 0 {
			verr.add(lineOf(m, "session", "ttl"), fmt.Sprintf("session.ttl must be positive, got %q", p.Session.TTL))
		} else if d > maxTTL {
			verr.add(lineOf(m, "session", "ttl"), fmt.Sprintf("session.ttl %q exceeds maximum %s", p.Session.TTL, maxTTL))
		}
	}
	// allow.kubectl.verbs
	for _, v := range p.Allow.Kubectl.Verbs {
		if !knownKubectlVerbs[v] {
			verr.add(lineOf(m, "allow", "kubectl", "verbs"), fmt.Sprintf("unknown verb %q in allow.kubectl.verbs", v))
		}
	}
	for _, ns := range p.Allow.Kubectl.Namespaces {
		if !validDNSLabel(ns) {
			verr.add(lineOf(m, "allow", "kubectl", "namespaces"), fmt.Sprintf("invalid namespace %q in allow.kubectl.namespaces", ns))
		}
	}
	// allow.terraform.commands
	for _, c := range p.Allow.Terraform.Commands {
		if !knownTerraformCommands[c] {
			verr.add(lineOf(m, "allow", "terraform", "commands"), fmt.Sprintf("unknown command %q in allow.terraform.commands", c))
		}
	}
	// allow.exec regexes
	for _, re := range p.Allow.Exec {
		if _, err := regexp.Compile(re); err != nil {
			verr.add(lineOf(m, "allow", "exec"), fmt.Sprintf("invalid regex %q in allow.exec: %v", re, err))
		}
	}
	// approval_required regexes
	for _, re := range p.ApprovalRequired {
		if _, err := regexp.Compile(re); err != nil {
			verr.add(lineOf(m, "approval_required"), fmt.Sprintf("invalid regex %q in approval_required: %v", re, err))
		}
	}
	// egress.domains
	for _, d := range p.Egress.Domains {
		if !validDomain(d) {
			verr.add(lineOf(m, "egress", "domains"), fmt.Sprintf("invalid domain %q in egress.domains", d))
		}
	}
	// dry_run rules (F4.4): each needs a compilable pattern and a non-empty
	// preview whose first token (the tool) is present.
	for i, rule := range p.DryRun {
		if strings.TrimSpace(rule.Pattern) == "" {
			verr.add(lineOf(m, "dry_run"), fmt.Sprintf("dry_run[%d]: pattern is required", i))
		} else if _, err := regexp.Compile(rule.Pattern); err != nil {
			verr.add(lineOf(m, "dry_run"), fmt.Sprintf("dry_run[%d]: invalid regex %q: %v", i, rule.Pattern, err))
		}
		if len(rule.Preview) == 0 || strings.TrimSpace(rule.Preview[0]) == "" {
			verr.add(lineOf(m, "dry_run"), fmt.Sprintf("dry_run[%d] %q: preview command is required", i, rule.Pattern))
		}
	}
	// creds
	for i, c := range p.Creds {
		if strings.TrimSpace(c.Name) == "" {
			verr.add(lineOf(m, "creds"), fmt.Sprintf("creds[%d]: name is required", i))
		}
		if strings.TrimSpace(c.Provider) == "" {
			verr.add(lineOf(m, "creds"), fmt.Sprintf("creds[%d] %q: provider is required", i, c.Name))
		}
	}
}

// add appends a line-level error.
func (e *ValidationError) add(line int, msg string) {
	e.Errors = append(e.Errors, LineError{Line: line, Msg: msg})
}

// sortErrors orders errors by line then message so `policy check` output is
// deterministic (stable across map-iteration order in the callers above).
func sortErrors(e *ValidationError) {
	sort.SliceStable(e.Errors, func(i, j int) bool {
		if e.Errors[i].Line != e.Errors[j].Line {
			return e.Errors[i].Line < e.Errors[j].Line
		}
		return e.Errors[i].Msg < e.Errors[j].Msg
	})
}

// documentMapping returns the top-level mapping node of a parsed document, or
// nil when the file is empty/non-mapping (semantic checks then report line 0).
func documentMapping(root *yaml.Node) *yaml.Node {
	if root == nil || root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil
	}
	return top
}

// lineOf walks a mapping node following the given key path and returns the line
// of the VALUE at the end of the path (or the nearest resolvable ancestor's key
// line). Returns 0 when nothing on the path is present.
func lineOf(m *yaml.Node, path ...string) int {
	cur := m
	line := 0
	for _, key := range path {
		if cur == nil || cur.Kind != yaml.MappingNode {
			return line
		}
		found := false
		for i := 0; i+1 < len(cur.Content); i += 2 {
			k := cur.Content[i]
			if k.Value == key {
				v := cur.Content[i+1]
				// Prefer the VALUE node's line: for a block sequence/mapping it
				// points at the first item (the actual data), which is the most
				// precise position for a content error; it falls back to the key
				// line for a same-line scalar/flow value.
				if v.Line > 0 {
					line = v.Line
				} else {
					line = k.Line
				}
				cur = v
				found = true
				break
			}
		}
		if !found {
			return line
		}
	}
	return line
}

// lineErrorFromYAML converts a yaml decode/parse error into a LineError, pulling
// the "line N" the yaml library reports; fallback is line 0.
func lineErrorFromYAML(err error, fallbackMsg string) LineError {
	le := lineErrorFromMsg(strings.TrimPrefix(err.Error(), "yaml: "))
	if le.Msg == "" {
		le.Msg = fallbackMsg
	}
	return le
}

// lineErrorFromMsg parses a single raw yaml message into a positioned LineError.
func lineErrorFromMsg(msg string) LineError {
	line := 0
	if mm := yamlLineRe.FindStringSubmatch(msg); mm != nil {
		fmt.Sscanf(mm[1], "%d", &line)
	}
	return LineError{Line: line, Msg: cleanYAMLMsg(msg)}
}

// splitYAMLErrors flattens a yaml.TypeError (which bundles many messages) into
// individual message strings; a plain error yields its single message.
func splitYAMLErrors(err error) []string {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		return te.Errors
	}
	return []string{err.Error()}
}

// cleanYAMLMsg tidies a raw yaml message into a policy-facing reason.
func cleanYAMLMsg(msg string) string {
	msg = strings.TrimSpace(msg)
	// Drop a leading "line N:" now that the number lives in LineError.Line.
	msg = yamlLineRe.ReplaceAllString(msg, "")
	msg = strings.TrimSpace(msg)
	msg = strings.TrimPrefix(msg, ":")
	return strings.TrimSpace(msg)
}

// validDNSLabel accepts a Kubernetes namespace (RFC 1123 label).
var dnsLabelRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

func validDNSLabel(s string) bool { return dnsLabelRe.MatchString(s) }

// validDomain accepts an egress domain: dot-separated DNS labels, optionally a
// leading "*." wildcard. No scheme, port, path, or whitespace.
var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`)

func validDomain(s string) bool { return domainRe.MatchString(strings.ToLower(s)) }
