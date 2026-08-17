package policy

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Verdict is the outcome of classifying a command against a resolved policy.
type Verdict string

const (
	// VerdictAllow permits the command to spawn.
	VerdictAllow Verdict = "allow"
	// VerdictDeny refuses the command; the process is NEVER spawned.
	VerdictDeny Verdict = "deny"
	// VerdictNeedsApproval marks a command that matches approval_required. F4.3
	// implements the human pause; F4.2 treats it as a distinct-reason refusal so
	// nothing hangs (the exec path does not spawn on needs_approval either).
	VerdictNeedsApproval Verdict = "needs_approval"
)

// Decision is the pure result of Classify: the verdict, the rule that fired, and
// a legible, non-secret reason. It carries NO argv payload (the caller derives an
// argv_summary for the trace) so a Decision can be logged/compared freely.
type Decision struct {
	Verdict Verdict
	// Rule identifies the matched rule, e.g. "approval_required:^kubectl delete",
	// "allow.kubectl", "allow.terraform", "allow.exec:<re>", "strict_exec",
	// "default-allow". It is the audit hook: a trace/log reader sees exactly which
	// clause decided.
	Rule string
	// Reason is a one-line operator-facing explanation naming the policy layer.
	Reason string
}

// Classify is the PURE, table-testable enforcement core. It maps a resolved
// policy + a concrete argv to a Decision WITHOUT any I/O, spawn, or shell-out —
// so it can never itself become an injection vector, and every enforcement
// outcome is reproducible from data alone.
//
// Evaluation order (fail-closed; first match wins):
//  1. empty argv → deny (defensive; the boundary also rejects this).
//  2. approval_required regex matches the joined argv → needs_approval.
//  3. structured tool awareness: when the policy constrains kubectl (namespaces
//     or verbs) or terraform (commands), the invocation of that tool is checked
//     against the allowlist — in-set → allow, out-of-set → deny.
//  4. generic allow.exec regexes: a match is an allow.
//  5. strict_exec on and nothing above allowed → deny (allowlist-only mode).
//  6. otherwise (non-strict, ungated) → allow.
//
// HONEST LIMIT (see F4.2 security considerations): steps 2–4 match against the
// literal argv. A shell wrapper that computes its sub-command at runtime
// (`sh -c "$X delete ..."`, env-var indirection, path tricks) presents only the
// wrapper's argv here — pattern-matching in non-strict mode is best-effort, not
// airtight. strict_exec + an explicit allowlist is the strong mode: the wrapper's
// own argv (e.g. "sh") is not in allow, so step 5 denies it.
//
// HONEST LIMIT 2 — kubectl namespace is argv-only. parseKubectl reads the
// namespace from the command line and treats an unscoped call as "default". It
// CANNOT see a namespace redirected by a kubeconfig context or a context's
// default namespace. So if a policy grants the "default" namespace AND the agent
// controls the kubeconfig (KUBECONFIG / ~/.kube/config in the workspace), an
// unscoped `kubectl get pods` classifies as allow ("default") yet may hit another
// namespace — and because the structured kubectl check (step 3) resolves before
// the strict allowlist (step 5), this slips even under strict_exec. It never lets
// an explicitly-denied namespace through (an out-of-set `-n <other>` is denied),
// and the spawn is still recorded under a known policy_hash (auditable). Mitigate
// by not granting "default" loosely, preferring an explicit allow.exec regex for
// kubectl, and pinning KUBECONFIG/--namespace out of agent control (P5).
func Classify(r Resolved, argv []string) Decision {
	if len(argv) == 0 {
		return Decision{Verdict: VerdictDeny, Rule: "empty-argv", Reason: "policy: empty command denied (fail-closed)"}
	}
	joined := strings.Join(argv, " ")

	// 1) approval_required — a superset restriction; checked first so an approval
	// gate wins even over an otherwise-allowed command.
	if rule, ok := matchAnyRegex(r.ApprovalRequired, joined); ok {
		return Decision{
			Verdict: VerdictNeedsApproval,
			Rule:    "approval_required:" + rule,
			Reason:  "policy: command requires human approval (approval_required); F4.3 gate not yet available",
		}
	}

	tool := toolName(argv[0])

	// 2) structured tool awareness. Only engaged when the policy actually
	// constrains that tool; otherwise the tool falls through to generic handling.
	switch tool {
	case "kubectl":
		if len(r.Allow.Kubectl.Namespaces) > 0 || len(r.Allow.Kubectl.Verbs) > 0 {
			return classifyKubectl(r, argv)
		}
	case "terraform":
		if len(r.Allow.Terraform.Commands) > 0 {
			return classifyTerraform(r, argv)
		}
	}

	// 3) generic allow.exec allowlist.
	allowRule, inAllow := matchAnyRegex(r.Allow.Exec, joined)

	// 4) strict vs. non-strict.
	if r.StrictExec {
		if inAllow {
			return Decision{Verdict: VerdictAllow, Rule: "allow.exec:" + allowRule, Reason: "policy: command matched allow.exec"}
		}
		return Decision{
			Verdict: VerdictDeny,
			Rule:    "strict_exec",
			Reason:  "policy: strict_exec is on and command is not in the allowlist",
		}
	}
	if inAllow {
		return Decision{Verdict: VerdictAllow, Rule: "allow.exec:" + allowRule, Reason: "policy: command matched allow.exec"}
	}
	return Decision{Verdict: VerdictAllow, Rule: "default-allow", Reason: "policy: non-strict mode, command not otherwise gated"}
}

// classifyKubectl checks a kubectl invocation against allow.kubectl. An empty
// constraint set on a dimension means "unconstrained on that dimension"; a
// non-empty set is an allowlist the request must fall inside. A namespace not
// given on the command line is treated as the "default" namespace (kubectl's own
// default), so a policy that does not permit "default" blocks an unscoped call.
func classifyKubectl(r Resolved, argv []string) Decision {
	ns, verb := parseKubectl(argv[1:])

	if len(r.Allow.Kubectl.Verbs) > 0 {
		if verb == "" || !sliceContains(r.Allow.Kubectl.Verbs, verb) {
			return Decision{
				Verdict: VerdictDeny,
				Rule:    "allow.kubectl.verbs",
				Reason:  "policy: kubectl verb " + quote(verb) + " not in allowed verbs",
			}
		}
	}
	if len(r.Allow.Kubectl.Namespaces) > 0 {
		effNS := ns
		if effNS == "" {
			effNS = "default"
		}
		if !sliceContains(r.Allow.Kubectl.Namespaces, effNS) {
			return Decision{
				Verdict: VerdictDeny,
				Rule:    "allow.kubectl.namespaces",
				Reason:  "policy: kubectl namespace " + quote(effNS) + " not in allowed namespaces",
			}
		}
	}
	return Decision{Verdict: VerdictAllow, Rule: "allow.kubectl", Reason: "policy: kubectl within allowed namespace/verb"}
}

// classifyTerraform checks a terraform invocation's subcommand against
// allow.terraform.commands.
func classifyTerraform(r Resolved, argv []string) Decision {
	sub := firstNonFlag(argv[1:])
	if sub == "" || !sliceContains(r.Allow.Terraform.Commands, sub) {
		return Decision{
			Verdict: VerdictDeny,
			Rule:    "allow.terraform.commands",
			Reason:  "policy: terraform subcommand " + quote(sub) + " not in allowed commands",
		}
	}
	return Decision{Verdict: VerdictAllow, Rule: "allow.terraform", Reason: "policy: terraform subcommand allowed"}
}

// parseKubectl extracts (namespace, verb) from kubectl args (argv after the
// binary). It understands every kubectl namespace spelling: "-n x", "-n=x",
// "-nx", "--namespace x", "--namespace=x". The verb is the first bare token that
// is not a flag and not consumed as a flag's separate value.
func parseKubectl(args []string) (namespace, verb string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-n" || a == "--namespace":
			if i+1 < len(args) {
				namespace = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--namespace="):
			namespace = strings.TrimPrefix(a, "--namespace=")
		case strings.HasPrefix(a, "-n=") && len(a) > 3:
			namespace = a[3:]
		case strings.HasPrefix(a, "-n") && len(a) > 2:
			// "-nx" shorthand-stuck form.
			namespace = a[2:]
		case strings.HasPrefix(a, "-"):
			// Some other flag; ignore. We do not consume a following value for
			// unknown flags — kubectl's boolean-vs-value flags are many, and the
			// verb is robustly the first *bare* token regardless, so a mis-guess
			// here cannot let a denied namespace/verb through.
		default:
			if verb == "" {
				verb = a
			}
		}
	}
	return namespace, verb
}

// firstNonFlag returns the first token that does not start with "-".
func firstNonFlag(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// toolName reduces argv[0] to its base command name so "/usr/bin/kubectl" and
// "kubectl" classify identically. It does NOT resolve symlinks or $PATH — an
// attacker who renames kubectl escapes structured awareness, which is exactly why
// strict_exec + allowlist (not tool-name heuristics) is the strong mode.
func toolName(arg0 string) string {
	return filepath.Base(arg0)
}

// matchAnyRegex reports whether any pattern matches s, returning the first
// matching pattern. A pattern that fails to compile is skipped (patterns are
// validated at policy load, so this only guards a defensively-constructed model);
// skipping a broken restriction never widens a grant.
func matchAnyRegex(patterns []string, s string) (string, bool) {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.MatchString(s) {
			return p, true
		}
	}
	return "", false
}

func sliceContains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func quote(s string) string {
	if s == "" {
		return `""`
	}
	return `"` + s + `"`
}
