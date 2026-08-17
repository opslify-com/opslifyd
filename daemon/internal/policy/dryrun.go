package policy

import (
	"regexp"
	"sort"
	"strings"
)

// F4.4 — Dry-run interception.
//
// This file is the PURE, table-testable rewrite mapping: given a gated
// destructive command it produces (a) the PREVIEW command to run in-sandbox so a
// human can review the diff, and (b) the command to run ON APPROVE. It performs
// NO I/O and NO shell-out — it can never itself be an injection vector, and every
// rewrite is reproducible from data alone (mirrors the F4.2 Classify discipline).
//
// The executed preview + approved commands are chosen so that WHAT IS APPROVED IS
// WHAT RUNS:
//   - terraform apply → `terraform plan -out=<planPath>` first; on approve
//     `terraform apply <planPath>` (the SAVED plan). Because the approved run
//     replays the exact saved plan rather than re-planning, the executed change
//     cannot drift from the reviewed diff (no TOCTOU gap). This is the strong
//     guarantee and the core security property of the feature.
//   - kubectl apply|delete → the same command with `--dry-run=server` first; on
//     approve the ORIGINAL command runs. kubectl has no saved-plan equivalent, so
//     the approved run is a FRESH apply against live state — an honest, weaker
//     guarantee (documented in Guarantee).
//
// Policy-defined rules (daemon-authoritative; see resolve.go — a WORKSPACE
// dry_run section is ignored) map a regex → a preview command PREFIX. The rewrite
// clamps a policy rule to the SAME TOOL as the matched command (preview[0] must be
// the same base binary as argv[0]); a rule that names a different binary is
// treated as no-match, so a preview can never substitute an arbitrary binary or
// escape the sandbox even if the daemon policy is mis-authored.

// DryRunGuarantee describes how tightly the approved run is bound to the reviewed
// preview.
type DryRunGuarantee string

const (
	// GuaranteeSavedPlan means the approved run replays a saved artifact (terraform
	// plan file), so the executed change equals the reviewed diff — no drift.
	GuaranteeSavedPlan DryRunGuarantee = "saved-plan"
	// GuaranteeFreshApply means the approved run re-executes against live state
	// (kubectl, custom rules); the preview is indicative, not a frozen artifact.
	GuaranteeFreshApply DryRunGuarantee = "fresh-apply"
)

// DryRunPreview is the pure result of RewriteForDryRun.
type DryRunPreview struct {
	// Matched is true when a built-in or policy rule produced a preview.
	Matched bool
	// Rule identifies the rewrite that fired ("builtin:terraform-apply",
	// "builtin:kubectl-delete", "dry_run:<pattern>") — the audit hook.
	Rule string
	// PreviewArgv is the command to run IN-SANDBOX to capture the diff. It never
	// runs on the host and never has more privilege than the real command (it runs
	// through the same session/container/policy as the original).
	PreviewArgv []string
	// ApprovedArgv is the command to run when a human approves. For terraform it is
	// `apply <planPath>` (the saved plan); for kubectl/custom rules it is the
	// original argv.
	ApprovedArgv []string
	// Guarantee names the strength of the preview→apply binding.
	Guarantee DryRunGuarantee
}

// RewriteForDryRun maps a gated command to its preview + approved forms. It is
// PURE: identical inputs always yield the identical DryRunPreview. planPath is the
// in-sandbox path terraform writes its saved plan to (ignored for other tools);
// the caller picks a per-exec path under /workspace so it survives to the approved
// apply in the same session/container.
//
// Evaluation order (first match wins): policy dry_run rules (sorted, same-tool
// clamped) → built-in terraform → built-in kubectl. When nothing matches, Matched
// is false and the caller registers the approval gate with no preview.
func RewriteForDryRun(argv []string, rules []DryRunRule, planPath string) DryRunPreview {
	if len(argv) == 0 {
		return DryRunPreview{}
	}
	joined := strings.Join(argv, " ")
	tool := toolName(argv[0])

	// 1) Policy-defined rules (daemon-authoritative). First match by sorted pattern.
	for _, rule := range sortedDryRun(rules) {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil || len(rule.Preview) == 0 {
			continue // validated at load; skip defensively (never widens)
		}
		if !re.MatchString(joined) {
			continue
		}
		// SAME-TOOL CLAMP: a preview may only re-invoke the same base binary as the
		// original command — it can never substitute an arbitrary binary. A rule that
		// names a different tool is treated as no-match (defence in depth even for a
		// mis-authored daemon rule; a workspace rule never reaches here at all).
		if toolName(rule.Preview[0]) != tool {
			continue
		}
		preview := append(append([]string(nil), rule.Preview...), argv[1:]...)
		return DryRunPreview{
			Matched:      true,
			Rule:         "dry_run:" + rule.Pattern,
			PreviewArgv:  preview,
			ApprovedArgv: append([]string(nil), argv...),
			Guarantee:    GuaranteeFreshApply,
		}
	}

	// 2) Built-in terraform apply → saved-plan preview.
	if tool == "terraform" {
		if sub := firstNonFlag(argv[1:]); sub == "apply" {
			// Carry over only FLAG arguments (tokens starting with "-", e.g.
			// -var-file=prod.tfvars) into the plan; bare positionals (a pre-supplied
			// plan file) are dropped so the preview is a clean `plan -out`.
			flags := flagsOf(argv[2:])
			preview := append([]string{"terraform", "plan", "-out=" + planPath}, flags...)
			return DryRunPreview{
				Matched:      true,
				Rule:         "builtin:terraform-apply",
				PreviewArgv:  preview,
				ApprovedArgv: []string{"terraform", "apply", planPath},
				Guarantee:    GuaranteeSavedPlan,
			}
		}
	}

	// 3) Built-in kubectl apply|delete → server-side dry-run preview.
	if tool == "kubectl" {
		if sub := firstNonFlag(argv[1:]); sub == "apply" || sub == "delete" {
			preview := append([]string(nil), argv...)
			if !hasDryRunFlag(argv) {
				preview = append(preview, "--dry-run=server")
			}
			return DryRunPreview{
				Matched:      true,
				Rule:         "builtin:kubectl-" + sub,
				PreviewArgv:  preview,
				ApprovedArgv: append([]string(nil), argv...),
				Guarantee:    GuaranteeFreshApply,
			}
		}
	}

	return DryRunPreview{}
}

// flagsOf returns the tokens that are flags (start with "-"); bare positionals are
// dropped. Used to carry terraform plan-relevant flags into the preview.
func flagsOf(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// hasDryRunFlag reports whether a kubectl invocation already carries a --dry-run
// flag (so the preview does not append a duplicate).
func hasDryRunFlag(argv []string) bool {
	for _, a := range argv {
		if a == "--dry-run" || strings.HasPrefix(a, "--dry-run=") {
			return true
		}
	}
	return false
}

// sortedDryRun returns the rules ordered by pattern (then by preview) so
// first-match evaluation is deterministic regardless of file order — matching the
// canonical order normalize() imposes for hashing.
func sortedDryRun(rules []DryRunRule) []DryRunRule {
	if len(rules) == 0 {
		return nil
	}
	out := append([]DryRunRule(nil), rules...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		return strings.Join(out[i].Preview, " ") < strings.Join(out[j].Preview, " ")
	})
	return out
}
