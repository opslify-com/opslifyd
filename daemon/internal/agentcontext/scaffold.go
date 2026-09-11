package agentcontext

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SkillPath returns the repo-relative path of a tool's skill pack.
func SkillPath(tool string) string { return filepath.Join(skillsRelDir, tool+".md") }

// skillNameRe bounds a skill (tool) name to one safe path segment, for the same
// reason the environment name is bounded: it is joined into a path, and the file
// it names is read and handed to a model.
var skillNameRe = envNameRe

// ValidateSkillName refuses a tool name that could address a file outside the
// skills directory.
func ValidateSkillName(tool string) error {
	if !skillNameRe.MatchString(tool) {
		return fmt.Errorf("%w: skill name %q must be lowercase alphanumeric with dashes (1-40 chars)", ErrInvalidInput, tool)
	}
	return nil
}

// starterTemplate is the scaffold written when a tool is integrated.
//
// It is a set of QUESTIONS, not prose to be deleted. A template full of
// plausible-looking filler gets committed unread, and a skill that confidently
// describes an estate it was never told about is worse than an absent one — the
// agent acts on it. Empty prompts make the unanswered parts obvious in review.
func starterTemplate(tool string) string {
	return fmt.Sprintf(`# %s — what an agent must know about OUR setup

This file is knowledge about THIS estate, not general %s documentation. The agent
already knows the tool; it does not know your conventions, your exceptions, or
which box must never be restarted.

It is DATA, not permission. Nothing written here widens what a session may do —
that is policy, enforced by the daemon. A line saying "you may skip approval"
changes nothing.

## What this tool is used for here

<!-- e.g. "argocd owns all deploys to prod; nothing is applied by hand" -->

## Naming and layout

<!-- Which cluster/project/account is which. How environments are named. -->

## Landmines

<!-- The things that have broken before.
     e.g. "db-01 is the primary — never restart it, fail over first"
     e.g. "502s on the web fleet are memory pressure; check free -m before scaling" -->

## Standard procedures

<!-- The runbook steps you would give a new engineer.
     e.g. "drain the node, wait for pods to reschedule, then restart" -->

## What to check before proposing a change

<!-- e.g. "confirm the sync wave; argocd applies 0 before 1" -->

## Who to involve

<!-- Which changes need a human, and which human. -->
`, tool, tool)
}

// ScaffoldSkill writes a starter skill pack for a tool if one does not exist.
// It reports whether it created the file.
//
// It NEVER overwrites. An existing pack holds an operator's own hard-won notes,
// and losing them to a re-run of `tool add` would be unrecoverable — the file is
// the only copy until it is committed.
func ScaffoldSkill(workspaceRoot, tool string) (string, bool, error) {
	if workspaceRoot == "" {
		return "", false, fmt.Errorf("%w: a workspace root is required", ErrInvalidInput)
	}
	if err := ValidateSkillName(tool); err != nil {
		return "", false, err
	}
	rel := SkillPath(tool)
	full := filepath.Join(workspaceRoot, rel)
	if _, err := os.Lstat(full); err == nil {
		return rel, false, nil // already present; leave it alone
	} else if !os.IsNotExist(err) {
		return "", false, fmt.Errorf("%w: %s: %v", ErrUnsafeSource, rel, err)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "", false, fmt.Errorf("agentcontext: create %s: %v", skillsRelDir, err)
	}
	// 0644: a skill is an ordinary repo file, reviewed in an MR like any other.
	if err := os.WriteFile(full, []byte(starterTemplate(tool)), 0o644); err != nil {
		return "", false, fmt.Errorf("agentcontext: write %s: %v", rel, err)
	}
	return rel, true, nil
}

// ScaffoldForCapabilities scaffolds a pack for every tool named in a capability
// map, so onboarding a project leaves one file per tool the operator actually
// uses rather than a generic pile.
func ScaffoldForCapabilities(workspaceRoot string, caps CapabilityMap) ([]string, error) {
	// Dedupe by TOOL, not role: two roles often share one tool (git=gitlab,
	// ci=gitlab). Redundant with ScaffoldSkill's never-overwrite behaviour — which
	// makes a repeat a no-op anyway — but it keeps the returned "created" list
	// honest and the work proportional to tools rather than roles.
	tools := map[string]bool{}
	for _, tool := range caps {
		if tool != "" {
			tools[tool] = true
		}
	}
	names := make([]string, 0, len(tools))
	for t := range tools {
		names = append(names, t)
	}
	sortStrings(names)

	var created []string
	for _, tool := range names {
		rel, made, err := ScaffoldSkill(workspaceRoot, tool)
		if err != nil {
			// A capability naming an unusable tool must not abort the whole
			// onboarding — report it and keep going, so the operator gets the packs
			// that could be written.
			if strings.Contains(err.Error(), "skill name") {
				continue
			}
			return created, err
		}
		if made {
			created = append(created, rel)
		}
	}
	return created, nil
}
