package main

import (
	"errors"
	"fmt"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/spf13/cobra"
)

// policyCmd groups policy-authoring helpers. Its only subcommand today is
// `check`, the F4.1 linter.
func policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Author and validate opslify.policy.yaml",
	}
	cmd.AddCommand(policyCheckCmd())
	return cmd
}

// policyCheckCmd lints a policy file and prints either line-level errors (one
// `file:line: reason` per line, exit 1) or `ok` plus the deterministic
// policy_hash of the resolved-against-empty-daemon policy (exit 0). It is a pure
// client-side operation: it never contacts the daemon, so an author can validate
// a policy before it is ever mounted into a session.
func policyCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check [path]",
		Short: "Validate a policy file; print line-level errors or ok + policy_hash",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := policy.DefaultFileName
			if len(args) == 1 {
				path = args[0]
			}
			p, err := policy.Load(path)
			if err != nil {
				// A ValidationError is already file:line: reason on each line —
				// print it verbatim and exit non-zero (fail-closed signal).
				var verr *policy.ValidationError
				if errors.As(err, &verr) {
					fmt.Fprintln(cmd.ErrOrStderr(), verr.Error())
					return &exitCodeError{code: 1}
				}
				return err
			}
			// The hash reported is the policy resolved on its own (no daemon
			// narrowing) — the stable identity of THIS file's content. When it is
			// mounted into a session the daemon re-resolves it over its default,
			// which can only narrow further.
			hash := policy.ResolveDefault(p).Hash
			fmt.Fprintf(cmd.OutOrStdout(), "ok\npolicy_hash: %s\n", hash)
			return nil
		},
	}
	return cmd
}
