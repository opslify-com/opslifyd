package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// policyShowCmd renders the RESOLVED policy for a scope, with the precedence that
// produced it.
//
// Resolved rather than per-layer, because the question an operator actually has
// is "what is in force here?" — and the layers only answer that after they have
// been composed.
func policyShowCmd() *cobra.Command {
	var socket, project, env string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the resolved policy in force for a scope, and how it was composed",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := newClient(socket).resolvedPolicy(cmd.Context(), project, env)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "scope        %s\n", orDash(v.Scope))
			fmt.Fprintf(out, "policy hash  %s\n\n", v.Hash)

			fmt.Fprintln(out, "PRECEDENCE (each layer may only narrow the one above)")
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "  LAYER\tEDITABLE\tNOTE")
			for _, l := range v.Layers {
				editable := "no"
				if l.Editable {
					editable = "yes"
				}
				fmt.Fprintf(tw, "  %s\t%s\t%s\n", l.Layer, editable, l.Note)
			}
			tw.Flush()

			fmt.Fprintf(out, "\nEGRESS       %s\n", orNone(strings.Join(v.EgressDomains, ", ")))
			fmt.Fprintf(out, "GATES        %s\n", orNone(strings.Join(v.ApprovalRequired, ", ")))
			fmt.Fprintf(out, "SESSION TTL  %s\n", orNone(v.SessionTTL))
			fmt.Fprintf(out, "STRICT EXEC  %v\n", v.StrictExec)
			if len(v.Clamps) > 0 {
				// Clamps are shown because a silently-clamped policy looks like a
				// policy that was simply ignored.
				fmt.Fprintln(out, "\nCLAMPED (a lower layer tried to widen and was narrowed back)")
				for _, c := range v.Clamps {
					fmt.Fprintf(out, "  %s\n", c)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "project scope")
	cmd.Flags().StringVar(&env, "env", "", "environment scope")
	return cmd
}

// policyDiffCmd reports the real difference between two resolved scopes.
func policyDiffCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "diff <scope-a> <scope-b>",
		Short: "Report the real difference between two environments' resolved policies",
		Long: "Compare what is actually in force in two scopes — after composition and\n" +
			"clamping, not the documents on disk.\n\n" +
			"  opslify policy diff tripon.staging tripon.prod",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := newClient(socket).policyDiff(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if d.Direction == "equivalent" {
				fmt.Fprintf(out, "%s and %s resolve to the same policy (%s)\n", args[0], args[1], d.HashA)
				return nil
			}
			fmt.Fprintf(out, "%s -> %s is a %s edit\n\n", args[0], args[1], d.Direction)
			// Widenings first: they are what a reader needs to see.
			for _, w := range d.Widenings {
				fmt.Fprintf(out, "  + %s\n", w)
			}
			for _, n := range d.Narrowings {
				fmt.Fprintf(out, "  - %s\n", n)
			}
			fmt.Fprintf(out, "\n%s  %s\n%s  %s\n", args[0], d.HashA, args[1], d.HashB)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

// policyAllowEgressCmd adds an egress host — always a widening, so always a
// Change.
func policyAllowEgressCmd() *cobra.Command {
	var socket, project, env, reason string
	cmd := &cobra.Command{
		Use:   "allow-egress <host>",
		Short: "Allow an egress host (a widening: needs approval)",
		Long: "Add a host to a scope's egress allowlist.\n\n" +
			"This always WIDENS the guardrails, so it creates a change for approval and\n" +
			"does not take effect until someone approves it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyEdit(cmd, socket, policyEditReq{
				ProjectID: project, EnvironmentID: env, Reason: reason,
				AddEgress: []string{args[0]},
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "project scope")
	cmd.Flags().StringVar(&env, "env", "", "environment scope")
	cmd.Flags().StringVar(&reason, "reason", "", "why this host is needed (shown to the approver)")
	return cmd
}

// policyDenyEgressCmd removes an egress host — a narrowing, applied immediately.
func policyDenyEgressCmd() *cobra.Command {
	var socket, project, env string
	cmd := &cobra.Command{
		Use:   "deny-egress <host>",
		Short: "Remove an egress host (a narrowing: applies immediately)",
		Long: "Remove a host from a scope's egress allowlist.\n\n" +
			"This TIGHTENS the guardrails, so it applies immediately and is still recorded.\n" +
			"Tightening during an incident never waits for an approver.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyEdit(cmd, socket, policyEditReq{
				ProjectID: project, EnvironmentID: env,
				RemoveEgress: []string{args[0]},
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "project scope")
	cmd.Flags().StringVar(&env, "env", "", "environment scope")
	return cmd
}

// policyGateCmd adds or removes an approval gate.
func policyGateCmd() *cobra.Command {
	var socket, project, env, reason string
	var remove bool
	cmd := &cobra.Command{
		Use:   "gate <pattern>",
		Short: "Add an approval gate (narrowing), or remove one with --remove (widening)",
		Long: "Gate commands matching a regex behind human approval.\n\n" +
			"ADDING a gate tightens the guardrails and applies immediately.\n" +
			"REMOVING one takes a human out of the loop, which is the widening that matters\n" +
			"most — it needs approval.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := policyEditReq{ProjectID: project, EnvironmentID: env, Reason: reason}
			if remove {
				req.RemoveGates = []string{args[0]}
			} else {
				req.AddGates = []string{args[0]}
			}
			return runPolicyEdit(cmd, socket, req)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "project scope")
	cmd.Flags().StringVar(&env, "env", "", "environment scope")
	cmd.Flags().StringVar(&reason, "reason", "", "why (shown to the approver when removing)")
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the gate instead of adding it (needs approval)")
	return cmd
}

// runPolicyEdit submits an edit and reports what happened to it.
func runPolicyEdit(cmd *cobra.Command, socket string, req policyEditReq) error {
	out, err := newClient(socket).editPolicy(cmd.Context(), req)
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	if out.Applied {
		fmt.Fprintf(w, "applied now (%s)\n", out.Direction)
		for _, n := range out.Narrowings {
			fmt.Fprintf(w, "  - %s\n", n)
		}
		fmt.Fprintf(w, "\npolicy hash is now %s; it takes effect for the NEXT session.\n", out.Hash)
		fmt.Fprintln(cmd.ErrOrStderr(), "sessions already running keep the policy they started with")
		return nil
	}
	fmt.Fprintf(w, "NOT applied — this widens the guardrails and needs approval\n\n")
	for _, wd := range out.Widenings {
		fmt.Fprintf(w, "  + %s\n", wd)
	}
	fmt.Fprintf(w, "\nreview it with:  opslify change show %s\n", out.ChangeID)
	fmt.Fprintf(w, "approve it with: opslify change approve %s\n", out.ChangeID)
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
