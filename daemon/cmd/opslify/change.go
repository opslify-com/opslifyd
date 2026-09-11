package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// changeCmd is the F8.6 review surface: a Change is what humans actually review.
func changeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "change",
		Short: "Review changes (ls, show, approve, deny, revert)",
		Long: "A Change is the unit of work: what an agent proposes, what a human reviews, and\n" +
			"what the audit trail is organised around.\n\n" +
			"Approving runs EXACTLY the plan that was previewed — the plan is hash-pinned\n" +
			"and re-verified at apply, so an approval cannot be carried onto a different\n" +
			"plan.",
	}
	cmd.AddCommand(changeLsCmd(), changeShowCmd(), changeApproveCmd(), changeDenyCmd(), changeRevertCmd())
	return cmd
}

func changeLsCmd() *cobra.Command {
	var socket, status string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List changes, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			list, err := newClient(socket).listChanges(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(list) == 0 {
				fmt.Fprintln(out, "no changes")
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATUS\tSCOPE\tBLAST\tREVERT\tPROPOSER\tINTENT")
			for _, c := range list {
				if status != "" && c.Status != status {
					continue
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					c.ID, c.Status, orDash(c.EnvironmentID), c.BlastSummary,
					revertCell(c), proposerCell(c), truncate(c.Intent, 48))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&status, "status", "", "only show changes in this status")
	return cmd
}

func changeShowCmd() *cobra.Command {
	var socket string
	var plan bool
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show a change: intent, plan, blast radius, and whether it can be reverted",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(socket).getChange(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s  [%s]\n\n%s\n\n", c.ID, c.Status, c.Intent)
			fmt.Fprintf(out, "proposed by   %s\n", proposerCell(c))
			fmt.Fprintf(out, "scope         %s\n", orDash(c.EnvironmentID))
			fmt.Fprintf(out, "blast radius  %s\n", c.BlastSummary)

			// Stated BEFORE approval, not after a failed revert: an operator's
			// willingness to approve depends on it.
			if c.Revertible {
				fmt.Fprintf(out, "revert        yes (%s)\n", c.InverseKind)
			} else {
				fmt.Fprintf(out, "revert        NO — %s\n", c.RevertReason)
			}
			if c.PolicyRule != "" {
				fmt.Fprintf(out, "gated by      %s (%s)\n", c.PolicyRule, c.PolicyEffect)
			}
			fmt.Fprintf(out, "\nprovenance\n")
			for label, v := range map[string]string{
				"  policy hash      ": c.PolicyHash,
				"  instruction hash ": c.ContextHash,
				"  agent            ": c.AgentName,
				"  model            ": c.AgentModel,
				"  session          ": c.SessionID,
				"  plan pin         ": c.PlanHash,
			} {
				if v != "" {
					fmt.Fprintf(out, "%s %s\n", label, v)
				}
			}
			if len(c.ConnectionRefs) > 0 {
				// REFS, never values — said explicitly so nobody reads this line
				// expecting a credential.
				fmt.Fprintf(out, "  connections       %s (refs)\n", strings.Join(c.ConnectionRefs, ", "))
			}
			if plan || c.Status == "awaiting_approval" {
				fmt.Fprintf(out, "\nplan (pinned as %s)\n", short12(c.PlanHash))
				for _, s := range c.Steps {
					gate := "  "
					if s.Gated {
						gate = "→ "
					}
					fmt.Fprintf(out, "%s%d. %s\n", gate, s.Index, strings.Join(s.Argv, " "))
				}
				if c.Preview != "" {
					fmt.Fprintf(out, "\npreview\n%s\n", c.Preview)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().BoolVar(&plan, "plan", false, "always show the pinned plan and preview")
	return cmd
}

func changeApproveCmd() *cobra.Command {
	var socket, note string
	cmd := &cobra.Command{
		Use:   "approve <id>",
		Short: "Approve a change — runs exactly the pinned plan",
		Long: "Approve a change. The plan is re-verified against the pin taken at preview, so\n" +
			"if anything about what would run has changed the approval is refused rather\n" +
			"than carried onto a different plan.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(socket).decideChange(cmd.Context(), args[0], "approve", note)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "approved %s — applying the plan pinned as %s\n", c.ID, short12(c.PlanHash))
			if !c.Revertible {
				// Repeated at the moment of approval, because this is the last point
				// at which the operator can change their mind.
				fmt.Fprintf(cmd.ErrOrStderr(), "note: this change CANNOT be reverted — %s\n", c.RevertReason)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&note, "note", "", "why you approved it (recorded)")
	return cmd
}

func changeDenyCmd() *cobra.Command {
	var socket, note string
	cmd := &cobra.Command{
		Use:   "deny <id>",
		Short: "Deny a change — terminal, nothing runs afterwards",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(socket).decideChange(cmd.Context(), args[0], "deny", note)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "denied %s — nothing from this change will run\n", c.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&note, "note", "", "why you denied it (recorded)")
	return cmd
}

func changeRevertCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "revert <id>",
		Short: "Apply a change's prepared inverse",
		Long: "Apply the inverse prepared when the change was planned.\n\n" +
			"Where no inverse exists this refuses and says why, rather than attempting\n" +
			"something and failing halfway — a half-applied revert leaves an estate in a\n" +
			"state nobody planned.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(socket).decideChange(cmd.Context(), args[0], "revert", "")
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "reverted %s (%s)\n", c.ID, c.InverseKind)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

// revertCell renders revertibility in a listing. It says NO loudly, because the
// absence of an inverse is the thing that changes a reviewer's decision.
func revertCell(c changeView) string {
	if c.Revertible {
		return "yes"
	}
	return "NO"
}

func proposerCell(c changeView) string {
	if c.ProposerModel != "" {
		return c.ProposerName + " (" + c.ProposerModel + ")"
	}
	return c.ProposerName
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func short12(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
