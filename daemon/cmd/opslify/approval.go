package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// approvalsCmd lists pending F4.3 human-approval gates. It is a PRIVILEGED
// operator action over the localhost socket (no auth in v1) — the sandboxed agent
// has no path to it, so it can never approve its own gated commands.
func approvalsCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "approvals",
		Short: "List pending approval gates awaiting a human decision",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			views, err := c.listApprovals(cmd.Context())
			if err != nil {
				return err
			}
			return renderApprovalTable(cmd.OutOrStdout(), views)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

// approveCmd resolves a pending gate as APPROVED — the paused command then runs.
func approveCmd() *cobra.Command {
	var (
		socket  string
		comment string
	)
	cmd := &cobra.Command{
		Use:   "approve <session> <exec_id>",
		Short: "Approve a pending gate; the paused command runs",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			v, err := c.resolveApproval(cmd.Context(), args[0], args[1], "approve", comment)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "approved %s/%s (status: %s)\n", v.SessionID, v.ExecID, v.Status)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&comment, "comment", "", "approver comment recorded in the trace")
	return cmd
}

// denyCmd resolves a pending gate as DENIED — the command never runs.
func denyCmd() *cobra.Command {
	var (
		socket  string
		comment string
	)
	cmd := &cobra.Command{
		Use:   "deny <session> <exec_id>",
		Short: "Deny a pending gate; the command is refused",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			v, err := c.resolveApproval(cmd.Context(), args[0], args[1], "deny", comment)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "denied %s/%s (status: %s)\n", v.SessionID, v.ExecID, v.Status)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&comment, "comment", "", "reason recorded in the trace")
	return cmd
}

func renderApprovalTable(w io.Writer, views []approvalView) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION ID\tEXEC ID\tRULE\tCOMMAND")
	for _, v := range views {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", v.SessionID, v.ExecID, v.Rule, v.ArgvSummary)
	}
	return tw.Flush()
}
