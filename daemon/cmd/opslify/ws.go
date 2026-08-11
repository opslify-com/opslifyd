package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// wsCmd is the F2.2 workspace-management surface: list and remove persistent
// workspaces (the named, resumable /workspace state built up across sessions).
func wsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ws",
		Short: "Manage persistent workspaces (ls, rm)",
	}
	cmd.AddCommand(wsLsCmd(), wsRmCmd())
	return cmd
}

func wsLsCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List persistent workspaces",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			ws, err := c.listWorkspaces(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSNAPSHOTS\tLATEST TAG\tLATEST TIME")
			for _, w := range ws {
				lt := w.LatestTime
				if lt == "" {
					lt = "-"
				}
				fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", w.Name, w.Snapshots, w.LatestTag, lt)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

func wsRmCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove a workspace (its snapshots + /workspace state). Refused if in use.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			if err := c.removeWorkspace(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed workspace %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}
