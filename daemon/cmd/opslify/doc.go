package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// docCmd is the CLI half of the cockpit's document editor.
//
// It exists because every Tower action must have one — a capability only the UI
// can reach is a capability nobody can script — and because these are the files
// an operator authors, so being able to pipe one in matters:
//
//	opslify doc write --kind skill kubernetes.md < kubernetes.md
func docCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doc",
		Short: "Read and write a project's markdown (skills, memory, instructions)",
		Long: "The documents a project is made of, in its workspace under .opslify/:\n\n" +
			"  skill        a rule the agent must ALWAYS follow. Injected into every\n" +
			"               session, so keep them short.\n" +
			"  memory       a document it MIGHT need to consult. Retrieved on demand\n" +
			"               and cited, so a corpus costs nothing until something matches.\n" +
			"  instructions the single project-wide instructions file.\n\n" +
			"The rule of thumb: a rule the agent must always follow is a skill; a\n" +
			"document it might need to look up is memory.",
	}
	cmd.AddCommand(docLsCmd(), docCatCmd(), docWriteCmd(), docRmCmd())
	return cmd
}

func docFlags(cmd *cobra.Command, socket, project, kind *string) {
	cmd.Flags().StringVar(socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(project, "project", "", "project the document belongs to")
	cmd.Flags().StringVar(kind, "kind", "memory", "skill | memory | instructions")
}

func docLsCmd() *cobra.Command {
	var socket, project, kind string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List a project's documents of one kind",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := newClient(socket).docList(cmd.Context(), project, kind)
			if err != nil {
				return err
			}
			if len(res.Docs) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "no %s documents\n", kind)
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "DOCUMENT\tBYTES\tMODIFIED")
			for _, d := range res.Docs {
				fmt.Fprintf(tw, "%s\t%d\t%s\n", d.Path, d.Bytes, d.Modified)
			}
			return tw.Flush()
		},
	}
	docFlags(cmd, &socket, &project, &kind)
	return cmd
}

func docCatCmd() *cobra.Command {
	var socket, project, kind string
	cmd := &cobra.Command{
		Use:   "cat <path>",
		Short: "Print one document",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := newClient(socket).docRead(cmd.Context(), project, kind, args[0])
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), d.Content)
			return nil
		},
	}
	docFlags(cmd, &socket, &project, &kind)
	return cmd
}

func docWriteCmd() *cobra.Command {
	var socket, project, kind, from string
	cmd := &cobra.Command{
		Use:   "write <path>",
		Short: "Create or replace a document (content on stdin, or --from)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var content []byte
			var err error
			if from != "" {
				content, err = os.ReadFile(from)
			} else {
				content, err = io.ReadAll(cmd.InOrStdin())
			}
			if err != nil {
				return err
			}
			if len(strings.TrimSpace(string(content))) == 0 {
				// An empty document is almost always a forgotten redirect, and writing
				// one would silently blank a skill the agent relies on.
				return fmt.Errorf("refusing to write an empty document; pass --from <file> or pipe content in")
			}
			d, err := newClient(socket).docWrite(cmd.Context(), project, kind, args[0], string(content))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%d bytes)\n", d.Path, d.Bytes)
			return nil
		},
	}
	docFlags(cmd, &socket, &project, &kind)
	cmd.Flags().StringVar(&from, "from", "", "read the content from this file instead of stdin")
	return cmd
}

func docRmCmd() *cobra.Command {
	var socket, project, kind string
	cmd := &cobra.Command{
		Use:   "rm <path>",
		Short: "Delete a document",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient(socket).docDelete(cmd.Context(), project, kind, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", args[0])
			return nil
		},
	}
	docFlags(cmd, &socket, &project, &kind)
	return cmd
}
