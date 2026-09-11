package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// memoryCmd is F8.10's operator surface.
//
// There is no `memory add`. Documents are files in the project's workspace —
// commit them, or copy them in — which is what makes them version and review like
// code. A subcommand that wrote them would be a second, unreviewed path into the
// thing the agent reads.
func memoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "memory",
		Short: "Search and manage a project's memory (runbooks, notes, postmortems)",
		Long: "A project's memory is a folder of your own markdown in its workspace —\n" +
			".opslify/memory/ by default, or .claude/memory/, docs/memory/ or memory/.\n\n" +
			"Memory is RETRIEVED, not injected: the agent searches it and cites what it\n" +
			"used. A rule the agent must always follow is a skill (.opslify/skills/); a\n" +
			"document it might need to consult is memory.",
	}
	cmd.AddCommand(memoryLsCmd(), memorySearchCmd(), memoryEnableCmd(false), memoryEnableCmd(true))
	return cmd
}

func memoryLsCmd() *cobra.Command {
	var socket, project string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List the documents in a project's memory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := newClient(socket).memoryList(cmd.Context(), project)
			if err != nil {
				return err
			}
			if len(res.Documents) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(),
					"no documents. Put markdown in the project's .opslify/memory/ and it is indexed on the next search.")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "DOCUMENT\tTITLE\tCHUNKS\tBYTES\tSTATE")
			for _, d := range res.Documents {
				state := "enabled"
				if !d.Enabled {
					state = "disabled"
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", d.Rel, orDash(d.Title), d.Chunks, d.Bytes, state)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "project whose memory to list")
	return cmd
}

func memorySearchCmd() *cobra.Command {
	var socket, project string
	var k int
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search a project's memory, as the agent does",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := newClient(socket).memorySearch(cmd.Context(), strings.Join(args, " "), project, k)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(res.Excerpts) == 0 {
				fmt.Fprintln(out, "no matches")
				return nil
			}
			for i, e := range res.Excerpts {
				if i > 0 {
					fmt.Fprintln(out)
				}
				// The citation first. It is what makes a retrieval checkable, and what
				// a Change records.
				loc := fmt.Sprintf("%s:%d-%d", e.Doc, e.StartLine, e.EndLine)
				if e.Heading != "" {
					loc += "  (" + e.Heading + ")"
				}
				fmt.Fprintln(out, loc)
				for _, line := range strings.Split(strings.TrimRight(e.Text, "\n"), "\n") {
					fmt.Fprintln(out, "  "+line)
				}
				if e.Truncated {
					fmt.Fprintln(out, "  [truncated at the excerpt cap — open the document for the rest]")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "project whose memory to search")
	cmd.Flags().IntVar(&k, "k", 0, "how many excerpts to return (default 5)")
	return cmd
}

func memoryEnableCmd(enable bool) *cobra.Command {
	var socket, project string
	verb, short := "disable", "Stop a document being returned by search"
	if enable {
		verb, short = "enable", "Return a document to search results"
	}
	cmd := &cobra.Command{
		Use:   verb + " <document>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient(socket).memoryEnable(cmd.Context(), project, args[0], enable); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %sd\n", args[0], verb)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "project the document belongs to")
	return cmd
}
