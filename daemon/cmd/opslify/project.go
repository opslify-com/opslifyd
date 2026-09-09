package main

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// projectCmd is the F8.1 project surface: create, ls, show. A project gathers
// what one body of work needs — the repo it lives in and the capability map
// (role → tool) later features route skills and tool contracts off — and owns the
// environments it is delivered through.
func projectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Manage projects (create, ls, show)",
	}
	cmd.AddCommand(projectCreateCmd(), projectLsCmd(), projectShowCmd())
	return cmd
}

func projectCreateCmd() *cobra.Command {
	var (
		socket     string
		repo       string
		policyFile string
		envs       []string
		caps       []string
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a project (with at least one environment)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			capMap, err := parseCapabilities(caps)
			if err != nil {
				return err
			}
			req := createProjectReq{
				Name:         args[0],
				RepoURL:      repo,
				Capabilities: capMap,
				PolicyFile:   policyFile,
			}
			for _, e := range envs {
				req.Environments = append(req.Environments, addEnvReq{Name: e})
			}
			c := newClient(socket)
			p, err := c.createProject(cmd.Context(), req)
			if err != nil {
				return err
			}
			names := make([]string, 0, len(p.Environments))
			for _, e := range p.Environments {
				names = append(names, e.Name)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "created project %s (environments: %s)\n", p.ID, strings.Join(names, ", "))
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&repo, "repo", "", "source repository URL (descriptive metadata)")
	cmd.Flags().StringVar(&policyFile, "policy", "", "absolute path to the project's policy layer (may only NARROW the daemon policy)")
	cmd.Flags().StringSliceVar(&envs, "env", nil, "environment to create (repeatable; default: one named 'default')")
	cmd.Flags().StringSliceVar(&caps, "capability", nil, "capability as role=tool (repeatable), e.g. git=gitlab, iac=terraform")
	return cmd
}

func projectLsCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List projects",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			ps, err := c.listProjects(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PROJECT\tENVIRONMENTS\tREPO\tCAPABILITIES")
			for _, p := range ps {
				names := make([]string, 0, len(p.Environments))
				for _, e := range p.Environments {
					n := e.Name
					if e.Production {
						n += "*"
					}
					names = append(names, n)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
					p.ID, orDash(strings.Join(names, ",")), orDash(p.RepoURL), orDash(formatCapabilities(p.Capabilities)))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "\n* = production environment")
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

func projectShowCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show a project and its environments",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			p, err := c.getProject(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "project:      %s\n", p.ID)
			fmt.Fprintf(out, "created:      %s\n", orDash(p.Created))
			fmt.Fprintf(out, "repo:         %s\n", orDash(p.RepoURL))
			fmt.Fprintf(out, "policy:       %s\n", orDash(p.PolicyFile))
			fmt.Fprintf(out, "capabilities: %s\n", orDash(formatCapabilities(p.Capabilities)))
			fmt.Fprintln(out, "\nenvironments:")
			return renderEnvironments(out, p.Environments)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

// envCmd is the F8.1 environment surface: add, ls. An environment is a SEPARATE
// layer inside a project, not a heading in one file — prod narrows staging, and
// the daemon (not convention) enforces that its policy overlay can only tighten.
func envCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Manage a project's environments (add, ls)",
	}
	cmd.AddCommand(envAddCmd(), envLsCmd())
	return cmd
}

func envAddCmd() *cobra.Command {
	var (
		socket     string
		overlay    string
		tier       string
		ttl        string
		production bool
	)
	cmd := &cobra.Command{
		Use:   "add <project> <name>",
		Short: "Add an environment to a project",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			e, err := c.addEnvironment(cmd.Context(), args[0], addEnvReq{
				Name:          args[1],
				PolicyOverlay: overlay,
				DefaultTier:   tier,
				DefaultTTL:    ttl,
				Production:    production,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added environment %s (production=%v)\n", e.ID, e.Production)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&overlay, "policy-overlay", "", "absolute path to this environment's policy overlay (may only NARROW the project's policy)")
	cmd.Flags().StringVar(&tier, "tier", "", "default isolation tier for sessions in this environment")
	cmd.Flags().StringVar(&ttl, "ttl", "", "default session idle lifetime in this environment (Go duration, e.g. 15m)")
	cmd.Flags().BoolVar(&production, "production", false, "mark this environment as production")
	return cmd
}

func envLsCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "ls <project>",
		Short: "List a project's environments",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			envs, err := c.listEnvironments(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return renderEnvironments(cmd.OutOrStdout(), envs)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

// renderEnvironments prints the environment table shared by `env ls` and
// `project show`.
func renderEnvironments(w interface{ Write([]byte) (int, error) }, envs []environmentView) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ENVIRONMENT\tID\tPRODUCTION\tTIER\tTTL\tPOLICY OVERLAY")
	for _, e := range envs {
		fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\t%s\n",
			e.Name, e.ID, e.Production, orDash(e.DefaultTier), orDash(e.DefaultTTL), orDash(e.PolicyOverlay))
	}
	return tw.Flush()
}

// parseCapabilities turns repeated --capability role=tool flags into the map the
// daemon validates. A malformed pair is rejected here so the operator sees the
// problem before a round trip.
func parseCapabilities(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		role, tool, ok := strings.Cut(p, "=")
		if !ok || role == "" || tool == "" {
			return nil, fmt.Errorf("invalid --capability %q: want role=tool (e.g. git=gitlab)", p)
		}
		if prev, dup := out[role]; dup {
			return nil, fmt.Errorf("invalid --capability %q: role %q is already mapped to %q", p, role, prev)
		}
		out[role] = tool
	}
	return out, nil
}

// formatCapabilities renders a capability map deterministically (role-sorted) so
// the table output is stable.
func formatCapabilities(caps map[string]string) string {
	if len(caps) == 0 {
		return ""
	}
	roles := make([]string, 0, len(caps))
	for r := range caps {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	parts := make([]string, 0, len(roles))
	for _, r := range roles {
		parts = append(parts, r+"="+caps[r])
	}
	return strings.Join(parts, ",")
}
