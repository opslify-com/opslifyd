package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// agentCmd is the F8.5 surface: bind any MCP-speaking command as the agent for a
// project and environment.
func agentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage agents (add, ls, use, test, rm)",
		Long: "opslify ships no model. Bind any MCP-speaking command — Claude Code, a local\n" +
			"Qwen via Ollama, Codex, a script of your own — per project and environment.\n\n" +
			"Which agent is bound changes cost, latency, and WHERE PROMPTS GO. It does not\n" +
			"change what the agent may do: the sandbox boundary, the connections and the\n" +
			"policy gates are identical whichever agent is bound. Capability lives in\n" +
			"policy, not here.",
	}
	cmd.AddCommand(agentAddCmd(), agentLsCmd(), agentUseCmd(), agentTestCmd(), agentRmCmd())
	return cmd
}

type agentFlags struct {
	socket      string
	command     string
	args        []string
	modelHint   string
	locality    string
	envAllow    []string
	description string
}

func (f *agentFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&f.command, "command", "", "absolute path to the MCP-speaking command")
	cmd.Flags().StringSliceVar(&f.args, "arg", nil, "argument passed on every invocation (repeatable)")
	cmd.Flags().StringVar(&f.modelHint, "model", "", "which model this command drives (recorded, never enforced)")
	cmd.Flags().StringVar(&f.locality, "locality", "unknown",
		"local (prompts stay on this host) or hosted (output is sent to a provider)")
	cmd.Flags().StringSliceVar(&f.envAllow, "env-allow", nil,
		"environment variable this command may inherit (repeatable). Everything else is withheld")
	cmd.Flags().StringVar(&f.description, "description", "", "free-text note")
}

func (f *agentFlags) request(name string) addAgentReq {
	return addAgentReq{
		Name: name, Command: f.command, Args: f.args, ModelHint: f.modelHint,
		Locality: f.locality, EnvAllow: f.envAllow, Description: f.description,
	}
}

func agentAddCmd() *cobra.Command {
	var f agentFlags
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Register an agent (proved by a real MCP handshake before it is stored)",
		Long: "Register an agent. The command is PROVED to work — opslify completes a real MCP\n" +
			"handshake and lists the tools it exposes — before anything is stored, so a\n" +
			"typo'd path or a non-MCP binary is reported now rather than at your first task.\n\n" +
			"Examples:\n" +
			"  opslify agent add claude --command /usr/local/bin/claude --arg mcp \\\n" +
			"      --model claude-opus-5 --locality hosted\n\n" +
			"  opslify agent add qwen --command /usr/bin/ollama --arg mcp \\\n" +
			"      --model qwen2.5-coder:32b --locality local --env-allow OLLAMA_HOST",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			view, err := newClient(f.socket).addAgent(cmd.Context(), f.request(args[0]))
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "registered agent %s\n", view.Name)
			fmt.Fprintf(out, "  handshake   ok — %d tool(s): %s\n", len(view.Tools), strings.Join(view.Tools, ", "))
			fmt.Fprintf(out, "  disclosure  %s\n", view.Disclosure)
			if view.Locality == "unknown" {
				// Said loudly: an undeclared locality is a disclosure gap, and the
				// operator is the only one who can close it.
				fmt.Fprintln(cmd.ErrOrStderr(),
					"warning: locality is undeclared. Pass --locality local or hosted so the audit trail records whether command output leaves this host.")
			}
			return nil
		},
	}
	f.bind(cmd)
	return cmd
}

func agentTestCmd() *cobra.Command {
	var f agentFlags
	cmd := &cobra.Command{
		Use:   "test <name>",
		Short: "Probe a command without registering it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			view, err := newClient(f.socket).testAgent(cmd.Context(), f.request(args[0]))
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s speaks MCP\n", view.Name)
			fmt.Fprintf(out, "  tools       %s\n", strings.Join(view.Tools, ", "))
			fmt.Fprintf(out, "  disclosure  %s\n", view.Disclosure)
			fmt.Fprintln(out, "\nNothing was registered. Re-run with `agent add` to keep it.")
			return nil
		},
	}
	f.bind(cmd)
	return cmd
}

func agentLsCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List registered agents and where each scope is bound",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := newClient(socket).listAgents(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(res.Agents) == 0 {
				fmt.Fprintln(out, "no agents registered")
				fmt.Fprintln(out, "opslify ships no model — register one with `opslify agent add`.")
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tMODEL\tLOCALITY\tPROMPTS")
			for _, a := range res.Agents {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Name, orDash(a.ModelHint), a.Locality, a.Disclosure)
			}
			tw.Flush()

			if len(res.Bindings) == 0 {
				fmt.Fprintln(out, "\nno scope is bound — sessions record no agent identity")
				return nil
			}
			fmt.Fprintln(out, "\nBINDINGS")
			btw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(btw, "SCOPE\tAGENT")
			for _, b := range res.Bindings {
				fmt.Fprintf(btw, "%s\t%s\n", b.Scope, b.Agent)
			}
			return btw.Flush()
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

func agentUseCmd() *cobra.Command {
	var socket, project, env string
	cmd := &cobra.Command{
		Use:   "use <name>",
		Short: "Bind an agent to a scope (does not touch sessions already running)",
		Long: "Bind an agent to a project, an environment, or as the fallback.\n\n" +
			"Sessions already running are NOT re-pointed. Each recorded which agent it ran\n" +
			"under at seq 0, and changing that mid-flight would make the record a lie.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient(socket).useAgent(cmd.Context(), project, env, args[0]); err != nil {
				return err
			}
			scope := "the fallback"
			if env != "" {
				scope = "environment " + env
			} else if project != "" {
				scope = "project " + project
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is now the agent for %s\n", args[0], scope)
			fmt.Fprintln(cmd.ErrOrStderr(), "sessions already running keep the agent they started under")
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "bind for a project")
	cmd.Flags().StringVar(&env, "env", "", "bind for an environment")
	return cmd
}

func agentRmCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove an agent (refused while a scope still binds it)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient(socket).removeAgent(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed agent %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}
