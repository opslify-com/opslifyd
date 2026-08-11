package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// exitCodeError carries a non-zero command exit code up to main so the CLI can
// mirror the sandboxed command's exit status without printing a spurious error.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("command exited with code %d", e.code) }

// runCmd: create → exec → stream → propagate exit → destroy (unless --keep).
func runCmd() *cobra.Command {
	var (
		socket string
		tier   string
		mode   string
		name   string
		cwd    string
		keep   bool
	)
	cmd := &cobra.Command{
		Use:   `run "<cmd>" [args...]`,
		Short: "Create a session, run a command in the sandbox, and stream its output",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c := newClient(socket)

			created, err := c.createSession(ctx, createReq{Mode: mode, Name: name, Tier: tier})
			if err != nil {
				return err
			}
			id := created.SessionID

			res, execErr := c.execStream(ctx, id, execReq{Argv: args, Cwd: cwd},
				cmd.OutOrStdout(), cmd.ErrOrStderr())

			// Tear down unless the caller asked to keep the session. Do this even on
			// exec error so a failed run doesn't leak a sandbox.
			if !keep {
				if derr := c.destroySession(ctx, id); derr != nil && execErr == nil {
					return derr
				}
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "[opslify: session %s kept]\n", id)
			}

			if execErr != nil {
				return execErr
			}
			return exitFromResult(res)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&tier, "tier", "", "isolation tier (default: daemon default, e.g. local-hardened)")
	cmd.Flags().StringVar(&mode, "mode", "", "session mode: scratch|workspace (default: daemon default)")
	cmd.Flags().StringVar(&name, "name", "", "workspace name (required for --mode workspace)")
	cmd.Flags().StringVar(&cwd, "cwd", "", "working directory inside the sandbox")
	cmd.Flags().BoolVar(&keep, "keep", false, "do not destroy the session after the command exits")
	// Stop flag parsing at the first positional so the sandboxed command keeps its
	// own flags (e.g. `run kubectl version --client`); opslify flags come before it.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// sessionCmd is the parent of ls/kill/exec.
func sessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage sandbox sessions (ls, kill, exec)",
	}
	cmd.AddCommand(sessionLsCmd(), sessionKillCmd(), sessionExecCmd())
	return cmd
}

func sessionLsCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List active sessions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			views, err := c.listSessions(cmd.Context())
			if err != nil {
				return err
			}
			return renderSessionTable(cmd.OutOrStdout(), views)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

func sessionKillCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "kill <id>",
		Short: "Destroy a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			if err := c.destroySession(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "killed %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

func sessionExecCmd() *cobra.Command {
	var (
		socket string
		cwd    string
	)
	cmd := &cobra.Command{
		Use:   `exec <id> "<cmd>" [args...]`,
		Short: "Run a command in an existing session and stream its output",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			id, argv := args[0], args[1:]
			res, err := c.execStream(cmd.Context(), id, execReq{Argv: argv, Cwd: cwd},
				cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			return exitFromResult(res)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&cwd, "cwd", "", "working directory inside the sandbox")
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// exitFromResult turns a non-zero sandboxed exit code into an exitCodeError so
// the CLI process mirrors it; a zero (or absent) code is success.
func exitFromResult(res execResult) error {
	if res.ExitCode != nil && *res.ExitCode != 0 {
		return &exitCodeError{code: *res.ExitCode}
	}
	return nil
}

// renderSessionTable prints id/state/age/ttl_remaining as an aligned table.
func renderSessionTable(w io.Writer, views []sessionView) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION ID\tMODE\tTIER\tSTATE\tAGE\tTTL REMAINING")
	for _, v := range views {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			v.SessionID, v.Mode, v.Tier, v.State,
			humanSeconds(v.AgeSeconds), ttlLabel(v.TTLRemaining))
	}
	return tw.Flush()
}

// ttlLabel renders ttl_remaining; 0 with no TTL is shown as "-" (never expires).
func ttlLabel(secs int64) string {
	if secs <= 0 {
		return "-"
	}
	return humanSeconds(secs)
}

// humanSeconds renders a seconds count compactly (e.g. 90 -> "1m30s").
func humanSeconds(secs int64) string {
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	m := secs / 60
	s := secs % 60
	if m < 60 {
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm%ds", m, s)
	}
	h := m / 60
	m = m % 60
	return fmt.Sprintf("%dh%dm", h, m)
}
