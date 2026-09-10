package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// secretsCmd is the F5.6 secret-management surface: add (write-only), ls
// (metadata only), rm. CRITICAL: a value is only ever WRITTEN — `add` reads it
// from stdin or --from-file, NEVER from an argv/flag (which would leak it into the
// process table, shell history, and `ps`). Nothing reads a value back: `ls` shows
// metadata only, and there is no `get`.
func secretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Manage broker secrets (add, ls, rm). Values are write-only — never read back.",
	}
	cmd.AddCommand(secretsAddCmd(), secretsLsCmd(), secretsRmCmd(),
		secretsRotateCmd(), secretsConsumersCmd(), secretsSyncCmd())
	return cmd
}

func secretsAddCmd() *cobra.Command {
	var (
		socket    string
		provider  string
		scope     string
		ttl       string
		fromFile  string
		overwrite bool
	)
	cmd := &cobra.Command{
		Use:   "add <ref>",
		Short: "Store a secret (value from stdin or --from-file, NEVER an argument)",
		Long: "Store a secret. The value is read from stdin or --from-file and NEVER from an\n" +
			"argument, so it cannot appear in the process table, shell history or `ps`.\n\n" +
			"With --overwrite on an existing ref this is a ROTATION: the ref and its history\n" +
			"survive, consumers keep working, and metadata you do not restate is carried\n" +
			"forward. That means a --ttl or --scope can be CHANGED but not CLEARED here — a\n" +
			"rotation must never silently relax a bound nobody chose to relax. To remove a\n" +
			"TTL or scope entirely, `secrets rm` the ref and add it again.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]

			// The value NEVER comes from argv. It is read from --from-file or stdin, so
			// it never appears in the process table / shell history / `ps`.
			var value []byte
			var err error
			switch {
			case fromFile != "":
				value, err = os.ReadFile(fromFile)
				if err != nil {
					return fmt.Errorf("read --from-file: %w", err)
				}
			default:
				value, err = io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return fmt.Errorf("read secret from stdin: %w", err)
				}
			}
			// Trim a single trailing newline a here-string / echo adds, so `echo -n` and
			// `echo` behave the same; do NOT trim interior bytes (binary-safe otherwise).
			value = trimOneTrailingNewline(value)
			if len(value) == 0 {
				return fmt.Errorf("empty secret value (pipe it on stdin or pass --from-file); values are never taken from the command line")
			}

			c := newClient(socket)
			meta, err := c.addSecret(cmd.Context(), addSecretReq{
				Ref:       ref,
				Provider:  provider,
				Scope:     scope,
				TTL:       ttl,
				ValueB64:  base64.StdEncoding.EncodeToString(value),
				Overwrite: overwrite,
			})
			// Best-effort scrub the local plaintext copy once it is on the wire.
			for i := range value {
				value[i] = 0
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored secret %s (provider=%s)\n", meta.Ref, orDash(meta.Provider))
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&provider, "provider", "", "credential provider (e.g. aws, github)")
	cmd.Flags().StringVar(&scope, "scope", "", "opaque provider scope hint (audited, never secret)")
	cmd.Flags().StringVar(&ttl, "ttl", "", "requested token lifetime hint (Go duration, e.g. 15m)")
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read the secret value from this file instead of stdin")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace an existing secret with the same ref")
	return cmd
}

func secretsLsCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List secrets (refs + metadata only — never a value)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			secrets, err := c.listSecrets(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			// LAST USED and ROTATED are the rotation-hygiene signals: together they
			// answer "which credentials are stale, and has the new one been picked
			// up?" — the question the stamps exist for, previously unanswerable from
			// the primary listing verb.
			fmt.Fprintln(tw, "REF\tPROVIDER\tSCOPE\tTTL\tCREATED\tLAST USED\tROTATED")
			for _, s := range secrets {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					s.Ref, orDash(s.Provider), orDash(s.Scope), orDash(s.TTL), orDash(s.CreatedAt),
					orNever(s.LastUsed), orNever(s.RotatedAt))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

func secretsRmCmd() *cobra.Command {
	var socket string
	var force bool
	cmd := &cobra.Command{
		Use:   "rm <ref>",
		Short: "Remove a secret by ref (refused while anything still uses it)",
		Long: "Remove a secret. The removal is REFUSED while a policy grant, an egress-inject\n" +
			"rule or a registry upstream still addresses the ref — otherwise the breakage would\n" +
			"only surface at the next session that tried to resolve it, in production. Run\n" +
			"`opslify secrets consumers <ref>` to see what is holding it, or pass --force to\n" +
			"remove it anyway (the consumers you are breaking are printed).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			ref := args[0]
			// With --force the consumers are read and PRINTED first. A 204 carries no
			// body, so the daemon cannot report them after the fact — and telling an
			// operator what they broke only in a daemon log they never read is not
			// telling them. Read-then-delete has a race, but the alternative is a
			// force that silently breaks a grant, and force already means "proceed".
			if force {
				switch cs, err := c.consumersOf(cmd.Context(), ref); {
				case err != nil:
					fmt.Fprintf(cmd.ErrOrStderr(),
						"warning: could not determine what uses %s (%v); forcing removal anyway\n", ref, err)
				case len(cs) == 0:
					fmt.Fprintf(cmd.ErrOrStderr(), "nothing currently uses %s; --force was not needed\n", ref)
				default:
					fmt.Fprintf(cmd.ErrOrStderr(), "forcing removal of %s, breaking %d consumer(s):\n", ref, len(cs))
					for _, con := range cs {
						scope := con.Scope
						if scope == "" {
							scope = "daemon"
						}
						fmt.Fprintf(cmd.ErrOrStderr(), "  %s %s (%s)\n", con.Kind, con.Name, scope)
					}
				}
			}
			if err := c.removeSecretForce(cmd.Context(), ref, force); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed secret %s\n", ref)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().BoolVar(&force, "force", false, "remove even while consumers still address the ref")
	return cmd
}

// trimOneTrailingNewline removes a single trailing "\n" (and a preceding "\r"), so
// a value piped with a trailing newline stores without it, while interior bytes
// (and deliberately-included trailing newlines beyond one) are preserved.
func trimOneTrailingNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// readSecretValue reads a secret value from --from-file, a --from-command's
// stdout, or stdin — NEVER from argv, so it cannot appear in the process table,
// `ps` output or shell history. This is the single entry point every verb that
// accepts a value uses.
func readSecretValue(cmd *cobra.Command, fromFile, fromCommand string) ([]byte, error) {
	var (
		value []byte
		err   error
	)
	switch {
	case fromCommand != "":
		// The manager's own CLI is the source of truth (`vault kv get -field=…`,
		// `doppler secrets get … --plain`, `aws secretsmanager get-secret-value …`).
		// We shell out and take stdout, so no manager SDK becomes a dependency and a
		// non-zero exit is a failed sync that leaves the previous value untouched.
		out, cerr := exec.Command("sh", "-c", fromCommand).Output()
		if cerr != nil {
			// Deliberately do NOT echo stderr. A manager CLI that prints the secret
			// to stderr on failure would otherwise leak it to the terminal, the
			// shell scrollback and CI logs — the one place in this feature where a
			// value could leave through an error message.
			var ee *exec.ExitError
			if errors.As(cerr, &ee) {
				return nil, fmt.Errorf("--from-command failed: %w (stderr suppressed: it may contain the secret; run the command yourself to debug it)", cerr)
			}
			return nil, fmt.Errorf("--from-command failed: %w", cerr)
		}
		value = out
	case fromFile != "":
		value, err = os.ReadFile(fromFile)
		if err != nil {
			return nil, fmt.Errorf("read --from-file: %w", err)
		}
	default:
		value, err = io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, fmt.Errorf("read secret from stdin: %w", err)
		}
	}
	value = trimOneTrailingNewline(value)
	if len(value) == 0 {
		return nil, fmt.Errorf("empty secret value (pipe it on stdin, or pass --from-file/--from-command); values are never taken from the command line")
	}
	return value, nil
}

// secretsRotateCmd replaces the value under an EXISTING ref. Consumers address
// the ref, so nothing downstream needs editing — that is the whole point of the
// reference model.
func secretsRotateCmd() *cobra.Command {
	var socket, provider, scope, ttl, fromFile, fromCommand string
	cmd := &cobra.Command{
		Use:   "rotate <ref>",
		Short: "Replace a secret's value in place (value from stdin, --from-file or --from-command)",
		Long: "Replace the value stored under an existing ref. Every consumer keeps working\n" +
			"because they address the ref, not the value. Rotating an unknown ref is refused —\n" +
			"use `secrets add` to create one.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			value, err := readSecretValue(cmd, fromFile, fromCommand)
			if err != nil {
				return err
			}
			c := newClient(socket)
			if err := c.rotateSecret(cmd.Context(), args[0], rotateSecretReq{
				ValueB64: base64.StdEncoding.EncodeToString(value),
				Provider: provider, Scope: scope, TTL: ttl,
			}); err != nil {
				return err
			}
			// Confirm WHICH ref rotated; never echo what it now holds.
			fmt.Fprintf(cmd.OutOrStdout(), "rotated secret %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&provider, "provider", "", "override the provider (kept from the existing secret when empty)")
	cmd.Flags().StringVar(&scope, "scope", "", "override the scope hint (kept when empty)")
	cmd.Flags().StringVar(&ttl, "ttl", "", "override the lifetime hint (kept when empty)")
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read the new value from this file instead of stdin")
	cmd.Flags().StringVar(&fromCommand, "from-command", "", "read the new value from this command's stdout")
	return cmd
}

// secretsSyncCmd is rotate with the value taken from an external manager's CLI.
// It is deliberately the same write-only path: a failed fetch never reaches the
// vault, so the previous value stays intact.
func secretsSyncCmd() *cobra.Command {
	var socket, fromCommand, provider string
	cmd := &cobra.Command{
		Use:   "sync <ref> --from-command <cmd>",
		Short: "Refresh a secret from an external manager (Vault, Doppler, ASM, Key Vault)",
		Long: "Fetch a value from your own secret manager's CLI and store it under an existing ref.\n" +
			"No manager SDK is bundled: the command's stdout is the value, so anything that can\n" +
			"print a secret works. Examples:\n" +
			"  opslify secrets sync gitlab-token --from-command 'vault kv get -field=token secret/gitlab'\n" +
			"  opslify secrets sync gitlab-token --from-command 'doppler secrets get GITLAB_TOKEN --plain'\n" +
			"A failing command aborts the sync and leaves the stored value unchanged.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if fromCommand == "" {
				return fmt.Errorf("--from-command is required (it is where the value comes from)")
			}
			value, err := readSecretValue(cmd, "", fromCommand)
			if err != nil {
				return err
			}
			c := newClient(socket)
			if err := c.rotateSecret(cmd.Context(), args[0], rotateSecretReq{
				ValueB64: base64.StdEncoding.EncodeToString(value),
				Provider: provider,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "synced secret %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&fromCommand, "from-command", "", "command whose stdout is the secret value")
	cmd.Flags().StringVar(&provider, "provider", "", "override the provider (kept when empty)")
	return cmd
}

// secretsConsumersCmd shows who addresses each ref — the answer to "is anything
// still using this?" before a rotation or a delete.
func secretsConsumersCmd() *cobra.Command {
	var socket, only string
	cmd := &cobra.Command{
		Use:   "consumers [ref]",
		Short: "Show what uses each secret (policy grants, egress rules, registry upstreams)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			views, err := c.listSecretsWithConsumers(cmd.Context())
			if err != nil {
				return err
			}
			if len(args) == 1 {
				only = args[0]
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "REF\tPROVIDER\tLAST USED\tIN USE\tCONSUMERS")
			for _, v := range views {
				if only != "" && v.Ref != only {
					continue
				}
				parts := make([]string, 0, len(v.Consumers))
				for _, cs := range v.Consumers {
					if cs.Scope != "" {
						parts = append(parts, fmt.Sprintf("%s %s (%s)", cs.Kind, cs.Name, cs.Scope))
					} else {
						parts = append(parts, fmt.Sprintf("%s %s", cs.Kind, cs.Name))
					}
				}
				used := "-"
				if v.LastUsed != nil {
					used = v.LastUsed.Format(time.RFC3339)
				}
				inUse := "no"
				if v.InUse {
					inUse = "yes"
				}
				list := strings.Join(parts, ", ")
				if list == "" {
					list = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", v.Ref, dashIfEmpty(v.Provider), used, inUse, list)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// orNever renders an optional timestamp, distinguishing "never happened" from a
// zero time that would otherwise print as year 1 and read like real data.
func orNever(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}
