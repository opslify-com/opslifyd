package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

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
	cmd.AddCommand(secretsAddCmd(), secretsLsCmd(), secretsRmCmd())
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
		Args:  cobra.ExactArgs(1),
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
			fmt.Fprintln(tw, "REF\tPROVIDER\tSCOPE\tTTL\tCREATED")
			for _, s := range secrets {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					s.Ref, orDash(s.Provider), orDash(s.Scope), orDash(s.TTL), orDash(s.CreatedAt))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

func secretsRmCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "rm <ref>",
		Short: "Remove a secret by ref",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			if err := c.removeSecret(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed secret %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
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
