// Command opslify is the operator CLI. Its entrypoint subcommand is
// `opslify init [dir]` (F0.1): detect a project, curate the agent toolset, write
// the declarative artifacts + daemon config + identity, and drive F0.2 to
// produce the signed toolchain layer.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/opslify-com/opslifyd/internal/install"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "opslify",
		Short:         "opslify — credential-blind DevOps sandbox for AI agents",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(initCmd())
	return root
}

func initCmd() *cobra.Command {
	var (
		configPath     string
		keyPath        string
		unitPath       string
		baseImage      string
		force          bool
		nonInteractive bool
	)
	cmd := &cobra.Command{
		Use:   "init [dir]",
		Short: "Detect a project, select agent tools, and build the signed toolchain",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			var prompter install.Prompter = install.NewSurveyPrompter()
			if nonInteractive {
				// Accept the detected suggestion set unchanged; overwrite nothing
				// unless --force is also given.
				prompter = install.ScriptedPrompter{}
			}
			opts := install.InitOptions{
				TargetDir:       dir,
				ConfigPath:      configPath,
				IdentityKeyPath: keyPath,
				SystemdUnitPath: unitPath,
				BaseImageDigest: baseImage,
				Prompter:        prompter,
				Force:           force,
				Out:             cmd.OutOrStdout(),
			}
			res, err := install.Run(context.Background(), opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\ninit complete: %d tool(s) selected, signed layer produced=%v\n",
				len(res.Selection.Tools), res.Baked)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "daemon config path (default /etc/opslify/config.yaml)")
	cmd.Flags().StringVar(&keyPath, "identity-key", "", "daemon Ed25519 identity key path (default /etc/opslify/identity.key)")
	cmd.Flags().StringVar(&unitPath, "systemd-unit", "", "write the systemd unit to this path (default: print it)")
	cmd.Flags().StringVar(&baseImage, "base-image", "", "digest-pinned base image (repo@sha256:...)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files without prompting")
	cmd.Flags().BoolVar(&nonInteractive, "yes", false, "non-interactive: accept detected tools, no TTY prompt")
	return cmd
}
