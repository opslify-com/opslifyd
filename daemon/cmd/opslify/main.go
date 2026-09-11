// Command opslify is the operator CLI. Its entrypoint subcommand is
// `opslify init [dir]` (F0.1): detect a project, curate the agent toolset, write
// the declarative artifacts + daemon config + identity, and drive F0.2 to
// produce the signed toolchain layer.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/opslify-com/opslifyd/internal/install"
	"github.com/spf13/cobra"
)

func main() {
	os.Exit(run())
}

// run executes the root command and maps errors to a process exit code. A
// sandboxed command's non-zero exit is mirrored verbatim (no extra "error:"
// noise); every other failure prints its message — layered errors already carry
// their "error [layer]: ..." prefix — and exits 1.
func run() int {
	err := rootCmd().ExecuteContext(context.Background())
	if err == nil {
		return 0
	}
	var ec *exitCodeError
	if errors.As(err, &ec) {
		return ec.code
	}
	// layerError and connError already carry a fully-formed, layer-named message;
	// print them verbatim rather than prefixing a redundant "error:".
	var le *layerError
	var ce *connError
	if errors.As(err, &le) || errors.As(err, &ce) {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "opslify",
		Short:         "opslify — credential-blind DevOps sandbox for AI agents",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(initCmd())
	root.AddCommand(runCmd())
	root.AddCommand(sessionCmd())
	root.AddCommand(wsCmd())
	root.AddCommand(workspaceCmd())
	root.AddCommand(verifyCmd())
	root.AddCommand(policyCmd())
	root.AddCommand(uiCmd())
	root.AddCommand(topCmd())
	root.AddCommand(approvalsCmd())
	root.AddCommand(approveCmd())
	root.AddCommand(denyCmd())
	root.AddCommand(secretsCmd())
	root.AddCommand(credsCmd())
	root.AddCommand(vaultCmd())
	root.AddCommand(projectCmd())
	root.AddCommand(envCmd())
	root.AddCommand(contextCmd())
	root.AddCommand(skillCmd())
	root.AddCommand(agentCmd())
	return root
}

func initCmd() *cobra.Command {
	var (
		configPath     string
		keyPath        string
		vaultKeyPath   string
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
				TargetDir:        dir,
				ConfigPath:       configPath,
				IdentityKeyPath:  keyPath,
				VaultKeyFilePath: vaultKeyPath,
				SystemdUnitPath:  unitPath,
				BaseImageDigest:  baseImage,
				Prompter:         prompter,
				Force:            force,
				Out:              cmd.OutOrStdout(),
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
	cmd.Flags().StringVar(&vaultKeyPath, "vault-key-file", "", "vault master-key file path (default /etc/opslify/vault.key)")
	cmd.Flags().StringVar(&unitPath, "systemd-unit", "", "write the systemd unit to this path (default: print it)")
	cmd.Flags().StringVar(&baseImage, "base-image", "", "digest-pinned base image (repo@sha256:...)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files without prompting")
	cmd.Flags().BoolVar(&nonInteractive, "yes", false, "non-interactive: accept detected tools, no TTY prompt")
	return cmd
}
