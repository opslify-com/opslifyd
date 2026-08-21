package main

import (
	"errors"
	"fmt"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/install"
	"github.com/spf13/cobra"
)

// vaultCmd is the F7.2 operator surface for the vault MASTER KEY. Its only
// subcommand is `vault key export`, the sole re-reveal path (init reveals once at
// generation; this re-prints for backup). CRITICAL: the master key is CLI-only —
// no daemon API/UI route ever returns it. This command reads the resolved key
// LOCALLY (from the same env → file chain the daemon uses), never over the socket.
func vaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Vault master-key operations (key export). The key is CLI-only — never served by any API/UI route.",
	}
	cmd.AddCommand(vaultKeyCmd())
	return cmd
}

func vaultKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Vault master-key backup (export)",
	}
	cmd.AddCommand(vaultKeyExportCmd())
	return cmd
}

func vaultKeyExportCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print the vault master key ONCE for backup (with a save-it warning). Refuses if no key is configured.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolve the key file / env from config when available; fall back to the
			// production defaults so `export` works before a config is written too.
			keyEnv := broker.DefaultVaultKeyEnv
			keyFile := install.DefaultVaultKeyFilePath
			if cfg, err := install.LoadConfig(configPath); err == nil {
				if cfg.Vault.KeyEnv != "" {
					keyEnv = cfg.Vault.KeyEnv
				}
				if cfg.Vault.KeyFile != "" {
					keyFile = cfg.Vault.KeyFile
				}
			}

			key, err := broker.ResolveKeySource(keyEnv, keyFile).MasterKey()
			if err != nil {
				if errors.Is(err, broker.ErrKeyAbsent) {
					return fmt.Errorf("no vault master key is configured (set %s or run `opslify init` to generate %s): %w", keyEnv, keyFile, err)
				}
				return fmt.Errorf("resolve vault master key: %w", err)
			}
			defer broker.Zeroize(key)

			w := cmd.OutOrStdout()
			const bar = "============================================================"
			fmt.Fprintf(w, "%s\n", bar)
			fmt.Fprintln(w, "VAULT MASTER KEY (backup copy — handle like a password):")
			fmt.Fprintf(w, "\n    %s\n\n", broker.EncodeKey(key))
			fmt.Fprintln(w, "Store it in a password manager. It is the ONLY copy — losing it")
			fmt.Fprintln(w, "makes every vaulted secret PERMANENTLY unrecoverable.")
			fmt.Fprintf(w, "%s\n", bar)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", install.DefaultConfigPath, "daemon config path (for the vault key_file / key_env)")
	return cmd
}
