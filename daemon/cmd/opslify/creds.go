package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/opslify-com/opslifyd/internal/install"
	"github.com/spf13/cobra"
)

// credsCmd is the F5.4 OAuth2 onboarding surface: `opslify creds add <service>`
// runs the OAuth2 device-authorization flow for a service configured in the
// daemon config (public {device_url, token_url, client_id, scopes}) and stores
// the resulting REFRESH token ENCRYPTED in the F5.6 vault.
//
// SECURITY: the refresh token is NEVER printed, NEVER passed as an argv/flag, and
// NEVER logged. It travels from this process to the daemon over the same
// value-write-only socket path as `secrets add` (base64 body, never argv) and is
// zeroized locally afterwards. Only the short-lived access token minted per
// request from it is ever injected — and that stays daemon-side.
func credsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "creds",
		Short: "Onboard OAuth2-backed services via device flow (creds add). Tokens are never printed.",
	}
	cmd.AddCommand(credsAddCmd())
	return cmd
}

func credsAddCmd() *cobra.Command {
	var (
		socket     string
		configPath string
		ref        string
		overwrite  bool
	)
	cmd := &cobra.Command{
		Use:   "add <service>",
		Short: "Run the OAuth2 device flow for <service> and store its refresh token (encrypted)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			service := args[0]
			cfgPath := configPath
			if cfgPath == "" {
				cfgPath = install.DefaultConfigPath
			}
			cfg, err := install.LoadConfig(cfgPath)
			if err != nil {
				return err
			}
			svc, ok := cfg.OAuth2[service]
			if !ok {
				return fmt.Errorf("no oauth2 service %q configured in %s (add it under `oauth2:` first)", service, cfgPath)
			}
			if err := svc.Validate(); err != nil {
				return fmt.Errorf("oauth2 service %q: %w", service, err)
			}

			onb := broker.DeviceOnboarder{Cfg: svc}
			da, err := onb.StartDeviceFlow(cmd.Context())
			if err != nil {
				return err
			}
			// Show the operator the verification URL + user code. This is the ONLY
			// thing printed — never a token.
			target := da.VerificationURIComplete
			if target == "" {
				target = da.VerificationURI
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"To authorize %q, open:\n  %s\nand enter the code:\n  %s\n\nWaiting for authorization...\n",
				service, target, da.UserCode)

			// Block until the operator authorizes; obtain the durable REFRESH token.
			refresh, err := onb.PollForRefreshToken(cmd.Context(), da)
			if err != nil {
				return err
			}

			// Store the refresh token ENCRYPTED via the daemon (value travels base64
			// in the body, never argv). provider "oauth2/<service>" routes resolves to
			// the generic OAuth2 adapter.
			storeRef := ref
			if storeRef == "" {
				storeRef = service
			}
			c := newClient(socket)
			meta, err := c.addSecret(cmd.Context(), addSecretReq{
				Ref:       storeRef,
				Provider:  broker.OAuth2Provider + "/" + service,
				Scope:     strings.Join(svc.Scopes, " "),
				ValueB64:  base64.StdEncoding.EncodeToString(refresh),
				Overwrite: overwrite,
			})
			// Best-effort scrub the local refresh-token copy once it is on the wire.
			for i := range refresh {
				refresh[i] = 0
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"authorized: stored refresh token for %s as %q (provider=%s). Access tokens are minted per request; the refresh token is never printed.\n",
				service, meta.Ref, orDash(meta.Provider))
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&configPath, "config", "", "daemon config path (default /etc/opslify/config.yaml)")
	cmd.Flags().StringVar(&ref, "ref", "", "vault ref to store the refresh token under (default: the service name)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace an existing stored credential for this service")
	return cmd
}
