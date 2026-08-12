package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/opslify-com/opslifyd/internal/install"
	"github.com/opslify-com/opslifyd/internal/trace"
	"github.com/spf13/cobra"
)

// verifyCmd fetches a session's tamper-evident trace and verifies it CLIENT-SIDE
// against a TRUSTED daemon identity resolved OUT-OF-BAND: it recomputes the
// SHA-256 hash chain and checks the daemon's Ed25519 seal against a public key
// the CLI loads independently of the daemon's response — never the key embedded
// in the seal. On any tamper (edited payload, reorder, dropped event, a seal
// re-signed with an attacker key, or no trustable identity) it prints the first
// broken seq and exits non-zero.
func verifyCmd() *cobra.Command {
	var (
		socket      string
		pubkeyPath  string
		fingerprint string
	)
	cmd := &cobra.Command{
		Use:   "verify <session>",
		Short: "Recompute and verify a session's tamper-evident trace chain against the trusted daemon identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			c := newClient(socket)
			tr, err := c.fetchTrace(cmd.Context(), id)
			if err != nil {
				return err
			}

			out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()

			// Resolve the trusted daemon public key out-of-band. Only a sealed
			// session needs it; an unsealed (still-live) session has no signature to
			// anchor and is checked structurally.
			var trustedPub ed25519.PublicKey
			if tr.Seal != nil {
				trustedPub, err = resolveTrustedPub(pubkeyPath, fingerprint, tr.Seal)
				if err != nil {
					// Fail closed: never fall back to trusting the seal's own key.
					fmt.Fprintf(errOut, "cannot verify session %s: %v\n", id, err)
					return &exitCodeError{code: 1}
				}
			}

			res := trace.Verify(tr.Events, tr.Seal, trustedPub)
			if !res.OK {
				fmt.Fprintf(errOut, "TAMPER: session %s FAILED verification at seq %d: %s\n", id, res.BrokenSeq, res.Reason)
				return &exitCodeError{code: 1}
			}

			sealed := "UNSEALED (session still live; chain intact, not yet signed)"
			if tr.Seal != nil {
				sealed = fmt.Sprintf("sealed + signature valid against trusted identity %s", tr.Seal.PubKeyFingerprint)
			}
			fmt.Fprintf(out, "OK: session %s verified — %d events, chain intact, %s\n", id, res.Events, sealed)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&pubkeyPath, "pubkey", "",
		"path to the trusted daemon Ed25519 public key (default: <identity-key>.pub, i.e. "+install.DefaultIdentityKeyPath+".pub)")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "",
		"pin the trusted daemon identity by fingerprint (16 hex chars) instead of a key file; "+
			"a 64-bit anchor — weaker than --pubkey (full 256-bit key equality), which is the recommended guard")
	return cmd
}

// resolveTrustedPub obtains the trusted daemon public key out-of-band, in
// priority order: an explicit --pubkey file, a --fingerprint pin, then the
// default `.pub` next to the daemon identity key. It NEVER returns the seal's
// embedded key on its own authority — a fingerprint pin only accepts the embedded
// key once its fingerprint matches the operator-supplied pin (a 64-bit out-of-band
// anchor an attacker cannot forge a matching key for). A failure to resolve any
// trustable key is an error, so verification fails closed rather than self-trusting.
func resolveTrustedPub(pubkeyPath, fingerprint string, seal *trace.Signature) (ed25519.PublicKey, error) {
	// 1. Explicit key file.
	if pubkeyPath != "" {
		pub, _, err := install.LoadPublicKey(pubkeyPath)
		return pub, err
	}
	// 2. Fingerprint pin: accept the seal's embedded key ONLY if its fingerprint
	//    matches the pin the operator supplied out-of-band.
	if fingerprint != "" {
		pub, err := hex.DecodeString(seal.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("seal public key is malformed; cannot check against --fingerprint")
		}
		if hex.EncodeToString(pub)[:16] != fingerprint {
			return nil, fmt.Errorf("seal identity %s does not match pinned --fingerprint %s", hex.EncodeToString(pub)[:16], fingerprint)
		}
		return ed25519.PublicKey(pub), nil
	}
	// 3. Default: the `.pub` written next to the daemon identity key by `opslify init`.
	defaultPath := install.DefaultIdentityKeyPath + ".pub"
	pub, _, err := install.LoadPublicKey(defaultPath)
	if err != nil {
		return nil, fmt.Errorf("no trusted daemon public key: %w (pass --pubkey <path> or --fingerprint <hex>)", err)
	}
	return pub, nil
}
