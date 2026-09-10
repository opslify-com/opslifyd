package main

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// connectionCmd is the F8.2 operator surface: define how a credential reaches an
// upstream WITHOUT the sandbox ever holding it.
func connectionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connection",
		Short: "Manage connections (add, ls, rm, test)",
		Long: "A connection is HOW a credential reaches an upstream without the sandbox ever\n" +
			"holding it. Each kind answers one question — what does the sandbox actually\n" +
			"receive? — and the answer is always something useless off this host:\n\n" +
			"  http        nothing; the proxy adds the header on the upstream leg\n" +
			"  kubernetes  a kubeconfig with no credential in it\n" +
			"  ssh         an agent socket; signatures only, never key material\n\n" +
			"A connection references a secret BY REF and never holds a value.",
	}
	cmd.AddCommand(connectionAddCmd(), connectionLsCmd(), connectionRmCmd(), connectionTestCmd())
	return cmd
}

// connectionFlags are the inputs shared by add and test.
type connectionFlags struct {
	socket    string
	kind      string
	secretRef string
	hosts     []string
	project   string
	env       string
	config    []string
}

func (f *connectionFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&f.kind, "kind", "", "connection kind (http, kubernetes, ssh)")
	cmd.Flags().StringVar(&f.secretRef, "secret", "", "vault ref of the credential (never a value)")
	cmd.Flags().StringSliceVar(&f.hosts, "host", nil,
		"upstream host (repeatable). For ssh these ARE the destination constraints — an empty list is refused, never treated as any host")
	cmd.Flags().StringVar(&f.project, "project", "", "scope to a project (default: daemon-wide)")
	cmd.Flags().StringVar(&f.env, "env", "", "scope to an environment (implies its project)")
	cmd.Flags().StringSliceVar(&f.config, "config", nil, "kind-specific key=value (repeatable)")
}

// request builds the wire request, parsing --config into a map.
func (f *connectionFlags) request(name string) (addConnectionReq, error) {
	cfg := map[string]string{}
	for _, kv := range f.config {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return addConnectionReq{}, fmt.Errorf("--config must be key=value, got %q", kv)
		}
		if _, dup := cfg[k]; dup {
			// Refuse rather than take one: which value applied would otherwise depend
			// on flag order.
			return addConnectionReq{}, fmt.Errorf("--config %s given twice", k)
		}
		cfg[k] = v
	}
	return addConnectionReq{
		Name:          name,
		Kind:          f.kind,
		SecretRef:     f.secretRef,
		Hosts:         f.hosts,
		ProjectID:     f.project,
		EnvironmentID: f.env,
		Config:        cfg,
	}, nil
}

func connectionAddCmd() *cobra.Command {
	var f connectionFlags
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Define a connection (validated by building it, so a broken one is refused now)",
		Long: "Define a connection. The spec is validated by BUILDING it, so a definition that\n" +
			"could not work is refused here — where you are watching — rather than at session\n" +
			"start, where it surfaces as an agent mysteriously lacking access.\n\n" +
			"Examples:\n" +
			"  opslify connection add gitlab --kind http --secret gitlab-token \\\n" +
			"      --host gitlab.example.com --config header_name=PRIVATE-TOKEN\n\n" +
			"  opslify connection add prod-cluster --kind kubernetes --secret k8s-token \\\n" +
			"      --host api.k8s.example.com:6443 --config namespace=default\n\n" +
			"  opslify connection add ops-fleet --kind ssh --secret ssh-ops-key \\\n" +
			"      --host prod-web-01 --host prod-web-02 \\\n" +
			"      --config known_hosts_path=/etc/opslify/known_hosts",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := f.request(args[0])
			if err != nil {
				return err
			}
			view, err := newClient(f.socket).addConnection(cmd.Context(), req)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "created connection %s (kind %s)\n", view.Name, view.Kind)
			fmt.Fprintf(cmd.OutOrStdout(), "the sandbox will receive: %s\n", sandboxReceives(view.Kind))
			return nil
		},
	}
	f.bind(cmd)
	return cmd
}

func connectionLsCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List connections, their scope, and what the sandbox receives",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conns, err := newClient(socket).listConnections(cmd.Context())
			if err != nil {
				return err
			}
			if len(conns) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no connections defined")
				return nil
			}
			sort.Slice(conns, func(i, j int) bool {
				if conns[i].Scope != conns[j].Scope {
					return conns[i].Scope < conns[j].Scope
				}
				return conns[i].Name < conns[j].Name
			})
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			// SECRET is the ref, never a value — the column header says "REF" so
			// nobody reads the listing expecting to see one.
			fmt.Fprintln(tw, "NAME\tKIND\tSCOPE\tHOSTS\tSECRET REF\tSANDBOX RECEIVES")
			for _, c := range conns {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
					c.Name, c.Kind, orDash(c.Scope), orDash(strings.Join(c.Hosts, ",")),
					c.SecretRef, sandboxReceives(c.Kind))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

func connectionRmCmd() *cobra.Command {
	var socket, project, env string
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove a connection",
		Long: "Remove a connection. The credential it referenced is NOT deleted — a connection\n" +
			"holds a ref, not a value, so removing it only removes the route. Use\n" +
			"`opslify secrets rm` for the credential itself.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient(socket).removeConnection(cmd.Context(), project, env, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed connection %s\n", args[0])
			fmt.Fprintln(cmd.ErrOrStderr(), "the credential it referenced still exists; `opslify secrets rm` removes that")
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "project the connection is scoped to")
	cmd.Flags().StringVar(&env, "env", "", "environment the connection is scoped to")
	return cmd
}

// connectionTestCmd validates a definition WITHOUT storing it.
func connectionTestCmd() *cobra.Command {
	var f connectionFlags
	cmd := &cobra.Command{
		Use:   "test <name>",
		Short: "Validate a connection definition without storing it",
		Long: "Validate a definition and report what the sandbox would receive, without\n" +
			"storing anything. Useful for getting kind-specific config right before it\n" +
			"becomes something a session depends on.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := f.request(args[0])
			if err != nil {
				return err
			}
			view, err := newClient(f.socket).testConnection(cmd.Context(), req)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s (kind %s) is valid\n", view.Name, view.Kind)
			fmt.Fprintf(out, "  secret ref        %s\n", view.SecretRef)
			fmt.Fprintf(out, "  hosts             %s\n", orDash(strings.Join(view.Hosts, ", ")))
			fmt.Fprintf(out, "  scope             %s\n", orDash(view.Scope))
			fmt.Fprintf(out, "  sandbox receives  %s\n", sandboxReceives(view.Kind))
			fmt.Fprintln(out, "\nNothing was stored. Re-run with `connection add` to keep it.")
			return nil
		},
	}
	f.bind(cmd)
	return cmd
}

// sandboxReceives states, per kind, what actually enters the sandbox.
//
// It is surfaced in the CLI on purpose. The claim is the whole product: an
// operator should be able to read what a connection hands over without reading
// the source, and a kind that cannot answer in one line does not ship.
func sandboxReceives(kind string) string {
	switch kind {
	case "http":
		return "nothing (header added upstream)"
	case "kubernetes":
		return "a kubeconfig with no credential in it"
	case "ssh":
		return "an agent socket (signatures only)"
	case "cloud":
		return "short-lived scoped credentials"
	default:
		return "unknown kind"
	}
}
