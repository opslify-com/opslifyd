package main

import (
	"fmt"
	"strings"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// pipTarget is the project-local pip install target under /workspace (F7.5). It is
// captured by the F2.2 workspace snapshot and the F7.3 sync — the read-only base
// image is never mutated. The agent uses it via PYTHONPATH=/workspace/.opslify/pip.
const pipTarget = "/workspace/.opslify/pip"

// workspaceMount is where the writable /workspace lives inside the sandbox (F0.3).
const workspaceMount = "/workspace"

// ecosystemAlias maps an operator-facing ecosystem word to the daemon's F5.5
// routing key. `pip` is accepted as a friendly alias for `pypi`.
var ecosystemAlias = map[string]string{
	"pip":  "pypi",
	"pypi": "pypi",
	"npm":  "npm",
	"go":   "go",
}

// workspaceInstallCmd is the F7.5 operator-initiated, allowlist-gated, audited,
// project-local package install. It is DELIBERATELY operator CLI only — there is no
// MCP tool and no in-sandbox trigger, so the agent can never self-install. The
// traffic is forced through the per-session F5.5 registry proxy (routing env the
// daemon injected at session create), which enforces the allowlist + attestation
// and emits the `pkg.install` audit event; this command additionally checks the
// allowlist up front so a non-allowlisted name is refused BEFORE any exec.
func workspaceInstallCmd() *cobra.Command {
	var (
		socket    string
		sessionID string
	)
	cmd := &cobra.Command{
		Use:   "install <ecosystem> <pkg>[@version]",
		Short: "Install a package into a running session's /workspace (allowlisted, proxied, audited)",
		Long: "Operator-initiated package install, forced through the F5.5 registry proxy:\n" +
			"  - only allowlisted packages resolve (checked BEFORE the install runs);\n" +
			"  - the upstream credential is injected server-side (never in the sandbox env);\n" +
			"  - every install is audited as a pkg.install event in the tamper-evident trace;\n" +
			"  - the target is project-local under /workspace (snapshot-captured; base image immutable).\n\n" +
			"Ecosystems: pip (python) | npm (node) | go. The agent CANNOT run this — operator only.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if sessionID == "" {
				return fmt.Errorf("--session <id> is required (install targets a running session's /workspace)")
			}
			ecoWord := strings.ToLower(args[0])
			eco, ok := ecosystemAlias[ecoWord]
			if !ok {
				return fmt.Errorf("unknown ecosystem %q (want pip|npm|go)", args[0])
			}
			name, version := splitPkgVersion(args[1])
			if name == "" {
				return fmt.Errorf("empty package name")
			}

			c := newClient(socket)

			// Pre-install allowlist gate (fail-closed): refuse a non-allowlisted name
			// BEFORE any exec, and refuse entirely when no registry proxy is configured
			// (never fall back to an open-egress install).
			gate, err := c.registryAllowed(cmd.Context(), eco, name)
			if err != nil {
				return err
			}
			if !gate.Configured {
				return fmt.Errorf("install unavailable: no registry proxy is configured on this daemon (fail-closed — opslify never runs an open-egress install)")
			}
			if !gate.Allowed {
				return fmt.Errorf("package %s/%s is NOT on the registry allowlist (deny-by-default); add it to the daemon registry_proxy.allow to permit it", eco, name)
			}

			argv, err := installArgv(eco, name, version)
			if err != nil {
				return err
			}

			// Run through the existing exec API so policy + trace apply, and so the pip/
			// npm/go traffic rides the routing env the daemon injected (PIP_INDEX_URL /
			// NPM_CONFIG_REGISTRY / GOPROXY -> the per-session proxy). The proxy emits
			// the pkg.install audit for each resolved artifact.
			fmt.Fprintf(cmd.OutOrStdout(), "[opslify: installing %s/%s%s into %s via the registry proxy]\n",
				eco, name, versionSuffix(version), workspaceMount)
			res, execErr := c.execStream(cmd.Context(), sessionID, execReq{Argv: argv, Cwd: workspaceMount},
				cmd.OutOrStdout(), cmd.ErrOrStderr())
			if execErr != nil {
				return execErr
			}
			if res.Pending {
				reportPending(cmd.ErrOrStderr(), sessionID, res)
				return exitFromResult(res)
			}
			if err := exitFromResult(res); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[opslify: installed %s/%s%s — pkg.install audited in the trace (opslify verify %s)]\n",
				eco, name, versionSuffix(version), sessionID)
			if eco == "pypi" {
				fmt.Fprintf(cmd.OutOrStdout(), "[opslify: use it with PYTHONPATH=%s]\n", pipTarget)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&sessionID, "session", "", "target session id (required)")
	return cmd
}

// splitPkgVersion splits "name@version" into (name, version). A leading '@' (an npm
// scope, e.g. @scope/pkg) is preserved; only a LATER '@' separates the version.
func splitPkgVersion(spec string) (name, version string) {
	scope := ""
	rest := spec
	if strings.HasPrefix(spec, "@") {
		scope = "@"
		rest = spec[1:]
	}
	if i := strings.Index(rest, "@"); i >= 0 {
		return scope + rest[:i], rest[i+1:]
	}
	return scope + rest, ""
}

func versionSuffix(version string) string {
	if version == "" {
		return ""
	}
	return "@" + version
}

// installArgv builds the ecosystem-appropriate, PROJECT-LOCAL install argv. Every
// target is under /workspace so the install is snapshot-captured and the read-only
// base image is never mutated. The routing env (injected by the daemon) points each
// tool at the per-session registry proxy, so no --index-url/--registry flag is
// needed here (and none is added, to keep the proxy the single routing authority).
func installArgv(eco, name, version string) ([]string, error) {
	switch eco {
	case "pypi":
		pkg := name
		if version != "" {
			pkg = name + "==" + version
		}
		// --target keeps the install project-local (no venv activation needed); the
		// agent adds it to PYTHONPATH.
		return []string{"pip", "install", "--no-input", "--target", pipTarget, pkg}, nil
	case "npm":
		pkg := name
		if version != "" {
			pkg = name + "@" + version
		}
		// --prefix /workspace installs into /workspace/node_modules (project-local).
		return []string{"npm", "install", "--prefix", workspaceMount, pkg}, nil
	case "go":
		v := version
		if v == "" {
			v = "latest"
		}
		// go get resolves through GOPROXY (the per-session proxy) into the module
		// cache; run it in /workspace (Cwd) so a project-local go.mod is updated.
		return []string{"go", "get", name + "@" + v}, nil
	default:
		return nil, fmt.Errorf("unsupported ecosystem %q", eco)
	}
}
