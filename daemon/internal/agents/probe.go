package agents

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// probeTimeout bounds a handshake. A command that hangs must not hang the bind —
// an operator waiting forever on `agent add` cannot tell a slow model load from a
// wedged process.
const probeTimeout = 20 * time.Second

// mcpProber completes a real MCP handshake against a registered command.
type mcpProber struct{}

// NewProber returns the production prober.
func NewProber() Prober { return mcpProber{} }

// Probe starts the command, completes the MCP initialize handshake, lists its
// tools, and shuts it down.
//
// The process is started with the agent's ALLOWLISTED environment and nothing
// else, so the probe exercises the same environment a real invocation gets — a
// probe that passed with the daemon's full environment and then failed in
// production would be worse than no probe.
func (mcpProber) Probe(ctx context.Context, a Agent) ([]string, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(a.Command); err != nil {
		// Checked explicitly so a missing binary reads as a missing binary rather
		// than as a handshake failure.
		return nil, fmt.Errorf("command %s is not executable: %w", a.Command, err)
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, a.Command, a.Args...)
	cmd.Env = a.Env(os.Environ())
	// stderr is discarded rather than captured into the error. A misconfigured
	// agent command can print its own configuration on startup, which may include
	// a provider key — the same reasoning as the F8.3 --from-command fix.
	cmd.Stderr = nil

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "opslifyd",
		Version: "probe",
	}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}
	defer session.Close()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("connected but could not list tools: %w", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, t := range res.Tools {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return names, nil
}
