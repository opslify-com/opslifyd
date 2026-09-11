package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/opslify-com/opslifyd/internal/agents"
)

// agentDriver adapts the registry + runner to the daemon's AgentDriver seam.
//
// It resolves the name here rather than taking an Agent from the caller, so a
// request can never hand the runner a command the registry never probed. The
// only agents that can be driven are ones that completed a real MCP handshake at
// `agent add`.
type agentDriver struct {
	reg     *agents.Registry
	runner  *agents.Runner
	socket  string
	binPath string
}

func newAgentDriver(reg *agents.Registry, stateDir, socket string) (*agentDriver, error) {
	if reg == nil {
		return nil, nil
	}
	// The daemon's OWN path, resolved once at startup. The agent's MCP server must
	// be this binary talking to this socket — resolving `opslifyd` through the
	// agent's PATH could reach a different build, or nothing at all.
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("opslifyd: locating self for agent runs: %w", err)
	}
	dir := filepath.Join(stateDir, "agent-runs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("opslifyd: agent run dir: %w", err)
	}
	// Chmod even when it already existed: MkdirAll leaves an existing directory's
	// mode alone, and these hold the socket path an agent is pointed at.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return &agentDriver{
		reg:     reg,
		runner:  &agents.Runner{WorkRoot: dir},
		socket:  socket,
		binPath: self,
	}, nil
}

func (d *agentDriver) Run(ctx context.Context, name string, req agents.RunRequest, sink agents.RunSink) error {
	list, err := d.reg.List()
	if err != nil {
		return err
	}
	for _, a := range list {
		if a.Name != name {
			continue
		}
		req.Socket = d.socket
		req.MCPCommand = d.binPath
		return d.runner.Run(ctx, a, req, sink)
	}
	return fmt.Errorf("%w: agent %q", agents.ErrNotFound, name)
}
