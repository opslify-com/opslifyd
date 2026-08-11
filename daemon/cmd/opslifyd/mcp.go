package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os/signal"
	"syscall"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/opslify-com/opslifyd/internal/mcp"
)

// runMCP serves the F2.1 stdio MCP server. It is a THIN client of the daemon
// over the same Unix socket the CLI uses: it exposes the five opslify session
// tools to any MCP client and forwards each to the daemon's REST API. It blocks
// until the MCP client disconnects or the process is signalled.
func runMCP(argv []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	var (
		socket    = fs.String("socket", daemon.DefaultSocketPath, "daemon REST API Unix socket path")
		outputCap = fs.Int("output-cap", mcp.DefaultOutputCap, "per-stream exec output cap in bytes (aggregated result is truncated with a marker beyond this)")
		maxFile   = fs.Int("max-file-bytes", mcp.DefaultMaxFileBytes, "max upload/download size in bytes (decoded)")
	)
	if err := fs.Parse(argv); err != nil {
		return err
	}

	// stdio transport uses stdin/stdout for JSON-RPC; terminate cleanly on signal.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	err := mcp.Run(ctx, mcp.Options{
		Socket:       *socket,
		OutputCap:    *outputCap,
		MaxFileBytes: *maxFile,
		Version:      version,
	})
	// A client disconnect (stdin EOF) or a signalled shutdown is a clean exit, not
	// a daemon fault — the MCP client owns the process lifetime over stdio.
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
