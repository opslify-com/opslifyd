package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/spf13/cobra"
)

// agentRunCmd is the CLI equivalent of the cockpit's agent composer.
//
// It exists for the same reason every other Tower action has one: the OSS daemon
// has to be complete standalone, and a capability that only the UI can reach is
// a capability nobody can script.
func agentRunCmd() *cobra.Command {
	var (
		socket  string
		project string
		env     string
	)
	cmd := &cobra.Command{
		Use:   "run <name> <prompt>",
		Short: "Give a registered agent a task (it works only through opslify's tools)",
		Long: "Hand a prompt to a registered agent.\n\n" +
			"The agent runs with NO host shell and NO host filesystem access: the daemon\n" +
			"starts it against a throwaway configuration that registers opslify's MCP\n" +
			"server and removes the CLI's own built-in tools. Everything it does happens\n" +
			"in a sandbox, through the same gates and the same trace as any other exec.\n\n" +
			"Requires the agent to have been registered with a --flavour.",
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			prompt := strings.Join(args[1:], " ")
			return newClient(socket).runAgent(cmd.Context(), args[0], runAgentReq{
				Prompt:        prompt,
				ProjectID:     project,
				EnvironmentID: env,
			}, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "project scope")
	cmd.Flags().StringVar(&env, "env", "", "environment scope")
	return cmd
}

type runAgentReq struct {
	Prompt        string `json:"prompt"`
	ProjectID     string `json:"project_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
}

// runAgent streams the agent's output as it is produced. A model working an
// estate takes minutes; buffering it until the end would mean an operator cannot
// see what it is doing in time to stop it.
func (c *client) runAgent(ctx context.Context, name string, req runAgentReq, stdout, stderr io.Writer) error {
	body, _ := json.Marshal(req)
	seg, err := pathSeg("agent name", name)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/agents/"+seg+"/run", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return c.wireError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.decodeError(resp)
	}

	sc := bufio.NewScanner(resp.Body)
	// Agent output is prose, and a single line of it can be long.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	exit := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var f struct {
			Stream string `json:"stream"`
			Data   string `json:"data"`
			Exit   *int   `json:"exit_code"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(line, &f); err != nil {
			continue
		}
		switch {
		case f.Error != "":
			return &layerError{Layer: "agent", Message: f.Error}
		case f.Exit != nil:
			exit = *f.Exit
		case f.Data != "":
			if f.Stream == "stderr" {
				io.WriteString(stderr, f.Data)
			} else {
				io.WriteString(stdout, f.Data)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return c.wireError(err)
	}
	if exit != 0 {
		// The agent's own exit code, surfaced rather than swallowed: a non-zero
		// agent is a task that did not finish.
		fmt.Fprintf(stderr, "\n[opslify: agent exited %d]\n", exit)
		os.Exit(exit)
	}
	return nil
}
