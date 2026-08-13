package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The KEY non-hang contract: a gated command returns PROMPTLY with a structured
// `pending` status carrying the exec_id — the tool call returns, it does not block
// on a human. A never-answered gate stays pending; the tool still returns.
func TestExecApprovalPendingNeverHangs(t *testing.T) {
	f := newFakeDaemon(t)
	// The daemon streams a single pending frame for a gated command.
	f.execFrames = []string{`{"status":"pending","exec_id":"ex-1","rule":"approval_required:kubectl delete"}`}
	cs, done := connect(t, f.sockPath, Options{})
	defer done()

	type execOutT struct {
		Status string `json:"status"`
		ExecID string `json:"exec_id"`
		Reason string `json:"reason"`
	}
	var out execOutT
	// Bound the whole call: if the tool blocked on a human this would fire.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "opslify_exec", Arguments: map[string]any{
		"session_id": "sess-1", "command": []string{"kubectl", "delete", "pod", "x"},
	}})
	if err != nil {
		t.Fatalf("CallTool exec (should return promptly): %v", err)
	}
	if res.IsError {
		t.Fatalf("pending must NOT be a tool error: %s", resultText(res))
	}
	b, _ := json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &out)
	if out.Status != "pending" || out.ExecID != "ex-1" {
		t.Fatalf("exec out = %+v, want pending/ex-1", out)
	}
}

// Poll → approved returns the captured output; poll → denied returns the reason.
func TestExecPollApprovedAndDenied(t *testing.T) {
	f := newFakeDaemon(t)
	cs, done := connect(t, f.sockPath, Options{})
	defer done()

	type execOutT struct {
		Status   string `json:"status"`
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
		Reason   string `json:"reason"`
	}

	// Approved with output.
	code := 0
	f.approval = map[string]any{"session_id": "sess-1", "exec_id": "ex-1", "status": "approved", "ran": true, "stdout": "pod deleted\n", "exit_code": code}
	var ap execOutT
	res := callTool(t, cs, "opslify_exec", map[string]any{"session_id": "sess-1", "poll_exec_id": "ex-1"}, &ap)
	if res.IsError || ap.Status != "approved" || ap.Stdout != "pod deleted\n" {
		t.Fatalf("approved poll = %+v (err=%v)", ap, res.IsError)
	}

	// Denied with reason + comment.
	f.approval = map[string]any{"session_id": "sess-1", "exec_id": "ex-2", "status": "denied", "deny_reason": "operator", "comment": "too risky"}
	var dn execOutT
	res = callTool(t, cs, "opslify_exec", map[string]any{"session_id": "sess-1", "poll_exec_id": "ex-2"}, &dn)
	if res.IsError || dn.Status != "denied" || dn.Reason != "operator: too risky" {
		t.Fatalf("denied poll = %+v (err=%v)", dn, res.IsError)
	}
}

// SECURITY: the agent-facing MCP tool surface has NO approve/deny/resolve tool, so
// the agent cannot self-approve a gate — resolution is exclusively the human plane.
func TestNoSelfApproveToolExposed(t *testing.T) {
	f := newFakeDaemon(t)
	cs, done := connect(t, f.sockPath, Options{})
	defer done()

	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range lt.Tools {
		n := tool.Name
		if contains(n, "approve") || contains(n, "deny") || contains(n, "resolve") {
			t.Fatalf("agent tool surface must not expose a resolution capability, found %q", n)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
