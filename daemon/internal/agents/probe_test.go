package agents

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// buildFakeMCPServer compiles a tiny REAL MCP server and returns its path.
//
// Compiling a real one is the point: a hand-rolled JSON-RPC stub would let the
// prober pass against something the SDK would reject, which is precisely the
// mistake `agent add` exists to catch. This exercises the actual handshake.
func buildFakeMCPServer(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("fake server build is linux-only here")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(`package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	// If given a path, record the environment we were started with. That is how a
	// test asserts the REAL prober passed only allowlisted variables — asserting it
	// through the fake prober would only test the fake.
	if len(os.Args) > 1 && os.Args[1] != "" {
		_ = os.WriteFile(os.Args[1], []byte(strings.Join(os.Environ(), "\n")), 0o600)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "fake-agent", Version: "1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "fake_exec", Description: "x"},
		func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "fake_list", Description: "y"},
		func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "fake-agent")
	// Built inside the module so the SDK resolves from the existing module cache
	// rather than needing network access.
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Dir = moduleRoot(t)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build the fake MCP server here: %v\n%s", err, out)
	}
	return bin
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Skipf("go env GOMOD: %v", err)
	}
	return filepath.Dir(string(trimNewline(out)))
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// TestProberCompletesARealHandshake: the connectivity test reports the tools the
// agent exposes, against a genuine MCP server.
func TestProberCompletesARealHandshake(t *testing.T) {
	bin := buildFakeMCPServer(t)
	tools, err := NewProber().Probe(context.Background(), Agent{
		Name: "fake", Command: bin, Locality: LocalityLocal,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	want := []string{"fake_exec", "fake_list"}
	if !reflect.DeepEqual(tools, want) {
		t.Fatalf("tools = %v, want %v", tools, want)
	}
}

// TestProberRejectsANonMCPCommand is the acceptance criterion: a custom command
// that fails the handshake is unusable at BIND time, not at first task.
func TestProberRejectsANonMCPCommand(t *testing.T) {
	// /bin/true exits immediately and speaks no protocol.
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true unavailable")
	}
	_, err := NewProber().Probe(context.Background(), Agent{
		Name: "not-mcp", Command: "/bin/true", Locality: LocalityLocal,
	})
	if err == nil {
		t.Fatal("a command that speaks no MCP must be reported unusable")
	}
}

// TestProberRejectsAMissingCommand: reported as a missing binary rather than as a
// handshake failure, because those are different problems for an operator.
func TestProberRejectsAMissingCommand(t *testing.T) {
	_, err := NewProber().Probe(context.Background(), Agent{
		Name: "ghost", Command: "/nonexistent/agent-binary", Locality: LocalityLocal,
	})
	if err == nil {
		t.Fatal("a missing command must be refused")
	}
	if !contains(err.Error(), "not executable") {
		t.Errorf("the error should say the binary is missing, got %v", err)
	}
}

// TestProberRefusesAnInvalidRecord: the probe validates first, so it cannot be
// used to run an arbitrary relative command.
func TestProberRefusesAnInvalidRecord(t *testing.T) {
	_, err := NewProber().Probe(context.Background(), Agent{
		Name: "bad", Command: "relative-command", Locality: LocalityLocal,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a relative command must be refused before execution, got %v", err)
	}
}

// TestProberRegistersAgainstTheRealRegistry ties it together: a real handshake
// through Add, so the bind-time path is exercised end to end.
func TestProberRegistersAgainstTheRealRegistry(t *testing.T) {
	bin := buildFakeMCPServer(t)
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(store, NewProber(), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	tools, err := r.Add(context.Background(), Agent{
		Name: "fake", Command: bin, ModelHint: "fake-1", Locality: LocalityLocal,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(tools) != 2 {
		t.Errorf("tools = %v", tools)
	}
	// And a non-MCP command is refused by the same path.
	if _, err := r.Add(context.Background(), Agent{
		Name: "not-mcp", Command: "/bin/true", Locality: LocalityLocal,
	}); !errors.Is(err, ErrUnusable) {
		t.Errorf("a non-MCP command must be ErrUnusable at bind time, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}

// TestRealProberPassesOnlyAllowlistedEnvironment closes a gap the fake prober
// left: it computes the environment itself, so mutating the real prober to pass
// os.Environ() wholesale was invisible. Here the fake MCP server records what it
// was actually started with.
//
// It matters because a registered command is third-party code and the daemon's
// environment may hold anything an operator put there — including, in this test,
// a canary that must not cross.
func TestRealProberPassesOnlyAllowlistedEnvironment(t *testing.T) {
	bin := buildFakeMCPServer(t)
	envDump := filepath.Join(t.TempDir(), "env.txt")
	t.Setenv("AGENT_CANARY", "CANARY-must-not-reach-the-agent")
	t.Setenv("AGENT_ALLOWED", "yes")

	if _, err := NewProber().Probe(context.Background(), Agent{
		Name: "fake", Command: bin, Args: []string{envDump},
		Locality: LocalityLocal, EnvAllow: []string{"AGENT_ALLOWED"},
	}); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	body, err := os.ReadFile(envDump)
	if err != nil {
		t.Fatalf("the fake server did not record its environment: %v", err)
	}
	got := string(body)
	if contains(got, "CANARY") {
		t.Fatalf("the agent process received a non-allowlisted variable:\n%s", got)
	}
	if !contains(got, "AGENT_ALLOWED=yes") {
		t.Errorf("the allowlisted variable should have crossed:\n%s", got)
	}
}
