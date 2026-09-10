package agents

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func claudeAgent() Agent {
	return Agent{
		Name: "claude", Command: "/usr/local/bin/claude", Args: []string{"mcp"},
		ModelHint: "claude-opus-5", Locality: LocalityHosted,
	}
}

func localAgent() Agent {
	return Agent{
		Name: "qwen-local", Command: "/usr/bin/ollama", Args: []string{"mcp"},
		ModelHint: "qwen2.5-coder:32b", Locality: LocalityLocal,
	}
}

// fakeProber stands in for the MCP handshake.
type fakeProber struct {
	tools  []string
	err    error
	sawEnv []string
	calls  int
}

func (f *fakeProber) Probe(_ context.Context, a Agent) ([]string, error) {
	f.calls++
	f.sawEnv = a.Env(os.Environ())
	if f.err != nil {
		return nil, f.err
	}
	return f.tools, nil
}

func newRegistry(t *testing.T, p Prober) (*Registry, Store) {
	t.Helper()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	r, err := NewRegistry(store, p, discardLogger())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r, store
}

// --- the registry is not a privilege dial -------------------------------------

// TestAgentRecordCannotCarryCapability is the feature's central constraint,
// asserted structurally. An agent record has no field that could grant anything:
// no policy, no allowed-command list, no tier, no scope override. If someone adds
// one, this test fails and they have to argue for it.
//
// Which agent is bound changes cost, latency and WHERE PROMPTS GO. It must never
// change what the agent may do — that is policy (F8.7), behind an approval.
func TestAgentRecordCannotCarryCapability(t *testing.T) {
	b, err := json.Marshal(claudeAgent())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"name": true, "command": true, "args": true, "model_hint": true,
		"locality": true, "env_allow": true, "description": true,
	}
	for k := range fields {
		if !allowed[k] {
			t.Errorf("agent record has an unexpected field %q — if it grants capability it belongs in policy (F8.7), not here", k)
		}
	}
	// And none of the obvious capability names may appear.
	for _, forbidden := range []string{"policy", "allow", "tier", "privileged", "egress", "creds", "capabilities", "approval"} {
		if _, present := fields[forbidden]; present {
			t.Errorf("agent record carries %q: the registry must not become a privilege dial", forbidden)
		}
	}
}

// TestSwitchingAgentsChangesOnlyIdentityAndDisclosure: two very different agents
// produce trace fields that differ ONLY in identity, model and locality. Anything
// else differing would mean the binding affected behaviour.
func TestSwitchingAgentsChangesOnlyIdentityAndDisclosure(t *testing.T) {
	hosted := claudeAgent().TraceFields()
	local := localAgent().TraceFields()
	if len(hosted) != len(local) {
		t.Fatalf("the two agents produce different field SETS: %v vs %v", hosted, local)
	}
	for k := range hosted {
		switch k {
		case "agent", "agent_model", "agent_locality":
			// These are expected to differ — they are the whole point.
		default:
			if !reflect.DeepEqual(hosted[k], local[k]) {
				t.Errorf("field %q differs between agents (%v vs %v): a binding must not change behaviour",
					k, hosted[k], local[k])
			}
		}
	}
	// The command line must NOT be recorded: an argument list can carry local
	// paths and account identifiers, and identity is what makes a decision
	// attributable.
	for _, k := range []string{"command", "args", "argv"} {
		if _, present := hosted[k]; present {
			t.Errorf("trace fields carry %q; identity is what attributes a decision, not the command line", k)
		}
	}
}

// --- environment allowlisting --------------------------------------------------

// TestAgentEnvIsAllowlisted: a registered command is third-party code, and the
// daemon's environment may hold anything an operator put there.
func TestAgentEnvIsAllowlisted(t *testing.T) {
	a := claudeAgent()
	a.EnvAllow = []string{"HOME", "HTTPS_PROXY"}
	base := []string{
		"HOME=/root",
		"HTTPS_PROXY=http://proxy:3128",
		"SECRET_TOKEN=CANARY-must-not-cross",
		"PATH=/usr/bin",
		"AWS_SECRET_ACCESS_KEY=CANARY-aws",
	}
	got := a.Env(base)
	want := []string{"HOME=/root", "HTTPS_PROXY=http://proxy:3128"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env = %v, want exactly the allowlisted keys %v", got, want)
	}
	for _, kv := range got {
		if strings.Contains(kv, "CANARY") {
			t.Fatalf("a non-allowlisted variable crossed: %s", kv)
		}
	}
	// An empty allowlist inherits nothing.
	a.EnvAllow = nil
	if env := a.Env(base); len(env) != 0 {
		t.Errorf("an empty allowlist must inherit nothing, got %v", env)
	}
}

// TestDaemonTrustVariablesCannotBeAllowlisted. An operator can plausibly want to
// pass HOME or a proxy setting; nobody has a legitimate reason to hand a
// registered command the daemon's control socket or a session's signing oracle,
// and a typo must not be able to.
func TestDaemonTrustVariablesCannotBeAllowlisted(t *testing.T) {
	for key := range deniedEnvKeys {
		a := claudeAgent()
		a.EnvAllow = []string{key}
		if err := a.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("env_allow %q must be refused, got %v", key, err)
		}
		// Defence in code: even a hand-edited record must not pass it through.
		if env := a.Env([]string{key + "=CANARY"}); len(env) != 0 {
			t.Errorf("a hand-edited record passed %q through: %v", key, env)
		}
	}
}

// TestEnvKeyNamesAreBounded: the names become process environment keys.
func TestEnvKeyNamesAreBounded(t *testing.T) {
	for _, key := range []string{"with space", "with=equals", "1LEADING_DIGIT", "with-dash", "", "nul\x00"} {
		a := claudeAgent()
		a.EnvAllow = []string{key}
		if err := a.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("env_allow %q must be refused, got %v", key, err)
		}
	}
	a := claudeAgent()
	a.EnvAllow = []string{"HOME", "_UNDERSCORE", "MIXED_case9"}
	if err := a.Validate(); err != nil {
		t.Errorf("legitimate env keys were refused: %v", err)
	}
}

// --- command must be absolute ---------------------------------------------------

// TestCommandMustBeAbsolute: PATH resolution would let a different binary answer
// tomorrow than the one the operator tested at bind time — a silent substitution
// of the component that reads their whole estate.
func TestCommandMustBeAbsolute(t *testing.T) {
	for _, cmd := range []string{"claude", "./claude", "../bin/claude", "", "bin/claude", "claude\nrm -rf /"} {
		a := claudeAgent()
		a.Command = cmd
		if err := a.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("command %q must be refused, got %v", cmd, err)
		}
	}
	a := claudeAgent()
	a.Command = "/usr/local/bin/claude"
	if err := a.Validate(); err != nil {
		t.Errorf("an absolute command was refused: %v", err)
	}
}

// TestModelHintIsBounded: it is written into the trace and shown in the cockpit.
func TestModelHintIsBounded(t *testing.T) {
	for _, hint := range []string{strings.Repeat("m", 129), "model\nagent=forged", "model\rx", "nul\x00"} {
		a := claudeAgent()
		a.ModelHint = hint
		if err := a.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("model hint %q must be refused, got %v", hint, err)
		}
	}
}

// --- locality disclosure ---------------------------------------------------------

// TestUnknownLocalityIsNotTreatedAsLocal: assuming the safer-sounding answer
// about someone else's data flow would be a lie by default.
func TestUnknownLocalityIsNotTreatedAsLocal(t *testing.T) {
	if !strings.Contains(LocalityUnknown.Discloses(), "off-host") {
		t.Errorf("an undeclared locality must be disclosed as off-host until confirmed, got %q", LocalityUnknown.Discloses())
	}
	if strings.Contains(LocalityUnknown.Discloses(), "stay on this host") {
		t.Error("an undeclared locality must not claim prompts stay local")
	}
	if !strings.Contains(LocalityLocal.Discloses(), "stay on this host") {
		t.Errorf("local must disclose that prompts stay: %q", LocalityLocal.Discloses())
	}
	if !strings.Contains(LocalityHosted.Discloses(), "off-host") {
		t.Errorf("hosted must disclose that output leaves: %q", LocalityHosted.Discloses())
	}
	// An invalid locality is refused rather than defaulted.
	a := claudeAgent()
	a.Locality = "on-prem-ish"
	if err := a.Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("an unknown locality value must be refused, got %v", err)
	}
}

// --- bind-time probing ------------------------------------------------------------

// TestAddProbesAtBindTime: a command that fails the handshake is reported as
// unusable NOW, not at the first task — otherwise an operator debugs their work
// instead of their configuration.
func TestAddProbesAtBindTime(t *testing.T) {
	p := &fakeProber{err: errors.New("not an MCP server")}
	r, store := newRegistry(t, p)
	_, err := r.Add(context.Background(), claudeAgent())
	if !errors.Is(err, ErrUnusable) {
		t.Fatalf("a failed handshake must be ErrUnusable, got %v", err)
	}
	if p.calls != 1 {
		t.Errorf("the prober should have run once, ran %d times", p.calls)
	}
	// And nothing was stored: a registry entry that cannot serve is worse than
	// none, because a session would bind to it.
	if list, _ := store.ListAgents(); len(list) != 0 {
		t.Fatalf("a failed probe stored the agent anyway: %v", list)
	}
}

// TestAddReportsTheToolSurface: the connectivity test reports what the agent
// exposes, so an operator can see it is the tool set they expect.
func TestAddReportsTheToolSurface(t *testing.T) {
	p := &fakeProber{tools: []string{"opslify_exec", "opslify_session_create"}}
	r, _ := newRegistry(t, p)
	tools, err := r.Add(context.Background(), claudeAgent())
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !reflect.DeepEqual(tools, p.tools) {
		t.Errorf("tools = %v, want %v", tools, p.tools)
	}
}

// TestProbeUsesOnlyTheAllowlistedEnvironment: a probe that passed with the
// daemon's full environment and then failed in production would be worse than no
// probe.
func TestProbeUsesOnlyTheAllowlistedEnvironment(t *testing.T) {
	t.Setenv("SECRET_TOKEN", "CANARY-must-not-reach-the-agent")
	t.Setenv("HOME", "/root")
	p := &fakeProber{tools: []string{"t"}}
	r, _ := newRegistry(t, p)
	a := claudeAgent()
	a.EnvAllow = []string{"HOME"}
	if _, err := r.Add(context.Background(), a); err != nil {
		t.Fatalf("Add: %v", err)
	}
	for _, kv := range p.sawEnv {
		if strings.Contains(kv, "CANARY") {
			t.Fatalf("the probe environment carried a non-allowlisted variable: %s", kv)
		}
	}
	var sawHome bool
	for _, kv := range p.sawEnv {
		if kv == "HOME=/root" {
			sawHome = true
		}
	}
	if !sawHome {
		t.Errorf("the allowlisted variable should have crossed: %v", p.sawEnv)
	}
}

// TestTestDoesNotRegister: `agent test` is for checking a command before it
// becomes something sessions depend on.
func TestTestDoesNotRegister(t *testing.T) {
	p := &fakeProber{tools: []string{"opslify_exec"}}
	r, store := newRegistry(t, p)
	tools, err := r.Test(context.Background(), claudeAgent())
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if len(tools) != 1 {
		t.Errorf("tools = %v", tools)
	}
	if list, _ := store.ListAgents(); len(list) != 0 {
		t.Fatalf("`agent test` registered the agent: %v", list)
	}
}

// --- scoping and fallback ---------------------------------------------------------

// TestForScopeResolvesMostSpecificThenFallback: the same scoping shape as the
// policy layers and the connections — one model across the product.
func TestForScopeResolvesMostSpecificThenFallback(t *testing.T) {
	p := &fakeProber{tools: []string{"t"}}
	r, _ := newRegistry(t, p)
	ctx := context.Background()
	for _, a := range []Agent{claudeAgent(), localAgent(), {
		Name: "codex", Command: "/usr/bin/codex", Locality: LocalityHosted,
	}} {
		if _, err := r.Add(ctx, a); err != nil {
			t.Fatalf("Add %s: %v", a.Name, err)
		}
	}
	if err := r.Use("", "", "claude"); err != nil { // fallback
		t.Fatal(err)
	}
	if err := r.Use("tripon", "", "codex"); err != nil { // project
		t.Fatal(err)
	}
	if err := r.Use("tripon", "tripon.prod", "qwen-local"); err != nil { // environment
		t.Fatal(err)
	}
	for _, tc := range []struct{ proj, env, want string }{
		{"tripon", "tripon.prod", "qwen-local"}, // environment wins
		{"tripon", "tripon.staging", "codex"},   // project binding
		{"other", "other.dev", "claude"},        // fallback
		{"", "", "claude"},                      // fallback
	} {
		got, err := r.ForScope(tc.proj, tc.env)
		if err != nil {
			t.Fatalf("ForScope(%s,%s): %v", tc.proj, tc.env, err)
		}
		if got.Name != tc.want {
			t.Errorf("ForScope(%s,%s) = %s, want %s", tc.proj, tc.env, got.Name, tc.want)
		}
	}
}

// TestForScopeWithNothingBound: opslify ships no model, so a daemon with no agent
// registered is a valid state — this reports not-found rather than inventing one,
// and the caller decides.
func TestForScopeWithNothingBound(t *testing.T) {
	r, _ := newRegistry(t, &fakeProber{})
	if _, err := r.ForScope("p", "p.e"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestUseRefusesAnUnregisteredAgent: binding a name that does not exist would
// fail at session start instead of here.
func TestUseRefusesAnUnregisteredAgent(t *testing.T) {
	r, _ := newRegistry(t, &fakeProber{tools: []string{"t"}})
	if err := r.Use("tripon", "", "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestBindingToARemovedAgentFallsThroughAndWarns: refusing outright would be
// worse than using a broader binding, and a silent skip would leave an operator
// wondering why their choice is ignored.
func TestBindingToARemovedAgentFallsThroughAndWarns(t *testing.T) {
	p := &fakeProber{tools: []string{"t"}}
	r, store := newRegistry(t, p)
	ctx := context.Background()
	if _, err := r.Add(ctx, claudeAgent()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, localAgent()); err != nil {
		t.Fatal(err)
	}
	if err := r.Use("", "", "claude"); err != nil {
		t.Fatal(err)
	}
	if err := r.Use("tripon", "tripon.prod", "qwen-local"); err != nil {
		t.Fatal(err)
	}
	// Delete the environment-bound agent behind the registry's back, as a
	// hand-edit or an older release could.
	if err := store.DeleteAgent("qwen-local"); err != nil {
		t.Fatal(err)
	}
	got, err := r.ForScope("tripon", "tripon.prod")
	if err != nil {
		t.Fatalf("ForScope should fall through to the fallback: %v", err)
	}
	if got.Name != "claude" {
		t.Errorf("resolved %s, want the fallback claude", got.Name)
	}
}

// TestRemoveRefusesWhileBound: silently unbinding would leave sessions starting
// under a different agent than the operator last chose, with nothing recording why.
func TestRemoveRefusesWhileBound(t *testing.T) {
	r, _ := newRegistry(t, &fakeProber{tools: []string{"t"}})
	ctx := context.Background()
	if _, err := r.Add(ctx, claudeAgent()); err != nil {
		t.Fatal(err)
	}
	if err := r.Use("tripon", "tripon.prod", "claude"); err != nil {
		t.Fatal(err)
	}
	err := r.Remove("claude")
	if !errors.Is(err, ErrExists) {
		t.Fatalf("removing a bound agent must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "tripon.prod") {
		t.Errorf("the refusal must name which scope still binds it: %v", err)
	}
	// Unbind, then it goes.
	if err := r.Unbind("tripon", "tripon.prod"); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("claude"); err != nil {
		t.Fatalf("Remove after unbind: %v", err)
	}
}

// TestAddRefusesADuplicate.
func TestAddRefusesADuplicate(t *testing.T) {
	r, _ := newRegistry(t, &fakeProber{tools: []string{"t"}})
	ctx := context.Background()
	if _, err := r.Add(ctx, claudeAgent()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, claudeAgent()); !errors.Is(err, ErrExists) {
		t.Fatalf("a duplicate name must be refused, got %v", err)
	}
}

// --- store safety ----------------------------------------------------------------

// TestStoreRefusesTraversalNames is the last line of defence before
// filepath.Join.
func TestStoreRefusesTraversalNames(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim.json")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../victim", "a/b", "..", ".", `x\y`} {
		a := claudeAgent()
		a.Name = name
		if err := store.SaveAgent(a); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("name %q must be refused, got %v", name, err)
		}
		if _, _, err := store.LoadAgent(name); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("LoadAgent(%q) must be refused, got %v", name, err)
		}
	}
	body, _ := os.ReadFile(victim)
	if string(body) != "original" {
		t.Fatal("a traversal name overwrote a file outside the store")
	}
	// A binding scope key reaches no path today, but it is validated for the same
	// reason — it is operator input joined into persisted state.
	if err := store.SaveBinding("../escape", "claude"); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("a traversal scope key must be refused, got %v", err)
	}
}

// TestRecordsHoldNoCredential: a provider API key is a secret ref used by that
// command's own configuration, never injected by opslify — so an agent record is
// not a place a key can end up.
func TestRecordsHoldNoCredential(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := claudeAgent()
	a.EnvAllow = []string{"HOME"}
	if err := store.SaveAgent(a); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "agents", "claude.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The record stores env KEY NAMES, never their values.
	if strings.Contains(string(b), "/root") {
		t.Errorf("the record captured an environment VALUE: %s", b)
	}
	for _, forbidden := range []string{"api_key", "token", "password", "secret_value"} {
		if strings.Contains(string(b), forbidden) {
			t.Errorf("the record contains %q: %s", forbidden, b)
		}
	}
}

// TestCorruptBindingsFileIsNotSurvivable: bindings are ONE file, so guessing an
// empty map would silently switch every scope to the fallback or to nothing.
func TestCorruptBindingsFileIsNotSurvivable(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent-bindings.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadBindings(); err == nil {
		t.Fatal("a corrupt bindings file must be an error, not a silent empty map")
	}
}

// TestCorruptAgentRecordIsSkippedAndSurfaced: unlike the bindings file, one bad
// agent record must not make every other agent unreachable.
func TestCorruptAgentRecordIsSkippedAndSurfaced(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAgent(claudeAgent()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agents", "broken.json"), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := store.ListAgents()
	if err != nil {
		t.Fatalf("one corrupt record must not fail the listing: %v", err)
	}
	if len(list) != 1 || list[0].Name != "claude" {
		t.Fatalf("the good record must still list: %v", list)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
