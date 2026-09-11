package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/agents"
)

// fakeAgentRegistry records what the routes handed it, so a test can assert over
// the RECORD the daemon built rather than the request it received.
type fakeAgentRegistry struct {
	added    agents.Agent
	tested   agents.Agent
	list     []agents.Agent
	bindings map[string]string
	bound    [3]string
	removed  string
	err      error

	drivenVerified bool
}

func (f *fakeAgentRegistry) Add(_ context.Context, a agents.Agent) ([]string, error) {
	f.added = a
	return []string{"tool_a"}, f.err
}

// AddDriven records the agent and runs the verifier, so a test can assert that a
// non-MCP-serving entry is checked by RUNNING it rather than by a handshake.
func (f *fakeAgentRegistry) AddDriven(ctx context.Context, a agents.Agent, verify func(context.Context, agents.Agent) error) error {
	f.added = a
	f.drivenVerified = verify != nil
	if f.err != nil {
		return f.err
	}
	return nil
}

func (f *fakeAgentRegistry) Test(_ context.Context, a agents.Agent) ([]string, error) {
	f.tested = a
	return []string{"tool_a"}, f.err
}

func (f *fakeAgentRegistry) List() ([]agents.Agent, error)        { return f.list, f.err }
func (f *fakeAgentRegistry) Bindings() (map[string]string, error) { return f.bindings, f.err }
func (f *fakeAgentRegistry) Remove(name string) error             { f.removed = name; return f.err }
func (f *fakeAgentRegistry) Use(p, e, n string) error             { f.bound = [3]string{p, e, n}; return f.err }

func agentDaemon(t *testing.T, reg AgentRegistry) http.Handler {
	t.Helper()
	d, err := New(Options{Agents: reg, Verifier: okVerifier()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d.Handler()
}

// TestOmittedLocalityIsUnknownNotLocal. This is the disclosure default, and
// getting it wrong is a lie by default: claiming prompts stay on this host when
// nobody said so is worse than saying nothing, because an operator reads the
// record later and believes it.
func TestOmittedLocalityIsUnknownNotLocal(t *testing.T) {
	reg := &fakeAgentRegistry{}
	h := agentDaemon(t, reg)
	body := `{"name":"a","command":"/usr/bin/agent"}` // no locality field at all
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/agents", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if reg.added.Locality != agents.LocalityUnknown {
		t.Fatalf("an omitted locality became %q; it must be unknown, never assumed local",
			reg.added.Locality)
	}
	// And the response must disclose it as off-host until confirmed.
	var out agentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Disclosure, "off-host") {
		t.Errorf("disclosure = %q, want it to say off-host until confirmed", out.Disclosure)
	}
	if strings.Contains(out.Disclosure, "stay on this host") {
		t.Error("an undeclared locality must not claim prompts stay local")
	}
}

// TestDisclosureTravelsWithEveryAgentResponse: it ships with the record so a UI
// cannot forget to render it, and so it is the same sentence everywhere.
func TestDisclosureTravelsWithEveryAgentResponse(t *testing.T) {
	reg := &fakeAgentRegistry{list: []agents.Agent{
		{Name: "hosted", Locality: agents.LocalityHosted},
		{Name: "local", Locality: agents.LocalityLocal},
	}}
	h := agentDaemon(t, reg)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var out agentListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, a := range out.Agents {
		if a.Disclosure == "" {
			t.Errorf("agent %s carries no disclosure", a.Name)
		}
	}
}

// TestUnusableAgentIs422NotBadRequest: the request was well-formed and the record
// is valid — the COMMAND did not answer. Conflating the two would have an
// operator re-reading their flags when the problem is their binary.
func TestUnusableAgentIs422NotBadRequest(t *testing.T) {
	reg := &fakeAgentRegistry{err: agents.ErrUnusable}
	h := agentDaemon(t, reg)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/agents",
		strings.NewReader(`{"name":"a","command":"/usr/bin/agent","locality":"local"}`)))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body.String())
	}
}

// TestAgentRoutesAreAbsentWithoutARegistry: an endpoint that exists but never
// works is worse than one that does not exist.
func TestAgentRoutesAreAbsentWithoutARegistry(t *testing.T) {
	d, err := New(Options{Verifier: okVerifier()})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/agents", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("with no registry the agent routes must be absent, got %d", rec.Code)
	}
}

// TestBindPassesTheScopeThrough.
func TestBindPassesTheScopeThrough(t *testing.T) {
	reg := &fakeAgentRegistry{}
	h := agentDaemon(t, reg)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
		"/v1/agents/qwen/bind?project=tripon&env=tripon.prod", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if reg.bound != [3]string{"tripon", "tripon.prod", "qwen"} {
		t.Errorf("bound = %v", reg.bound)
	}
}

// TestAgentRoutesCarryNoCredentialField: the request shape has no place for one,
// so a provider key cannot be put in a script that calls this API.
func TestAgentRoutesCarryNoCredentialField(t *testing.T) {
	reg := &fakeAgentRegistry{}
	h := agentDaemon(t, reg)
	// A body carrying a credential-looking field must be REFUSED (unknown field),
	// not silently ignored — silently ignoring it would let an operator believe
	// they had configured something.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/agents",
		strings.NewReader(`{"name":"a","command":"/usr/bin/agent","api_key":"CANARY"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown field must be refused, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "CANARY") {
		t.Error("the error echoed the rejected value")
	}
}
