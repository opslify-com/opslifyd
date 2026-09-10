package agentcontext

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTracePayloadCarriesNoContent is the F8.4 AC: instruction content never
// appears in the trace, only names, hashes and sizes. The trace is permanent and
// verifiable, so a leak here is a leak that cannot be retracted.
func TestTracePayloadCarriesNoContent(t *testing.T) {
	f := newFixture(t)
	const canary = "CANARY-instruction-text-must-not-be-traced"
	f.writeHouseRules(t, canary+" house")
	f.write(t, ".opslify/instructions.md", canary+" project")
	f.write(t, ".opslify/env/prod.md", canary+" env")
	f.write(t, ".opslify/skills/kubernetes.md", canary+" skill")

	src := f.sources()
	src.Env = "prod"
	src.ToolContracts = []ToolContract{{Tool: "kubectl", Body: canary + " contract"}}
	a, err := Assemble(src)
	if err != nil {
		t.Fatal(err)
	}

	b, err := json.Marshal(a.TracePayload())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), canary) {
		t.Fatalf("instruction content reached the trace payload:\n%s", b)
	}
	// Every layer must still be REPRESENTED, or the provenance the event exists
	// for is missing and this test could pass by emitting nothing.
	for _, name := range []string{"house-rules", "instructions", "env/prod", "skills/kubernetes", "tools/kubectl"} {
		if !strings.Contains(string(b), name) {
			t.Errorf("the trace payload omits layer %q — provenance is the point of the event", name)
		}
	}
	if !strings.Contains(string(b), a.Hash) {
		t.Error("the trace payload must carry the assembly hash, or a Change cannot bind to it")
	}
}

// TestTracePayloadShapeIsStable pins the payload keys a verifier and the UI read.
func TestTracePayloadShapeIsStable(t *testing.T) {
	f := newFixture(t)
	f.writeHouseRules(t, houseRuleText)
	f.write(t, ".opslify/skills/kubernetes.md", "Drain first.")
	src := f.sources()
	src.Capabilities = CapabilityMap{RoleOrchestration: "kubernetes", RoleDeploy: "argocd"}
	src.Roles = []string{RoleOrchestration, RoleDeploy}

	a, err := Assemble(src)
	if err != nil {
		t.Fatal(err)
	}
	p := a.TracePayload()
	for _, key := range []string{"hash", "layers", "bytes", "tokens", "budget", "overrun", "routing"} {
		if _, ok := p[key]; !ok {
			t.Errorf("payload is missing key %q", key)
		}
	}
	layers, ok := p["layers"].([]map[string]any)
	if !ok || len(layers) == 0 {
		t.Fatalf("layers = %T", p["layers"])
	}
	for _, key := range []string{"kind", "name", "hash", "bytes", "tokens"} {
		if _, ok := layers[0][key]; !ok {
			t.Errorf("layer entry is missing key %q", key)
		}
	}
	if _, ok := layers[0]["content"]; ok {
		t.Error("a layer entry must never have a content key")
	}
	routing := p["routing"].(map[string]any)
	// argocd was routed but has no pack — the trace must say so, since it explains
	// a gap in what the agent knew.
	missing, ok := routing["missing"].([]string)
	if !ok || len(missing) != 1 || missing[0] != "argocd" {
		t.Errorf("routing.missing = %v, want [argocd]", routing["missing"])
	}
}

// TestTracePayloadIsDeterministic: same instructions, same payload — the event
// lands in a hash chain, so instability would break verification.
func TestTracePayloadIsDeterministic(t *testing.T) {
	f := newFixture(t)
	f.writeHouseRules(t, houseRuleText)
	f.write(t, ".opslify/skills/a.md", "pack a")
	f.write(t, ".opslify/skills/b.md", "pack b")

	first, err := Assemble(f.sources())
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(first.TracePayload())
	for i := 0; i < 5; i++ {
		again, err := Assemble(f.sources())
		if err != nil {
			t.Fatal(err)
		}
		got, _ := json.Marshal(again.TracePayload())
		if string(got) != string(want) {
			t.Fatalf("trace payload is not deterministic:\n%s\n%s", got, want)
		}
	}
}
