package agentcontext

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultBudget is the assembled-context size a session reserves for
// instructions, in estimated tokens. Overrun WARNS; it never truncates.
const DefaultBudget = 24000

// ToolContract is a generated description of what a tool can actually do in this
// session, derived from the tools present and the RESOLVED policy. It is layer 5
// and is not hand-edited, so it cannot drift from what the daemon will permit.
type ToolContract struct {
	Tool string
	// Body is the generated text. Callers build it from policy; this package does
	// not interpret it.
	Body string
}

// Sources is everything an assembly reads from. It is an explicit struct rather
// than a pile of arguments so that adding a layer later is a compile error at
// every call site instead of a silently-missing layer.
type Sources struct {
	// HouseRulesPath is the DAEMON-held layer 1. Empty uses DefaultHouseRulesPath.
	// It must never be derived from the workspace; Assemble refuses if it resolves
	// inside WorkspaceRoot.
	HouseRulesPath string
	// WorkspaceRoot is the repo checkout. UNTRUSTED: the agent can write here
	// during a session, so everything read from it is treated as data and symlinks
	// are refused.
	WorkspaceRoot string
	// Env selects the environment overlay (layer 3). Empty means none.
	Env string
	// Capabilities maps roles to tools for skill routing.
	Capabilities CapabilityMap
	// Roles are the task's role hints. Empty loads every available skill pack.
	Roles []string
	// ToolContracts are the generated layer-5 entries, in caller order.
	ToolContracts []ToolContract
	// Budget is the token budget for warning purposes. Zero uses DefaultBudget.
	Budget int
}

// Assembly is the ordered layer set with its provenance and accounting.
type Assembly struct {
	Layers []Layer `json:"layers"`
	// Hash identifies this exact instruction set. It goes into the trace and is
	// bound into a Change, so the Change can be replayed against the rules it
	// actually ran under.
	Hash    string  `json:"hash"`
	Routing Routing `json:"routing"`
	Bytes   int     `json:"bytes"`
	Tokens  int     `json:"tokens"`
	Budget  int     `json:"budget"`
	// Overrun reports that Tokens exceeds Budget. The content is STILL COMPLETE:
	// nothing is dropped or cut. An operator decides what to remove, because only
	// they know which rule is safe to lose.
	Overrun bool `json:"overrun"`
	// Warnings are operator-facing notes (budget overrun, routed packs with no
	// file). Never fatal, always shown.
	Warnings []string `json:"warnings,omitempty"`
}

// Assemble loads every layer in precedence order and returns the assembly.
//
// It FAILS CLOSED. Any unreadable or unsafe source is an error, not a skipped
// layer: a session that runs with its house rules quietly missing is precisely
// the outcome layer 1 exists to prevent, and it would be invisible — the agent
// would simply behave as if the rule had never been written.
func Assemble(s Sources) (*Assembly, error) {
	if err := validateEnvName(s.Env); err != nil {
		return nil, err
	}

	var layers []Layer

	// Layer 1 — daemon-held. Loaded FIRST and from the daemon path only.
	house, err := loadHouseRules(s.HouseRulesPath, s.WorkspaceRoot)
	if err != nil {
		return nil, err
	}
	if house != nil {
		layers = append(layers, *house)
	}

	// Layer 2 — project instructions from the repo.
	proj, err := loadProjectInstructions(s.WorkspaceRoot)
	if err != nil {
		return nil, err
	}
	if proj != nil {
		layers = append(layers, *proj)
	}

	// Layer 3 — environment overlay.
	env, err := loadEnvOverlay(s.WorkspaceRoot, s.Env)
	if err != nil {
		return nil, err
	}
	if env != nil {
		layers = append(layers, *env)
	}

	// Layer 4 — skills, routed by the capability map.
	available, err := skillsOnDisk(s.WorkspaceRoot)
	if err != nil {
		return nil, err
	}
	routing := Route(s.Capabilities, s.Roles, available)
	skills, err := loadSkills(s.WorkspaceRoot, routing.selectionSet())
	if err != nil {
		return nil, err
	}
	layers = append(layers, skills...)

	// Layer 5 — generated tool contracts.
	for _, tc := range s.ToolContracts {
		if tc.Body == "" {
			continue
		}
		layers = append(layers, *newLayer(LayerToolContract, "tools/"+tc.Tool, tc.Body))
	}

	// Sort by precedence. STABLE, so the within-layer order established above
	// (name-sorted skills, caller-ordered contracts) survives.
	if err := checkKinds(layers); err != nil {
		return nil, err
	}
	sort.SliceStable(layers, func(i, j int) bool {
		ri, _ := layers[i].Kind.Rank()
		rj, _ := layers[j].Kind.Rank()
		return ri < rj
	})

	a := &Assembly{Layers: layers, Routing: routing, Budget: s.Budget}
	if a.Budget <= 0 {
		a.Budget = DefaultBudget
	}
	for _, l := range layers {
		a.Bytes += l.Bytes
		a.Tokens += l.Tokens
	}
	if a.Bytes > maxTotalBytes {
		return nil, tooBig("the assembled context", a.Bytes, maxTotalBytes)
	}
	a.Hash = assemblyHash(layers)

	if a.Tokens > a.Budget {
		// Warn, never truncate. See Assembly.Overrun.
		a.Overrun = true
		a.Warnings = append(a.Warnings, fmt.Sprintf(
			"assembled context is ~%d tokens against a budget of %d; nothing was truncated — remove or shorten a layer (opslify context show)",
			a.Tokens, a.Budget))
	}
	for _, m := range routing.Missing {
		a.Warnings = append(a.Warnings, fmt.Sprintf(
			"no skill pack for %q (the capability map routes to it); run `opslify skill draft %s`", m, m))
	}
	return a, nil
}

// checkKinds refuses a layer whose kind has no precedence rank. An unranked kind
// would sort to position zero and could therefore precede the house rules.
func checkKinds(layers []Layer) error {
	for _, l := range layers {
		if _, ok := l.Kind.Rank(); !ok {
			return fmt.Errorf("%w: layer %q has unknown kind %q, so its precedence is undefined", ErrInvalidInput, l.Name, l.Kind)
		}
	}
	return nil
}

// Render produces the text handed to the agent: every layer in precedence order,
// each under a provenance header naming its origin and authority.
//
// The header matters. Without it the model sees one undifferentiated wall of
// text and has no way to tell a non-negotiable house rule from a repo note that
// an agent may itself have written moments ago.
func (a *Assembly) Render() string {
	var b strings.Builder
	for i, l := range a.Layers {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "<!-- opslify:layer kind=%s name=%s authority=%s -->\n", l.Kind, l.Name, authorityOf(l.Kind))
		b.WriteString(strings.TrimRight(l.Content, "\n"))
		b.WriteString("\n")
	}
	return b.String()
}

// authorityOf labels where a layer's authority comes from, so the model is told
// which text a repo commit could have changed and which it could not.
func authorityOf(k LayerKind) string {
	switch k {
	case LayerHouseRules:
		return "daemon-operator (repo cannot change)"
	case LayerToolContract:
		return "daemon-generated (authoritative)"
	default:
		return "repo (reviewed commit)"
	}
}

// Find returns the layer with a logical name, for `opslify context show`.
func (a *Assembly) Find(name string) (Layer, bool) {
	for _, l := range a.Layers {
		if l.Name == name {
			return l, true
		}
	}
	return Layer{}, false
}
