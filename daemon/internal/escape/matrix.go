package escape

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// Cell is one probe×tier result in the published matrix.
type Cell struct {
	Probe    string   `json:"probe"`
	Category Category `json:"category"`
	Tier     string   `json:"tier"`
	Outcome  Outcome  `json:"outcome"`
	// Where records how/where this cell was produced (e.g. "podman+runsc" or
	// "netns+nft") so the public artifact is honest about what actually ran.
	Where string `json:"where,omitempty"`
}

// Matrix is the machine-readable results artifact — the "verify our claims
// yourself" public output. It is emitted after a run in both JSON and a
// human-readable table.
type Matrix struct {
	GeneratedAt time.Time `json:"generated_at"`
	Cells       []Cell    `json:"cells"`
}

// NewMatrix assembles a Matrix from the probe catalog and per-tier outcome maps.
// probes is the full registry (a probe not present in a tier's map is recorded
// N/A there). where labels the harness that produced these results.
func NewMatrix(probes []Probe, byTier map[runtime.Tier]map[string]Outcome, where string) Matrix {
	m := Matrix{GeneratedAt: time.Now().UTC()}
	tiers := make([]runtime.Tier, 0, len(byTier))
	for t := range byTier {
		tiers = append(tiers, t)
	}
	sort.Slice(tiers, func(i, j int) bool { return tiers[i] < tiers[j] })

	for _, p := range probes {
		for _, t := range tiers {
			oc, ok := byTier[t][p.Name]
			if !ok {
				if p.appliesTo(t) {
					// Applies here but no result recorded → the harness didn't run
					// it; surface as error (inconclusive), never silently green.
					oc = OutcomeError
				} else {
					oc = OutcomeNA
				}
			}
			m.Cells = append(m.Cells, Cell{
				Probe: p.Name, Category: p.Category, Tier: string(t), Outcome: oc, Where: where,
			})
		}
	}
	return m
}

// Merge folds another matrix's cells in (e.g. the isolation matrix + the egress
// matrix into one published artifact).
func (m *Matrix) Merge(other Matrix) {
	m.Cells = append(m.Cells, other.Cells...)
	if other.GeneratedAt.After(m.GeneratedAt) {
		m.GeneratedAt = other.GeneratedAt
	}
}

// AllSecure reports whether every cell is the secure posture (blocked or N/A).
// A single allowed/error cell makes the whole suite red.
func (m Matrix) AllSecure() bool {
	for _, c := range m.Cells {
		if !c.Outcome.Secure() {
			return false
		}
	}
	return true
}

// Failures returns the non-secure cells, for a legible test failure message.
func (m Matrix) Failures() []Cell {
	var out []Cell
	for _, c := range m.Cells {
		if !c.Outcome.Secure() {
			out = append(out, c)
		}
	}
	return out
}

// JSON renders the machine-readable artifact.
func (m Matrix) JSON() string {
	b, _ := json.MarshalIndent(m, "", "  ")
	return string(b)
}

// Table renders the human-readable artifact: probes as rows, tiers as columns,
// each cell blocked/allowed/n-a/error. A trailing legend states the verdict.
func (m Matrix) Table() string {
	// Collect ordered tiers and probes (stable, first-seen order).
	var tiers []string
	seenTier := map[string]bool{}
	var probeRows []string
	seenProbe := map[string]bool{}
	cat := map[string]Category{}
	cell := map[string]map[string]Outcome{} // probe -> tier -> outcome
	for _, c := range m.Cells {
		if !seenTier[c.Tier] {
			seenTier[c.Tier] = true
			tiers = append(tiers, c.Tier)
		}
		if !seenProbe[c.Probe] {
			seenProbe[c.Probe] = true
			probeRows = append(probeRows, c.Probe)
			cat[c.Probe] = c.Category
		}
		if cell[c.Probe] == nil {
			cell[c.Probe] = map[string]Outcome{}
		}
		cell[c.Probe][c.Tier] = c.Outcome
	}
	sort.Strings(tiers)

	// Column widths.
	probeW := len("PROBE")
	for _, p := range probeRows {
		if len(p) > probeW {
			probeW = len(p)
		}
	}
	catW := len("CATEGORY")
	for _, p := range probeRows {
		if l := len(cat[p]); l > catW {
			catW = l
		}
	}
	colW := make(map[string]int, len(tiers))
	for _, t := range tiers {
		colW[t] = len(t)
		if colW[t] < len("blocked") {
			colW[t] = len("blocked")
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Opslify escape/exfil results matrix — generated %s\n\n", m.GeneratedAt.Format(time.RFC3339))
	// Header.
	fmt.Fprintf(&b, "%-*s  %-*s", probeW, "PROBE", catW, "CATEGORY")
	for _, t := range tiers {
		fmt.Fprintf(&b, "  %-*s", colW[t], t)
	}
	b.WriteByte('\n')
	// Rows.
	for _, p := range probeRows {
		fmt.Fprintf(&b, "%-*s  %-*s", probeW, p, catW, string(cat[p]))
		for _, t := range tiers {
			oc := cell[p][t]
			if oc == "" {
				oc = OutcomeNA
			}
			fmt.Fprintf(&b, "  %-*s", colW[t], string(oc))
		}
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	if m.AllSecure() {
		b.WriteString("VERDICT: PASS — every probe blocked (or N/A) on every tier.\n")
	} else {
		b.WriteString("VERDICT: FAIL — the following cells are NOT secure:\n")
		for _, c := range m.Failures() {
			fmt.Fprintf(&b, "  - %s on %s: %s\n", c.Probe, c.Tier, c.Outcome)
		}
	}
	return b.String()
}
