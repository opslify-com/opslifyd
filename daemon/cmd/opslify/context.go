package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/opslify-com/opslifyd/internal/agentcontext"
	"github.com/spf13/cobra"
)

// contextCmd is the F8.4 operator surface over the assembled instruction set:
// what the agent will actually be told, where each part came from, and what it
// costs. It runs LOCALLY against the repo and the daemon's house-rules file —
// there is no daemon round-trip, because assembly is pure and an operator
// checking their instructions should not need a running daemon.
func contextCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "context",
		Short: "Inspect the layered instructions an agent runs under (show, diff)",
	}
	cmd.AddCommand(contextShowCmd(), contextDiffCmd())
	return cmd
}

// contextFlags are the inputs shared by show and diff.
type contextFlags struct {
	root       string
	houseRules string
	env        string
	roles      []string
	caps       []string
	budget     int
}

func (f *contextFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.root, "workspace", ".", "repo root to read .opslify/ from")
	cmd.Flags().StringVar(&f.houseRules, "house-rules", "", "daemon house-rules file (default "+agentcontext.DefaultHouseRulesPath+")")
	cmd.Flags().StringVar(&f.env, "env", "", "environment overlay to include")
	cmd.Flags().StringSliceVar(&f.roles, "role", nil, "route skills for these capability roles (default: load every pack)")
	cmd.Flags().StringSliceVar(&f.caps, "capability", nil, "role=tool (repeatable), for routing")
	cmd.Flags().IntVar(&f.budget, "budget", 0, "token budget to warn against (default "+fmt.Sprint(agentcontext.DefaultBudget)+")")
}

func (f *contextFlags) assemble() (*agentcontext.Assembly, error) {
	root, err := filepath.Abs(f.root)
	if err != nil {
		return nil, err
	}
	caps, err := parseCapabilities(f.caps)
	if err != nil {
		return nil, err
	}
	return agentcontext.Assemble(agentcontext.Sources{
		HouseRulesPath: f.houseRules,
		WorkspaceRoot:  root,
		Env:            f.env,
		Capabilities:   agentcontext.CapabilityMap(caps),
		Roles:          f.roles,
		Budget:         f.budget,
	})
}

func contextShowCmd() *cobra.Command {
	var f contextFlags
	var render bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the assembled layers, their provenance, and their token cost",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := f.assemble()
			if err != nil {
				return err
			}
			if render {
				// The exact text an agent is given. Useful for review, and the reason
				// it is opt-in: it is long, and printing it by default would bury the
				// accounting that `show` exists for.
				fmt.Fprint(cmd.OutOrStdout(), a.Render())
				return nil
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "hash    %s\n", a.Hash)
			fmt.Fprintf(out, "tokens  ~%d of %d budgeted", a.Tokens, a.Budget)
			if a.Overrun {
				fmt.Fprint(out, "  OVER BUDGET")
			}
			fmt.Fprintf(out, "\nbytes   %d\n\n", a.Bytes)

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "LAYER\tKIND\tAUTHORITY\tBYTES\t~TOKENS\tHASH")
			for _, l := range a.Layers {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\n",
					l.Name, l.Kind, authorityLabel(l.Kind), l.Bytes, l.Tokens, short(l.Hash))
			}
			tw.Flush()

			if a.Routing.LoadedAll {
				fmt.Fprintf(out, "\nrouting  every skill pack loaded (no --role given)\n")
			} else {
				fmt.Fprintf(out, "\nrouting  roles %s -> packs %s\n",
					strings.Join(a.Routing.Roles, ","), strings.Join(a.Routing.Selected, ","))
			}
			for _, w := range a.Warnings {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", w)
			}
			return nil
		},
	}
	f.bind(cmd)
	cmd.Flags().BoolVar(&render, "render", false, "print the exact text the agent is given")
	return cmd
}

// contextDiffCmd compares the assembly against a previously recorded hash, so an
// operator can answer "did the instructions change since that Change ran?"
// without needing the old text.
func contextDiffCmd() *cobra.Command {
	var f contextFlags
	var against string
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare the current assembly against a recorded hash",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := f.assemble()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if against == "" {
				return fmt.Errorf("--against <hash> is required (take it from a Change or a context.assemble trace event)")
			}
			if a.Hash == against {
				fmt.Fprintf(out, "unchanged  %s\n", a.Hash)
				return nil
			}
			// The layer hashes are what make this useful: a whole-assembly hash only
			// says "something moved", which is not actionable.
			fmt.Fprintf(out, "CHANGED\n  recorded %s\n  current  %s\n\nper-layer hashes now:\n", against, a.Hash)
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			for _, l := range a.Layers {
				fmt.Fprintf(tw, "  %s\t%s\n", l.Name, short(l.Hash))
			}
			tw.Flush()
			fmt.Fprintf(out, "\nThe recorded hash cannot be decomposed into layers — it is a digest.\n"+
				"To see WHAT changed, diff the files in git: .opslify/ and the daemon's house-rules file.\n")
			return nil
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&against, "against", "", "the recorded assembly hash to compare with")
	return cmd
}

// skillCmd manages the per-tool knowledge packs.
func skillCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "skill",
		Short: "Manage per-tool skill packs (add, ls)",
		Long: "Skill packs are knowledge about YOUR estate, one per tool.\n\n" +
			"They are data, not permission: nothing in a pack widens what a session may do — " +
			"that is policy, enforced by the daemon.",
	}
	cmd.AddCommand(skillAddCmd(), skillLsCmd())
	return cmd
}

func skillAddCmd() *cobra.Command {
	var root string
	cmd := &cobra.Command{
		Use:   "add <tool>",
		Short: "Scaffold a starter skill pack for a tool (never overwrites)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			abs, err := filepath.Abs(root)
			if err != nil {
				return err
			}
			rel, created, err := agentcontext.ScaffoldSkill(abs, args[0])
			if err != nil {
				return err
			}
			if !created {
				fmt.Fprintf(cmd.OutOrStdout(), "%s already exists — left untouched\n", rel)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "created %s\n\nIt is a set of prompts, not filler: fill in what an agent could not guess\nabout your estate, then commit it like any other change.\n", rel)
			return nil
		},
	}
	cmd.Flags().StringVar(&root, "workspace", ".", "repo root")
	return cmd
}

func skillLsCmd() *cobra.Command {
	var root string
	var f contextFlags
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List the skill packs in this repo and their size",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			abs, err := filepath.Abs(root)
			if err != nil {
				return err
			}
			f.root = abs
			a, err := f.assemble()
			if err != nil {
				return err
			}
			var packs []agentcontextLayerRow
			for _, l := range a.Layers {
				if l.Kind == agentcontext.LayerSkill {
					packs = append(packs, agentcontextLayerRow{
						name: strings.TrimPrefix(l.Name, "skills/"), bytes: l.Bytes, tokens: l.Tokens, hash: l.Hash,
					})
				}
			}
			sort.Slice(packs, func(i, j int) bool { return packs[i].name < packs[j].name })
			if len(packs) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "no skill packs in %s\nRun `opslify skill add <tool>` to scaffold one.\n",
					filepath.Join(".opslify", "skills"))
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "TOOL\tBYTES\t~TOKENS\tHASH")
			for _, p := range packs {
				fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", p.name, p.bytes, p.tokens, short(p.hash))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&root, "workspace", ".", "repo root")
	return cmd
}

type agentcontextLayerRow struct {
	name   string
	bytes  int
	tokens int
	hash   string
}

// authorityLabel says who can change a layer — the distinction that makes the
// listing worth reading.
func authorityLabel(k agentcontext.LayerKind) string {
	switch k {
	case agentcontext.LayerHouseRules:
		return "daemon (repo cannot change)"
	case agentcontext.LayerToolContract:
		return "daemon-generated"
	default:
		return "repo"
	}
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
