package install

import (
	"strings"

	"github.com/AlecAivazis/survey/v2"
)

// Prompter is the injectable seam over all interactive input. The real impl
// (surveyPrompter) draws a TTY checklist; tests supply ScriptedPrompter so the
// whole init flow runs headlessly with no terminal.
type Prompter interface {
	// SelectTools presents the catalog (with suggested entries pre-checked) and
	// returns the operator's chosen catalog ids. It must not require the returned
	// ids to be a subset of suggested — the operator adds and removes freely.
	SelectTools(all []CatalogEntry, suggested []string) ([]string, error)
	// AddCustom collects any extra raw Nix package names (comma/space separated
	// entries are split). Returning nil means "no custom packages".
	AddCustom() ([]CustomTool, error)
	// Confirm asks a yes/no question with a default (used for overwrite prompts
	// and the runc-fallback offer).
	Confirm(question string, def bool) (bool, error)
}

// surveyPrompter is the production Prompter backed by AlecAivazis/survey. It is
// only wired in the cobra command (a real TTY); it is never used in tests.
type surveyPrompter struct{}

// NewSurveyPrompter returns the interactive TTY prompter.
func NewSurveyPrompter() Prompter { return surveyPrompter{} }

func (surveyPrompter) SelectTools(all []CatalogEntry, suggested []string) ([]string, error) {
	sugSet := map[string]struct{}{}
	for _, s := range suggested {
		sugSet[s] = struct{}{}
	}
	opts := make([]string, len(all))
	labelToID := map[string]string{}
	var defaults []string
	for i, e := range all {
		label := e.ID + " — " + e.Desc
		opts[i] = label
		labelToID[label] = e.ID
		if _, ok := sugSet[e.ID]; ok {
			defaults = append(defaults, label)
		}
	}
	var picked []string
	q := &survey.MultiSelect{
		Message: "Select the DevOps tools your agents should have:",
		Options: opts,
		Default: defaults,
	}
	if err := survey.AskOne(q, &picked); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(picked))
	for _, p := range picked {
		ids = append(ids, labelToID[p])
	}
	return ids, nil
}

func (surveyPrompter) AddCustom() ([]CustomTool, error) {
	var raw string
	q := &survey.Input{
		Message: "Add custom Nix packages (space/comma separated, blank to skip):",
	}
	if err := survey.AskOne(q, &raw); err != nil {
		return nil, err
	}
	return parseCustom(raw), nil
}

func (surveyPrompter) Confirm(question string, def bool) (bool, error) {
	ans := def
	q := &survey.Confirm{Message: question, Default: def}
	if err := survey.AskOne(q, &ans); err != nil {
		return false, err
	}
	return ans, nil
}

// parseCustom splits a free-form list of Nix package names into CustomTools,
// supporting an optional "@version" pin per entry.
func parseCustom(raw string) []CustomTool {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	var out []CustomTool
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		name, ver := f, ""
		if i := strings.IndexByte(f, '@'); i > 0 {
			name, ver = f[:i], f[i+1:]
		}
		out = append(out, CustomTool{NixPackage: name, Version: ver})
	}
	return out
}

// ScriptedPrompter is a headless Prompter for tests and non-interactive runs. It
// returns pre-programmed answers with no TTY.
type ScriptedPrompter struct {
	Tools       []string
	Custom      []CustomTool
	ConfirmFunc func(question string, def bool) bool
}

func (p ScriptedPrompter) SelectTools(_ []CatalogEntry, suggested []string) ([]string, error) {
	if p.Tools != nil {
		return p.Tools, nil
	}
	return suggested, nil // default: accept the suggestion set unchanged
}

func (p ScriptedPrompter) AddCustom() ([]CustomTool, error) { return p.Custom, nil }

func (p ScriptedPrompter) Confirm(question string, def bool) (bool, error) {
	if p.ConfirmFunc != nil {
		return p.ConfirmFunc(question, def), nil
	}
	return def, nil
}
