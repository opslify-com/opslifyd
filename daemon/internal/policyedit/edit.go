// Package policyedit makes guardrail changes governable.
//
// Operators need to add an egress host or a gate without editing YAML on the host
// and restarting the daemon. But an edit surface that applies anything an
// operator asks for is not a guardrail — so the direction of the edit decides how
// it is treated:
//
//   - NARROWING applies immediately and ungated. Tightening during an incident
//     must never wait for an approver.
//   - WIDENING becomes a Change (F8.6) and does not take effect until approved.
//     That is what makes "who opened this, when, and who approved it" answerable
//     a year later.
//
// Two things are structurally impossible here rather than merely refused: editing
// the DAEMON layer (which is the operator's host-side baseline and the thing
// every other layer can only narrow), and applying a widening without an approved
// Change.
package policyedit

import (
	"errors"
	"fmt"
	"strings"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// ErrInvalidInput marks a malformed edit.
var ErrInvalidInput = errors.New("policyedit: invalid input")

// ErrReadOnlyLayer is returned for any attempt to edit a layer this surface does
// not own.
//
// Its own error because it is not a validation failure — the request is
// well-formed and the operator may well have the authority. It is the wrong
// ROUTE: the daemon baseline is host-side by design, and being told that is more
// useful than being told the input was bad.
var ErrReadOnlyLayer = errors.New("policyedit: layer is read-only through this surface")

// ErrNeedsApproval is returned when a widening edit was submitted without going
// through a Change.
var ErrNeedsApproval = errors.New("policyedit: this edit widens the guardrails and needs an approved change")

// Layer names an editable policy layer.
type Layer string

const (
	// LayerDaemon is the host-side baseline. READ-ONLY here: it is the thing every
	// other layer can only narrow, so an edit surface that could widen it would
	// make the whole precedence model meaningless.
	LayerDaemon Layer = "daemon"
	// LayerProject is a project-wide overlay.
	LayerProject Layer = "project"
	// LayerEnvironment is one environment's overlay.
	LayerEnvironment Layer = "environment"
	// LayerWorkspace is the repo-supplied policy. READ-ONLY here because it is
	// UNTRUSTED input, not daemon state — it lives in the repo and is edited by a
	// reviewed commit, which is a stronger control than this surface offers.
	LayerWorkspace Layer = "workspace"
)

// Editable reports whether this surface owns a layer.
func (l Layer) Editable() bool {
	return l == LayerProject || l == LayerEnvironment
}

// Scope identifies which layer of which project/environment an edit targets.
type Scope struct {
	Layer         Layer
	ProjectID     string
	EnvironmentID string
}

// Validate checks an edit target.
func (s Scope) Validate() error {
	switch {
	case s.Layer == "":
		return fmt.Errorf("%w: an edit must name a layer", ErrInvalidInput)
	case !s.Layer.Editable():
		return fmt.Errorf("%w: the %s layer is not editable here (%s)", ErrReadOnlyLayer, s.Layer, whyReadOnly(s.Layer))
	case s.Layer == LayerProject && s.ProjectID == "":
		return fmt.Errorf("%w: a project-layer edit must name a project", ErrInvalidInput)
	case s.Layer == LayerEnvironment && s.EnvironmentID == "":
		return fmt.Errorf("%w: an environment-layer edit must name an environment", ErrInvalidInput)
	}
	return nil
}

// whyReadOnly explains a refusal in terms an operator can act on.
func whyReadOnly(l Layer) string {
	switch l {
	case LayerDaemon:
		return "the daemon baseline is host-side by design: every other layer can only narrow it, " +
			"so edit /etc/opslify/policy.yaml and reload"
	case LayerWorkspace:
		return "the workspace policy lives in the repo and changes by a reviewed commit, " +
			"which is a stronger control than this surface"
	default:
		return "unknown layer"
	}
}

// Edit is a requested change to one layer, expressed as the policy it should
// become.
//
// Whole-document rather than a patch language on purpose: the classifier compares
// two policies, and a patch would have to be applied before it could be
// classified — which means the thing being approved and the thing being applied
// would be different representations, with a translation step between them. That
// is exactly the gap a pinned plan exists to close.
type Edit struct {
	Scope Scope
	// To is the layer's policy after the edit.
	To policy.Policy
	// Reason is the operator's stated purpose, carried into the Change.
	Reason string
}

// Outcome is what happened to an edit.
type Outcome struct {
	// Applied reports whether the edit took effect now.
	Applied bool
	// ChangeID is set when the edit was routed through a Change for approval.
	ChangeID string
	// Classification explains the decision, including every widening found.
	Classification policy.Classification
}

// Summary renders the outcome for an operator.
func (o Outcome) Summary() string {
	switch {
	case o.Applied && o.Classification.Direction == policy.DirectionEquivalent:
		return "no effective change"
	case o.Applied:
		return "applied now (narrowing): " + strings.Join(o.Classification.Narrowings, "; ")
	default:
		return "needs approval (widening): " + strings.Join(o.Classification.Widenings, "; ")
	}
}
