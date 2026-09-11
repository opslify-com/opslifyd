package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/opslify-com/opslifyd/internal/change"
	"github.com/opslify-com/opslifyd/internal/install"
	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/policyedit"
	"github.com/opslify-com/opslifyd/internal/project"
	"gopkg.in/yaml.v3"
)

// policyLayers stores the editable policy layers as YAML documents under the
// daemon state directory.
//
// They are DAEMON-OWNED files, not repo files: an editable layer that lived in
// the checkout could be changed by an agent with commit access, which would make
// the F8.7 approval gate decorative. The repo's own policy remains a separate,
// read-only layer.
type policyLayers struct{ dir string }

func newPolicyLayers(dir string) (*policyLayers, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("opslifyd: create policy layer dir %s: %w", dir, err)
	}
	// MkdirAll does not tighten an existing directory; a layer left world-readable
	// discloses an estate's guardrails.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("opslifyd: secure policy layer dir %s: %w", dir, err)
	}
	return &policyLayers{dir: dir}, nil
}

// path renders a scope as one safe filename. The ids are already validated by
// project.ValidateName at their own trust boundary; this refuses anything that
// could still address a file outside the directory.
func (l *policyLayers) path(s policyedit.Scope) (string, error) {
	id := string(s.Layer) + "__" + s.ProjectID + "__" + s.EnvironmentID
	if id != filepath.Base(id) || id == "." || id == ".." {
		return "", fmt.Errorf("%w: unsafe policy layer id %q", policyedit.ErrInvalidInput, id)
	}
	return filepath.Join(l.dir, id+".yaml"), nil
}

func (l *policyLayers) Load(s policyedit.Scope) (policy.Policy, bool, error) {
	p, err := l.path(s)
	if err != nil {
		return policy.Policy{}, false, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			// An absent layer is an EMPTY policy, not an error: a scope that has
			// never been edited has no overlay, and refusing would make the first
			// edit impossible.
			return policy.Policy{}, false, nil
		}
		return policy.Policy{}, false, err
	}
	var out policy.Policy
	if err := yaml.Unmarshal(b, &out); err != nil {
		// Fail CLOSED: a layer that cannot be parsed must not be treated as empty,
		// because "empty" reads as "no restrictions from this layer".
		return policy.Policy{}, false, fmt.Errorf("opslifyd: policy layer %s is unparseable: %w", p, err)
	}
	return out, true, nil
}

func (l *policyLayers) Save(s policyedit.Scope, pol policy.Policy) error {
	p, err := l.path(s)
	if err != nil {
		return err
	}
	b, err := yaml.Marshal(pol)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// policyEditor adapts the F8.7 service to what the daemon routes need.
type policyEditor struct {
	layers   *policyLayers
	projects *project.Service
	svc      *policyedit.Service
	base     policy.Policy
}

// Resolved reports what is actually in force for a scope, composed through the
// F4.1 resolver so the answer is the same one a session would get.
func (e *policyEditor) Resolved(projectID, environmentID string) (policy.Resolved, error) {
	if e.projects == nil || projectID == "" {
		return policy.ResolveDefault(e.base), nil
	}
	scope, err := e.projects.ResolveScope(e.base, projectID, environmentID)
	if err != nil {
		return policy.Resolved{}, err
	}
	return scope.Resolved, nil
}

// Current returns the editable layer's OWN document — what an edit composes onto.
func (e *policyEditor) Current(s policyedit.Scope) (policy.Policy, error) {
	p, _, err := e.layers.Load(s)
	return p, err
}

func (e *policyEditor) Submit(ed policyedit.Edit, proposer change.Proposer) (policyedit.Outcome, error) {
	return e.svc.Submit(ed, proposer)
}

// buildPolicyEditor wires F8.7.
//
// The change service is REQUIRED: without it a widening edit has nowhere to be
// governed, and the service refuses rather than applying one ungoverned — so
// passing nil here would make every widening impossible rather than unsafe, which
// is the right failure but a confusing one to debug.
func buildPolicyEditor(cfg install.Config, projects *project.Service, changes *change.Service,
	base policy.Policy, newID func() string) (*policyEditor, error) {
	layers, err := newPolicyLayers(filepath.Join(filepath.Dir(cfg.WorkspaceDir), "policy-layers"))
	if err != nil {
		return nil, err
	}
	svc, err := policyedit.NewService(layers, changes, newID)
	if err != nil {
		return nil, err
	}
	return &policyEditor{layers: layers, projects: projects, svc: svc, base: base}, nil
}

// buildChangeService wires the F8.6 review surface.
//
// REQUIRED: every gated exec records a Change, and F8.7 routes a widening policy
// edit through one. A daemon without it would gate commands that no reviewer
// could reach through the review surface.
func buildChangeService(cfg install.Config, log *slog.Logger) (*change.Service, error) {
	dir := filepath.Join(filepath.Dir(cfg.WorkspaceDir), "changes")
	store, err := change.NewFileStore(dir)
	if err != nil {
		return nil, fmt.Errorf("opslifyd: change store: %w", err)
	}
	svc, err := change.NewService(store, nil)
	if err != nil {
		return nil, fmt.Errorf("opslifyd: change service: %w", err)
	}
	log.Info("F8.6 change surface active", "dir", dir)
	return svc, nil
}

// newChangeID generates an id for a policy-edit Change.
//
// Random rather than sequential: an id that counts tells anyone who sees one how
// many changes an estate has had, and ids appear in URLs an operator may paste.
func newChangeID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// A failure here is a broken system RNG. Falling back to something
		// predictable would be worse than the panic it will cause downstream, so
		// return a value that cannot be mistaken for a real id.
		return "chg-policy-entropy-failure"
	}
	return "chg-policy-" + hex.EncodeToString(b)
}
