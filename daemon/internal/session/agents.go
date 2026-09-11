package session

import (
	"github.com/opslify-com/opslifyd/internal/agents"
)

// AgentSource resolves the F8.5 agent bound to a scope.
//
// A seam so this package keeps no knowledge of the registry. It returns an error
// for "nothing bound", which is NOT fatal: opslify ships no model, so a daemon
// with no agent registered is a perfectly valid state for someone driving the CLI
// directly.
type AgentSource func(projectID, environmentID string) (agents.Agent, error)

// resolveAgent records which agent serves this session.
//
// A failure is deliberately NON-fatal, unlike the F8.4 context assembly. That
// changes what a session can DO; this only changes what it is attributed to.
// Refusing to start a session because no agent is bound would break every
// CLI-only workflow, and the registry is explicitly not a prerequisite for
// running a sandbox.
func (m *Manager) resolveAgent(s *Session) {
	if m.agents == nil {
		return
	}
	a, err := m.agents(s.ProjectID, s.EnvironmentID)
	if err != nil {
		// DEBUG, not WARN: "no agent bound" is an ordinary state, and a warning per
		// session would train operators to ignore warnings.
		m.log.Debug("session: no agent bound for this scope; the session records no agent identity",
			"session", s.ID, "project", s.ProjectID, "environment", s.EnvironmentID, "err", err)
		return
	}
	s.agentName = a.Name
	s.agentModel = a.ModelHint
	s.agentLocality = string(a.Locality)
}
