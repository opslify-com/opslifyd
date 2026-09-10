package session

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/egressproxy"
)

// ConnectionSource resolves the F8.2 connections in force for one scope.
//
// A seam rather than a concrete store so this package keeps no knowledge of how
// connections are persisted. Returning an error is FATAL to session creation: a
// session that silently runs without a connection an operator configured would
// fail later, inside the agent's work, as a confusing permission error.
type ContextConnectionSource func(projectID, environmentID string) ([]broker.Connection, error)

// sessionConnections is the per-session state the connection kinds allocated.
type sessionConnections struct {
	// closers tear down agents, listeners and sockets. Nothing a kind allocated
	// may outlive the session.
	closers []io.Closer
	// excluded is the set of refs resolved at a connection boundary, which must
	// therefore never reach F5.1 environment injection.
	excluded map[string]bool
}

// close tears everything down, continuing past the first failure so one stuck
// closer cannot leave the rest running — a leaked agent socket is a live signing
// endpoint.
func (sc *sessionConnections) close() error {
	if sc == nil {
		return nil
	}
	var firstErr error
	for _, c := range sc.closers {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	sc.closers = nil
	return firstErr
}

// resolveConnections builds the connections for a session's scope and records
// which refs they resolve.
//
// This runs BEFORE credential injection, which is why the exclusion set is
// derived from SecretRefs (available now) rather than from the injection a kind
// produces later (available only after the proxy exists).
func (m *Manager) resolveConnections(s *Session) ([]broker.Connection, error) {
	if m.connections == nil {
		return nil, nil
	}
	conns, err := m.connections(s.ProjectID, s.EnvironmentID)
	if err != nil {
		return nil, fmt.Errorf("session: resolve connections for %s/%s: %w", s.ProjectID, s.EnvironmentID, err)
	}
	if len(conns) == 0 {
		return nil, nil
	}
	state := &sessionConnections{excluded: map[string]bool{}}
	for _, c := range conns {
		for _, ref := range c.SecretRefs() {
			state.excluded[ref] = true
		}
	}
	s.conns = state
	return conns, nil
}

// connectionEgressRules collects phase-one rules from every connection, for the
// per-session proxy to be built from.
func connectionEgressRules(conns []broker.Connection) []egressproxy.InjectRule {
	var out []egressproxy.InjectRule
	for _, c := range conns {
		for _, r := range c.EgressRules() {
			out = append(out, egressproxy.InjectRule{
				Host:         r.Host,
				CredRef:      r.SecretRef,
				HeaderName:   r.HeaderName,
				HeaderFormat: r.HeaderFormat,
			})
		}
	}
	return out
}

// buildConnections runs phase two: each kind is given the bound proxy's address
// and CA, and its injection is applied to the session.
//
// FAIL-CLOSED as a whole. If any connection cannot be built, everything already
// built is torn down and the session gets NO connection injection. A partial set
// would be the worst outcome: the agent would have some credentials and not
// others, and the failure would surface as an authorization error deep inside its
// work rather than as a session that refused to start.
func (m *Manager) buildConnections(ctx context.Context, s *Session, conns []broker.Connection, proxyAddr string, proxyCA []byte) error {
	if len(conns) == 0 {
		return nil
	}
	if s.conns == nil {
		s.conns = &sessionConnections{excluded: map[string]bool{}}
	}
	sctx := broker.SessionContext{
		SessionID:     s.ID,
		WorkspaceDir:  s.WorkspaceDir,
		ProxyAddr:     proxyAddr,
		ProxyCAPEM:    proxyCA,
		AdvertiseHost: proxyAddr,
	}

	var merged broker.ConnectionInjection
	for _, c := range conns {
		inj, closer, err := c.BuildForSession(ctx, sctx)
		if err != nil {
			_ = s.conns.close()
			return fmt.Errorf("session: build %s connection %q: %w", c.Kind(), c.Name(), err)
		}
		if closer != nil {
			s.conns.closers = append(s.conns.closers, closer)
		}
		if err := merged.Merge(inj); err != nil {
			_ = s.conns.close()
			return fmt.Errorf("session: connection %q: %w", c.Name(), err)
		}
	}
	if err := merged.Validate(); err != nil {
		_ = s.conns.close()
		return err
	}
	if err := m.applyConnectionInjection(s, merged); err != nil {
		_ = s.conns.close()
		return err
	}
	return nil
}

// applyConnectionInjection writes injected files and adds injected env.
func (m *Manager) applyConnectionInjection(s *Session, inj broker.ConnectionInjection) error {
	for _, f := range inj.Files {
		if s.WorkspaceDir == "" {
			// Without a workspace there is nowhere daemon-authoritative to put the
			// file. Refuse rather than fall back to somewhere the sandbox could
			// replace it.
			return fmt.Errorf("session: connection needs a workspace to write %s", f.Path)
		}
		full := filepath.Join(s.WorkspaceDir, f.Path)
		// The path was already validated as workspace-relative and traversal-free by
		// ConnectionInjection.Validate; this re-check is what makes that guarantee
		// local to the write rather than something a future caller must remember.
		if rel, err := filepath.Rel(s.WorkspaceDir, full); err != nil || rel != filepath.Clean(f.Path) {
			return fmt.Errorf("session: refusing to write connection file outside the workspace: %s", f.Path)
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return fmt.Errorf("session: create dir for %s: %w", f.Path, err)
		}
		mode := f.Mode
		if mode == 0 {
			mode = 0o600
		}
		if err := os.WriteFile(full, f.Content, mode); err != nil {
			return fmt.Errorf("session: write %s: %w", f.Path, err)
		}
	}
	// Sorted so the env is deterministic, which keeps a session's recorded
	// environment stable across runs.
	keys := make([]string, 0, len(inj.Env))
	for k := range inj.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s.credEnv = append(s.credEnv, k+"="+inj.Env[k])
	}
	return nil
}

// isConnectionRef reports whether a ref is resolved at a connection boundary and
// must therefore be kept out of the sandbox environment.
func (s *Session) isConnectionRef(ref string) bool {
	if s == nil || s.conns == nil {
		return false
	}
	return s.conns.excluded[ref]
}
