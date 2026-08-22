package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// F7.4 host-directory linking runs on the `opslify ui` HOST process, never the
// daemon. The ui server already runs host-side, so it hosts the F7.3 sync engine
// for a linked dir; the daemon only ever sees /workspace-relative file transfers
// and never learns the host path. Arbitrary host-path ENTRY from a browser is the
// sharp edge, so every path is validated against a sensitive-dir deny-list +
// existence + no-symlink-escape BEFORE any engine starts, and the whole /ui/*
// surface sits behind the same F7.1 token + DNS-rebind Host-guard as everything
// else (they wrap the mux, so these routes inherit them).

// linkManager owns the set of active host↔sandbox sync engines, one per session.
// It is the state behind the /ui/link + /ui/link/status routes.
type linkManager struct {
	socketPath string

	mu    sync.Mutex
	links map[string]*activeLink // keyed by session id
}

func newLinkManager(socketPath string) *linkManager {
	return &linkManager{socketPath: socketPath, links: map[string]*activeLink{}}
}

// activeLink is one running (or stopped) sync engine for a {sessionID, dir}.
type activeLink struct {
	sessionID string
	dir       string
	cancel    context.CancelFunc
	sink      *statusSink
	done      chan struct{}

	mu       sync.Mutex
	startErr string
}

func (al *activeLink) setErr(msg string) {
	al.mu.Lock()
	al.startErr = msg
	al.mu.Unlock()
}

func (al *activeLink) err() string {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.startErr
}

func (al *activeLink) running() bool {
	select {
	case <-al.done:
		return false
	default:
		return true
	}
}

// statusSink is a thread-safe io.Writer that captures the sync engine's progress
// lines so GET /ui/link/status can surface live status/conflicts. It replaces the
// CLI's stdout/stderr; no host bytes ever leave through it (it stores only the
// engine's own status messages, which reference rel paths, never file content).
type statusSink struct {
	mu        sync.Mutex
	lines     []string
	conflicts int
}

func (s *statusSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ln := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if ln == "" {
			continue
		}
		s.lines = append(s.lines, ln)
		if strings.Contains(ln, "conflict on") {
			s.conflicts++
		}
	}
	const cap = 200
	if len(s.lines) > cap {
		s.lines = append([]string(nil), s.lines[len(s.lines)-cap:]...)
	}
	return len(p), nil
}

func (s *statusSink) snapshot() (recent []string, conflicts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recent = append([]string(nil), s.lines...)
	return recent, s.conflicts
}

// linkRequest is the POST /ui/link body: link (on=true) or unlink (on=false) a
// host dir to a session's /workspace.
type linkRequest struct {
	Dir       string `json:"dir"`
	SessionID string `json:"session_id"`
	On        bool   `json:"on"`
}

// linkStatus is one row of GET /ui/link/status.
type linkStatus struct {
	SessionID string   `json:"session_id"`
	Dir       string   `json:"dir"`
	Running   bool     `json:"running"`
	Conflicts int      `json:"conflicts"`
	Recent    []string `json:"recent"`
	Error     string   `json:"error,omitempty"`
}

func (m *linkManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/ui/link/status" && r.Method == http.MethodGet:
		m.handleStatus(w, r)
	case r.URL.Path == "/ui/link" && r.Method == http.MethodPost:
		m.handleLink(w, r)
	default:
		http.Error(w, "opslify ui: unknown /ui route", http.StatusNotFound)
	}
}

func (m *linkManager) handleLink(w http.ResponseWriter, r *http.Request) {
	var req linkRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "opslify ui: bad link request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.SessionID) == "" {
		http.Error(w, "opslify ui: link requires a session_id", http.StatusBadRequest)
		return
	}
	if !req.On {
		m.stop(req.SessionID)
		writeUIJSON(w, http.StatusOK, map[string]any{"session_id": req.SessionID, "running": false})
		return
	}
	real, err := validateLinkDir(req.Dir)
	if err != nil {
		// A denied path is a clear 400 — the guardrail refused it, nothing started.
		http.Error(w, "opslify ui: refusing to link "+req.Dir+": "+err.Error(), http.StatusBadRequest)
		return
	}
	m.start(req.SessionID, real)
	writeUIJSON(w, http.StatusOK, map[string]any{"session_id": req.SessionID, "dir": real, "running": true})
}

func (m *linkManager) handleStatus(w http.ResponseWriter, r *http.Request) {
	want := r.URL.Query().Get("session_id")
	m.mu.Lock()
	als := make([]*activeLink, 0, len(m.links))
	for _, al := range m.links {
		if want == "" || al.sessionID == want {
			als = append(als, al)
		}
	}
	m.mu.Unlock()

	out := make([]linkStatus, 0, len(als))
	for _, al := range als {
		recent, conflicts := al.sink.snapshot()
		out = append(out, linkStatus{
			SessionID: al.sessionID,
			Dir:       al.dir,
			Running:   al.running(),
			Conflicts: conflicts,
			Recent:    recent,
			Error:     al.err(),
		})
	}
	writeUIJSON(w, http.StatusOK, out)
}

// start launches (or replaces) the sync engine for a validated {sessionID, dir}.
// The engine drives F7.3 (copy-not-bind, secrets excluded) via the daemon socket
// using rel-path transfers only — the daemon never receives the host path.
func (m *linkManager) start(sessionID, realDir string) {
	m.mu.Lock()
	if old := m.links[sessionID]; old != nil {
		old.cancel()
	}
	sink := &statusSink{}
	ctx, cancel := context.WithCancel(context.Background())
	al := &activeLink{
		sessionID: sessionID,
		dir:       realDir,
		cancel:    cancel,
		sink:      sink,
		done:      make(chan struct{}),
	}
	m.links[sessionID] = al
	m.mu.Unlock()

	c := newClient(m.socketPath)
	eng := newSyncEngine(c, sessionID, realDir, sink, sink)
	go func() {
		defer close(al.done)
		if err := eng.initialCopyIn(ctx); err != nil {
			al.setErr(err.Error())
			return
		}
		if err := eng.watch(ctx); err != nil {
			al.setErr(err.Error())
		}
	}()
}

// stop cancels a session's sync engine (the engine does a final reconcile on
// cancel). The record is retained so status can still report the stopped state.
func (m *linkManager) stop(sessionID string) {
	m.mu.Lock()
	al := m.links[sessionID]
	m.mu.Unlock()
	if al != nil {
		al.cancel()
	}
}

// validateLinkDir enforces the F7.4 host-path guardrails and returns the resolved
// (symlink-followed) directory. It refuses: any path containing "..", a sensitive
// system dir or the operator's $HOME root itself, a nonexistent path, a non-dir,
// and a symlink whose target resolves onto a sensitive dir (out-of-tree escape).
// It fails safe — on any doubt it returns an error and nothing is linked.
func validateLinkDir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("empty directory")
	}
	// Reject a ".." path *segment* (traversal) — but not an innocent name that
	// merely contains the substring (e.g. k8s-style "..data"). Abs+Clean below
	// resolves any traversal anyway; this is the early, explicit refusal.
	for _, seg := range strings.Split(filepath.ToSlash(dir), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path must not contain a %q segment", "..")
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)

	denied := sensitiveDirs()
	if denied[abs] {
		return "", fmt.Errorf("%q is a sensitive directory and cannot be linked", abs)
	}
	// Follow symlinks: a symlink that escapes onto a sensitive dir must be caught
	// by its RESOLVED target, not its (innocent-looking) name. EvalSymlinks also
	// fails for a nonexistent path (fail closed).
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("path does not resolve: %w", err)
	}
	real = filepath.Clean(real)
	if denied[real] {
		return "", fmt.Errorf("symlink target %q is a sensitive directory", real)
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%q is not a directory", abs)
	}
	return real, nil
}

// sensitiveDirs is the deny-list of host roots that may never be linked into a
// sandbox: the filesystem root, credential/system trees, and the operator's $HOME
// root itself (linking the whole home dir would drag every dotfile in).
func sensitiveDirs() map[string]bool {
	d := map[string]bool{
		"/":     true,
		"/etc":  true,
		"/root": true,
		"/var":  true,
		"/usr":  true,
		"/boot": true,
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		d[filepath.Clean(home)] = true
	}
	return d
}

func writeUIJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
