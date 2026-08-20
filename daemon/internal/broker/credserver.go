package broker

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CredServer is the daemon's loopback credential-metadata endpoint — the fully
// credential-blind AWS path (F5.1). It serves each session a short-lived, scoped
// credential body that the AWS CLI/SDK fetches UNMODIFIED via
// AWS_CONTAINER_CREDENTIALS_FULL_URI, so the RAW durable secret is NEVER placed
// in the container env/files/argv — only the endpoint URL + a per-session bearer
// token are. The served body is itself TTL-bounded and, once F5.3 lands, a
// short-lived STS credential rather than a durable one.
//
// SECURITY POSTURE — this handler is a TRUST BOUNDARY facing a hostile sandbox:
//   - A request must carry the OWNING session's per-session bearer token
//     (Authorization header, the value of AWS_CONTAINER_CREDENTIALS_TOKEN). A
//     missing/wrong token, or a token that belongs to a DIFFERENT session than the
//     one in the path, is refused with 403 and no body.
//   - Tokens are compared in constant time (subtle.ConstantTimeCompare) so a
//     timing side-channel cannot recover one byte at a time.
//   - An expired entry is refused (403) — a captured token is near-expiry by
//     construction and cannot be replayed past its TTL.
//   - Host-network reachability is denied by the PINNED bind address the daemon
//     listens on (a sandbox-reachable loopback/bridge address, never 0.0.0.0); the
//     real in-sandbox→daemon network path is integration-gated (egress allowlist).
//     This handler is unit-tested for the token/cross-session/expiry gates.
type CredServer struct {
	mu      sync.Mutex
	entries map[string]credEntry
	now     func() time.Time
}

// credEntry is one session's served credential: the bearer token that authorizes
// a fetch, the opaque body served, and the hard expiry after which it is refused.
type credEntry struct {
	token       string
	body        []byte
	contentType string
	expiresAt   time.Time
}

// CredPath is the URL path prefix the endpoint serves per-session creds under.
// The full per-session URI is <baseURL><CredPath><sessionID>.
const CredPath = "/creds/"

// NewCredServer builds an empty endpoint. now defaults to time.Now (injected in
// tests so expiry is deterministic).
func NewCredServer(now func() time.Time) *CredServer {
	if now == nil {
		now = time.Now
	}
	return &CredServer{entries: map[string]credEntry{}, now: now}
}

// Register stores (or replaces) the credential body served for sessionID, gated on
// token and valid until expiresAt. Called by the injector at session create for
// the AWS endpoint path.
func (s *CredServer) Register(sessionID, token string, body []byte, contentType string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[sessionID] = credEntry{token: token, body: body, contentType: contentType, expiresAt: expiresAt}
}

// Release drops sessionID's served credential (called on session teardown), so a
// dead session's token can never fetch again.
func (s *CredServer) Release(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, sessionID)
}

// ServeHTTP is the endpoint handler. It authorizes strictly and fails closed:
// unknown session, wrong/missing token, or expiry → 403 with no credential body.
func (s *CredServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessionID, ok := strings.CutPrefix(r.URL.Path, CredPath)
	if !ok || sessionID == "" || strings.Contains(sessionID, "/") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// The AWS SDK sends the token as the raw Authorization header value.
	presented := strings.TrimSpace(r.Header.Get("Authorization"))
	presented = strings.TrimPrefix(presented, "Bearer ")

	s.mu.Lock()
	entry, found := s.entries[sessionID]
	now := s.now()
	s.mu.Unlock()

	// Deny-by-default: no entry, empty token, or a non-constant-time-equal token is
	// refused identically (no oracle distinguishing "no such session" from "wrong
	// token"). A cross-session request (B's token against A's path) fails here
	// because A's stored token differs from B's.
	if !found || presented == "" ||
		subtle.ConstantTimeCompare([]byte(presented), []byte(entry.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !now.Before(entry.expiresAt) {
		// Expired: the near-expiry token cannot be replayed past its TTL.
		http.Error(w, "credential expired", http.StatusForbidden)
		return
	}
	ct := entry.contentType
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(entry.body)
}
