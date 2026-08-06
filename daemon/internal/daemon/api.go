package daemon

import (
	"encoding/json"
	"net/http"
)

// APIVersion is the daemon REST API version prefix. The daemon ↔ dashboard/CLI
// contract is versioned from the start (shared-engineering §9).
const APIVersion = "v1"

// RuntimeHealth reports whether the configured isolation runtime can actually
// run on this host (F0.3 Available() probe), surfaced so callers learn gVisor
// present/absent before they try to create a session.
type RuntimeHealth struct {
	// Tier is the configured default isolation rung (e.g. local-hardened).
	Tier string `json:"tier"`
	// Available is true when the engine + OCI runtime for Tier are present.
	Available bool `json:"available"`
	// Detail carries the legible, layer-tagged reason when Available is false
	// (e.g. "runtime: OCI runtime \"runsc\" unavailable ..."). Empty on success.
	// It never contains secrets.
	Detail string `json:"detail,omitempty"`
}

// Health is the GET /v1/health response body.
type Health struct {
	// Status is "ok" once the daemon is serving (it only serves after
	// verify-before-serve passed, so serving implies a verified toolchain).
	Status string `json:"status"`
	// Version is the daemon build version.
	Version string `json:"version"`
	// Identity is the daemon's public identity fingerprint (safe to expose; the
	// private key never leaves its 0600 file).
	Identity string `json:"identity,omitempty"`
	// Runtime reports isolation-runtime capability.
	Runtime RuntimeHealth `json:"runtime"`
}

// Handler builds the versioned REST mux. stdlib net/http is used (no router
// dependency): the F1.1 surface is a single endpoint, and Go 1.22+ pattern
// routing covers method+path matching cleanly.
func (d *Daemon) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /"+APIVersion+"/health", d.handleHealth)
	return mux
}

// handleHealth reports liveness plus runtime capability. It probes the runtime
// on each call so a runtime that appears/disappears (e.g. runsc installed after
// start) is reflected without a restart.
func (d *Daemon) handleHealth(w http.ResponseWriter, r *http.Request) {
	h := Health{
		Status:   "ok",
		Version:  d.version,
		Identity: d.identity,
		Runtime: RuntimeHealth{
			Tier:      d.tier,
			Available: true,
		},
	}
	if err := d.runtimeProbe(); err != nil {
		h.Runtime.Available = false
		h.Runtime.Detail = err.Error()
	}
	writeJSON(w, http.StatusOK, h)
}

// writeJSON encodes v as JSON with the given status. On an encode failure it has
// already written the header, so it can only log — but Health is always
// encodable, so this is defensive.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
