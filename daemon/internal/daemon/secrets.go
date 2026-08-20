package daemon

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
)

// F5.6 secret MANAGEMENT surface. CRITICAL INVARIANT: no route here (nor anywhere
// else) ever returns a secret VALUE. Values are WRITE-ONLY from outside the daemon
// — POST accepts a value, GET/DELETE deal in metadata only. The value-read path
// (broker Get) is daemon-internal (session.Manager.ResolveSecret) and is NOT
// routed; the daemon holds only broker.SecretManager, which has no Get, so a value
// read is not even expressible at this layer.

// registerSecretRoutes adds the /v1/secrets management endpoints. With no secret
// backend wired the routes stay 404 (like the session routes under F1.1).
func (d *Daemon) registerSecretRoutes(mux *http.ServeMux) {
	if d.secrets == nil {
		return
	}
	mux.HandleFunc("GET /"+APIVersion+"/secrets", d.handleSecretList)
	mux.HandleFunc("POST /"+APIVersion+"/secrets", d.handleSecretAdd)
	// {ref...} is a multi-segment wildcard so refs containing '/' (e.g. "aws/deploy")
	// match. r.PathValue("ref") returns the full remaining path.
	mux.HandleFunc("DELETE /"+APIVersion+"/secrets/{ref...}", d.handleSecretDelete)
}

// secretMetaResponse is the metadata-only projection of a secret. It carries NO
// value and NO value length — only descriptive fields safe to return.
type secretMetaResponse struct {
	Ref       string    `json:"ref"`
	Provider  string    `json:"provider,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	TTL       string    `json:"ttl,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func secretMetaResp(m broker.SecretMeta) secretMetaResponse {
	return secretMetaResponse{Ref: m.Ref, Provider: m.Provider, Scope: m.Scope, TTL: m.TTL, CreatedAt: m.CreatedAt}
}

// addSecretRequest is the POST /v1/secrets body. The value arrives base64-encoded
// (it may be binary) and is the ONLY direction a value ever travels — in. It never
// comes back out of any response.
type addSecretRequest struct {
	Ref       string `json:"ref"`
	Provider  string `json:"provider,omitempty"`
	Scope     string `json:"scope,omitempty"`
	TTL       string `json:"ttl,omitempty"`
	ValueB64  string `json:"value_b64"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

// handleSecretList returns metadata for every secret — NEVER a value.
func (d *Daemon) handleSecretList(w http.ResponseWriter, r *http.Request) {
	metas, err := d.secrets.List(r.Context())
	if err != nil {
		writeSecretError(w, err)
		return
	}
	out := make([]secretMetaResponse, 0, len(metas))
	for _, m := range metas {
		out = append(out, secretMetaResp(m))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSecretAdd stores a secret (write-only). The 201 response echoes METADATA
// only — never the value. The daemon decodes the base64 here so it bounds the
// decoded size; the value buffer is zeroed after the Put returns.
func (d *Daemon) handleSecretAdd(w http.ResponseWriter, r *http.Request) {
	var body addSecretRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
		return
	}
	value, err := base64.StdEncoding.DecodeString(body.ValueB64)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "input", "invalid value_b64: "+err.Error())
		return
	}
	defer broker.Zeroize(value)
	if len(value) == 0 {
		writeAPIError(w, http.StatusBadRequest, "input", "secret value is empty")
		return
	}
	meta := broker.PutMeta{Provider: body.Provider, Scope: body.Scope, TTL: body.TTL}
	if err := d.secrets.Put(r.Context(), body.Ref, value, meta, body.Overwrite); err != nil {
		writeSecretError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, secretMetaResponse{
		Ref: body.Ref, Provider: body.Provider, Scope: body.Scope, TTL: body.TTL,
	})
}

// handleSecretDelete removes a secret by ref.
func (d *Daemon) handleSecretDelete(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if err := d.secrets.Delete(r.Context(), ref); err != nil {
		writeSecretError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeSecretError maps a broker error to a layer-tagged HTTP status. Every secret
// failure names layer "cred" (failure legibility), so an operator can tell a
// credential-layer refusal from a sandbox/egress/policy one.
func writeSecretError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, broker.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "cred", err.Error())
	case errors.Is(err, broker.ErrExists):
		writeAPIError(w, http.StatusConflict, "cred", err.Error())
	case errors.Is(err, broker.ErrInvalidInput):
		writeAPIError(w, http.StatusBadRequest, "input", err.Error())
	case errors.Is(err, broker.ErrDenied):
		writeAPIError(w, http.StatusForbidden, "cred", err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "cred", err.Error())
	}
}
