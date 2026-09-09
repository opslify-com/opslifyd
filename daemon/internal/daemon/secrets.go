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
	d.registerSecretsServiceRoutes(mux)
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
	// With the F8.3 service wired the delete is GUARDED: a ref something still
	// addresses is refused unless ?force=true, and the refusal names the
	// consumers. Without it, the F5.6 behaviour is unchanged.
	if d.secretsSvc != nil {
		force := r.URL.Query().Get("force") == "true"
		if _, err := d.secretsSvc.Delete(r.Context(), ref, force); err != nil {
			writeSecretError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
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
	case errors.Is(err, broker.ErrInUse):
		writeAPIError(w, http.StatusConflict, "cred", err.Error())
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

// --- F8.3 operator surface ---------------------------------------------------
//
// These routes add listing-with-consumers, rotation, and a guarded delete. They
// hold the SAME Get-less SecretManager as everything above, so the write-only
// invariant is preserved by construction rather than by review: there is no type
// in this file that can produce a value.

// secretViewResponse is a secret's metadata plus who addresses it. Still no value
// and no value length — consumers are refs and names, which are safe to render.
type secretViewResponse struct {
	secretMetaResponse
	LastUsed  *time.Time        `json:"last_used,omitempty"`
	RotatedAt *time.Time        `json:"rotated_at,omitempty"`
	Consumers []broker.Consumer `json:"consumers,omitempty"`
	InUse     bool              `json:"in_use"`
}

func secretViewResp(v broker.SecretView) secretViewResponse {
	out := secretViewResponse{
		secretMetaResponse: secretMetaResp(v.SecretMeta),
		Consumers:          v.Consumers,
		InUse:              v.InUse,
	}
	if !v.LastUsed.IsZero() {
		t := v.LastUsed
		out.LastUsed = &t
	}
	if !v.RotatedAt.IsZero() {
		t := v.RotatedAt
		out.RotatedAt = &t
	}
	return out
}

// rotateSecretRequest is the PUT body. Like add, the value travels IN only.
type rotateSecretRequest struct {
	ValueB64 string `json:"value_b64"`
	Provider string `json:"provider,omitempty"`
	Scope    string `json:"scope,omitempty"`
	TTL      string `json:"ttl,omitempty"`
}

// registerSecretsServiceRoutes adds the F8.3 endpoints when the service is wired.
func (d *Daemon) registerSecretsServiceRoutes(mux *http.ServeMux) {
	if d.secretsSvc == nil {
		return
	}
	mux.HandleFunc("GET /"+APIVersion+"/secrets/consumers", d.handleSecretConsumers)
	mux.HandleFunc("PUT /"+APIVersion+"/secrets/{ref...}", d.handleSecretRotate)
}

// handleSecretConsumers returns every secret with its consumers — metadata only.
func (d *Daemon) handleSecretConsumers(w http.ResponseWriter, r *http.Request) {
	views, err := d.secretsSvc.List(r.Context())
	if err != nil {
		writeSecretError(w, err)
		return
	}
	out := make([]secretViewResponse, 0, len(views))
	for _, v := range views {
		out = append(out, secretViewResp(v))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSecretRotate replaces the value under an existing ref. Consumers address
// the ref, so nothing downstream changes — which is the point.
func (d *Daemon) handleSecretRotate(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	var body rotateSecretRequest
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
	if err := d.secretsSvc.Rotate(r.Context(), ref, value, meta); err != nil {
		writeSecretError(w, err)
		return
	}
	// Metadata only: the response says WHICH ref rotated, never what it now holds.
	writeJSON(w, http.StatusOK, secretMetaResponse{Ref: ref})
}
