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
	// DELETE /v1/secrets?ref=… is the path-free form, and it exists for exactly one
	// reason: a ref containing a "." or ".." segment cannot be addressed by URL
	// path at all, because ServeMux normalises the path before routing and
	// 307-redirects. A secret stored under such a ref by an earlier release would
	// otherwise be listed, live, resolvable and impossible to remove without
	// hand-editing an encrypted file. The guard is identical — this changes how the
	// ref is transported, not what is permitted.
	mux.HandleFunc("DELETE /"+APIVersion+"/secrets", d.handleSecretDeleteByQuery)
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
	// LastUsed and RotatedAt are the rotation-hygiene signals. They were carried
	// only by the consumers route, which meant the primary listing verb could not
	// answer "which credentials are stale?" — the question the stamps exist for.
	// Pointers so "never used" is absent rather than a zero time that renders as
	// year 1.
	LastUsed  *time.Time `json:"last_used,omitempty"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

func secretMetaResp(m broker.SecretMeta) secretMetaResponse {
	r := secretMetaResponse{Ref: m.Ref, Provider: m.Provider, Scope: m.Scope, TTL: m.TTL, CreatedAt: m.CreatedAt}
	if !m.LastUsed.IsZero() {
		t := m.LastUsed
		r.LastUsed = &t
	}
	if !m.RotatedAt.IsZero() {
		t := m.RotatedAt
		r.RotatedAt = &t
	}
	return r
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
	if err := decodeJSONLimit(r, &body, maxSecretBody); err != nil {
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
	// An overwrite of an existing ref IS a rotation, whatever verb the caller used,
	// so it goes through the service and is audited as one. It is a SINGLE call:
	// composing it from rotate-then-create-on-ErrNotFound stored an all-zero value
	// (the rotation path zeroizes the caller's plaintext, correctly, and the create
	// that followed reused the wiped buffer) and reported 201 Created.
	if body.Overwrite && d.secretsSvc != nil {
		stored, replaced, err := d.secretsSvc.Upsert(r.Context(), body.Ref, value, meta)
		if err != nil {
			writeSecretError(w, err)
			return
		}
		// 200 for a replacement, 201 for a create: the code the caller gets should
		// describe what happened, not which verb they typed.
		status := http.StatusCreated
		if replaced {
			status = http.StatusOK
		}
		writeJSON(w, status, secretMetaResp(stored))
		return
	}
	if err := d.secrets.Put(r.Context(), body.Ref, value, meta, false); err != nil {
		writeSecretError(w, err)
		return
	}
	// Echo the STORED record, not the request. Returning the request meant every
	// add reported created_at of year 1, and an --overwrite echoed the caller's
	// (often empty) provider/scope while the real record carried the previous
	// values forward.
	writeJSON(w, http.StatusCreated, secretMetaResp(d.storedMeta(r, body.Ref, meta)))
}

// handleSecretDeleteByQuery removes a secret whose ref arrives as a query
// parameter rather than a path segment. See the route registration for why.
func (d *Daemon) handleSecretDeleteByQuery(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeAPIError(w, http.StatusBadRequest, "input",
			"DELETE /v1/secrets requires ?ref= (use it only for refs that cannot be expressed as a path)")
		return
	}
	d.deleteSecret(w, r, ref)
}

// handleSecretDelete removes a secret by ref.
func (d *Daemon) handleSecretDelete(w http.ResponseWriter, r *http.Request) {
	d.deleteSecret(w, r, r.PathValue("ref"))
}

// deleteSecret is the single guarded delete, shared by the path and query forms
// so the two transports cannot drift into different permissions.
func (d *Daemon) deleteSecret(w http.ResponseWriter, r *http.Request, ref string) {
	// Deliberately NO ValidateRef here. It bought nothing — the lookup already
	// 404s a ref that cannot be stored, and the ref never reaches a filesystem or
	// a second URL from this handler — while it made a secret stored under an
	// earlier, looser rule permanently UN-DELETABLE: listed, live, resolvable, and
	// refused with a 400 even with force. Deletion must always be reachable, or
	// the only escape is hand-editing an encrypted vault file.
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

// storedMeta looks up what was actually persisted for ref, falling back to the
// requested metadata if the listing cannot be read. The response describing the
// record rather than the request is what makes created_at and a carried-forward
// provider truthful.
func (d *Daemon) storedMeta(r *http.Request, ref string, requested broker.PutMeta) broker.SecretMeta {
	metas, err := d.secrets.List(r.Context())
	if err == nil {
		for _, m := range metas {
			if m.Ref == ref {
				return m
			}
		}
	}
	return broker.SecretMeta{Ref: ref, Provider: requested.Provider, Scope: requested.Scope, TTL: requested.TTL}
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
// secretViewResponse is the consumers listing: metadata (which now carries
// last_used/rotated_at via the embedded struct) plus who addresses the ref.
type secretViewResponse struct {
	secretMetaResponse
	Consumers []broker.Consumer `json:"consumers,omitempty"`
	InUse     bool              `json:"in_use"`
}

func secretViewResp(v broker.SecretView) secretViewResponse {
	return secretViewResponse{
		secretMetaResponse: secretMetaResp(v.SecretMeta),
		Consumers:          v.Consumers,
		InUse:              v.InUse,
	}
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
	// No ValidateRef here either: the write path enforces what may be STORED, and
	// a ref that fails it cannot be rotated in any case — but the refusal should
	// come from the vault with its own message rather than from a route-level copy
	// of the same rule. See handleSecretDelete.
	ref := r.PathValue("ref")
	var body rotateSecretRequest
	if err := decodeJSONLimit(r, &body, maxSecretBody); err != nil {
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
