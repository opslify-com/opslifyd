package agentcontext

// TracePayload builds the context.assemble event payload.
//
// It is a SEPARATE function from the Assembly type on purpose. Serializing the
// assembly directly would mean one `json:"-"` tag is all that stands between the
// instruction content and the permanent audit chain — and a future field added
// without that tag would leak silently. Here the payload is constructed
// field-by-field from an explicit allowlist, so content can only reach the trace
// if someone adds it deliberately.
//
// What goes in: identity (hash), provenance (layer kinds and logical names),
// accounting (bytes, tokens, budget) and the routing decision. What never goes
// in: a single byte of instruction text.
func (a *Assembly) TracePayload() map[string]any {
	layers := make([]map[string]any, 0, len(a.Layers))
	for _, l := range a.Layers {
		layers = append(layers, map[string]any{
			"kind":   string(l.Kind),
			"name":   l.Name,
			"hash":   l.Hash,
			"bytes":  l.Bytes,
			"tokens": l.Tokens,
		})
	}
	payload := map[string]any{
		"hash":    a.Hash,
		"layers":  layers,
		"bytes":   a.Bytes,
		"tokens":  a.Tokens,
		"budget":  a.Budget,
		"overrun": a.Overrun,
	}
	routing := map[string]any{"loaded_all": a.Routing.LoadedAll}
	if len(a.Routing.Roles) > 0 {
		routing["roles"] = a.Routing.Roles
	}
	if len(a.Routing.Selected) > 0 {
		routing["selected"] = a.Routing.Selected
	}
	if len(a.Routing.Missing) > 0 {
		// Recorded because it explains a gap in what the agent knew. An operator
		// reading a bad action back needs to see that the pack was absent.
		routing["missing"] = a.Routing.Missing
	}
	payload["routing"] = routing
	return payload
}
