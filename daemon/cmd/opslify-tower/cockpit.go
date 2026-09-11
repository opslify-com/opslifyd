package main

import (
	"embed"
	"net/http"
)

// cockpitFS is the self-contained SPA.
//
// Embedded, and with no external asset host anywhere in it: the page is served
// over loopback to an operator who may well be on an air-gapped host, and a
// stylesheet fetched from a CDN would both break there and hand a third party a
// log of when the cockpit is opened.
//
//go:embed cockpit
var cockpitFS embed.FS

// cockpitHandler serves the SPA.
func cockpitHandler() http.Handler {
	sub, err := fsSub(cockpitFS, "cockpit")
	if err != nil {
		panic("opslify-tower: embedded cockpit is missing: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A strict CSP: the page loads nothing it did not ship with. 'self' only —
		// no inline-script escape hatch, no remote origin. If this page is ever
		// injected into, the injection has nowhere to send what it finds.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Not cached: the cockpit shows live state, and a stale shell served from
		// disk after an upgrade is a confusing way to debug a daemon.
		w.Header().Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	})
}
