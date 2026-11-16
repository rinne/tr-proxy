package admin

import (
	"embed"
	"io/fs"
	"net/http"
)

// The UI is plain files: no build step. Alpine.js is vendored; see
// ui/VENDOR.md.
//
//go:embed ui/index.html ui/app.js ui/style.css ui/alpine.min.js
var uiFiles embed.FS

// Alpine evaluates the expressions in the markup with Function(), which
// needs 'unsafe-eval'. Everything else is same-origin only.
const contentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-eval'; " +
	"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// securityHeaders sets the headers every admin response carries.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

// registerUI serves the page at / and its files under /ui/. The page itself
// is public; it shows a login form and gets everything else from the API.
func registerUI(mux *http.ServeMux) {
	files, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		panic(err)
	}
	static := http.FileServerFS(files)
	noCache := func(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-cache") }

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		noCache(w)
		http.ServeFileFS(w, r, files, "index.html")
	})
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noCache(w)
		static.ServeHTTP(w, r)
	})))
}
