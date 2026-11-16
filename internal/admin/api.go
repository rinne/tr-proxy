package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"tr-proxy/internal/config"
	"tr-proxy/internal/wgkey"
)

const (
	sessionCookie = "tr_proxy_session"
	maxBody       = 1 << 20
)

// Backend is what the API needs from the supervisor.
type Backend interface {
	// Config returns a copy of the current config, secrets included.
	Config() *config.Config
	// Apply validates cfg, saves it and makes it the running config. A
	// config that fails validation is reported as *InvalidError.
	Apply(cfg *config.Config) error
	// Status returns the live status, to be encoded as JSON.
	Status() any
	// TestRoute reports how a destination requested on a listener would be
	// routed right now.
	TestRoute(listener, host string) RouteTest
	// RestartTunnel restarts a WireGuard connection's worker; false if there
	// is no such connection.
	RestartTunnel(name string) bool
	// Event adds an entry to the event log.
	Event(kind, message string)
}

// InvalidError is a config that failed validation.
type InvalidError struct {
	Err error
}

func (e *InvalidError) Error() string { return "invalid configuration:\n" + e.Err.Error() }

// RouteTest is the answer of POST /api/test-route.
type RouteTest struct {
	Rule   string   `json:"rule"`   // empty: a default applied
	Via    []string `json:"via"`    // the egress list of the rule or default
	Egress string   `json:"egress"` // what would be used; empty if nothing is usable
	Error  string   `json:"error,omitempty"`
}

type api struct {
	b    Backend
	auth *Auth
	log  *slog.Logger
	// mu serializes read-modify-apply of the config.
	mu sync.Mutex
}

// NewHandler returns the admin HTTP handler.
func NewHandler(b Backend, creds Credentials, log *slog.Logger) http.Handler {
	a := &api{b: b, auth: NewAuth(creds), log: log}
	mux := http.NewServeMux()

	// Unauthenticated.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /api/session", a.session)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.logout)

	// Everything else needs a session.
	mux.HandleFunc("GET /api/config", a.protect(a.getConfig))
	mux.HandleFunc("PUT /api/config", a.protect(a.putConfig))
	mux.HandleFunc("GET /api/status", a.protect(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.b.Status())
	}))
	mux.HandleFunc("POST /api/test-route", a.protect(a.testRoute))
	mux.HandleFunc("POST /api/keys/generate", a.protect(a.generateKey))
	mux.HandleFunc("POST /api/wireguard/{name}/restart", a.protect(a.restartTunnel))
	mux.HandleFunc("POST /api/rules/order", a.protect(a.orderRules))

	register(mux, a, "keys",
		func(c *config.Config) *[]config.Key { return &c.Keys },
		func(k *config.Key) *string { return &k.Name })
	register(mux, a, "wireguard",
		func(c *config.Config) *[]config.WireGuard { return &c.WireGuard },
		func(w *config.WireGuard) *string { return &w.Name })
	register(mux, a, "upstreams",
		func(c *config.Config) *[]config.Upstream { return &c.Upstreams },
		func(u *config.Upstream) *string { return &u.Name })
	register(mux, a, "listeners",
		func(c *config.Config) *[]config.Listener { return &c.Listeners },
		func(l *config.Listener) *string { return &l.Name })
	register(mux, a, "rules",
		func(c *config.Config) *[]config.Rule { return &c.Rules },
		func(r *config.Rule) *string { return &r.Name })

	return mux
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

// decode reads a JSON body strictly. It answers the request itself on error.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return false
	}
	return true
}

// sameOrigin rejects requests that a browser sent from another site. A
// request without browser headers (curl, scripts) passes.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

func isSafe(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func (a *api) token(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// protect wraps a handler that needs a session, and for requests that change
// something, the same origin.
func (a *api) protect(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isSafe(r.Method) && !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
		if !a.auth.Valid(a.token(r)) {
			writeError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		h(w, r)
	}
}

// apply merges kept secrets into cfg and applies it. It answers the request
// itself on error. The caller holds a.mu.
func (a *api) apply(w http.ResponseWriter, cfg *config.Config) bool {
	config.MergeSecrets(cfg, a.b.Config())
	err := a.b.Apply(cfg)
	var invalid *InvalidError
	switch {
	case err == nil:
		return true
	case errors.As(err, &invalid):
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":    "invalid configuration",
			"problems": strings.Split(invalid.Err.Error(), "\n"),
		})
	default:
		a.log.Error("applying config failed", "err", err)
		writeError(w, http.StatusInternalServerError, err.Error())
	}
	return false
}

// --- session ---

func (a *api) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": a.auth.Valid(a.token(r)),
		"totp":          a.auth.TOTPRequired(),
	})
}

func (a *api) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if !decode(w, r, &body) {
		return
	}
	token, expires, err := a.auth.Login(body.Username, body.Password, body.TOTP)
	switch {
	case errors.Is(err, ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	case errors.Is(err, ErrBadLogin):
		a.b.Event("admin", "admin login rejected from "+r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
	a.b.Event("admin", "admin logged in from "+r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
}

func (a *api) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	a.auth.Logout(a.token(r))
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

// --- config ---

func (a *api) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, config.Redact(a.b.Config()))
}

func (a *api) putConfig(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if !decode(w, r, &cfg) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.apply(w, &cfg) {
		writeJSON(w, http.StatusOK, config.Redact(a.b.Config()))
	}
}

func (a *api) generateKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	secret, _, err := wgkey.Generate()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg := a.b.Config()
	if _, exists := cfg.KeyByName(body.Name); exists {
		writeError(w, http.StatusConflict, "a key with that name exists")
		return
	}
	cfg.Keys = append(cfg.Keys, config.Key{Name: body.Name, SecretKey: secret})
	if a.apply(w, cfg) {
		key, _ := config.Redact(a.b.Config()).KeyByName(body.Name)
		writeJSON(w, http.StatusCreated, key)
	}
}

func (a *api) orderRules(w http.ResponseWriter, r *http.Request) {
	var names []string
	if !decode(w, r, &names) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg := a.b.Config()
	byName := map[string]config.Rule{}
	for _, rule := range cfg.Rules {
		byName[rule.Name] = rule
	}
	ordered := make([]config.Rule, 0, len(names))
	for _, n := range names {
		rule, ok := byName[n]
		if !ok {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown or repeated rule %q", n))
			return
		}
		delete(byName, n)
		ordered = append(ordered, rule)
	}
	if len(byName) != 0 {
		writeError(w, http.StatusBadRequest, "the order must name every rule")
		return
	}
	cfg.Rules = ordered
	if a.apply(w, cfg) {
		writeJSON(w, http.StatusOK, config.Redact(a.b.Config()).Rules)
	}
}

// --- actions ---

func (a *api) restartTunnel(w http.ResponseWriter, r *http.Request) {
	if !a.b.RestartTunnel(r.PathValue("name")) {
		writeError(w, http.StatusNotFound, "no such connection")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) testRoute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Listener string `json:"listener"`
		Host     string `json:"host"`
	}
	if !decode(w, r, &body) {
		return
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(body.Host)), ".")
	if host == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}
	known := false
	for _, l := range a.b.Config().Listeners {
		known = known || l.Name == body.Listener
	}
	if !known {
		writeError(w, http.StatusBadRequest, "no such listener")
		return
	}
	writeJSON(w, http.StatusOK, a.b.TestRoute(body.Listener, host))
}

// --- collections ---

// register adds list, create, read, replace and delete for one config
// collection under /api/<path>. Every change goes through the same
// validate-save-apply path as a whole-config write.
func register[T any](mux *http.ServeMux, a *api, path string, items func(*config.Config) *[]T, name func(*T) *string) {
	find := func(c *config.Config, n string) int {
		list := *items(c)
		for i := range list {
			if *name(&list[i]) == n {
				return i
			}
		}
		return -1
	}
	// respond sends the redacted form of the named item.
	respond := func(w http.ResponseWriter, status int, n string) {
		red := config.Redact(a.b.Config())
		if i := find(red, n); i >= 0 {
			writeJSON(w, status, (*items(red))[i])
			return
		}
		writeError(w, http.StatusNotFound, "not found")
	}

	mux.HandleFunc("GET /api/"+path, a.protect(func(w http.ResponseWriter, r *http.Request) {
		list := *items(config.Redact(a.b.Config()))
		if list == nil {
			list = []T{}
		}
		writeJSON(w, http.StatusOK, list)
	}))

	mux.HandleFunc("POST /api/"+path, a.protect(func(w http.ResponseWriter, r *http.Request) {
		var item T
		if !decode(w, r, &item) {
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		cfg := a.b.Config()
		if find(cfg, *name(&item)) >= 0 {
			writeError(w, http.StatusConflict, "an entry with that name exists")
			return
		}
		*items(cfg) = append(*items(cfg), item)
		if a.apply(w, cfg) {
			respond(w, http.StatusCreated, *name(&item))
		}
	}))

	mux.HandleFunc("GET /api/"+path+"/{name}", a.protect(func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, r.PathValue("name"))
	}))

	mux.HandleFunc("PUT /api/"+path+"/{name}", a.protect(func(w http.ResponseWriter, r *http.Request) {
		var item T
		if !decode(w, r, &item) {
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		cfg := a.b.Config()
		i := find(cfg, r.PathValue("name"))
		if i < 0 {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if j := find(cfg, *name(&item)); j >= 0 && j != i {
			writeError(w, http.StatusConflict, "an entry with that name exists")
			return
		}
		(*items(cfg))[i] = item
		if a.apply(w, cfg) {
			respond(w, http.StatusOK, *name(&item))
		}
	}))

	mux.HandleFunc("DELETE /api/"+path+"/{name}", a.protect(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		cfg := a.b.Config()
		i := find(cfg, r.PathValue("name"))
		if i < 0 {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		list := *items(cfg)
		*items(cfg) = append(list[:i], list[i+1:]...)
		if a.apply(w, cfg) {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
}
