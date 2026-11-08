// Package api serves the LabWarden REST API, agent files and the web UI.
package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/amanahlab/labwarden/server/internal/jobs"
	"github.com/amanahlab/labwarden/server/internal/notify"
	"github.com/amanahlab/labwarden/server/internal/scanner"
	"github.com/amanahlab/labwarden/server/internal/store"
)

type Config struct {
	Version       string
	AdminPassword string // empty disables UI auth
	SessionKey    []byte
	CookieSecure  bool
	MaxReportMB   int64
	// TrustedProxies may set X-Forwarded-For and X-Forwarded-Proto; requests
	// from anywhere else are taken at their TCP address.
	TrustedProxies []netip.Prefix
	// PublicURL is the dashboard's address (LABWARDEN_PUBLIC_URL). Browsers
	// on it pass the cross-origin check even when a proxy rewrites Host, and
	// an https one marks the session cookie Secure on requests for its host.
	PublicURL string
}

type Server struct {
	cfg     Config
	st      *store.Store
	scan    *scanner.Scanner
	jobs    *jobs.Queue
	notify  *notify.Notifier
	log     *slog.Logger
	webFS   fs.FS // built SPA (may be empty)
	agentFS fs.FS
	limiter *loginLimiter
	budget  *failBudget // failed logins from all clients together
	// agentLimiter and agentEvents handle bad agent tokens.
	agentLimiter *loginLimiter
	agentEvents  *eventGate
	pwFP         string   // see passwordFingerprint
	public       *url.URL // cfg.PublicURL, nil when unset or unusable
}

func New(cfg Config, st *store.Store, sc *scanner.Scanner, q *jobs.Queue, nt *notify.Notifier, log *slog.Logger, webFS, agentFS fs.FS) *Server {
	if cfg.MaxReportMB <= 0 {
		cfg.MaxReportMB = 256
	}
	s := &Server{cfg: cfg, st: st, scan: sc, jobs: q, notify: nt, log: log, webFS: webFS, agentFS: agentFS,
		limiter: newLoginLimiter(), budget: newFailBudget(loginBudget, loginBudgetWindow),
		agentLimiter: newLoginLimiter(), agentEvents: newEventGate(rejectedAgentEvery),
		pwFP: passwordFingerprint(cfg.SessionKey, cfg.AdminPassword)}
	if u, err := url.Parse(strings.TrimSpace(cfg.PublicURL)); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		s.public = u
	} else if cfg.PublicURL != "" {
		log.Warn("LABWARDEN_PUBLIC_URL is not an http(s) URL; ignoring it for origin and cookie checks")
	}
	return s
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, s.accessLog, s.securityHeaders, s.crossOriginProtection().Handler)

	r.Get("/healthz", s.health)
	r.Get("/install.sh", s.agentFile("install.sh"))
	r.Get("/agent/labwarden-agent.sh", s.agentFile("labwarden-agent.sh"))

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/login", s.login)
		r.Post("/auth/logout", s.logout)
		r.Get("/auth/me", s.me)

		// Agent endpoints: an enrollment token enrolls a host, which then uses
		// its own credential for everything else.
		r.Post("/ingest/enroll", s.enroll)
		r.Group(func(r chi.Router) {
			r.Use(s.requireAgent)
			r.Post("/ingest/sbom", s.ingestSBOM)
			r.Post("/ingest/event", s.ingestEvent)
			r.Post("/ingest/run", s.ingestRun)
		})

		// UI endpoints: admin session (when a password is configured).
		r.Group(func(r chi.Router) {
			r.Use(s.requireSession)
			r.Post("/auth/logout-all", s.logoutAll)
			r.Get("/summary", s.summary)
			r.Get("/trends", s.trends)
			r.Get("/vulnerabilities", s.listVulns)
			r.Get("/vulnerabilities/export.csv", s.exportVulns)
			r.Get("/vulnerabilities/{id}", s.getVuln)
			r.Put("/vulnerabilities/{id}/triage", s.setTriage)
			r.Get("/findings", s.listFindings)
			r.Get("/hosts", s.listHosts)
			r.Get("/hosts/{id}", s.getHost)
			r.Patch("/hosts/{id}", s.updateHost)
			r.Delete("/hosts/{id}", s.deleteHost)
			r.Delete("/hosts/{id}/credential", s.resetCredential)
			r.Get("/groups", s.listGroups)
			r.Get("/scans", s.listScans)
			r.Get("/events", s.listEvents)
			r.Get("/tokens", s.listTokens)
			r.Post("/tokens", s.createToken)
			r.Delete("/tokens/{id}", s.revokeToken)
			r.Get("/agent-credentials", s.listCredentials)
			r.Get("/central-targets", s.listCentral)
			r.Post("/central-targets", s.createCentral)
			r.Patch("/central-targets/{id}", s.updateCentral)
			r.Delete("/central-targets/{id}", s.deleteCentral)
			r.Post("/central-targets/{id}/scan", s.scanCentral)
			r.Get("/system", s.system)
			r.Post("/db/update", s.updateDB)
			r.Post("/rematch", s.rematchAll)
			r.Post("/notify/test", s.testNotify)
		})
		r.NotFound(func(w http.ResponseWriter, r *http.Request) { writeErr(w, http.StatusNotFound, "not found") })
	})

	r.NotFound(s.spa)
	return r
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.st.Ping(r.Context()); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) agentFile(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := fs.ReadFile(s.agentFS, name)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	}
}

// spa serves the built UI, falling back to index.html for client routes.
func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p != "" {
		if f, err := s.webFS.Open(p); err == nil {
			st, _ := f.Stat()
			f.Close()
			if st != nil && !st.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.ServeFileFS(w, r, s.webFS, p)
				return
			}
		}
		// A missing hashed asset (e.g. an old chunk after a redeploy) must 404,
		// not get index.html: the UI detects the failed import and reloads.
		if strings.HasPrefix(p, "assets/") {
			http.NotFound(w, r)
			return
		}
	}
	index, err := fs.ReadFile(s.webFS, "index.html")
	if err != nil {
		http.Error(w, "LabWarden UI is not built into this binary. The API is available under /api/v1.", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(index)
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// storeErr maps store errors onto HTTP responses without leaking internals.
func (s *Server) storeErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		s.log.Error("request failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	return id, err == nil && id > 0
}

func qInt(r *http.Request, key string, def int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil {
		return def
	}
	return v
}

func qInt64(r *http.Request, key string) int64 {
	v, _ := strconv.ParseInt(r.URL.Query().Get(key), 10, 64)
	return v
}

func qList(r *http.Request, key string) []string {
	var out []string
	for _, v := range r.URL.Query()[key] {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func pageFrom(r *http.Request) store.Page {
	q := r.URL.Query()
	return store.Page{Page: qInt(r, "page", 1), Size: qInt(r, "size", 25), Sort: q.Get("sort"), Order: q.Get("order")}
}

// crossOriginProtection refuses state-changing requests that a browser
// sends from another site (CSRF), including the login form. Agents and
// other non-browser clients send neither Sec-Fetch-Site nor Origin and pass.
func (s *Server) crossOriginProtection() *http.CrossOriginProtection {
	c := http.NewCrossOriginProtection()
	if s.public != nil {
		if err := c.AddTrustedOrigin(s.public.Scheme + "://" + s.public.Host); err != nil {
			s.log.Warn("LABWARDEN_PUBLIC_URL is not usable as a trusted origin", "err", err)
		}
	}
	c.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusForbidden, "cross-origin request refused")
	}))
	return c
}

const contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'"

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		// Browsers ignore HSTS over plain HTTP; sending it only over HTTPS
		// keeps a plain-HTTP homelab install from advertising it at all.
		if s.viaHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		// API responses hold findings and settings: keep them out of caches.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		if r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/assets/") {
			return
		}
		s.log.Info("http", "method", r.Method, "path", r.URL.Path, "status", ww.Status(),
			"bytes_in", r.ContentLength, "dur_ms", time.Since(start).Milliseconds(), "ip", s.clientIP(r))
	})
}
