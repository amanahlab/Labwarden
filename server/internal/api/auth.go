package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amanahlab/labwarden/server/internal/store"
)

// An admin session ends after SessionIdleTimeout without use, and after
// sessionMaxAge in any case.
const (
	SessionIdleTimeout = 24 * time.Hour
	sessionMaxAge      = 7 * 24 * time.Hour
	sessionCookie      = "labwarden_session"

	loginBudget       = 30 // failed logins from all clients together per window
	loginBudgetWindow = 10 * time.Minute
)

func (s *Server) authEnabled() bool { return s.cfg.AdminPassword != "" }

// passwordFingerprint ties sessions to the admin password they were opened
// with: change the password and every session ends.
func passwordFingerprint(key []byte, password string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(password))
	return hex.EncodeToString(m.Sum(nil))
}

// sessionCookieName is the cookie's name for requests like r. Over HTTPS the
// cookie is Secure and carries the __Host- prefix, so the browser never sends
// it over plain HTTP and nothing on another subdomain can set or overwrite it.
func (s *Server) sessionCookieName(r *http.Request) string {
	if s.secureCookie(r) {
		return "__Host-" + sessionCookie
	}
	return sessionCookie
}

// secureCookie: an https LABWARDEN_PUBLIC_URL only counts for requests to its
// host, so the dashboard still works when opened by plain-HTTP LAN address.
func (s *Server) secureCookie(r *http.Request) bool {
	return s.cfg.CookieSecure || s.viaHTTPS(r) ||
		s.public != nil && s.public.Scheme == "https" && strings.EqualFold(r.Host, s.public.Host)
}

// setSessionCookie sets the session cookie, or deletes it when id is empty.
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, id string) {
	maxAge := int(sessionMaxAge.Seconds())
	if id == "" {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName(r), Value: id, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.secureCookie(r)})
}

func (s *Server) validSession(r *http.Request) bool {
	c, err := r.Cookie(s.sessionCookieName(r))
	if err != nil {
		return false
	}
	ok, err := s.st.ValidSession(r.Context(), c.Value, s.pwFP, SessionIdleTimeout)
	if err != nil {
		s.log.Error("check session", "err", err)
	}
	return ok
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authEnabled() && !s.validSession(r) {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		// Mutations must be JSON (or bodiless), a second line of defence
		// against cross-site form posts. ContentLength is -1 for a chunked
		// body, which must not slip past.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.ContentLength != 0 &&
			!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeErr(w, http.StatusUnsupportedMediaType, "expected application/json")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled() {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "auth_enabled": false})
		return
	}
	ip := s.clientIP(r)
	wait := s.limiter.blocked(ip)
	if wait == 0 && s.limiter.failed(ip) {
		wait = s.budget.wait()
	}
	if wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	a := sha256.Sum256([]byte(body.Password))
	b := sha256.Sum256([]byte(s.cfg.AdminPassword))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		s.limiter.fail(ip)
		s.event(r, "warn", "auth", "", "", "failed admin login from "+ip)
		if s.budget.spend() {
			s.event(r, "warn", "auth", "", "", fmt.Sprintf("more than %d failed admin logins in %s from all addresses together: addresses that already failed are paused until the rate drops", loginBudget, loginBudgetWindow))
		}
		writeErr(w, http.StatusUnauthorized, "invalid password")
		return
	}
	s.limiter.reset(ip)
	id, err := s.st.CreateSession(r.Context(), ip, r.UserAgent(), s.pwFP, sessionMaxAge)
	if err != nil {
		s.log.Error("create session", "err", err)
		writeErr(w, http.StatusInternalServerError, "could not start a session")
		return
	}
	s.setSessionCookie(w, r, id)
	s.event(r, "info", "auth", "", "", "admin login from "+ip)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "auth_enabled": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.sessionCookieName(r)); err == nil {
		if err := s.st.DeleteSession(r.Context(), c.Value); err != nil {
			s.log.Error("delete session", "err", err)
			writeErr(w, http.StatusInternalServerError, "could not end the session")
			return
		}
	}
	s.setSessionCookie(w, r, "")
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

// logoutAll ends every admin session, this one included.
func (s *Server) logoutAll(w http.ResponseWriter, r *http.Request) {
	n, err := s.st.DeleteAllSessions(r.Context())
	if err != nil {
		s.log.Error("delete sessions", "err", err)
		writeErr(w, http.StatusInternalServerError, "could not end the sessions")
		return
	}
	s.event(r, "info", "auth", "", "", fmt.Sprintf("all admin sessions ended (%d) from %s", n, s.clientIP(r)))
	s.setSessionCookie(w, r, "")
	writeJSON(w, http.StatusOK, map[string]int64{"ended": n})
}

// me tells the UI whether to show the login page. The version, which would
// help an attacker pick exploits, is only for signed-in users.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	authed := !s.authEnabled() || s.validSession(r)
	out := map[string]any{"authenticated": authed, "auth_enabled": s.authEnabled()}
	if authed {
		out["version"] = s.cfg.Version
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) event(r *http.Request, level, source, host, runID, msg string) {
	if err := s.st.AddEvent(r.Context(), store.Event{Level: level, Source: source, Host: host, RunID: runID, Message: msg}); err != nil {
		s.log.Error("add event", "err", err)
	}
}
