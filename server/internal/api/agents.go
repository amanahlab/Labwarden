package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amanahlab/labwarden/server/internal/store"
)

// Agents enroll once with a shared enrollment token and get a credential
// bound to their host name; every other ingest call carries that credential
// and may only speak for its own host.

type agentHostKey struct{}

// rejectedAgentEvery bounds the "rejected agent request" events per client.
const rejectedAgentEvery = 10 * time.Minute

func bearer(r *http.Request) string {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return strings.TrimSpace(tok)
}

// agentAuthOK refuses clients that keep presenting bad tokens.
func (s *Server) agentAuthOK(w http.ResponseWriter, ip string) bool {
	if wait := s.agentLimiter.blocked(ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return false
	}
	return true
}

// agentAuthFailed counts a bad token. The log gets every one, the event log
// at most one per client every rejectedAgentEvery; neither repeats anything
// the client sent.
func (s *Server) agentAuthFailed(r *http.Request, ip, why string) {
	s.agentLimiter.fail(ip)
	s.log.Warn("rejected agent request", "ip", ip, "path", r.URL.Path, "reason", why)
	if s.agentEvents.allow(ip) {
		s.event(r, "warn", "auth", "", "", fmt.Sprintf("rejected agent request from %s: %s (further ones for %s are only logged to stdout)",
			ip, why, rejectedAgentEvery))
	}
}

// requireAgent admits requests with an active agent credential and records
// the host it belongs to.
func (s *Server) requireAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		if !s.agentAuthOK(w, ip) {
			return
		}
		tok := bearer(r)
		if tok == "" {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		host, err := s.st.VerifyCredential(r.Context(), tok, ip)
		if errors.Is(err, store.ErrUnauthorized) {
			s.agentAuthFailed(r, ip, "invalid agent credential")
			writeErr(w, http.StatusUnauthorized, "invalid agent credential; re-run install.sh to enroll this host")
			return
		}
		if err != nil {
			s.storeErr(w, r, err)
			return
		}
		s.agentLimiter.reset(ip)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), agentHostKey{}, host)))
	})
}

// agentHost returns the host the request's credential belongs to. A claimed
// host name, when given, must be that host.
func (s *Server) agentHost(w http.ResponseWriter, r *http.Request, claimed string) (string, bool) {
	host, _ := r.Context().Value(agentHostKey{}).(string)
	if claimed != "" && claimed != host {
		s.event(r, "warn", "auth", host, "", "refused a request from "+host+"'s agent credential that claimed to be another host, from "+s.clientIP(r))
		writeErr(w, http.StatusForbidden, "this credential belongs to host "+host)
		return "", false
	}
	return host, true
}

// enroll trades an enrollment token for a credential bound to one host.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.agentAuthOK(w, ip) {
		return
	}
	var body struct {
		Host string `json:"host"`
	}
	if err := decodeJSON(r, &body); err != nil || !hostnameRe.MatchString(body.Host) {
		writeErr(w, http.StatusBadRequest, "expected {host}, host matching "+hostnameRe.String())
		return
	}
	cred, err := s.st.Enroll(r.Context(), bearer(r), body.Host, ip)
	switch {
	case errors.Is(err, store.ErrUnauthorized):
		s.agentAuthFailed(r, ip, "enrollment refused: "+strings.TrimPrefix(err.Error(), "unauthorized: "))
		writeErr(w, http.StatusUnauthorized, "enrollment token is unknown, revoked, expired or used up")
	case errors.Is(err, store.ErrConflict):
		s.event(r, "warn", "auth", body.Host, "", "refused to enroll "+body.Host+" again from "+ip+": it already has an agent credential")
		writeErr(w, http.StatusConflict, strings.TrimPrefix(err.Error(), "conflict: "))
	case err != nil:
		s.storeErr(w, r, err)
	default:
		s.agentLimiter.reset(ip)
		s.event(r, "info", "auth", body.Host, "", "host "+body.Host+" enrolled from "+ip)
		writeJSON(w, http.StatusCreated, map[string]string{"host": body.Host, "credential": cred})
	}
}

// ---- admin side ----

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ListTokens(r.Context())
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		TTLHours *int   `json:"ttl_hours"` // 0: never expires; default 24
		MaxUses  int    `json:"max_uses"`  // 0: any number of hosts
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	ttl := 24
	if body.TTLHours != nil {
		ttl = *body.TTLHours
	}
	if ttl < 0 || ttl > 24*365 || body.MaxUses < 0 || body.MaxUses > 10000 {
		writeErr(w, http.StatusBadRequest, "ttl_hours must be 0-8760 and max_uses 0-10000")
		return
	}
	t, plain, err := s.st.CreateToken(r.Context(), clean(body.Name, 64), time.Duration(ttl)*time.Hour, body.MaxUses)
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	s.event(r, "info", "system", "", "", "enrollment token created: "+t.Name)
	writeJSON(w, http.StatusCreated, map[string]any{"token": t, "value": plain})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.RevokeToken(r.Context(), id); err != nil {
		s.storeErr(w, r, err)
		return
	}
	s.event(r, "warn", "system", "", "", fmt.Sprintf("enrollment token #%d revoked", id))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ListCredentials(r.Context())
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// resetCredential ends a host's agent credential; its agent has to enroll
// again with a valid enrollment token.
func (s *Server) resetCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	h, err := s.st.GetHost(r.Context(), id)
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	if err := s.st.RevokeCredential(r.Context(), h.Name); err != nil {
		s.storeErr(w, r, err)
		return
	}
	s.event(r, "warn", "system", h.Name, "", "agent credential reset; the host must enroll again")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
