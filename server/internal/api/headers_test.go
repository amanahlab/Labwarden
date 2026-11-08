package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	srv, _ := newTestAPI(t, func(c *Config) { c.TrustedProxies, _ = ParseTrustedProxies("10.0.0.0/8") })
	h := srv.Handler()
	get := func(url, peer string, header ...string) http.Header {
		r := httptest.NewRequest(http.MethodGet, url, nil)
		r.RemoteAddr = peer
		for i := 0; i+1 < len(header); i += 2 {
			r.Header.Set(header[i], header[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Result().Header
	}

	page := get("http://labwarden.lan/", "192.0.2.1:5000")
	csp := page.Get("Content-Security-Policy")
	for _, d := range []string{"default-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP %q lacks %q", csp, d)
		}
	}
	for k, want := range map[string]string{
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"X-Frame-Options":              "DENY",
		"X-Content-Type-Options":       "nosniff",
	} {
		if got := page.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if page.Get("Permissions-Policy") == "" {
		t.Error("no Permissions-Policy")
	}
	if page.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent over plain HTTP")
	}
	if page.Get("Cache-Control") == "no-store" {
		t.Error("the SPA shell is no-store; it should stay cacheable with revalidation")
	}

	if got := get("http://labwarden.lan/api/v1/auth/me", "192.0.2.1:5000").Get("Cache-Control"); got != "no-store" {
		t.Errorf("API Cache-Control = %q, want no-store", got)
	}
	if get("https://labwarden.lan/", "192.0.2.1:5000").Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS over TLS")
	}
	if get("http://labwarden.lan/", "10.0.0.2:5000", "X-Forwarded-Proto", "https").Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS behind a trusted HTTPS proxy")
	}
	if get("http://labwarden.lan/", "192.0.2.1:5000", "X-Forwarded-Proto", "https").Get("Strict-Transport-Security") != "" {
		t.Error("HSTS on a forged X-Forwarded-Proto")
	}
}
