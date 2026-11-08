package api

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func sessionCookieOf(t *testing.T, ts *httptest.Server, c *http.Client) *http.Cookie {
	t.Helper()
	u, _ := url.Parse(ts.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == sessionCookie {
			return ck
		}
	}
	t.Fatal("no session cookie after login")
	return nil
}

// statusWithCookie replays a session cookie outside the client's jar, as a
// thief would.
func statusWithCookie(t *testing.T, ts *httptest.Server, ck *http.Cookie) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/summary", nil)
	req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestLogoutEndsSessionOnServer(t *testing.T) {
	ts, _ := newTestServer(t)
	c := login(t, ts, testPassword)
	ck := sessionCookieOf(t, ts, c)
	if got := statusWithCookie(t, ts, ck); got != http.StatusOK {
		t.Fatalf("fresh session: status %d", got)
	}
	resp, err := c.Post(ts.URL+"/api/v1/auth/logout", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := statusWithCookie(t, ts, ck); got != http.StatusUnauthorized {
		t.Fatalf("cookie replayed after logout: status %d, want 401", got)
	}
}

func TestLogoutAllEndsEverySession(t *testing.T) {
	ts, _ := newTestServer(t)
	laptop := sessionCookieOf(t, ts, login(t, ts, testPassword))
	phone := login(t, ts, testPassword)
	if got := statusWithCookie(t, ts, laptop); got != http.StatusOK {
		t.Fatalf("laptop session: status %d", got)
	}
	resp, err := phone.Post(ts.URL+"/api/v1/auth/logout-all", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout-all: status %d", resp.StatusCode)
	}
	if got := statusWithCookie(t, ts, laptop); got != http.StatusUnauthorized {
		t.Fatalf("other session after logout-all: status %d, want 401", got)
	}
	if got := getJSON(t, phone, ts.URL+"/api/v1/summary", nil); got != http.StatusUnauthorized {
		t.Fatalf("own session after logout-all: status %d, want 401", got)
	}
	// Only a signed-in admin may end everyone's sessions.
	resp, err = http.Post(ts.URL+"/api/v1/auth/logout-all", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("logout-all without a session: status %d, want 401", resp.StatusCode)
	}
}

func TestPasswordFingerprint(t *testing.T) {
	k1, k2 := []byte("key-one-key-one-key-one-key-one-"), []byte("key-two-key-two-key-two-key-two-")
	if passwordFingerprint(k1, "a password") == passwordFingerprint(k1, "another one") {
		t.Error("two passwords share a fingerprint")
	}
	if passwordFingerprint(k1, "a password") == passwordFingerprint(k2, "a password") {
		t.Error("the fingerprint does not depend on the key")
	}
}

func loginCookie(t *testing.T, h http.Handler, r *http.Request) *http.Cookie {
	t.Helper()
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("login: status %d", w.Code)
	}
	cs := w.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("login set %d cookies, want 1", len(cs))
	}
	return cs[0]
}

func TestSessionCookieSecurity(t *testing.T) {
	body := `{"password":"` + testPassword + `"}`
	newReq := func(peer, scheme string, header ...string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, scheme+"://labwarden.lan/api/v1/auth/login", strings.NewReader(body))
		r.RemoteAddr = peer
		for i := 0; i+1 < len(header); i += 2 {
			r.Header.Set(header[i], header[i+1])
		}
		return r
	}
	srv, _ := newTestAPI(t, func(c *Config) { c.TrustedProxies, _ = ParseTrustedProxies("10.0.0.0/8") })
	h := srv.Handler()
	cases := []struct {
		name   string
		r      *http.Request
		secure bool
	}{
		{"plain HTTP", newReq("192.0.2.1:5000", "http"), false},
		{"TLS", newReq("192.0.2.1:5000", "https"), true},
		{"HTTPS at a trusted proxy", newReq("10.0.0.2:5000", "http", "X-Forwarded-Proto", "https"), true},
		{"forged X-Forwarded-Proto", newReq("192.0.2.1:5000", "http", "X-Forwarded-Proto", "https"), false},
	}
	for _, c := range cases {
		ck := loginCookie(t, h, c.r)
		if ck.Secure != c.secure {
			t.Errorf("%s: Secure = %v, want %v", c.name, ck.Secure, c.secure)
		}
		if want := c.secure; strings.HasPrefix(ck.Name, "__Host-") != want {
			t.Errorf("%s: cookie name %q, __Host- prefix wanted: %v", c.name, ck.Name, want)
		}
		if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.Domain != "" {
			t.Errorf("%s: cookie attributes %+v", c.name, ck)
		}
	}

	forced, _ := newTestAPI(t, func(c *Config) { c.CookieSecure = true })
	if ck := loginCookie(t, forced.Handler(), newReq("192.0.2.1:5000", "http")); !ck.Secure || ck.Name != "__Host-"+sessionCookie {
		t.Errorf("LABWARDEN_COOKIE_SECURE: cookie %q secure=%v", ck.Name, ck.Secure)
	}
}

// The __Host- cookie set over HTTPS is the one checked on later requests.
func TestSecureSessionIsAccepted(t *testing.T) {
	srv, _ := newTestAPI(t, nil)
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)
	c := ts.Client()
	c.Jar, _ = cookiejar.New(nil)
	resp, err := c.Post(ts.URL+"/api/v1/auth/login", "application/json", strings.NewReader(`{"password":"`+testPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := getJSON(t, c, ts.URL+"/api/v1/summary", nil); got != http.StatusOK {
		t.Fatalf("summary over HTTPS after login: status %d", got)
	}
}
