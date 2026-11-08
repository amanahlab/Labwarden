package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
