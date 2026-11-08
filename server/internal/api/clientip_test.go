package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies("10.0.0.0/8, 192.168.1.1 ::1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.168.1.1/32", "::1/128"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("proxy %d = %s, want %s", i, got[i], want[i])
		}
	}
	if _, err := ParseTrustedProxies("proxy.lan"); err == nil {
		t.Error("a host name was accepted as a trusted proxy")
	}
	if got, err := ParseTrustedProxies(""); err != nil || len(got) != 0 {
		t.Errorf("empty list = %v, %v", got, err)
	}
}

func TestClientIP(t *testing.T) {
	proxies, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{TrustedProxies: proxies}}
	cases := []struct {
		name, peer string
		xff        []string
		want       string
	}{
		{"direct client", "203.0.113.5:4000", nil, "203.0.113.5"},
		{"forged header from an untrusted peer", "203.0.113.5:4000", []string{"1.2.3.4"}, "203.0.113.5"},
		{"trusted proxy", "10.0.0.2:4000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"client-written hops left of the proxy are ignored", "10.0.0.2:4000", []string{"1.2.3.4, 198.51.100.7"}, "198.51.100.7"},
		{"chain of trusted proxies", "10.0.0.2:4000", []string{"1.2.3.4, 198.51.100.7, 10.0.0.9"}, "198.51.100.7"},
		{"repeated headers", "10.0.0.2:4000", []string{"1.2.3.4", "198.51.100.7"}, "198.51.100.7"},
		{"malformed hop", "10.0.0.2:4000", []string{"1.2.3.4, not-an-ip"}, "10.0.0.2"},
		{"trusted proxy without a header", "10.0.0.2:4000", nil, "10.0.0.2"},
		{"IPv6 peer", "[2001:db8::1]:4000", []string{"1.2.3.4"}, "2001:db8::1"},
		{"IPv4-mapped peer", "[::ffff:10.0.0.2]:4000", []string{"198.51.100.7"}, "198.51.100.7"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.peer
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("%s: clientIP = %s, want %s", c.name, got, c.want)
		}
	}
}

// A client must not dodge the login lockout by sending a new
// X-Forwarded-For on every attempt.
func TestLoginLockoutIgnoresForgedForwardedFor(t *testing.T) {
	ts, _ := newTestServer(t)
	status := 0
	for i := range 6 {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", bytes.NewReader([]byte(`{"password":"wrong"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "198.51.100."+string(rune('1'+i)))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		status = resp.StatusCode
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("sixth wrong password with a new X-Forwarded-For: status %d, want 429", status)
	}
}

// Behind a trusted proxy each client is limited on its own address, so one
// client's lockout does not lock everyone else out.
func TestLoginLockoutPerClientBehindTrustedProxy(t *testing.T) {
	ts, _ := newTestServerWith(t, func(c *Config) {
		c.TrustedProxies, _ = ParseTrustedProxies("127.0.0.0/8, ::1")
	})
	try := func(client, password string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", bytes.NewReader([]byte(`{"password":"`+password+`"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", client)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for range 5 {
		try("198.51.100.1", "wrong")
	}
	if got := try("198.51.100.1", "wrong"); got != http.StatusTooManyRequests {
		t.Fatalf("locked-out client: status %d, want 429", got)
	}
	if got := try("198.51.100.2", testPassword); got != http.StatusOK {
		t.Fatalf("another client behind the proxy: status %d, want 200", got)
	}
}
