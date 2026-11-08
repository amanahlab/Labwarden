package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCrossSiteRequestsRefused(t *testing.T) {
	ts, _ := newTestServer(t)
	c := login(t, ts, testPassword)
	post := func(path, body string, header ...string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for i := 0; i+1 < len(header); i += 2 {
			req.Header.Set(header[i], header[i+1])
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// A bodiless endpoint is the one the content-type check cannot guard.
	if got := post("/api/v1/db/update", "", "Sec-Fetch-Site", "cross-site"); got != http.StatusForbidden {
		t.Errorf("cross-site POST (Sec-Fetch-Site): status %d, want 403", got)
	}
	if got := post("/api/v1/db/update", "", "Origin", "https://evil.example"); got != http.StatusForbidden {
		t.Errorf("cross-site POST (Origin): status %d, want 403", got)
	}
	if got := post("/api/v1/auth/login", `{"password":"`+testPassword+`"}`, "Sec-Fetch-Site", "cross-site"); got != http.StatusForbidden {
		t.Errorf("cross-site login: status %d, want 403", got)
	}
	if got := post("/api/v1/auth/logout-all", "", "Sec-Fetch-Site", "same-site"); got != http.StatusForbidden {
		t.Errorf("same-site (other subdomain) POST: status %d, want 403", got)
	}
	if got := post("/api/v1/db/update", "", "Sec-Fetch-Site", "same-origin"); got != http.StatusAccepted && got != http.StatusOK {
		t.Errorf("same-origin POST: status %d", got)
	}
	if got := post("/api/v1/auth/logout", "", "Origin", ts.URL); got != http.StatusOK {
		t.Errorf("same-origin POST (Origin): status %d", got)
	}
}

// A chunked body has ContentLength -1; it used to skip the JSON check.
func TestChunkedFormPostRefused(t *testing.T) {
	ts, _ := newTestServer(t)
	c := login(t, ts, testPassword)
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("name=x"))
		pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/tokens", pr)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("chunked form POST: status %d, want 415", resp.StatusCode)
	}
}
