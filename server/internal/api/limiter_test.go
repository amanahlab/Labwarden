package api

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/amanahlab/labwarden/server/internal/store"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newFakeClock() *fakeClock           { return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }
func failN(l *loginLimiter, ip string, n int) {
	for range n {
		l.fail(ip)
	}
}

func TestLimiterLocksOutAndEscalates(t *testing.T) {
	c := newFakeClock()
	l := newLoginLimiter()
	l.now = c.now
	failN(l, "198.51.100.1", 4)
	if w := l.blocked("198.51.100.1"); w != 0 {
		t.Fatalf("locked out after 4 failures: %s", w)
	}
	l.fail("198.51.100.1")
	if w := l.blocked("198.51.100.1"); w != 30*time.Second {
		t.Fatalf("after 5 failures wait = %s, want 30s", w)
	}
	c.add(31 * time.Second)
	l.fail("198.51.100.1")
	if w := l.blocked("198.51.100.1"); w != time.Minute {
		t.Fatalf("after 6 failures wait = %s, want 1m", w)
	}
	// A long quiet spell forgets the failures.
	c.add(2 * time.Hour)
	l.fail("198.51.100.1")
	if w := l.blocked("198.51.100.1"); w != 0 {
		t.Fatalf("first failure after a quiet hour locked out: %s", w)
	}
}

// The old limiter emptied its table when it filled up, which unlocked every
// client that was locked out.
func TestLimiterFullTableKeepsLockouts(t *testing.T) {
	c := newFakeClock()
	l := newLoginLimiter()
	l.now, l.max = c.now, 3
	failN(l, "198.51.100.1", 5)
	failN(l, "198.51.100.2", 1)
	failN(l, "198.51.100.3", 1)
	failN(l, "198.51.100.4", 1) // no room: not tracked, and the table is kept
	if w := l.blocked("198.51.100.1"); w == 0 {
		t.Fatal("a locked-out client was unlocked when the table filled up")
	}
	if w := l.blocked("198.51.100.4"); w != fullWait {
		t.Fatalf("new client with a full table: wait %s, want %s", w, fullWait)
	}
	// Once the others have been quiet long enough, they make room.
	c.add(forgetAfter + time.Minute)
	if w := l.blocked("198.51.100.4"); w != 0 {
		t.Fatalf("new client after quiet clients expired: wait %s", w)
	}
}

func TestLimiterGroupsIPv6By64(t *testing.T) {
	l := newLoginLimiter()
	for i := range 5 {
		l.fail(fmt.Sprintf("2001:db8:1:2::%x", i+1))
	}
	if l.blocked("2001:db8:1:2::ffff") == 0 {
		t.Error("addresses in one /64 are limited separately")
	}
	if l.blocked("2001:db8:1:3::1") != 0 {
		t.Error("a neighbouring /64 is locked out too")
	}
}

func TestFailBudget(t *testing.T) {
	c := newFakeClock()
	b := newFailBudget(30, 10*time.Minute)
	b.now = c.now
	warnings := 0
	for range 30 {
		if b.wait() != 0 {
			t.Fatal("budget ran out early")
		}
		if b.spend() {
			warnings++
		}
	}
	if b.wait() == 0 {
		t.Fatal("31st failure in the window allowed")
	}
	if warnings != 1 {
		t.Fatalf("warnings = %d, want 1", warnings)
	}
	c.add(20 * time.Second) // one token back
	if b.wait() != 0 {
		t.Fatal("budget did not refill")
	}
	if b.spend() {
		t.Error("warned again within the same window")
	}
	c.add(10 * time.Minute)
	if b.wait() != 0 {
		t.Fatal("budget did not refill after a window")
	}
}

// Failures spread over many addresses still run out the shared budget. Then
// addresses that failed before wait, while the right password from a clean
// address still gets in: a stranger cannot lock the owner out.
func TestLoginBudgetAcrossClients(t *testing.T) {
	ts, st := newTestServerWith(t, func(c *Config) {
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
	for i := range loginBudget {
		if got := try(fmt.Sprintf("198.51.100.%d", i+1), "wrong"); got != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d, want 401", i+1, got)
		}
	}
	if got := try("198.51.100.1", "wrong"); got != http.StatusTooManyRequests {
		t.Fatalf("second failure after the budget ran out: status %d, want 429", got)
	}
	if got := try("203.0.113.9", testPassword); got != http.StatusOK {
		t.Fatalf("right password from a clean address after the budget ran out: status %d, want 200", got)
	}
	evs, err := st.ListEvents(t.Context(), store.EventFilter{Q: "are paused"}, store.Page{Size: 100})
	if err != nil {
		t.Fatal(err)
	}
	paused := 0
	for _, e := range evs.Items {
		if strings.Contains(e.Message, "are paused") {
			paused++
		}
	}
	if paused != 1 {
		t.Errorf("pause warnings = %d, want 1", paused)
	}
}
