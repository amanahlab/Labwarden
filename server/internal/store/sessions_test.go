package store

import (
	"context"
	"testing"
	"time"
)

func TestSessions(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	const fp, idle = "fp-1", 24 * time.Hour
	valid := func(id, fp string) bool {
		t.Helper()
		ok, err := s.ValidSession(ctx, id, fp, idle)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	set := func(id, col string, at time.Time) {
		t.Helper()
		if _, err := s.w.ExecContext(ctx, `UPDATE sessions SET `+col+` = ? WHERE id_hash = ?`, stamp(at), hashToken(id)); err != nil {
			t.Fatal(err)
		}
	}

	a, err := s.CreateSession(ctx, "192.0.2.1", "test", fp, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.CreateSession(ctx, "192.0.2.1", "test", fp, 7*24*time.Hour)
	if a == b || len(a) < 40 {
		t.Fatalf("session IDs %q and %q are not unique random values", a, b)
	}
	var stored int
	_ = s.r.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id_hash = ?`, a).Scan(&stored)
	if stored != 0 {
		t.Fatal("the session ID is stored in plain text")
	}
	if !valid(a, fp) || valid("", fp) || valid("nope", fp) {
		t.Fatal("session lookup is wrong")
	}
	if valid(a, "fp-2") {
		t.Fatal("a session outlived a password change")
	}

	// Use is recorded at most once a minute.
	set(a, "last_seen", time.Now().Add(-2*time.Hour))
	if !valid(a, fp) {
		t.Fatal("a session used 2 hours ago is idle")
	}
	var last string
	_ = s.r.QueryRowContext(ctx, `SELECT last_seen FROM sessions WHERE id_hash = ?`, hashToken(a)).Scan(&last)
	if seen, _ := time.Parse(time.RFC3339, last); time.Since(seen) > time.Minute {
		t.Fatalf("last_seen not updated: %s", last)
	}

	set(a, "last_seen", time.Now().Add(-idle-time.Minute))
	if valid(a, fp) {
		t.Fatal("an idle session is still valid")
	}
	set(b, "expires_at", time.Now().Add(-time.Second))
	if valid(b, fp) {
		t.Fatal("an expired session is still valid")
	}
	c, _ := s.CreateSession(ctx, "192.0.2.1", "test", fp, 7*24*time.Hour)
	if err := s.PruneSessions(ctx, idle); err != nil {
		t.Fatal(err)
	}
	var left int
	_ = s.r.QueryRowContext(ctx, `SELECT count(*) FROM sessions`).Scan(&left)
	if left != 1 || !valid(c, fp) {
		t.Fatalf("after pruning %d sessions are left, want only the live one", left)
	}

	if err := s.DeleteSession(ctx, c); err != nil || valid(c, fp) {
		t.Fatalf("deleted session still valid (err %v)", err)
	}
	d, _ := s.CreateSession(ctx, "", "", fp, time.Hour)
	e, _ := s.CreateSession(ctx, "", "", fp, time.Hour)
	if n, err := s.DeleteAllSessions(ctx); err != nil || n != 2 {
		t.Fatalf("DeleteAllSessions = %d, %v; want 2", n, err)
	}
	if valid(d, fp) || valid(e, fp) {
		t.Fatal("sessions survived DeleteAllSessions")
	}
}
