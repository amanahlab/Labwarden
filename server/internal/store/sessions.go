package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"
)

// ---- admin sessions ----

// CreateSession opens a session that ends at maxAge at the latest and returns
// the session ID for the cookie. pwFP fingerprints the admin password, so a
// new password ends every session opened with the old one.
func (s *Store) CreateSession(ctx context.Context, ip, userAgent, pwFP string, maxAge time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	if len(userAgent) > 200 {
		userAgent = userAgent[:200]
	}
	t := time.Now().UTC()
	_, err := s.w.ExecContext(ctx, `INSERT INTO sessions(id_hash, created_at, expires_at, last_seen, ip, user_agent, pw_fp)
		VALUES (?,?,?,?,?,?,?)`, hashToken(id), stamp(t), stamp(t.Add(maxAge)), stamp(t), ip, userAgent, pwFP)
	return id, err
}

// ValidSession reports whether id is a live session for the password pwFP
// that has been used within idle. It records use at most once a minute.
func (s *Store) ValidSession(ctx context.Context, id, pwFP string, idle time.Duration) (bool, error) {
	if id == "" {
		return false, nil
	}
	h := hashToken(id)
	var expires, lastSeen, fp string
	err := s.r.QueryRowContext(ctx, `SELECT expires_at, last_seen, pw_fp FROM sessions WHERE id_hash = ?`, h).
		Scan(&expires, &lastSeen, &fp)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	exp, err1 := time.Parse(time.RFC3339, expires)
	last, err2 := time.Parse(time.RFC3339, lastSeen)
	if err := errors.Join(err1, err2); err != nil {
		return false, err
	}
	t := time.Now().UTC()
	if !t.Before(exp) || t.Sub(last) >= idle || subtle.ConstantTimeCompare([]byte(fp), []byte(pwFP)) != 1 {
		return false, nil
	}
	if t.Sub(last) >= time.Minute {
		if _, err := s.w.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE id_hash = ?`, stamp(t), h); err != nil {
			return false, err
		}
	}
	return true, nil
}

// DeleteSession ends one session; an unknown id is not an error.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, hashToken(id))
	return err
}

// DeleteAllSessions ends every session and returns how many there were.
func (s *Store) DeleteAllSessions(ctx context.Context) (int64, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM sessions`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneSessions deletes sessions that have expired or been idle too long.
func (s *Store) PruneSessions(ctx context.Context, idle time.Duration) error {
	t := time.Now().UTC()
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?`, stamp(t), stamp(t.Add(-idle)))
	return err
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }
