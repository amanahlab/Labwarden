package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func itoa(i int) string { return strconv.Itoa(i) }

// ---- events (the Logs page) ----

type Event struct {
	ID      int64  `json:"id"`
	TS      string `json:"ts"`
	Level   string `json:"level"`
	Source  string `json:"source"`
	Host    string `json:"host"`
	RunID   string `json:"run_id"`
	Message string `json:"message"`
}

var eventLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}

func (s *Store) AddEvent(ctx context.Context, e Event) error {
	if !eventLevels[e.Level] {
		e.Level = "info"
	}
	if len(e.Message) > 4000 {
		e.Message = e.Message[:4000] + "…"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO events(ts, level, source, host, run_id, message) VALUES (?,?,?,?,?,?)`,
		now(), e.Level, e.Source, e.Host, e.RunID, e.Message)
	return err
}

type EventFilter struct {
	Q      string
	Level  []string
	Source string
	Host   string
	RunID  string
}

func (s *Store) ListEvents(ctx context.Context, f EventFilter, p Page) (*List[Event], error) {
	p.norm()
	var w where
	w.in("level", f.Level)
	if f.Source != "" {
		w.add("source = ?", f.Source)
	}
	if f.Host != "" {
		w.add("host = ?", f.Host)
	}
	if f.RunID != "" {
		w.add("run_id = ?", f.RunID)
	}
	if f.Q != "" {
		w.add(`(message LIKE ? ESCAPE '\' OR host LIKE ? ESCAPE '\')`, like(f.Q), like(f.Q))
	}
	out := &List[Event]{Items: []Event{}, Page: p.Page, Size: p.Size}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`+w.sql(), w.args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT id, ts, level, source, host, run_id, message FROM events`+w.sql()+
		p.orderBy(map[string]string{"ts": "id", "level": "level", "host": "host", "source": "source"}, "ts", "id DESC")+p.limit(), w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Level, &e.Source, &e.Host, &e.RunID, &e.Message); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, e)
	}
	return out, rows.Err()
}

// PruneEvents keeps the newest n events.
func (s *Store) PruneEvents(ctx context.Context, keep int) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)`, keep)
	return err
}

// ---- ingest tokens (stored as SHA-256; the plaintext is shown once) ----

type Token struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Prefix    string `json:"prefix"`
	CreatedAt string `json:"created_at"`
	LastUsed  string `json:"last_used"`
}

const tokenPrefix = "vx_"

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// CreateToken returns the stored token and its plaintext value.
func (s *Store) CreateToken(ctx context.Context, name string) (*Token, string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, "", err
	}
	plain := tokenPrefix + hex.EncodeToString(b)
	t, err := s.ImportToken(ctx, name, plain)
	return t, plain, err
}

// ImportToken stores a caller-provided token (the bootstrap token from the
// environment). It is idempotent.
func (s *Store) ImportToken(ctx context.Context, name, plain string) (*Token, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if len(plain) < 16 {
		return nil, fmt.Errorf("%w: token must be at least 16 characters", ErrInvalid)
	}
	t := Token{Name: name, Prefix: plain[:min(8, len(plain))], CreatedAt: now()}
	err := s.w.QueryRowContext(ctx, `INSERT INTO tokens(name, prefix, hash, created_at) VALUES (?,?,?,?)
		ON CONFLICT(hash) DO UPDATE SET name=tokens.name RETURNING id, created_at`,
		t.Name, t.Prefix, hashToken(plain), t.CreatedAt).Scan(&t.ID, &t.CreatedAt)
	return &t, err
}

func (s *Store) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, name, prefix, created_at, COALESCE(last_used,'') FROM tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedAt, &t.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteToken(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM tokens WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// VerifyToken checks a presented bearer token and returns its name.
func (s *Store) VerifyToken(ctx context.Context, plain string) (string, bool) {
	h := hashToken(plain)
	var id int64
	var name, stored string
	err := s.r.QueryRowContext(ctx, `SELECT id, name, hash FROM tokens WHERE hash=?`, h).Scan(&id, &name, &stored)
	if err != nil || subtle.ConstantTimeCompare([]byte(h), []byte(stored)) != 1 {
		return "", false
	}
	_, _ = s.w.ExecContext(ctx, `UPDATE tokens SET last_used=? WHERE id=?`, now(), id)
	return name, true
}

// ---- central scan targets ----

type CentralTarget struct {
	ID          int64  `json:"id"`
	Ref         string `json:"ref"`
	HostName    string `json:"host_name"`
	Group       string `json:"group"`
	IntervalMin int    `json:"interval_min"`
	Enabled     bool   `json:"enabled"`
	LastRun     string `json:"last_run"`
	LastStatus  string `json:"last_status"`
	CreatedAt   string `json:"created_at"`
}

func (s *Store) ListCentralTargets(ctx context.Context) ([]CentralTarget, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, ref, host_name, grp, interval_min, enabled, COALESCE(last_run,''), last_status, created_at
		FROM central_targets ORDER BY ref`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CentralTarget{}
	for rows.Next() {
		var c CentralTarget
		if err := rows.Scan(&c.ID, &c.Ref, &c.HostName, &c.Group, &c.IntervalMin, &c.Enabled, &c.LastRun, &c.LastStatus, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetCentralTarget(ctx context.Context, id int64) (*CentralTarget, error) {
	var c CentralTarget
	err := s.r.QueryRowContext(ctx, `SELECT id, ref, host_name, grp, interval_min, enabled, COALESCE(last_run,''), last_status, created_at
		FROM central_targets WHERE id=?`, id).Scan(&c.ID, &c.Ref, &c.HostName, &c.Group, &c.IntervalMin, &c.Enabled, &c.LastRun, &c.LastStatus, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) CreateCentralTarget(ctx context.Context, c CentralTarget) (*CentralTarget, error) {
	c.Ref = strings.TrimSpace(c.Ref)
	if c.Ref == "" || strings.ContainsAny(c.Ref, " \t\n") || strings.HasPrefix(c.Ref, "-") {
		return nil, fmt.Errorf("%w: invalid image reference", ErrInvalid)
	}
	if c.HostName == "" {
		c.HostName = "central"
	}
	if c.Group == "" {
		c.Group = "central"
	}
	if c.IntervalMin < 15 {
		c.IntervalMin = 1440
	}
	c.CreatedAt = now()
	err := s.w.QueryRowContext(ctx, `INSERT INTO central_targets(ref, host_name, grp, interval_min, enabled, created_at)
		VALUES (?,?,?,?,1,?) RETURNING id`, c.Ref, c.HostName, c.Group, c.IntervalMin, c.CreatedAt).Scan(&c.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("%w: %s is already a target", ErrInvalid, c.Ref)
		}
		return nil, err
	}
	c.Enabled = true
	return &c, nil
}

func (s *Store) DeleteCentralTarget(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM central_targets WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetCentralTargetEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := s.w.ExecContext(ctx, `UPDATE central_targets SET enabled=? WHERE id=?`, b2i(enabled), id)
	return err
}

func (s *Store) MarkCentralRun(ctx context.Context, id int64, status string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE central_targets SET last_run=?, last_status=? WHERE id=?`, now(), status, id)
	return err
}

// DueCentralTargets returns enabled targets whose interval has elapsed.
func (s *Store) DueCentralTargets(ctx context.Context) ([]CentralTarget, error) {
	all, err := s.ListCentralTargets(ctx)
	if err != nil {
		return nil, err
	}
	var due []CentralTarget
	for _, c := range all {
		if !c.Enabled {
			continue
		}
		if c.LastRun == "" {
			due = append(due, c)
			continue
		}
		var elapsed float64
		if err := s.r.QueryRowContext(ctx, `SELECT (julianday('now') - julianday(?)) * 1440`, c.LastRun).Scan(&elapsed); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return nil, err
		}
		if elapsed >= float64(c.IntervalMin) {
			due = append(due, c)
		}
	}
	return due, nil
}
