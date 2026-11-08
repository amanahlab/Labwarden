package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ---- agent enrollment ----
//
// An enrollment token (vxe_…) can only enroll a host. Enrolling returns a host
// credential (vxa_…) bound to that one host name, which the agent sends on
// every other ingest call. Both are stored as SHA-256 hashes; the plaintext is
// shown once.

var (
	ErrConflict     = errors.New("conflict")
	ErrUnauthorized = errors.New("unauthorized")
)

const (
	enrollPrefix     = "vxe_"
	credentialPrefix = "vxa_"
)

type Token struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Prefix    string `json:"prefix"`
	CreatedAt string `json:"created_at"`
	LastUsed  string `json:"last_used"`
	ExpiresAt string `json:"expires_at"` // "" = never
	MaxUses   int    `json:"max_uses"`   // 0 = unlimited
	Uses      int    `json:"uses"`
	RevokedAt string `json:"revoked_at"`
}

// Credential is an enrolled host's agent credential.
type Credential struct {
	ID         int64  `json:"id"`
	Host       string `json:"host"`
	Prefix     string `json:"prefix"`
	CreatedAt  string `json:"created_at"`
	LastUsed   string `json:"last_used"`
	LastIP     string `json:"last_ip"`
	EnrolledBy string `json:"enrolled_by"` // name of the enrollment token
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func newSecret(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

// CreateToken creates an enrollment token that expires after ttl (0: never)
// and enrolls at most maxUses hosts (0: any number). It returns the stored
// token and its plaintext value.
func (s *Store) CreateToken(ctx context.Context, name string, ttl time.Duration, maxUses int) (*Token, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if ttl < 0 || maxUses < 0 {
		return nil, "", fmt.Errorf("%w: expiry and uses must not be negative", ErrInvalid)
	}
	plain, err := newSecret(enrollPrefix)
	if err != nil {
		return nil, "", err
	}
	t := Token{Name: name, Prefix: plain[:8], CreatedAt: now(), MaxUses: maxUses}
	if ttl > 0 {
		t.ExpiresAt = stamp(time.Now().UTC().Add(ttl))
	}
	err = s.w.QueryRowContext(ctx, `INSERT INTO tokens(name, prefix, hash, created_at, expires_at, max_uses) VALUES (?,?,?,?,?,?)
		RETURNING id`, t.Name, t.Prefix, hashToken(plain), t.CreatedAt, nullStr(t.ExpiresAt), t.MaxUses).Scan(&t.ID)
	return &t, plain, err
}

// ImportToken stores the bootstrap enrollment token from the environment. A
// token that is already stored, revoked or not, is left as it is, so revoking
// the bootstrap token survives a restart.
func (s *Store) ImportToken(ctx context.Context, name, plain string) error {
	if len(plain) < 16 {
		return fmt.Errorf("%w: token must be at least 16 characters", ErrInvalid)
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO tokens(name, prefix, hash, created_at) VALUES (?,?,?,?)
		ON CONFLICT(hash) DO NOTHING`, name, plain[:8], hashToken(plain), now())
	return err
}

func (s *Store) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, name, prefix, created_at, COALESCE(last_used,''), COALESCE(expires_at,''),
		max_uses, uses, COALESCE(revoked_at,'') FROM tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedAt, &t.LastUsed, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken stops an enrollment token from enrolling more hosts. Hosts it
// already enrolled keep their credentials.
func (s *Store) RevokeToken(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, `UPDATE tokens SET revoked_at=COALESCE(revoked_at, ?) WHERE id=?`, now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Enroll trades a valid enrollment token for a credential bound to host. A
// host can hold one active credential at a time, and centrally scanned hosts
// cannot be enrolled.
func (s *Store) Enroll(ctx context.Context, token, host, ip string) (string, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var id int64
	var maxUses, uses int
	var expires, revoked sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id, expires_at, max_uses, uses, revoked_at FROM tokens WHERE hash=?`, hashToken(token)).
		Scan(&id, &expires, &maxUses, &uses, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: unknown enrollment token", ErrUnauthorized)
	}
	if err != nil {
		return "", err
	}
	if revoked.Valid || expires.Valid && expires.String <= now() || maxUses > 0 && uses >= maxUses {
		return "", fmt.Errorf("%w: enrollment token is revoked, expired or used up", ErrUnauthorized)
	}
	var kind string
	err = tx.QueryRowContext(ctx, `SELECT kind FROM hosts WHERE name=?`, host).Scan(&kind)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if kind == "central" {
		return "", fmt.Errorf("%w: %s is scanned centrally", ErrConflict, host)
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_credentials WHERE host=? AND revoked_at IS NULL`, host).Scan(&active); err != nil {
		return "", err
	}
	if active > 0 {
		return "", fmt.Errorf("%w: %s is already enrolled; reset its agent credential in the dashboard", ErrConflict, host)
	}
	plain, err := newSecret(credentialPrefix)
	if err != nil {
		return "", err
	}
	ts := now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_credentials(host, prefix, hash, created_at, last_ip, enrolled_by) VALUES (?,?,?,?,?,?)`,
		host, plain[:8], hashToken(plain), ts, ip, id); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE tokens SET uses=uses+1, last_used=? WHERE id=?`, ts, id); err != nil {
		return "", err
	}
	return plain, tx.Commit()
}

// VerifyCredential returns the host an active agent credential belongs to,
// or ErrUnauthorized.
func (s *Store) VerifyCredential(ctx context.Context, plain, ip string) (string, error) {
	var id int64
	var host string
	err := s.r.QueryRowContext(ctx, `SELECT id, host FROM agent_credentials WHERE hash=? AND revoked_at IS NULL`, hashToken(plain)).Scan(&id, &host)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUnauthorized
	}
	if err != nil {
		return "", err
	}
	_, _ = s.w.ExecContext(ctx, `UPDATE agent_credentials SET last_used=?, last_ip=? WHERE id=?`, now(), ip, id)
	return host, nil
}

// ListCredentials lists the active agent credentials.
func (s *Store) ListCredentials(ctx context.Context) ([]Credential, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT c.id, c.host, c.prefix, c.created_at, COALESCE(c.last_used,''), c.last_ip, COALESCE(t.name,'')
		FROM agent_credentials c LEFT JOIN tokens t ON t.id = c.enrolled_by WHERE c.revoked_at IS NULL ORDER BY c.host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.Host, &c.Prefix, &c.CreatedAt, &c.LastUsed, &c.LastIP, &c.EnrolledBy); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeCredential ends host's agent credential, so the host has to enroll
// again. It returns ErrNotFound when the host has none.
func (s *Store) RevokeCredential(ctx context.Context, host string) error {
	res, err := s.w.ExecContext(ctx, `UPDATE agent_credentials SET revoked_at=? WHERE host=? AND revoked_at IS NULL`, now(), host)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
