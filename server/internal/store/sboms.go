package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// SetTargetSBOM records sha as the latest SBOM of a target, with the
// metadata to re-ingest it with.
func (s *Store) SetTargetSBOM(ctx context.Context, targetID int64, sha string, size int64, m IngestMeta) error {
	meta, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = s.w.ExecContext(ctx, `INSERT INTO target_sboms(target_id, sha256, size_bytes, meta, received_at)
		VALUES(?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET
		  sha256=excluded.sha256, size_bytes=excluded.size_bytes, meta=excluded.meta, received_at=excluded.received_at`,
		targetID, sha, size, string(meta), now())
	return err
}

// TargetSBOM returns the latest SBOM of a target and its metadata.
func (s *Store) TargetSBOM(ctx context.Context, targetID int64) (sha string, m IngestMeta, err error) {
	var meta string
	err = s.r.QueryRowContext(ctx, `SELECT sha256, meta FROM target_sboms WHERE target_id=?`, targetID).Scan(&sha, &meta)
	if errors.Is(err, sql.ErrNoRows) {
		return "", m, ErrNotFound
	}
	if err != nil {
		return "", m, err
	}
	return sha, m, json.Unmarshal([]byte(meta), &m)
}

// LiveSBOMTargets lists targets that are not retired and have an SBOM.
func (s *Store) LiveSBOMTargets(ctx context.Context) ([]int64, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT ts.target_id FROM target_sboms ts
		JOIN targets t ON t.id = ts.target_id WHERE t.retired_at IS NULL ORDER BY ts.target_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SBOMRefs is the set of SBOM files still referenced by a target.
func (s *Store) SBOMRefs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT DISTINCT sha256 FROM target_sboms`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := map[string]bool{}
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return nil, err
		}
		refs[sha] = true
	}
	return refs, rows.Err()
}
