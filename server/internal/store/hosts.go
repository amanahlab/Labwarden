package store

import (
	"context"
	"fmt"
	"strings"
)

// staleAfterSec is the fallback silence threshold for hosts that never
// declared a scan interval.
const staleAfterSec = 26 * 3600

// hostStatusSQL classifies a host: failing (last run reported an error),
// stale (silent for 2.5x its interval) or ok.
var hostStatusSQL = fmt.Sprintf(`CASE
	WHEN (julianday('now') - julianday(h.last_seen)) * 86400 >
	     (CASE WHEN h.interval_sec > 0 THEN h.interval_sec * 2.5 ELSE %d END) THEN 'stale'
	WHEN h.last_run_status = 'error' THEN 'failing'
	ELSE 'ok' END`, staleAfterSec)

type Counts struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Unknown    int `json:"unknown"`
	Total      int `json:"total"`
	Fixable    int `json:"fixable"`
}

type HostRow struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Group         string `json:"group"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	IP            string `json:"ip"`
	AgentVersion  string `json:"agent_version"`
	Notes         string `json:"notes"`
	IntervalSec   int    `json:"interval_sec"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	LastRunStatus string `json:"last_run_status"`
	Status        string `json:"status"`
	Targets       int    `json:"targets"`
	Score         int    `json:"score"`
	Counts
}

// active counts per host from current findings.
const hostCountsSQL = `
	SELECT host_id,
	  SUM(severity='Critical') c, SUM(severity='High') h, SUM(severity='Medium') m, SUM(severity='Low') l,
	  SUM(severity='Negligible') n, SUM(severity='Unknown') u, COUNT(*) t, SUM(fix_state='fixed') f
	FROM current_findings WHERE status IN ('open','acknowledged') GROUP BY host_id`

// score weights severities so the "most exposed" sort is meaningful.
const scoreSQL = `(COALESCE(c.c,0)*100 + COALESCE(c.h,0)*20 + COALESCE(c.m,0)*5 + COALESCE(c.l,0))`

var hostSorts = map[string]string{
	"name":      "h.name",
	"group":     "h.grp",
	"kind":      "h.kind",
	"last_seen": "h.last_seen",
	"critical":  "COALESCE(c.c,0)",
	"high":      "COALESCE(c.h,0)",
	"total":     "COALESCE(c.t,0)",
	"score":     scoreSQL,
	"status":    "status",
	"targets":   "targets",
}

type HostFilter struct {
	Q      string
	Group  string
	Kind   string
	Status string
}

func (s *Store) ListHosts(ctx context.Context, f HostFilter, p Page) (*List[HostRow], error) {
	p.norm()
	var w where
	if f.Q != "" {
		w.add(`(h.name LIKE ? ESCAPE '\' OR h.ip LIKE ? ESCAPE '\' OR h.os LIKE ? ESCAPE '\' OR h.grp LIKE ? ESCAPE '\')`,
			like(f.Q), like(f.Q), like(f.Q), like(f.Q))
	}
	if f.Group != "" {
		w.add("h.grp = ?", f.Group)
	}
	if f.Kind != "" {
		w.add("h.kind = ?", f.Kind)
	}
	if f.Status != "" {
		w.add(hostStatusSQL+" = ?", f.Status)
	}
	from := ` FROM hosts h LEFT JOIN (` + hostCountsSQL + `) c ON c.host_id = h.id` + w.sql()
	out := &List[HostRow]{Items: []HostRow{}, Page: p.Page, Size: p.Size}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*)`+from, w.args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	q := `SELECT h.id, h.name, h.kind, h.grp, h.os, h.arch, h.ip, h.agent_version, h.notes, h.interval_sec, h.first_seen, h.last_seen,
		h.last_run_status, ` + hostStatusSQL + ` AS status,
		(SELECT COUNT(*) FROM targets t WHERE t.host_id=h.id AND t.retired_at IS NULL) AS targets, ` + scoreSQL + `,
		COALESCE(c.c,0), COALESCE(c.h,0), COALESCE(c.m,0), COALESCE(c.l,0), COALESCE(c.n,0), COALESCE(c.u,0), COALESCE(c.t,0), COALESCE(c.f,0)` +
		from + p.orderBy(hostSorts, "score", "h.name") + p.limit()
	rows, err := s.r.QueryContext(ctx, q, w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, *r)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scanHost(sc scanner) (*HostRow, error) {
	var r HostRow
	err := sc.Scan(&r.ID, &r.Name, &r.Kind, &r.Group, &r.OS, &r.Arch, &r.IP, &r.AgentVersion, &r.Notes, &r.IntervalSec,
		&r.FirstSeen, &r.LastSeen, &r.LastRunStatus, &r.Status, &r.Targets, &r.Score,
		&r.Critical, &r.High, &r.Medium, &r.Low, &r.Negligible, &r.Unknown, &r.Total, &r.Fixable)
	return &r, err
}

func (s *Store) GetHost(ctx context.Context, id int64) (*HostRow, error) {
	row := s.r.QueryRowContext(ctx, `SELECT h.id, h.name, h.kind, h.grp, h.os, h.arch, h.ip, h.agent_version, h.notes, h.interval_sec,
		h.first_seen, h.last_seen, h.last_run_status, `+hostStatusSQL+`,
		(SELECT COUNT(*) FROM targets t WHERE t.host_id=h.id AND t.retired_at IS NULL), `+scoreSQL+`,
		COALESCE(c.c,0), COALESCE(c.h,0), COALESCE(c.m,0), COALESCE(c.l,0), COALESCE(c.n,0), COALESCE(c.u,0), COALESCE(c.t,0), COALESCE(c.f,0)
		FROM hosts h LEFT JOIN (`+hostCountsSQL+`) c ON c.host_id = h.id WHERE h.id=?`, id)
	return scanHost(row)
}

func (s *Store) UpdateHost(ctx context.Context, id int64, group, notes *string) error {
	var sets []string
	var args []any
	if group != nil {
		g := strings.TrimSpace(*group)
		if g == "" {
			g = "default"
		}
		sets, args = append(sets, "grp=?"), append(args, g)
	}
	if notes != nil {
		sets, args = append(sets, "notes=?"), append(args, *notes)
	}
	if len(sets) == 0 {
		return nil
	}
	res, err := s.w.ExecContext(ctx, `UPDATE hosts SET `+strings.Join(sets, ",")+` WHERE id=?`, append(args, id)...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteHost(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM hosts WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, _ = s.w.ExecContext(ctx, `DELETE FROM triage WHERE host_id=?`, id)
	return s.RefreshDaily(ctx)
}

type TargetRow struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Distro      string `json:"distro"`
	FirstSeen   string `json:"first_seen"`
	LastScanned string `json:"last_scanned"`
	RetiredAt   string `json:"retired_at"`
	Counts
}

func (s *Store) HostTargets(ctx context.Context, hostID int64) ([]TargetRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT t.id, t.name, t.type, t.distro, t.first_seen, t.last_scanned, COALESCE(t.retired_at,''),
		COALESCE(SUM(cf.severity='Critical'),0), COALESCE(SUM(cf.severity='High'),0), COALESCE(SUM(cf.severity='Medium'),0),
		COALESCE(SUM(cf.severity='Low'),0), COALESCE(SUM(cf.severity='Negligible'),0), COALESCE(SUM(cf.severity='Unknown'),0),
		COUNT(cf.id), COALESCE(SUM(cf.fix_state='fixed'),0)
		FROM targets t LEFT JOIN current_findings cf ON cf.target_id = t.id AND cf.status IN ('open','acknowledged')
		WHERE t.host_id=? GROUP BY t.id ORDER BY t.retired_at IS NOT NULL, t.name`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TargetRow{}
	for rows.Next() {
		var r TargetRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Distro, &r.FirstSeen, &r.LastScanned, &r.RetiredAt,
			&r.Critical, &r.High, &r.Medium, &r.Low, &r.Negligible, &r.Unknown, &r.Total, &r.Fixable); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type GroupRow struct {
	Name  string `json:"name"`
	Hosts int    `json:"hosts"`
	Stale int    `json:"stale"`
	Counts
}

func (s *Store) ListGroups(ctx context.Context) ([]GroupRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT h.grp, COUNT(*), SUM(`+hostStatusSQL+` = 'stale'),
		COALESCE(SUM(c.c),0), COALESCE(SUM(c.h),0), COALESCE(SUM(c.m),0), COALESCE(SUM(c.l),0), COALESCE(SUM(c.n),0),
		COALESCE(SUM(c.u),0), COALESCE(SUM(c.t),0), COALESCE(SUM(c.f),0)
		FROM hosts h LEFT JOIN (`+hostCountsSQL+`) c ON c.host_id = h.id GROUP BY h.grp ORDER BY h.grp`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupRow{}
	for rows.Next() {
		var r GroupRow
		if err := rows.Scan(&r.Name, &r.Hosts, &r.Stale, &r.Critical, &r.High, &r.Medium, &r.Low, &r.Negligible,
			&r.Unknown, &r.Total, &r.Fixable); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type ScanRow struct {
	ID           int64  `json:"id"`
	HostID       int64  `json:"host_id"`
	HostName     string `json:"host_name"`
	TargetID     int64  `json:"target_id"`
	TargetName   string `json:"target_name"`
	TargetType   string `json:"target_type"`
	Source       string `json:"source"`
	RunID        string `json:"run_id"`
	GrypeVersion string `json:"grype_version"`
	DBBuilt      string `json:"db_built"`
	ScannedAt    string `json:"scanned_at"`
	ReceivedAt   string `json:"received_at"`
	DurationMS   int64  `json:"duration_ms"`
	New          int    `json:"new"`
	FixedCount   int    `json:"fixed"`
	Counts
}

var scanSorts = map[string]string{
	"received_at": "s.id",
	"host":        "h.name",
	"target":      "t.name",
	"total":       "s.total",
	"critical":    "s.critical",
	"duration":    "s.duration_ms",
}

type ScanFilter struct {
	HostID   int64
	TargetID int64
	Q        string
	Source   string
}

func (s *Store) ListScans(ctx context.Context, f ScanFilter, p Page) (*List[ScanRow], error) {
	p.norm()
	var w where
	if f.HostID > 0 {
		w.add("s.host_id = ?", f.HostID)
	}
	if f.TargetID > 0 {
		w.add("s.target_id = ?", f.TargetID)
	}
	if f.Source != "" {
		w.add("s.source = ?", f.Source)
	}
	if f.Q != "" {
		w.add(`(h.name LIKE ? ESCAPE '\' OR t.name LIKE ? ESCAPE '\')`, like(f.Q), like(f.Q))
	}
	from := ` FROM scans s JOIN hosts h ON h.id=s.host_id JOIN targets t ON t.id=s.target_id` + w.sql()
	out := &List[ScanRow]{Items: []ScanRow{}, Page: p.Page, Size: p.Size}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*)`+from, w.args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT s.id, s.host_id, h.name, s.target_id, t.name, t.type, s.source, s.run_id, s.grype_version,
		s.db_built, s.scanned_at, s.received_at, s.duration_ms, s.new_count, s.fixed_count,
		s.critical, s.high, s.medium, s.low, s.negligible, s.unknown, s.total, s.fixable`+
		from+p.orderBy(scanSorts, "received_at", "s.id DESC")+p.limit(), w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ScanRow
		if err := rows.Scan(&r.ID, &r.HostID, &r.HostName, &r.TargetID, &r.TargetName, &r.TargetType, &r.Source, &r.RunID,
			&r.GrypeVersion, &r.DBBuilt, &r.ScannedAt, &r.ReceivedAt, &r.DurationMS, &r.New, &r.FixedCount,
			&r.Critical, &r.High, &r.Medium, &r.Low, &r.Negligible, &r.Unknown, &r.Total, &r.Fixable); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, r)
	}
	return out, rows.Err()
}
