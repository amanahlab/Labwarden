package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/amanahlab/labwarden/server/internal/grype"
)

// IngestMeta describes where a report came from.
type IngestMeta struct {
	Host         string
	Kind         string // vm | docker | central
	Group        string
	OS           string
	Arch         string
	IP           string
	AgentVersion string
	IntervalSec  int
	Target       string // overrides the name derived from the report
	Source       string // agent | server
	RunID        string
	DurationMS   int64
	// Rematch marks a re-match of a stored SBOM: the host was not heard
	// from, so its last_seen stays.
	Rematch bool `json:"-"`
}

type IngestResult struct {
	HostID   int64  `json:"host_id"`
	TargetID int64  `json:"target_id"`
	ScanID   int64  `json:"scan_id"`
	Target   string `json:"target"`
	Findings int    `json:"findings"`
	New      int    `json:"new"`
	Fixed    int    `json:"fixed"`
	// NewFindings lists findings absent from the previous scan of the target
	// (every finding on a first scan). Used for notifications.
	NewFindings []NewFinding `json:"-"`
}

type NewFinding struct {
	VulnID     string `json:"id"`
	Severity   string `json:"severity"`
	KEV        bool   `json:"kev"`
	PkgName    string `json:"package"`
	PkgVersion string `json:"version"`
	FixVersion string `json:"fix,omitempty"`
}

// OnIngest registers fn to run after each stored report. Set it before serving.
func (s *Store) OnIngest(fn func(IngestMeta, *IngestResult)) { s.onIngest = fn }

var ErrInvalid = errors.New("invalid input")

// IngestReport stores one Grype report as the newest scan of its target.
func (s *Store) IngestReport(ctx context.Context, m IngestMeta, rep *grype.Report) (*IngestResult, error) {
	if m.Host == "" {
		return nil, fmt.Errorf("%w: host is required", ErrInvalid)
	}
	targetName := m.Target
	if targetName == "" {
		targetName = rep.TargetName()
	}
	if m.Source == "" {
		m.Source = "agent"
	}
	vulns, findings := grype.Normalize(rep)
	ts := now()

	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	hostID, err := upsertHost(ctx, tx, m, ts)
	if err != nil {
		return nil, fmt.Errorf("upsert host: %w", err)
	}

	var targetID int64
	var prevScan sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO targets(host_id, name, type, distro, first_seen, last_scanned)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(host_id, name) DO UPDATE SET
		  type=excluded.type, distro=excluded.distro, last_scanned=excluded.last_scanned,
		  retired_at=CASE WHEN ? THEN targets.retired_at ELSE NULL END
		RETURNING id, latest_scan_id`,
		hostID, targetName, rep.TargetType(), rep.DistroString(), ts, ts, m.Rematch).Scan(&targetID, &prevScan)
	if err != nil {
		return nil, fmt.Errorf("upsert target: %w", err)
	}

	// Carry first_seen forward and compute new/fixed against the previous scan.
	prev := map[string]string{}
	if prevScan.Valid {
		rows, err := tx.QueryContext(ctx, `SELECT vuln_id, pkg_name, pkg_type, location, first_seen FROM findings WHERE scan_id=?`, prevScan.Int64)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var v, n, t, l, fs string
			if err := rows.Scan(&v, &n, &t, &l, &fs); err != nil {
				rows.Close()
				return nil, err
			}
			prev[v+"|"+n+"|"+t+"|"+l] = fs
		}
		rows.Close()
	}

	counts := map[string]int{}
	fixable, newCount := 0, 0
	current := map[string]bool{}
	var fresh []NewFinding
	for _, f := range findings {
		counts[f.Severity]++
		if f.FixState == "fixed" {
			fixable++
		}
		k := f.VulnID + "|" + f.PkgName + "|" + f.PkgType + "|" + f.Location
		current[k] = true
		if _, ok := prev[k]; !ok {
			if prevScan.Valid {
				newCount++
			}
			fresh = append(fresh, NewFinding{VulnID: f.VulnID, Severity: f.Severity, KEV: f.KEV,
				PkgName: f.PkgName, PkgVersion: f.PkgVersion, FixVersion: f.FixVersions})
		}
	}
	fixedCount := 0
	for k := range prev {
		if !current[k] {
			fixedCount++
		}
	}

	scannedAt := rep.Descriptor.Timestamp
	if t, err := time.Parse(time.RFC3339Nano, scannedAt); err == nil {
		scannedAt = t.UTC().Format(time.RFC3339)
	} else {
		scannedAt = ts
	}
	var scanID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO scans(target_id, host_id, source, run_id, grype_version, db_built, scanned_at, received_at, duration_ms,
		  critical, high, medium, low, negligible, unknown, total, fixable, new_count, fixed_count)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`,
		targetID, hostID, m.Source, m.RunID, rep.Descriptor.Version, rep.DBBuilt(), scannedAt, ts, m.DurationMS,
		counts["Critical"], counts["High"], counts["Medium"], counts["Low"], counts["Negligible"], counts["Unknown"],
		len(findings), fixable, newCount, fixedCount).Scan(&scanID)
	if err != nil {
		return nil, fmt.Errorf("insert scan: %w", err)
	}

	vstmt, err := tx.PrepareContext(ctx, `
		INSERT INTO vulns(id, severity, description, data_source, namespace, urls, cvss_score, cvss_vector, epss, epss_pct, kev, cwes, aliases, risk, first_seen, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		  severity=excluded.severity,
		  description=CASE WHEN excluded.description <> '' THEN excluded.description ELSE vulns.description END,
		  data_source=excluded.data_source, namespace=excluded.namespace, urls=excluded.urls,
		  cvss_score=excluded.cvss_score, cvss_vector=excluded.cvss_vector,
		  epss=excluded.epss, epss_pct=excluded.epss_pct, kev=excluded.kev,
		  cwes=excluded.cwes, aliases=excluded.aliases, risk=excluded.risk, updated_at=excluded.updated_at`)
	if err != nil {
		return nil, err
	}
	defer vstmt.Close()
	for _, v := range vulns {
		urls, _ := json.Marshal(v.URLs)
		if _, err := vstmt.ExecContext(ctx, v.ID, v.Severity, v.Description, v.DataSource, v.Namespace, string(urls),
			v.CVSSScore, v.CVSSVector, v.EPSS, v.EPSSPct, b2i(v.KEV), strings.Join(v.CWEs, ","), strings.Join(v.Aliases, ","),
			v.Risk, ts, ts); err != nil {
			return nil, fmt.Errorf("upsert vuln %s: %w", v.ID, err)
		}
	}

	fstmt, err := tx.PrepareContext(ctx, `
		INSERT INTO findings(scan_id, vuln_id, severity, sev_rank, pkg_name, pkg_version, pkg_type, purl, location, fix_state, fix_versions, risk, epss, kev, cvss_score, first_seen)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return nil, err
	}
	defer fstmt.Close()
	for _, f := range findings {
		fs := ts
		if p, ok := prev[f.VulnID+"|"+f.PkgName+"|"+f.PkgType+"|"+f.Location]; ok {
			fs = p
		}
		if _, err := fstmt.ExecContext(ctx, scanID, f.VulnID, f.Severity, grype.SeverityRank(f.Severity), f.PkgName, f.PkgVersion,
			f.PkgType, f.PURL, f.Location, f.FixState, f.FixVersions, f.Risk, f.EPSS, b2i(f.KEV), f.CVSSScore, fs); err != nil {
			return nil, fmt.Errorf("insert finding: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `UPDATE targets SET latest_scan_id=? WHERE id=?`, scanID, targetID); err != nil {
		return nil, err
	}
	// Only the latest two scans per target keep their findings (current + diff base).
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM findings WHERE scan_id IN (
		  SELECT id FROM scans WHERE target_id=? AND id NOT IN (SELECT id FROM scans WHERE target_id=? ORDER BY id DESC LIMIT 2))`,
		targetID, targetID); err != nil {
		return nil, err
	}
	if err := refreshDaily(ctx, tx); err != nil {
		return nil, fmt.Errorf("daily stats: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	res := &IngestResult{HostID: hostID, TargetID: targetID, ScanID: scanID, Target: targetName,
		Findings: len(findings), New: newCount, Fixed: fixedCount, NewFindings: fresh}
	if s.onIngest != nil {
		s.onIngest(m, res)
	}
	return res, nil
}

func upsertHost(ctx context.Context, tx *sql.Tx, m IngestMeta, ts string) (int64, error) {
	kind := m.Kind
	if kind == "" {
		kind = "vm"
	}
	grp := m.Group
	if grp == "" {
		grp = "default"
	}
	var id int64
	// Group is taken from the agent only when the host is first created, so a
	// regrouping done in the UI is not overwritten by the next report.
	err := tx.QueryRowContext(ctx, `
		INSERT INTO hosts(name, kind, grp, os, arch, ip, agent_version, interval_sec, first_seen, last_seen)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
		  kind=excluded.kind,
		  os=CASE WHEN excluded.os <> '' THEN excluded.os ELSE hosts.os END,
		  arch=CASE WHEN excluded.arch <> '' THEN excluded.arch ELSE hosts.arch END,
		  ip=CASE WHEN excluded.ip <> '' THEN excluded.ip ELSE hosts.ip END,
		  agent_version=CASE WHEN excluded.agent_version <> '' THEN excluded.agent_version ELSE hosts.agent_version END,
		  interval_sec=CASE WHEN excluded.interval_sec > 0 THEN excluded.interval_sec ELSE hosts.interval_sec END,
		  last_seen=CASE WHEN ? THEN hosts.last_seen ELSE excluded.last_seen END
		RETURNING id`,
		m.Host, kind, grp, m.OS, m.Arch, m.IP, m.AgentVersion, m.IntervalSec, ts, ts, m.Rematch).Scan(&id)
	return id, err
}

// Heartbeat records that a host is alive without a report (run start/end).
func (s *Store) Heartbeat(ctx context.Context, m IngestMeta) (int64, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	id, err := upsertHost(ctx, tx, m, now())
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// CompleteRun marks the end of an agent run. Targets the agent no longer
// reports (removed containers, deleted images) are retired so they stop
// counting. An empty target list retires nothing.
func (s *Store) CompleteRun(ctx context.Context, m IngestMeta, status string, targets []string) (retired int64, err error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	hostID, err := upsertHost(ctx, tx, m, now())
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET last_run_status=? WHERE id=?`, status, hostID); err != nil {
		return 0, err
	}
	if targets != nil {
		q := `UPDATE targets SET retired_at=? WHERE host_id=? AND retired_at IS NULL`
		args := []any{now(), hostID}
		if len(targets) > 0 { // an empty list retires every target
			q += ` AND name NOT IN (` + strings.TrimSuffix(strings.Repeat("?,", len(targets)), ",") + `)`
			for _, t := range targets {
				args = append(args, t)
			}
		}
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return 0, err
		}
		retired, _ = res.RowsAffected()
		if retired > 0 {
			if err := refreshDaily(ctx, tx); err != nil {
				return 0, err
			}
		}
	}
	return retired, tx.Commit()
}

// refreshDaily snapshots today's active exposure for trend charts.
func refreshDaily(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO stats_daily(day, critical, high, medium, low, negligible, unknown, total, fixable, hosts, kev)
		SELECT date('now'),
		  COALESCE(SUM(severity='Critical'),0), COALESCE(SUM(severity='High'),0), COALESCE(SUM(severity='Medium'),0),
		  COALESCE(SUM(severity='Low'),0), COALESCE(SUM(severity='Negligible'),0), COALESCE(SUM(severity='Unknown'),0),
		  COUNT(*), COALESCE(SUM(fix_state='fixed'),0), COUNT(DISTINCT host_id), COUNT(DISTINCT CASE WHEN kev=1 THEN vuln_id END)
		FROM current_findings WHERE status IN ('open','acknowledged')
		ON CONFLICT(day) DO UPDATE SET
		  critical=excluded.critical, high=excluded.high, medium=excluded.medium, low=excluded.low,
		  negligible=excluded.negligible, unknown=excluded.unknown, total=excluded.total,
		  fixable=excluded.fixable, hosts=excluded.hosts, kev=excluded.kev`)
	return err
}

// RefreshDaily is called after triage changes and on a daily tick so the
// trend line has a point for every day even without new reports.
func (s *Store) RefreshDaily(ctx context.Context) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := refreshDaily(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
