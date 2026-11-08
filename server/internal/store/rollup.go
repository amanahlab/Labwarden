package store

import "context"

// Per-severity counts over a group of current findings, in Counts field order.
const findingCountsSQL = `SUM(cf.severity='Critical'), SUM(cf.severity='High'), SUM(cf.severity='Medium'), SUM(cf.severity='Low'),
	SUM(cf.severity='Negligible'), SUM(cf.severity='Unknown'), COUNT(*), SUM(cf.fix_state='fixed')`

// findingScoreSQL weights a group's severities like scoreSQL does for hosts.
const findingScoreSQL = `(SUM(cf.severity='Critical')*100 + SUM(cf.severity='High')*20 + SUM(cf.severity='Medium')*5 + SUM(cf.severity='Low'))`

func (c *Counts) dest() []any {
	return []any{&c.Critical, &c.High, &c.Medium, &c.Low, &c.Negligible, &c.Unknown, &c.Total, &c.Fixable}
}

// HostVulnRow is the filtered findings of one host.
type HostVulnRow struct {
	HostID    int64   `json:"host_id"`
	HostName  string  `json:"host_name"`
	Group     string  `json:"group"`
	Kind      string  `json:"kind"`
	Vulns     int     `json:"vulns"`
	KEV       int     `json:"kev"`
	MaxRisk   float64 `json:"max_risk"`
	FirstSeen string  `json:"first_seen"`
	Counts
}

var vulnHostSorts = map[string]string{
	"severity":   findingScoreSQL,
	"host":       "cf.host_name",
	"group":      "cf.grp",
	"critical":   "SUM(cf.severity='Critical')",
	"high":       "SUM(cf.severity='High')",
	"total":      "COUNT(*)",
	"vulns":      "COUNT(DISTINCT cf.vuln_id)",
	"risk":       "MAX(cf.risk)",
	"first_seen": "MIN(cf.first_seen)",
}

// ListVulnHosts groups the filtered current findings by host.
func (s *Store) ListVulnHosts(ctx context.Context, f FindingFilter, p Page) (*List[HostVulnRow], error) {
	p.norm()
	var w where
	f.apply(&w)
	base := ` FROM current_findings cf JOIN vulns v ON v.id = cf.vuln_id` + w.sql() + ` GROUP BY cf.host_id`
	out := &List[HostVulnRow]{Items: []HostVulnRow{}, Page: p.Page, Size: p.Size}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT cf.host_id`+base+`)`, w.args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	q := `SELECT cf.host_id, cf.host_name, cf.grp, cf.host_kind, COUNT(DISTINCT cf.vuln_id),
	        COUNT(DISTINCT CASE WHEN cf.kev THEN cf.vuln_id END), MAX(cf.risk), MIN(cf.first_seen), ` + findingCountsSQL +
		base + p.orderBy(vulnHostSorts, "severity", "cf.host_name, cf.host_id") + p.limit()
	rows, err := s.r.QueryContext(ctx, q, w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r HostVulnRow
		dest := append([]any{&r.HostID, &r.HostName, &r.Group, &r.Kind, &r.Vulns, &r.KEV, &r.MaxRisk, &r.FirstSeen}, r.Counts.dest()...)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, r)
	}
	return out, rows.Err()
}

// LocationRow is the filtered findings at one package path on one target.
type LocationRow struct {
	Location   string  `json:"location"`
	HostID     int64   `json:"host_id"`
	HostName   string  `json:"host_name"`
	TargetID   int64   `json:"target_id"`
	TargetName string  `json:"target_name"`
	Packages   string  `json:"packages"`
	Vulns      int     `json:"vulns"`
	KEV        int     `json:"kev"`
	MaxRisk    float64 `json:"max_risk"`
	FirstSeen  string  `json:"first_seen"`
	Counts
}

var locationSorts = map[string]string{
	"severity":   findingScoreSQL,
	"location":   "cf.location",
	"host":       "cf.host_name",
	"target":     "cf.target_name",
	"total":      "COUNT(*)",
	"vulns":      "COUNT(DISTINCT cf.vuln_id)",
	"risk":       "MAX(cf.risk)",
	"first_seen": "MIN(cf.first_seen)",
}

// ListVulnLocations groups the filtered current findings by target and
// package path, so the same path in two images stays two rows.
func (s *Store) ListVulnLocations(ctx context.Context, f FindingFilter, p Page) (*List[LocationRow], error) {
	p.norm()
	var w where
	f.apply(&w)
	base := ` FROM current_findings cf JOIN vulns v ON v.id = cf.vuln_id` + w.sql() + ` GROUP BY cf.target_id, cf.location`
	out := &List[LocationRow]{Items: []LocationRow{}, Page: p.Page, Size: p.Size}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT cf.target_id`+base+`)`, w.args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	q := `SELECT cf.location, cf.host_id, cf.host_name, cf.target_id, cf.target_name, GROUP_CONCAT(DISTINCT cf.pkg_name),
	        COUNT(DISTINCT cf.vuln_id), COUNT(DISTINCT CASE WHEN cf.kev THEN cf.vuln_id END), MAX(cf.risk), MIN(cf.first_seen), ` +
		findingCountsSQL + base + p.orderBy(locationSorts, "severity", "cf.host_name, cf.target_id, cf.location") + p.limit()
	rows, err := s.r.QueryContext(ctx, q, w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r LocationRow
		dest := append([]any{&r.Location, &r.HostID, &r.HostName, &r.TargetID, &r.TargetName, &r.Packages,
			&r.Vulns, &r.KEV, &r.MaxRisk, &r.FirstSeen}, r.Counts.dest()...)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, r)
	}
	return out, rows.Err()
}
