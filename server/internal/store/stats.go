package store

import (
	"context"
	"database/sql"
)

type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type TopVuln struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity"`
	Risk     float64 `json:"risk"`
	EPSS     float64 `json:"epss"`
	KEV      bool    `json:"kev"`
	Hosts    int     `json:"hosts"`
	Packages string  `json:"packages"`
}

type TopHost struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Score int    `json:"score"`
	Counts
}

type Summary struct {
	Findings       Counts      `json:"findings"`        // package instances
	Unique         Counts      `json:"unique"`          // distinct vulnerability IDs
	KEV            int         `json:"kev"`             // distinct known-exploited vulns
	Hosts          int         `json:"hosts"`
	StaleHosts     int         `json:"stale_hosts"`
	FailingHosts   int         `json:"failing_hosts"`
	Targets        int         `json:"targets"`
	NewLast7d      int         `json:"new_last_7d"`
	Scans24h       int         `json:"scans_24h"`
	LastScan       string      `json:"last_scan"`
	ByFixState     []NameCount `json:"by_fix_state"`
	ByPkgType      []NameCount `json:"by_pkg_type"`
	ByGroup        []NameCount `json:"by_group"`
	ByStatus       []NameCount `json:"by_status"`
	TopVulns       []TopVuln   `json:"top_vulns"`
	TopHosts       []TopHost   `json:"top_hosts"`
	TopPackages    []NameCount `json:"top_packages"`
}

const activeCF = `current_findings WHERE status IN ('open','acknowledged')`

func (s *Store) Summary(ctx context.Context) (*Summary, error) {
	var out Summary
	q := func(query string, dest ...any) error { return s.r.QueryRowContext(ctx, query).Scan(dest...) }

	f := &out.Findings
	if err := q(`SELECT COALESCE(SUM(severity='Critical'),0), COALESCE(SUM(severity='High'),0), COALESCE(SUM(severity='Medium'),0),
		COALESCE(SUM(severity='Low'),0), COALESCE(SUM(severity='Negligible'),0), COALESCE(SUM(severity='Unknown'),0),
		COUNT(*), COALESCE(SUM(fix_state='fixed'),0) FROM `+activeCF,
		&f.Critical, &f.High, &f.Medium, &f.Low, &f.Negligible, &f.Unknown, &f.Total, &f.Fixable); err != nil {
		return nil, err
	}
	u := &out.Unique
	if err := q(`SELECT COALESCE(SUM(r=5),0), COALESCE(SUM(r=4),0), COALESCE(SUM(r=3),0),
		COALESCE(SUM(r=2),0), COALESCE(SUM(r=1),0), COALESCE(SUM(r=0),0),
		COUNT(*), COALESCE(SUM(fixable),0), COALESCE(SUM(kev),0)
		FROM (SELECT vuln_id, MAX(sev_rank) r, MAX(fix_state='fixed') fixable, MAX(kev) kev FROM `+activeCF+` GROUP BY vuln_id)`,
		&u.Critical, &u.High, &u.Medium, &u.Low, &u.Negligible, &u.Unknown, &u.Total, &u.Fixable, &out.KEV); err != nil {
		return nil, err
	}
	if err := q(`SELECT COUNT(*), COALESCE(SUM(`+hostStatusSQL+`='stale'),0), COALESCE(SUM(`+hostStatusSQL+`='failing'),0) FROM hosts h`,
		&out.Hosts, &out.StaleHosts, &out.FailingHosts); err != nil {
		return nil, err
	}
	var last sql.NullString
	if err := q(`SELECT (SELECT COUNT(*) FROM targets WHERE retired_at IS NULL),
		(SELECT COUNT(DISTINCT vuln_id||pkg_name||host_id) FROM `+activeCF+` AND first_seen >= strftime('%Y-%m-%dT%H:%M:%SZ','now','-7 days')),
		(SELECT COUNT(*) FROM scans WHERE received_at >= strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 day')),
		(SELECT MAX(received_at) FROM scans)`, &out.Targets, &out.NewLast7d, &out.Scans24h, &last); err != nil {
		return nil, err
	}
	out.LastScan = last.String

	var err error
	if out.ByFixState, err = s.nameCounts(ctx, `SELECT fix_state, COUNT(*) FROM `+activeCF+` GROUP BY fix_state ORDER BY 2 DESC`); err != nil {
		return nil, err
	}
	if out.ByPkgType, err = s.nameCounts(ctx, `SELECT pkg_type, COUNT(*) FROM `+activeCF+` GROUP BY pkg_type ORDER BY 2 DESC LIMIT 10`); err != nil {
		return nil, err
	}
	if out.ByGroup, err = s.nameCounts(ctx, `SELECT grp, COUNT(*) FROM `+activeCF+` GROUP BY grp ORDER BY 2 DESC LIMIT 10`); err != nil {
		return nil, err
	}
	if out.ByStatus, err = s.nameCounts(ctx, `SELECT status, COUNT(*) FROM current_findings GROUP BY status ORDER BY 2 DESC`); err != nil {
		return nil, err
	}
	if out.TopPackages, err = s.nameCounts(ctx, `SELECT pkg_name, COUNT(DISTINCT vuln_id) FROM `+activeCF+` GROUP BY pkg_name ORDER BY 2 DESC LIMIT 10`); err != nil {
		return nil, err
	}

	rows, err := s.r.QueryContext(ctx, `SELECT v.id, v.severity, v.risk, v.epss, v.kev, COUNT(DISTINCT cf.host_id), GROUP_CONCAT(DISTINCT cf.pkg_name)
		FROM current_findings cf JOIN vulns v ON v.id=cf.vuln_id WHERE cf.status IN ('open','acknowledged')
		GROUP BY v.id ORDER BY v.risk DESC, MAX(cf.sev_rank) DESC LIMIT 10`)
	if err != nil {
		return nil, err
	}
	out.TopVulns = []TopVuln{}
	for rows.Next() {
		var t TopVuln
		if err := rows.Scan(&t.ID, &t.Severity, &t.Risk, &t.EPSS, &t.KEV, &t.Hosts, &t.Packages); err != nil {
			rows.Close()
			return nil, err
		}
		out.TopVulns = append(out.TopVulns, t)
	}
	rows.Close()

	hosts, err := s.ListHosts(ctx, HostFilter{}, Page{Page: 1, Size: 8, Sort: "score", Order: "desc"})
	if err != nil {
		return nil, err
	}
	out.TopHosts = []TopHost{}
	for _, h := range hosts.Items {
		if h.Total == 0 {
			continue
		}
		out.TopHosts = append(out.TopHosts, TopHost{ID: h.ID, Name: h.Name, Score: h.Score, Counts: h.Counts})
	}
	return &out, nil
}

func (s *Store) nameCounts(ctx context.Context, query string) ([]NameCount, error) {
	rows, err := s.r.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NameCount{}
	for rows.Next() {
		var n NameCount
		if err := rows.Scan(&n.Name, &n.Count); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

type DailyStat struct {
	Day string `json:"day"`
	Counts
	Hosts int `json:"hosts"`
	KEV   int `json:"kev"`
}

func (s *Store) Trends(ctx context.Context, days int) ([]DailyStat, error) {
	if days < 1 || days > 365 {
		days = 30
	}
	rows, err := s.r.QueryContext(ctx, `SELECT day, critical, high, medium, low, negligible, unknown, total, fixable, hosts, kev
		FROM stats_daily WHERE day >= date('now', ?) ORDER BY day`, "-"+itoa(days)+" days")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DailyStat{}
	for rows.Next() {
		var d DailyStat
		if err := rows.Scan(&d.Day, &d.Critical, &d.High, &d.Medium, &d.Low, &d.Negligible, &d.Unknown, &d.Total,
			&d.Fixable, &d.Hosts, &d.KEV); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
