package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Page is a request for one page of a list, plus its sort.
type Page struct {
	Page  int
	Size  int
	Sort  string
	Order string // asc | desc
}

// List is one page of results.
type List[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
	Page  int `json:"page"`
	Size  int `json:"size"`
}

func (p *Page) norm() {
	if p.Page < 1 {
		p.Page = 1
	}
	if p.Size < 1 {
		p.Size = 25
	}
	if p.Size > 500 {
		p.Size = 500
	}
	if p.Order != "asc" {
		p.Order = "desc"
	}
}

func (p Page) limit() string {
	return fmt.Sprintf(" LIMIT %d OFFSET %d", p.Size, (p.Page-1)*p.Size)
}

// orderBy resolves a user-supplied sort key against a whitelist; unknown keys
// fall back to def. Values are SQL expressions, never user input.
func (p Page) orderBy(allowed map[string]string, def string, tiebreak string) string {
	expr, ok := allowed[p.Sort]
	if !ok {
		expr = allowed[def]
	}
	return " ORDER BY " + expr + " " + strings.ToUpper(p.Order) + ", " + tiebreak
}

// where accumulates SQL conditions with their arguments.
type where struct {
	conds []string
	args  []any
}

func (w *where) add(cond string, args ...any) {
	w.conds = append(w.conds, cond)
	w.args = append(w.args, args...)
}

func (w *where) in(col string, vals []string) {
	if len(vals) == 0 {
		return
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(vals)), ",")
	args := make([]any, len(vals))
	for i, v := range vals {
		args[i] = v
	}
	w.add(col+" IN ("+ph+")", args...)
}

func (w *where) sql() string {
	if len(w.conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.conds, " AND ")
}

func like(q string) string {
	q = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
	return "%" + q + "%"
}

// statusFilter maps the UI triage filter onto statuses. "active" (default)
// hides ignored and false-positive findings.
func statusFilter(w *where, col, status string) {
	switch status {
	case "all":
	case "open", "acknowledged", "ignored", "false_positive":
		w.add(col+" = ?", status)
	default:
		w.add(col + " IN ('open','acknowledged')")
	}
}

// FindingFilter narrows current findings.
type FindingFilter struct {
	Q        string
	Severity []string
	Fix      string // fixed | not-fixed | wont-fix | unknown
	HostID   int64
	TargetID int64
	VulnID   string
	Location string // exact package path; "" = any
	Group    string
	PkgType  string
	KEV      bool
	Status   string
}

func (f FindingFilter) apply(w *where) {
	if f.Q != "" {
		w.add(`(cf.vuln_id LIKE ? ESCAPE '\' OR cf.pkg_name LIKE ? ESCAPE '\' OR v.aliases LIKE ? ESCAPE '\' OR v.description LIKE ? ESCAPE '\')`,
			like(f.Q), like(f.Q), like(f.Q), like(f.Q))
	}
	w.in("cf.severity", f.Severity)
	if f.Fix != "" {
		w.add("cf.fix_state = ?", f.Fix)
	}
	if f.HostID > 0 {
		w.add("cf.host_id = ?", f.HostID)
	}
	if f.TargetID > 0 {
		w.add("cf.target_id = ?", f.TargetID)
	}
	if f.VulnID != "" {
		w.add("cf.vuln_id = ?", f.VulnID)
	}
	if f.Location != "" {
		w.add("cf.location = ?", f.Location)
	}
	if f.Group != "" {
		w.add("cf.grp = ?", f.Group)
	}
	if f.PkgType != "" {
		w.add("cf.pkg_type = ?", f.PkgType)
	}
	if f.KEV {
		w.add("cf.kev = 1")
	}
	statusFilter(w, "cf.status", f.Status)
}

// VulnRow is one vulnerability aggregated across all affected hosts.
type VulnRow struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Aliases     string  `json:"aliases"`
	CVSS        float64 `json:"cvss"`
	EPSS        float64 `json:"epss"`
	EPSSPct     float64 `json:"epss_pct"`
	KEV         bool    `json:"kev"`
	Risk        float64 `json:"risk"`
	Hosts       int     `json:"hosts"`
	Instances   int     `json:"instances"`
	Packages    string  `json:"packages"`
	Fixable     bool    `json:"fixable"`
	FirstSeen   string  `json:"first_seen"`
	Status      string  `json:"status"`
}

var vulnSorts = map[string]string{
	"severity":   "MAX(cf.sev_rank)",
	"id":         "v.id",
	"cvss":       "v.cvss_score",
	"epss":       "v.epss",
	"risk":       "v.risk",
	"hosts":      "COUNT(DISTINCT cf.host_id)",
	"instances":  "COUNT(*)",
	"first_seen": "MIN(cf.first_seen)",
	"package":    "MIN(cf.pkg_name)",
}

func (s *Store) ListVulns(ctx context.Context, f FindingFilter, p Page) (*List[VulnRow], error) {
	p.norm()
	var w where
	f.apply(&w)
	base := ` FROM current_findings cf JOIN vulns v ON v.id = cf.vuln_id` + w.sql() + ` GROUP BY v.id`

	out := &List[VulnRow]{Items: []VulnRow{}, Page: p.Page, Size: p.Size}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT v.id`+base+`)`, w.args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	q := `SELECT v.id, v.severity, substr(v.description,1,300), v.aliases, v.cvss_score, v.epss, v.epss_pct, v.kev, v.risk,
	        COUNT(DISTINCT cf.host_id), COUNT(*), GROUP_CONCAT(DISTINCT cf.pkg_name), MAX(cf.fix_state='fixed'), MIN(cf.first_seen),
	        COALESCE((SELECT status FROM triage t WHERE t.vuln_id=v.id AND t.host_id=0),'open')` +
		base + p.orderBy(vulnSorts, "severity", "v.risk DESC, v.id") + p.limit()
	rows, err := s.r.QueryContext(ctx, q, w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r VulnRow
		if err := rows.Scan(&r.ID, &r.Severity, &r.Description, &r.Aliases, &r.CVSS, &r.EPSS, &r.EPSSPct, &r.KEV, &r.Risk,
			&r.Hosts, &r.Instances, &r.Packages, &r.Fixable, &r.FirstSeen, &r.Status); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, r)
	}
	return out, rows.Err()
}

// FindingRow is one vulnerable package on one target.
type FindingRow struct {
	ID          int64   `json:"id"`
	VulnID      string  `json:"vuln_id"`
	Severity    string  `json:"severity"`
	PkgName     string  `json:"pkg_name"`
	PkgVersion  string  `json:"pkg_version"`
	PkgType     string  `json:"pkg_type"`
	PURL        string  `json:"purl"`
	Location    string  `json:"location"`
	FixState    string  `json:"fix_state"`
	FixVersions string  `json:"fix_versions"`
	Risk        float64 `json:"risk"`
	EPSS        float64 `json:"epss"`
	KEV         bool    `json:"kev"`
	CVSS        float64 `json:"cvss"`
	FirstSeen   string  `json:"first_seen"`
	TargetID    int64   `json:"target_id"`
	TargetName  string  `json:"target_name"`
	HostID      int64   `json:"host_id"`
	HostName    string  `json:"host_name"`
	Group       string  `json:"group"`
	Status      string  `json:"status"`
}

var findingSorts = map[string]string{
	"severity":   "cf.sev_rank",
	"vuln_id":    "cf.vuln_id",
	"package":    "cf.pkg_name",
	"pkg_type":   "cf.pkg_type",
	"fix_state":  "cf.fix_state",
	"risk":       "cf.risk",
	"epss":       "cf.epss",
	"cvss":       "cf.cvss_score",
	"host":       "cf.host_name",
	"target":     "cf.target_name",
	"first_seen": "cf.first_seen",
}

func (s *Store) ListFindings(ctx context.Context, f FindingFilter, p Page) (*List[FindingRow], error) {
	p.norm()
	var w where
	f.apply(&w)
	base := ` FROM current_findings cf JOIN vulns v ON v.id = cf.vuln_id` + w.sql()
	out := &List[FindingRow]{Items: []FindingRow{}, Page: p.Page, Size: p.Size}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*)`+base, w.args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT cf.id, cf.vuln_id, cf.severity, cf.pkg_name, cf.pkg_version, cf.pkg_type, cf.purl, cf.location,
		cf.fix_state, cf.fix_versions, cf.risk, cf.epss, cf.kev, cf.cvss_score, cf.first_seen, cf.target_id, cf.target_name,
		cf.host_id, cf.host_name, cf.grp, cf.status`+base+p.orderBy(findingSorts, "severity", "cf.risk DESC, cf.id")+p.limit(), w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r FindingRow
		if err := rows.Scan(&r.ID, &r.VulnID, &r.Severity, &r.PkgName, &r.PkgVersion, &r.PkgType, &r.PURL, &r.Location,
			&r.FixState, &r.FixVersions, &r.Risk, &r.EPSS, &r.KEV, &r.CVSS, &r.FirstSeen, &r.TargetID, &r.TargetName,
			&r.HostID, &r.HostName, &r.Group, &r.Status); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, r)
	}
	return out, rows.Err()
}

// VulnDetail is the full catalog record plus its triage state.
type VulnDetail struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	DataSource  string  `json:"data_source"`
	Namespace   string  `json:"namespace"`
	URLs        string  `json:"urls"` // JSON array
	CVSS        float64 `json:"cvss"`
	CVSSVector  string  `json:"cvss_vector"`
	EPSS        float64 `json:"epss"`
	EPSSPct     float64 `json:"epss_pct"`
	KEV         bool    `json:"kev"`
	CWEs        string  `json:"cwes"`
	Aliases     string  `json:"aliases"`
	Risk        float64 `json:"risk"`
	FirstSeen   string  `json:"first_seen"`
	UpdatedAt   string  `json:"updated_at"`
	Status      string  `json:"status"`
	Note        string  `json:"note"`
}

var ErrNotFound = sql.ErrNoRows

func (s *Store) GetVuln(ctx context.Context, id string) (*VulnDetail, error) {
	var d VulnDetail
	err := s.r.QueryRowContext(ctx, `SELECT v.id, v.severity, v.description, v.data_source, v.namespace, v.urls, v.cvss_score, v.cvss_vector,
		v.epss, v.epss_pct, v.kev, v.cwes, v.aliases, v.risk, v.first_seen, v.updated_at,
		COALESCE(t.status,'open'), COALESCE(t.note,'')
		FROM vulns v LEFT JOIN triage t ON t.vuln_id=v.id AND t.host_id=0 WHERE v.id=?`, id).Scan(
		&d.ID, &d.Severity, &d.Description, &d.DataSource, &d.Namespace, &d.URLs, &d.CVSS, &d.CVSSVector,
		&d.EPSS, &d.EPSSPct, &d.KEV, &d.CWEs, &d.Aliases, &d.Risk, &d.FirstSeen, &d.UpdatedAt, &d.Status, &d.Note)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

var TriageStatuses = map[string]bool{"open": true, "acknowledged": true, "ignored": true, "false_positive": true}

// SetTriage records a triage decision. hostID 0 applies to every host.
// Setting "open" for a host-specific entry removes the override.
func (s *Store) SetTriage(ctx context.Context, vulnID string, hostID int64, status, note string) error {
	if !TriageStatuses[status] {
		return fmt.Errorf("%w: unknown status %q", ErrInvalid, status)
	}
	var err error
	if status == "open" && note == "" {
		_, err = s.w.ExecContext(ctx, `DELETE FROM triage WHERE vuln_id=? AND host_id=?`, vulnID, hostID)
	} else {
		_, err = s.w.ExecContext(ctx, `INSERT INTO triage(vuln_id, host_id, status, note, updated_at) VALUES (?,?,?,?,?)
			ON CONFLICT(vuln_id, host_id) DO UPDATE SET status=excluded.status, note=excluded.note, updated_at=excluded.updated_at`,
			vulnID, hostID, status, note, now())
	}
	if err != nil {
		return err
	}
	return s.RefreshDaily(ctx)
}

// SuppressedVulns returns the vulnerabilities triaged as ignored or false
// positive for a host. A host-specific decision overrides the global one.
func (s *Store) SuppressedVulns(ctx context.Context, hostID int64) (map[string]bool, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT vuln_id, status FROM triage WHERE host_id IN (0, ?) ORDER BY host_id`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			return nil, err
		}
		out[id] = status == "ignored" || status == "false_positive" // host rows come last and win
	}
	return out, rows.Err()
}
