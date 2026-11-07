// Package grype parses Grype JSON reports (`grype -o json`) into the
// normalized shape VulnX stores.
package grype

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Report is the subset of the Grype JSON document VulnX consumes.
type Report struct {
	Matches    []Match    `json:"matches"`
	Source     Source     `json:"source"`
	Distro     Distro     `json:"distro"`
	Descriptor Descriptor `json:"descriptor"`
}

type Match struct {
	Vulnerability          Vulnerability   `json:"vulnerability"`
	RelatedVulnerabilities []Vulnerability `json:"relatedVulnerabilities"`
	Artifact               Artifact        `json:"artifact"`
}

type Vulnerability struct {
	ID             string   `json:"id"`
	DataSource     string   `json:"dataSource"`
	Namespace      string   `json:"namespace"`
	Severity       string   `json:"severity"`
	URLs           []string `json:"urls"`
	Description    string   `json:"description"`
	CVSS           []CVSS   `json:"cvss"`
	EPSS           []EPSS   `json:"epss"`
	CWEs           []CWE    `json:"cwes"`
	KnownExploited []KEV    `json:"knownExploited"`
	Fix            Fix      `json:"fix"`
	Risk           float64  `json:"risk"`
}

type CVSS struct {
	Source  string `json:"source"`
	Type    string `json:"type"`
	Version string `json:"version"`
	Vector  string `json:"vector"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

type EPSS struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

type CWE struct {
	CWE string `json:"cwe"`
}

type KEV struct {
	CVE string `json:"cve"`
}

type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type Artifact struct {
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Type      string     `json:"type"`
	Language  string     `json:"language"`
	PURL      string     `json:"purl"`
	Locations []Location `json:"locations"`
}

type Location struct {
	Path string `json:"path"`
}

type Source struct {
	Type   string          `json:"type"`
	Target json.RawMessage `json:"target"`
}

type Distro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Descriptor struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	DB        struct {
		Status struct {
			Built string `json:"built"`
		} `json:"status"`
		// Older Grype versions put `built` directly under `db`.
		Built string `json:"built"`
	} `json:"db"`
}

// Parse decodes a Grype JSON report.
func Parse(r io.Reader) (*Report, error) {
	var rep Report
	dec := json.NewDecoder(r)
	if err := dec.Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode grype report: %w", err)
	}
	if rep.Descriptor.Name != "" && rep.Descriptor.Name != "grype" {
		return nil, fmt.Errorf("not a grype report (descriptor %q)", rep.Descriptor.Name)
	}
	if rep.Matches == nil && rep.Source.Type == "" {
		return nil, fmt.Errorf("not a grype report: no matches or source")
	}
	return &rep, nil
}

// TargetName returns a human name for the scanned source: the image
// reference the user asked for, or the scanned path.
func (r *Report) TargetName() string {
	var img struct {
		UserInput string   `json:"userInput"`
		Tags      []string `json:"tags"`
	}
	if json.Unmarshal(r.Source.Target, &img) == nil && img.UserInput != "" {
		return img.UserInput
	}
	var s string
	if json.Unmarshal(r.Source.Target, &s) == nil && s != "" {
		return s
	}
	var dir struct {
		Path string `json:"path"`
	}
	if json.Unmarshal(r.Source.Target, &dir) == nil && dir.Path != "" {
		return dir.Path
	}
	return r.Source.Type
}

// TargetType maps the Grype source type onto VulnX target types.
func (r *Report) TargetType() string {
	switch r.Source.Type {
	case "image":
		return "image"
	case "directory", "file":
		return "filesystem"
	case "sbom", "purl-file":
		return "sbom"
	default:
		if r.Source.Type == "" {
			return "unknown"
		}
		return r.Source.Type
	}
}

func (r *Report) DistroString() string {
	return strings.TrimSpace(r.Distro.Name + " " + r.Distro.Version)
}

func (r *Report) DBBuilt() string {
	if r.Descriptor.DB.Status.Built != "" {
		return r.Descriptor.DB.Status.Built
	}
	return r.Descriptor.DB.Built
}

// Vuln is the normalized catalog entry for one vulnerability ID.
type Vuln struct {
	ID          string
	Severity    string
	Description string
	DataSource  string
	Namespace   string
	URLs        []string
	CVSSScore   float64
	CVSSVector  string
	EPSS        float64
	EPSSPct     float64
	KEV         bool
	CWEs        []string
	Aliases     []string
	Risk        float64
}

// Finding is one vulnerable package instance.
type Finding struct {
	VulnID      string
	Severity    string
	PkgName     string
	PkgVersion  string
	PkgType     string
	PURL        string
	Location    string
	FixState    string
	FixVersions string
	Risk        float64
	EPSS        float64
	KEV         bool
	CVSSScore   float64
}

// Normalize flattens a report into deduplicated catalog entries and findings.
// Distro matches often carry no description; it is filled from related
// (usually NVD) records, as are missing CVSS and EPSS values.
func Normalize(rep *Report) (map[string]*Vuln, []Finding) {
	vulns := make(map[string]*Vuln)
	findings := make([]Finding, 0, len(rep.Matches))
	seen := make(map[string]bool)

	for _, m := range rep.Matches {
		v := m.Vulnerability
		if v.ID == "" {
			continue
		}
		cat, ok := vulns[v.ID]
		if !ok {
			cat = &Vuln{ID: v.ID}
			vulns[v.ID] = cat
		}
		merge(cat, v, true)
		for _, rel := range m.RelatedVulnerabilities {
			if rel.ID != "" && rel.ID != v.ID && !contains(cat.Aliases, rel.ID) {
				cat.Aliases = append(cat.Aliases, rel.ID)
			}
			merge(cat, rel, false)
		}

		loc := ""
		if len(m.Artifact.Locations) > 0 {
			loc = m.Artifact.Locations[0].Path
		}
		key := v.ID + "|" + m.Artifact.Name + "|" + m.Artifact.Version + "|" + m.Artifact.Type + "|" + loc
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, Finding{
			VulnID:      v.ID,
			Severity:    NormalizeSeverity(v.Severity),
			PkgName:     m.Artifact.Name,
			PkgVersion:  m.Artifact.Version,
			PkgType:     m.Artifact.Type,
			PURL:        m.Artifact.PURL,
			Location:    loc,
			FixState:    normalizeFixState(v.Fix.State),
			FixVersions: strings.Join(v.Fix.Versions, ", "),
			Risk:        v.Risk,
		})
	}

	for _, c := range vulns {
		sort.Strings(c.Aliases)
		sort.Strings(c.CWEs)
	}
	// Findings inherit catalog-level enrichment (EPSS/KEV/CVSS may only be
	// present on related records).
	for i := range findings {
		c := vulns[findings[i].VulnID]
		findings[i].EPSS = c.EPSS
		findings[i].KEV = c.KEV
		findings[i].CVSSScore = c.CVSSScore
		if findings[i].Risk == 0 {
			findings[i].Risk = c.Risk
		}
	}
	return vulns, findings
}

// merge folds v into cat. primary records win for severity and data source;
// related records only fill gaps.
func merge(cat *Vuln, v Vulnerability, primary bool) {
	sev := NormalizeSeverity(v.Severity)
	if primary {
		if cat.Severity == "" || cat.Severity == "Unknown" || SeverityRank(sev) > SeverityRank(cat.Severity) {
			cat.Severity = sev
		}
		if cat.DataSource == "" {
			cat.DataSource = v.DataSource
		}
		if cat.Namespace == "" {
			cat.Namespace = v.Namespace
		}
	} else if cat.Severity == "" || cat.Severity == "Unknown" {
		cat.Severity = sev
	}
	if cat.Description == "" {
		cat.Description = strings.TrimSpace(v.Description)
	}
	for _, u := range v.URLs {
		if len(cat.URLs) < 25 && !contains(cat.URLs, u) {
			cat.URLs = append(cat.URLs, u)
		}
	}
	if score, vec := bestCVSS(v.CVSS); score > cat.CVSSScore {
		cat.CVSSScore, cat.CVSSVector = score, vec
	}
	for _, e := range v.EPSS {
		if e.EPSS > cat.EPSS {
			cat.EPSS, cat.EPSSPct = e.EPSS, e.Percentile
		}
	}
	if len(v.KnownExploited) > 0 {
		cat.KEV = true
	}
	for _, c := range v.CWEs {
		if c.CWE != "" && !contains(cat.CWEs, c.CWE) {
			cat.CWEs = append(cat.CWEs, c.CWE)
		}
	}
	if v.Risk > cat.Risk {
		cat.Risk = v.Risk
	}
}

// bestCVSS prefers the newest CVSS version, then the highest score.
func bestCVSS(list []CVSS) (float64, string) {
	var best CVSS
	for _, c := range list {
		if c.Metrics.BaseScore == 0 {
			continue
		}
		if best.Vector == "" || c.Version > best.Version ||
			(c.Version == best.Version && c.Metrics.BaseScore > best.Metrics.BaseScore) {
			best = c
		}
	}
	return best.Metrics.BaseScore, best.Vector
}

var severityRank = map[string]int{
	"Unknown": 0, "Negligible": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5,
}

// Severities lists the canonical severities from most to least severe.
var Severities = []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}

func SeverityRank(s string) int { return severityRank[s] }

func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium", "moderate":
		return "Medium"
	case "low":
		return "Low"
	case "negligible":
		return "Negligible"
	default:
		return "Unknown"
	}
}

func normalizeFixState(s string) string {
	switch s {
	case "fixed", "not-fixed", "wont-fix":
		return s
	default:
		return "unknown"
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
