package api

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/amanahlab/labwarden/server/internal/store"
)

func findingFilter(r *http.Request) store.FindingFilter {
	q := r.URL.Query()
	return store.FindingFilter{
		Q:        strings.TrimSpace(q.Get("q")),
		Severity: qList(r, "severity"),
		Fix:      q.Get("fix"),
		HostID:   qInt64(r, "host_id"),
		TargetID: qInt64(r, "target_id"),
		VulnID:   q.Get("vuln_id"),
		Location: q.Get("location"),
		Group:    q.Get("group"),
		PkgType:  q.Get("pkg_type"),
		KEV:      q.Get("kev") == "true",
		Status:   q.Get("status"),
	}
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.Summary(r.Context())
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) trends(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.Trends(r.Context(), qInt(r, "days", 30))
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listVulns(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ListVulns(r.Context(), findingFilter(r), pageFrom(r))
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) exportVulns(w http.ResponseWriter, r *http.Request) {
	p := pageFrom(r)
	p.Page, p.Size = 1, 500
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="labwarden-findings.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"host", "group", "target", "vulnerability", "severity", "cvss", "epss", "kev", "package", "version", "type", "fix_state", "fix_versions", "status", "first_seen"})
	for {
		page, err := s.st.ListFindings(r.Context(), findingFilter(r), p)
		if err != nil {
			s.log.Error("export", "err", err)
			break
		}
		for _, f := range page.Items {
			_ = cw.Write(csvRow(f.HostName, f.Group, f.TargetName, f.VulnID, f.Severity, fmt.Sprintf("%.1f", f.CVSS),
				fmt.Sprintf("%.4f", f.EPSS), strconv.FormatBool(f.KEV), f.PkgName, f.PkgVersion, f.PkgType, f.FixState,
				f.FixVersions, f.Status, f.FirstSeen))
		}
		if p.Page*p.Size >= page.Total {
			break
		}
		p.Page++
	}
	cw.Flush()
}

// csvRow neutralizes spreadsheet formulas: host and package names come from
// agents, so a cell like "=HYPERLINK(...)" must not execute when opened.
func csvRow(cells ...string) []string {
	for i, c := range cells {
		if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
			cells[i] = "'" + c
		}
	}
	return cells
}

func (s *Server) getVuln(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	v, err := s.st.GetVuln(r.Context(), id)
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	affected, err := s.st.ListFindings(r.Context(), store.FindingFilter{VulnID: id, Status: "all"},
		store.Page{Page: 1, Size: 500, Sort: "host", Order: "asc"})
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vulnerability": v, "affected": affected.Items, "affected_total": affected.Total})
}

func (s *Server) setTriage(w http.ResponseWriter, r *http.Request) {
	var body struct {
		HostID int64  `json:"host_id"`
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := s.st.GetVuln(r.Context(), id); err != nil {
		s.storeErr(w, r, err)
		return
	}
	if err := s.st.SetTriage(r.Context(), id, body.HostID, body.Status, clean(body.Note, 2000)); err != nil {
		s.storeErr(w, r, err)
		return
	}
	scope := "all hosts"
	if body.HostID > 0 {
		scope = fmt.Sprintf("host #%d", body.HostID)
	}
	s.event(r, "info", "triage", "", "", fmt.Sprintf("%s marked %s for %s", id, body.Status, scope))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ListFindings(r.Context(), findingFilter(r), pageFrom(r))
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listVulnHosts(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ListVulnHosts(r.Context(), findingFilter(r), pageFrom(r))
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listVulnLocations(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ListVulnLocations(r.Context(), findingFilter(r), pageFrom(r))
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	out, err := s.st.ListHosts(r.Context(), store.HostFilter{
		Q: strings.TrimSpace(q.Get("q")), Group: q.Get("group"), Kind: q.Get("kind"), Status: q.Get("status"),
	}, pageFrom(r))
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	h, err := s.st.GetHost(r.Context(), id)
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	targets, err := s.st.HostTargets(r.Context(), id)
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": h, "targets": targets})
}

func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		Group *string `json:"group"`
		Notes *string `json:"notes"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if body.Group != nil {
		g := clean(*body.Group, 64)
		body.Group = &g
	}
	if body.Notes != nil {
		n := clean(*body.Notes, 2000)
		body.Notes = &n
	}
	if err := s.st.UpdateHost(r.Context(), id, body.Group, body.Notes); err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	h, err := s.st.GetHost(r.Context(), id)
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	if err := s.st.DeleteHost(r.Context(), id); err != nil {
		s.storeErr(w, r, err)
		return
	}
	s.event(r, "warn", "system", h.Name, "", "host deleted with all its scans")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ListGroups(r.Context())
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	out, err := s.st.ListScans(r.Context(), store.ScanFilter{
		HostID: qInt64(r, "host_id"), TargetID: qInt64(r, "target_id"), Q: strings.TrimSpace(q.Get("q")), Source: q.Get("source"),
	}, pageFrom(r))
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	out, err := s.st.ListEvents(r.Context(), store.EventFilter{
		Q: strings.TrimSpace(q.Get("q")), Level: qList(r, "level"), Source: q.Get("source"), Host: q.Get("host"), RunID: q.Get("run_id"),
	}, pageFrom(r))
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ListTokens(r.Context())
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	t, plain, err := s.st.CreateToken(r.Context(), clean(body.Name, 64))
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	s.event(r, "info", "system", "", "", "ingest token created: "+t.Name)
	writeJSON(w, http.StatusCreated, map[string]any{"token": t, "value": plain})
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteToken(r.Context(), id); err != nil {
		s.storeErr(w, r, err)
		return
	}
	s.event(r, "warn", "system", "", "", fmt.Sprintf("ingest token #%d revoked", id))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listCentral(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ListCentralTargets(r.Context())
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createCentral(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ref         string `json:"ref"`
		HostName    string `json:"host_name"`
		Group       string `json:"group"`
		IntervalMin int    `json:"interval_min"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if body.HostName != "" && !hostnameRe.MatchString(body.HostName) {
		writeErr(w, http.StatusBadRequest, "invalid host name")
		return
	}
	c, err := s.st.CreateCentralTarget(r.Context(), store.CentralTarget{Ref: clean(body.Ref, 512), HostName: body.HostName,
		Group: clean(body.Group, 64), IntervalMin: body.IntervalMin})
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	if _, err := s.jobs.EnqueueCentral(r.Context(), c.ID); err != nil {
		s.log.Error("queue central scan", "id", c.ID, "err", err) // the scheduler queues it within a minute
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) updateCentral(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := s.st.SetCentralTargetEnabled(r.Context(), id, body.Enabled); err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteCentral(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteCentralTarget(r.Context(), id); err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) scanCentral(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := s.st.GetCentralTarget(r.Context(), id); err != nil {
		s.storeErr(w, r, err)
		return
	}
	queued, err := s.jobs.EnqueueCentral(r.Context(), id)
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	if !queued {
		writeErr(w, http.StatusConflict, "a scan of this target is already queued or running")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"queued": true})
}

func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	queue, err := s.jobs.Stats(r.Context())
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":       s.cfg.Version,
		"auth_enabled":  s.authEnabled(),
		"scanner":       s.scan.Status(),
		"queue":         queue,
		"max_report_mb": s.cfg.MaxReportMB,
		"notify":        s.notify.Status(),
	})
}

// updateDB queues a check for a new vulnerability DB; a new one re-matches everything.
func (s *Server) updateDB(w http.ResponseWriter, r *http.Request) {
	queued, err := s.jobs.EnqueueDBUpdate(r.Context())
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	if !queued {
		writeErr(w, http.StatusConflict, "a DB update is already queued or running")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"queued": true})
}

// rematchAll re-matches every stored SBOM against the current DB.
func (s *Server) rematchAll(w http.ResponseWriter, r *http.Request) {
	queued, err := s.jobs.EnqueueRematchAll(r.Context())
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	if !queued {
		writeErr(w, http.StatusConflict, "a re-match of all targets is already queued")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"queued": true})
}

func (s *Server) testNotify(w http.ResponseWriter, r *http.Request) {
	if err := s.notify.Test(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}
