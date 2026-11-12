package api

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/amanahlab/labwarden/server/internal/jobs"
	"github.com/amanahlab/labwarden/server/internal/store"
)

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// hostKinds an agent may report; "central" hosts belong to the server.
var hostKinds = map[string]bool{"vm": true, "docker": true, "host": true}

// metaFromQuery reads agent metadata for host from query parameters.
func metaFromQuery(r *http.Request, host string) (store.IngestMeta, error) {
	q := r.URL.Query()
	m := store.IngestMeta{
		Host:         host,
		Kind:         q.Get("kind"),
		Group:        clean(q.Get("group"), 64),
		OS:           clean(q.Get("os"), 128),
		Arch:         clean(q.Get("arch"), 32),
		IP:           clean(q.Get("ip"), 64),
		AgentVersion: clean(q.Get("agent_version"), 32),
		Target:       clean(q.Get("target"), 512),
		RunID:        clean(q.Get("run_id"), 64),
		Source:       "agent",
	}
	m.IntervalSec, _ = strconv.Atoi(q.Get("interval"))
	m.DurationMS, _ = strconv.ParseInt(q.Get("duration_ms"), 10, 64)
	return m, validateMeta(&m)
}

func validateMeta(m *store.IngestMeta) error {
	if !hostnameRe.MatchString(m.Host) {
		return fmt.Errorf("host must match %s", hostnameRe.String())
	}
	if m.Kind == "" {
		m.Kind = "vm"
	}
	if !hostKinds[m.Kind] {
		return fmt.Errorf("kind must be one of vm, docker, host")
	}
	if m.IntervalSec < 0 || m.IntervalSec > 30*86400 {
		m.IntervalSec = 0
	}
	return nil
}

func clean(s string, max int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s))
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// body returns the request body, transparently gunzipped and size-limited.
func (s *Server) body(w http.ResponseWriter, r *http.Request) (io.ReadCloser, error) {
	limit := s.cfg.MaxReportMB << 20
	rc := http.MaxBytesReader(w, r.Body, limit)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(rc)
		if err != nil {
			return nil, fmt.Errorf("invalid gzip body: %w", err)
		}
		// Bound the decompressed size too (gzip bombs), failing rather than truncating.
		return struct {
			io.Reader
			io.Closer
		}{&capReader{r: gz, n: limit * 4}, gz}, nil
	}
	return rc, nil
}

// capReader fails with *http.MaxBytesError once more than n bytes are read.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n < 0 {
		return 0, &http.MaxBytesError{}
	}
	if int64(len(p)) > c.n+1 {
		p = p[:c.n+1]
	}
	n, err := c.r.Read(p)
	c.n -= int64(n)
	if c.n < 0 {
		return n, &http.MaxBytesError{}
	}
	return n, err
}

// ingestSBOM accepts a Syft JSON SBOM and queues it for matching, so agents
// only need syft and the server holds the single vulnerability DB. It answers
// 202 as soon as the SBOM is on disk; findings follow within seconds.
func (s *Server) ingestSBOM(w http.ResponseWriter, r *http.Request) {
	host, ok := s.agentHost(w, r, strings.TrimSpace(r.URL.Query().Get("host")))
	if !ok {
		return
	}
	m, err := metaFromQuery(r, host)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	body, err := s.body(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer body.Close()
	id, err := s.jobs.SubmitSBOM(r.Context(), m, body)
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		writeErr(w, http.StatusRequestEntityTooLarge, "sbom too large")
	case errors.Is(err, jobs.ErrBusy):
		s.event(r, "warn", "ingest", m.Host, m.RunID, "SBOM refused: "+err.Error())
		writeErr(w, http.StatusServiceUnavailable, err.Error())
	case err != nil:
		s.event(r, "error", "ingest", m.Host, m.RunID, "failed to queue SBOM: "+err.Error())
		writeErr(w, http.StatusBadRequest, "sbom upload failed: "+err.Error())
	default:
		writeJSON(w, http.StatusAccepted, map[string]any{"queued": true, "job_id": id})
	}
}

type eventIn struct {
	Host    string `json:"host"`
	Level   string `json:"level"`
	Message string `json:"message"`
	RunID   string `json:"run_id"`
}

func (s *Server) ingestEvent(w http.ResponseWriter, r *http.Request) {
	var e eventIn
	if err := decodeJSON(r, &e); err != nil || strings.TrimSpace(e.Message) == "" {
		writeErr(w, http.StatusBadRequest, "expected {host, level, message, run_id}")
		return
	}
	host, ok := s.agentHost(w, r, strings.TrimSpace(e.Host))
	if !ok {
		return
	}
	if err := s.st.AddEvent(r.Context(), store.Event{Level: e.Level, Source: "agent", Host: host,
		RunID: clean(e.RunID, 64), Message: clean(e.Message, 4000)}); err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

type runIn struct {
	Host         string   `json:"host"`
	Kind         string   `json:"kind"`
	Group        string   `json:"group"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	IP           string   `json:"ip"`
	AgentVersion string   `json:"agent_version"`
	IntervalSec  int      `json:"interval"`
	RunID        string   `json:"run_id"`
	Status       string   `json:"status"` // started | ok | error
	Message      string   `json:"message"`
	Targets      []string `json:"targets"`
	// Images lists the running containers (final call of a Docker run).
	// nil = not sent (an older agent, or listing failed): keep what is stored.
	Images []imageIn `json:"images"`
}

// ingestRun records the start or end of an agent run. The final call
// carries the complete list of targets so vanished ones are retired.
func (s *Server) ingestRun(w http.ResponseWriter, r *http.Request) {
	var in runIn
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid run payload: "+err.Error())
		return
	}
	host, ok := s.agentHost(w, r, strings.TrimSpace(in.Host))
	if !ok {
		return
	}
	m := store.IngestMeta{Host: host, Kind: in.Kind, Group: clean(in.Group, 64), OS: clean(in.OS, 128),
		Arch: clean(in.Arch, 32), IP: clean(in.IP, 64), AgentVersion: clean(in.AgentVersion, 32), IntervalSec: in.IntervalSec,
		RunID: clean(in.RunID, 64)}
	if err := validateMeta(&m); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	msg := clean(in.Message, 2000)
	switch in.Status {
	case "started":
		if _, err := s.st.Heartbeat(r.Context(), m); err != nil {
			s.storeErr(w, r, err)
			return
		}
		s.event(r, "info", "agent", m.Host, m.RunID, orDefault(msg, "scan run started"))
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
	case "ok", "error":
		// nil = the agent sent no target list (retire nothing); an empty list
		// means the run succeeded and found no targets (retire them all).
		var targets []string
		if in.Targets != nil {
			targets = make([]string, 0, len(in.Targets))
		}
		for _, t := range in.Targets {
			if t = clean(t, 512); t != "" {
				targets = append(targets, t)
			}
		}
		// A failed run may not have reached every target; don't retire on error.
		if in.Status == "error" {
			targets = nil
		}
		var imgs []store.ContainerImage
		dropped := 0
		if in.Images != nil {
			var err error
			if imgs, dropped, err = containerImages(in.Images); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		retired, err := s.st.CompleteRun(r.Context(), m, in.Status, targets)
		if err != nil {
			s.storeErr(w, r, err)
			return
		}
		// Listing containers does not depend on the scans, so even a failed
		// run reports what is running.
		if imgs != nil {
			if err := s.st.ReplaceHostImages(r.Context(), m.Host, imgs); err != nil {
				s.storeErr(w, r, err)
				return
			}
			// New images get their upstream status within minutes, not at
			// the next sweep. The run is stored either way.
			if _, err := s.jobs.EnqueueImageChecks(r.Context(), m.Host); err != nil {
				s.log.Warn("queue image checks", "host", m.Host, "err", err)
			}
		}
		if dropped > 0 {
			s.event(r, "warn", "agent", m.Host, m.RunID, fmt.Sprintf("ignored %d container(s) with an invalid name, image reference or image ID", dropped))
		}
		level := "info"
		if in.Status == "error" {
			level = "error"
		}
		text := orDefault(msg, "scan run finished: "+in.Status)
		if retired > 0 {
			text += fmt.Sprintf(" (%d target(s) no longer present were retired)", retired)
		}
		s.event(r, level, "agent", m.Host, m.RunID, text)
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "retired": retired})
	default:
		writeErr(w, http.StatusBadRequest, "status must be started, ok or error")
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
