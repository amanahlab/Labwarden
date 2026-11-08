// Package scanner runs Grype on the server: registry-image scans ("central
// targets", catalogued with Syft), SBOMs uploaded by agents, and DB updates.
// Package jobs decides when each runs.
package scanner

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amanahlab/labwarden/server/internal/grype"
	"github.com/amanahlab/labwarden/server/internal/sboms"
	"github.com/amanahlab/labwarden/server/internal/store"
)

type Scanner struct {
	bin     string
	syft    string
	sboms   *sboms.Files
	st      *store.Store
	log     *slog.Logger
	timeout time.Duration

	dbDir    string       // grype's cache dir; see db.go
	dbLock   sync.RWMutex // scans read-lock; swapping in a new DB write-locks
	updating atomic.Bool  // a DB update is running

	mu     sync.Mutex
	status Status
}

type Status struct {
	Available    bool   `json:"available"`
	GrypeVersion string `json:"grype_version"`
	DBBuilt      string `json:"db_built"`
	DBSchema     string `json:"db_schema"`
	DBChecked    string `json:"db_checked"`
	DBError      string `json:"db_error,omitempty"`
	Running      string `json:"running,omitempty"`
}

// New returns a scanner running grype from bin. Central scans catalog images
// with the syft binary and keep the SBOM in files, so they are re-matched
// against every new DB like the SBOMs agents upload.
func New(bin, syft string, files *sboms.Files, st *store.Store, log *slog.Logger) *Scanner {
	return &Scanner{bin: bin, syft: syft, sboms: files, st: st, log: log, timeout: 20 * time.Minute, dbDir: grypeDBDir()}
}

func (s *Scanner) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Init finds the grype binary. The DB on disk is found by the first UpdateDB:
// reading its status cold takes about 20 seconds, too long to hold up startup.
func (s *Scanner) Init(ctx context.Context) {
	s.refreshVersion(ctx)
}

// ScanCentral scans a central target and records the outcome; a target
// deleted since it was queued is skipped.
func (s *Scanner) ScanCentral(ctx context.Context, id int64) error {
	c, err := s.st.GetCentralTarget(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.status.Running = c.Ref
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.status.Running = ""
		s.mu.Unlock()
	}()
	s.event(ctx, "info", c.HostName, "central scan started: "+c.Ref)
	start := time.Now()
	rep, sha, size, err := s.scanImage(ctx, c.Ref)
	meta := store.IngestMeta{Host: c.HostName, Kind: "central", Group: c.Group, Target: c.Ref, Source: "server",
		IntervalSec: c.IntervalMin * 60, DurationMS: time.Since(start).Milliseconds(), AgentVersion: "server"}
	var res *store.IngestResult
	if err == nil {
		res, err = s.st.IngestReport(ctx, meta, rep)
	}
	if err == nil {
		err = s.st.SetTargetSBOM(ctx, res.TargetID, sha, size, meta)
	}
	if err == nil {
		_ = s.st.MarkCentralRun(ctx, id, "ok")
		_, _ = s.st.CompleteRun(ctx, meta, "ok", nil)
		s.event(ctx, "info", c.HostName, fmt.Sprintf("central scan of %s finished in %s: %d findings (%d new, %d fixed)",
			c.Ref, time.Since(start).Round(time.Second), res.Findings, res.New, res.Fixed))
		return nil
	}
	_ = s.st.MarkCentralRun(ctx, id, "error: "+trim(err.Error(), 300))
	_, _ = s.st.CompleteRun(ctx, meta, "error", nil)
	s.event(ctx, "error", c.HostName, "central scan of "+c.Ref+" failed: "+trim(err.Error(), 1500))
	return err
}

// MatchSBOM matches a Syft SBOM file against the DB and stores the result.
func (s *Scanner) MatchSBOM(ctx context.Context, m store.IngestMeta, path string) (*store.IngestResult, error) {
	start := time.Now()
	rep, err := s.grype(ctx, "sbom:"+path)
	if err != nil {
		return nil, err
	}
	m.Source = "server"
	if m.DurationMS == 0 {
		m.DurationMS = time.Since(start).Milliseconds()
	}
	if m.Target == "" {
		m.Target = "sbom" // grype would name it after the temp file
	}
	return s.st.IngestReport(ctx, m, rep)
}

// scanImage catalogs a registry image with syft, stores the SBOM and matches it.
func (s *Scanner) scanImage(ctx context.Context, ref string) (rep *grype.Report, sha string, size int64, err error) {
	if !s.HasDB() {
		return nil, "", 0, errors.New("the vulnerability DB has not been downloaded yet; try again later")
	}
	if sha, size, err = s.catalog(ctx, "registry:"+ref); err != nil {
		return nil, "", 0, err
	}
	path, err := s.sboms.Extract(sha)
	if err != nil {
		return nil, "", 0, err
	}
	defer os.Remove(path)
	rep, err = s.grype(ctx, "sbom:"+path)
	return rep, sha, size, err
}

// catalog runs syft on source and streams its SBOM into the SBOM files.
func (s *Scanner) catalog(ctx context.Context, source string) (sha string, size int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, s.syft, "scan", source, "-o", "syft-json", "-q")
	cmd.Env = syftEnv(os.Environ())
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", 0, err
	}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", 0, fmt.Errorf("syft binary %q not found", s.syft)
		}
		return "", 0, err
	}
	sha, size, putErr := s.sboms.Put(out)
	_, _ = io.Copy(io.Discard, out) // a failed Put must not leave syft blocked on a full pipe
	if err := cmd.Wait(); err != nil {
		return "", 0, fmt.Errorf("syft %s: %v: %s", source, err, trim(stderr.String(), 1000))
	}
	return sha, size, putErr
}

// syftEnv lets syft, which now pulls central images, use the registry
// settings and credentials configured for grype (GRYPE_REGISTRY_*), unless
// the matching SYFT_REGISTRY_* is set.
func syftEnv(environ []string) []string {
	set := map[string]bool{}
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		set[k] = true
	}
	env := append([]string{}, environ...)
	for _, kv := range environ {
		if rest, ok := strings.CutPrefix(kv, "GRYPE_REGISTRY_"); ok {
			k, _, _ := strings.Cut(rest, "=")
			if !set["SYFT_REGISTRY_"+k] {
				env = append(env, "SYFT_REGISTRY_"+rest)
			}
		}
	}
	return append(env, "SYFT_CHECK_FOR_APP_UPDATE=false")
}

// grype runs one scan. Callers are jobs on the scan queue, whose MaxWorkers
// bounds how many run at once.
func (s *Scanner) grype(ctx context.Context, source string) (*grype.Report, error) {
	if !s.HasDB() {
		return nil, errors.New("the vulnerability DB has not been downloaded yet; try again later")
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	s.dbLock.RLock()
	defer s.dbLock.RUnlock()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, s.bin, source, "-o", "json", "-q")
	cmd.Env = grypeEnv(s.dbDir)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("grype binary %q not found", s.bin)
		}
		return nil, fmt.Errorf("grype %s: %v: %s", source, err, trim(stderr.String(), 1000))
	}
	return grype.Parse(&stdout)
}

func (s *Scanner) refreshVersion(ctx context.Context) {
	out, err := exec.CommandContext(ctx, s.bin, "version", "-o", "json").Output()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.status.Available = false
		s.log.Warn("grype not available; central scanning disabled", "bin", s.bin, "err", err)
		return
	}
	var v struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(out, &v)
	s.status.Available = true
	s.status.GrypeVersion = v.Version
}

func (s *Scanner) event(ctx context.Context, level, host, msg string) {
	if err := s.st.AddEvent(ctx, store.Event{Level: level, Source: "scanner", Host: host, Message: msg}); err != nil {
		s.log.Error("add event", "err", err)
	}
	s.log.Info("scanner", "level", level, "host", host, "msg", msg)
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
