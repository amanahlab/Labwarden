// Package scanner runs Grype on the server: scheduled registry-image scans
// ("central targets"), SBOMs uploaded by agents, and DB updates.
package scanner

import (
	"bytes"
	"context"
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
	"github.com/amanahlab/labwarden/server/internal/store"
)

type Scanner struct {
	bin     string
	st      *store.Store
	log     *slog.Logger
	timeout time.Duration
	queue   chan int64
	sem     chan struct{} // bounds concurrent grype processes

	dbDir    string       // grype's cache dir; see db.go
	dbLock   sync.RWMutex // scans read-lock; swapping in a new DB write-locks
	updating atomic.Bool  // a DB update is running

	mu      sync.Mutex
	pending map[int64]bool
	status  Status
}

type Status struct {
	Available    bool   `json:"available"`
	GrypeVersion string `json:"grype_version"`
	DBBuilt      string `json:"db_built"`
	DBSchema     string `json:"db_schema"`
	DBChecked    string `json:"db_checked"`
	DBError      string `json:"db_error,omitempty"`
	Running      string `json:"running,omitempty"`
	Queued       int    `json:"queued"`
}

func New(bin string, st *store.Store, log *slog.Logger) *Scanner {
	return &Scanner{bin: bin, st: st, log: log, timeout: 20 * time.Minute, dbDir: grypeDBDir(),
		queue: make(chan int64, 256), sem: make(chan struct{}, 2), pending: map[int64]bool{}}
}

func (s *Scanner) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	st.Queued = len(s.pending)
	return st
}

// Enqueue schedules a central target scan; false if already queued or full.
func (s *Scanner) Enqueue(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[id] {
		return false
	}
	select {
	case s.queue <- id:
		s.pending[id] = true
		return true
	default:
		return false
	}
}

// Run drives the worker, scheduler and DB updates until ctx ends.
func (s *Scanner) Run(ctx context.Context, schedule bool, dbUpdateEvery time.Duration) {
	s.refreshVersion(ctx)
	s.refreshDBStatus(ctx)
	go s.worker(ctx)
	go func() {
		s.updateDB(ctx)
		t := time.NewTicker(dbUpdateEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.updateDB(ctx)
			}
		}
	}()
	if !schedule {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		due, err := s.st.DueCentralTargets(ctx)
		if err != nil && ctx.Err() == nil {
			s.log.Error("scheduler", "err", err)
		}
		for _, c := range due {
			s.Enqueue(c.ID)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Scanner) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-s.queue:
			s.scanCentral(ctx, id)
			s.mu.Lock()
			delete(s.pending, id)
			s.status.Running = ""
			s.mu.Unlock()
		}
	}
}

func (s *Scanner) scanCentral(ctx context.Context, id int64) {
	c, err := s.st.GetCentralTarget(ctx, id)
	if err != nil {
		return // deleted while queued
	}
	s.mu.Lock()
	s.status.Running = c.Ref
	s.mu.Unlock()
	s.event(ctx, "info", c.HostName, "central scan started: "+c.Ref)
	start := time.Now()
	rep, err := s.grype(ctx, "registry:"+c.Ref)
	meta := store.IngestMeta{Host: c.HostName, Kind: "central", Group: c.Group, Target: c.Ref, Source: "server",
		IntervalSec: c.IntervalMin * 60, DurationMS: time.Since(start).Milliseconds(), AgentVersion: "server"}
	if err == nil {
		var res *store.IngestResult
		res, err = s.st.IngestReport(ctx, meta, rep)
		if err == nil {
			_ = s.st.MarkCentralRun(ctx, id, "ok")
			_, _ = s.st.CompleteRun(ctx, meta, "ok", nil)
			s.event(ctx, "info", c.HostName, fmt.Sprintf("central scan of %s finished in %s: %d findings (%d new, %d fixed)",
				c.Ref, time.Since(start).Round(time.Second), res.Findings, res.New, res.Fixed))
			return
		}
	}
	_ = s.st.MarkCentralRun(ctx, id, "error: "+trim(err.Error(), 300))
	_, _ = s.st.CompleteRun(ctx, meta, "error", nil)
	s.event(ctx, "error", c.HostName, "central scan of "+c.Ref+" failed: "+trim(err.Error(), 1500))
}

// ScanSBOM scans an uploaded Syft SBOM and stores the result.
func (s *Scanner) ScanSBOM(ctx context.Context, m store.IngestMeta, r io.Reader) (*store.IngestResult, error) {
	f, err := os.CreateTemp("", "labwarden-sbom-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	start := time.Now()
	rep, err := s.grype(ctx, "sbom:"+f.Name())
	if err != nil {
		return nil, err
	}
	m.Source = "server"
	if m.DurationMS == 0 {
		m.DurationMS = time.Since(start).Milliseconds()
	}
	if m.Target == "" {
		m.Target = "sbom"
	}
	return s.st.IngestReport(ctx, m, rep)
}

func (s *Scanner) grype(ctx context.Context, source string) (*grype.Report, error) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if !s.hasDB() {
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
