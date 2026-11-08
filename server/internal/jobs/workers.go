package jobs

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/riverqueue/river"

	"github.com/amanahlab/labwarden/server/internal/scanner"
	"github.com/amanahlab/labwarden/server/internal/store"
)

// CentralScanArgs scans a central (registry) target.
type CentralScanArgs struct {
	TargetID int64 `json:"target_id" river:"unique"`
}

func (CentralScanArgs) Kind() string { return "central_scan" }

func (CentralScanArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueScan, Priority: 2, MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

type centralScanWorker struct {
	river.WorkerDefaults[CentralScanArgs]
	sc *scanner.Scanner
}

// Above the scanner's own 20 minute grype timeout, which pulls the image.
func (w *centralScanWorker) Timeout(*river.Job[CentralScanArgs]) time.Duration {
	return 25 * time.Minute
}

func (w *centralScanWorker) Work(ctx context.Context, job *river.Job[CentralScanArgs]) error {
	if !w.sc.HasDB() {
		return river.JobSnooze(noDBSnooze)
	}
	return w.sc.ScanCentral(ctx, job.Args.TargetID)
}

// DBUpdateArgs checks for a new vulnerability DB and swaps it in.
type DBUpdateArgs struct{}

func (DBUpdateArgs) Kind() string { return "db_update" }

func (DBUpdateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueDB, MaxAttempts: 5,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

type dbUpdateWorker struct {
	river.WorkerDefaults[DBUpdateArgs]
	sc *scanner.Scanner
}

// Above the 30 minute download limit in scanner.UpdateDB.
func (w *dbUpdateWorker) Timeout(*river.Job[DBUpdateArgs]) time.Duration { return 35 * time.Minute }

func (w *dbUpdateWorker) Work(ctx context.Context, _ *river.Job[DBUpdateArgs]) error {
	return w.sc.UpdateDB(ctx)
}

// ScheduleArgs queues every central target that is due.
type ScheduleArgs struct{}

func (ScheduleArgs) Kind() string { return "schedule" }

func (ScheduleArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMaint, MaxAttempts: 1,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

type scheduleWorker struct {
	river.WorkerDefaults[ScheduleArgs]
	q *Queue
}

func (w *scheduleWorker) Timeout(*river.Job[ScheduleArgs]) time.Duration { return time.Minute }

func (w *scheduleWorker) Work(ctx context.Context, _ *river.Job[ScheduleArgs]) error {
	due, err := w.q.st.DueCentralTargets(ctx)
	if err != nil {
		return err
	}
	for _, c := range due {
		if _, err := w.q.EnqueueCentral(ctx, c.ID); err != nil {
			return err
		}
	}
	return nil
}

// MatchSBOMArgs matches an uploaded SBOM, stored by sboms.Files, and ingests
// the result. An agent retrying the same upload of a run is matched once.
type MatchSBOMArgs struct {
	SHA256 string           `json:"sha256" river:"unique"`
	Size   int64            `json:"size"`
	Host   string           `json:"host" river:"unique"`
	Target string           `json:"target" river:"unique"`
	RunID  string           `json:"run_id" river:"unique"`
	Meta   store.IngestMeta `json:"meta"`
}

func (MatchSBOMArgs) Kind() string { return "match_sbom" }

// Fresh uploads go ahead of central scans and re-matches.
func (MatchSBOMArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueScan, Priority: 1, MaxAttempts: 5,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

type matchSBOMWorker struct {
	river.WorkerDefaults[MatchSBOMArgs]
	q *Queue
}

func (w *matchSBOMWorker) Timeout(*river.Job[MatchSBOMArgs]) time.Duration { return 10 * time.Minute }

func (w *matchSBOMWorker) Work(ctx context.Context, job *river.Job[MatchSBOMArgs]) error {
	if !w.q.sc.HasDB() {
		return river.JobSnooze(noDBSnooze)
	}
	a := job.Args
	path, err := w.q.sboms.Extract(a.SHA256)
	if err != nil {
		return fmt.Errorf("sbom of %s/%s: %w", a.Host, a.Target, err)
	}
	defer os.Remove(path)
	res, err := w.q.sc.MatchSBOM(ctx, a.Meta, path)
	if err != nil { // the error handler records the final failure
		return fmt.Errorf("match %s/%s: %w", a.Host, a.Target, err)
	}
	m := a.Meta
	m.Target = res.Target
	if err := w.q.st.SetTargetSBOM(ctx, res.TargetID, a.SHA256, a.Size, m); err != nil {
		return err
	}
	w.q.event(ctx, "info", a.Meta, fmt.Sprintf("matched SBOM for %s: %d findings (%d new, %d fixed)",
		res.Target, res.Findings, res.New, res.Fixed))
	return nil
}
