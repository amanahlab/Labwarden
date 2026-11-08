package jobs

import (
	"context"
	"errors"
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

// syft pulls the image and grype matches it, each within the scanner's 20
// minute limit; a scan slower than this is cancelled and retried.
func (w *centralScanWorker) Timeout(*river.Job[CentralScanArgs]) time.Duration {
	return 25 * time.Minute
}

func (w *centralScanWorker) Work(ctx context.Context, job *river.Job[CentralScanArgs]) error {
	if !w.sc.HasDB() {
		return river.JobSnooze(noDBSnooze)
	}
	return w.sc.ScanCentral(ctx, job.Args.TargetID)
}

// DBUpdateArgs checks for a new vulnerability DB and swaps it in, then
// queues a re-match of every stored SBOM against it. With MaxAge set it does
// nothing while the live DB is younger than that.
type DBUpdateArgs struct {
	MaxAge time.Duration `json:"max_age,omitempty"`
}

func (DBUpdateArgs) Kind() string { return "db_update" }

func (DBUpdateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueDB, MaxAttempts: 5,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

type dbUpdateWorker struct {
	river.WorkerDefaults[DBUpdateArgs]
	q *Queue
}

// Above the 30 minute download limit in scanner.UpdateDB.
func (w *dbUpdateWorker) Timeout(*river.Job[DBUpdateArgs]) time.Duration { return 35 * time.Minute }

func (w *dbUpdateWorker) Work(ctx context.Context, job *river.Job[DBUpdateArgs]) error {
	updated, err := w.q.sc.UpdateDB(ctx, job.Args.MaxAge)
	if err != nil {
		return err
	}
	// On a retry the DB may have been swapped in by the failed attempt, which
	// then reports no update; re-matching once too often is cheap, never is not.
	if !updated && job.Attempt == 1 {
		return nil
	}
	if _, err := w.q.client.Insert(ctx, RematchAllArgs{}, nil); err != nil {
		return fmt.Errorf("queue re-match: %w", err)
	}
	return nil
}

// RematchArgs matches a target's latest stored SBOM against the current DB,
// so new vulnerabilities show up without waiting for the agent.
type RematchArgs struct {
	TargetID int64 `json:"target_id" river:"unique"`
}

func (RematchArgs) Kind() string { return "rematch" }

// Behind fresh uploads and central scans: a re-match is never urgent.
func (RematchArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueScan, Priority: 4, MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

// RematchAllArgs queues a re-match of every stored SBOM. It is its own job so
// a failed fan-out is retried instead of lost after the DB swap succeeded.
type RematchAllArgs struct{}

func (RematchAllArgs) Kind() string { return "rematch_all" }

func (RematchAllArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMaint, MaxAttempts: 10,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

type rematchAllWorker struct {
	river.WorkerDefaults[RematchAllArgs]
	q *Queue
}

func (w *rematchAllWorker) Work(ctx context.Context, job *river.Job[RematchAllArgs]) error {
	n, err := w.q.EnqueueRematches(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		w.q.event(ctx, "info", store.IngestMeta{}, fmt.Sprintf("re-matching %d targets against the current DB", n))
	}
	return nil
}

type rematchWorker struct {
	river.WorkerDefaults[RematchArgs]
	q *Queue
}

func (w *rematchWorker) Timeout(*river.Job[RematchArgs]) time.Duration { return 10 * time.Minute }

func (w *rematchWorker) Work(ctx context.Context, job *river.Job[RematchArgs]) error {
	if !w.q.sc.HasDB() {
		return river.JobSnooze(noDBSnooze)
	}
	sha, m, err := w.q.st.TargetSBOM(ctx, job.Args.TargetID)
	if errors.Is(err, store.ErrNotFound) {
		return nil // target deleted since
	}
	if err != nil {
		return err
	}
	path, err := w.q.sboms.Extract(sha)
	if err != nil {
		return fmt.Errorf("sbom of %s/%s: %w", m.Host, m.Target, err)
	}
	defer os.Remove(path)
	m.Rematch, m.RunID, m.DurationMS = true, "", 0
	if _, err := w.q.sc.MatchSBOM(ctx, m, path); err != nil {
		return fmt.Errorf("re-match %s/%s: %w", m.Host, m.Target, err)
	}
	return nil
}

// SBOMGCArgs deletes stored SBOMs that no target references any more.
type SBOMGCArgs struct{}

func (SBOMGCArgs) Kind() string { return "sbom_gc" }

func (SBOMGCArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMaint, MaxAttempts: 1,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

type sbomGCWorker struct {
	river.WorkerDefaults[SBOMGCArgs]
	q *Queue
}

func (w *sbomGCWorker) Work(ctx context.Context, _ *river.Job[SBOMGCArgs]) error {
	if w.q.sboms == nil {
		return nil
	}
	keep, err := w.q.st.SBOMRefs(ctx)
	if err != nil {
		return err
	}
	n, err := w.q.sboms.GC(keep, sbomGrace)
	if n > 0 {
		w.q.log.Info("deleted unreferenced SBOMs", "count", n)
	}
	return err
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
