package jobs

import (
	"context"
	"time"

	"github.com/riverqueue/river"

	"github.com/amanahlab/labwarden/server/internal/scanner"
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
