// Package jobs runs LabWarden's background work on River, a durable job
// queue kept in its own SQLite file (queue.db) so queue traffic never blocks
// the store. Jobs hold only IDs; results live in the store, so losing
// queue.db loses nothing that the scheduler won't queue again.
//
// Queues:
//   - scan: grype work, MaxWorkers bounds concurrent grype processes
//   - db:   vulnerability DB updates, one worker so there is never a second download
//   - maintenance: quick bookkeeping such as queueing due central targets
package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riversqlite"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
	_ "modernc.org/sqlite"

	"github.com/amanahlab/labwarden/server/internal/scanner"
	"github.com/amanahlab/labwarden/server/internal/store"
)

const (
	QueueScan  = "scan"
	QueueDB    = "db"
	QueueMaint = "maintenance"

	// SQLite has no LISTEN/NOTIFY, so workers poll. 100 ms measured a p99
	// pickup of about 100 ms on a homelab box; the cost is an indexed query.
	pollInterval = 100 * time.Millisecond

	// No DB known yet: right after startup until the first db_update has read
	// the DB's status, or on first start until the download finishes.
	noDBSnooze = 15 * time.Second
)

// pendingStates makes a job unique only until it finishes, so the next
// scheduled run of the same target is not skipped as a duplicate.
var pendingStates = []rivertype.JobState{
	rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
	rivertype.JobStateRetryable, rivertype.JobStateScheduled,
}

type Config struct {
	Path          string        // queue.db
	ScanWorkers   int           // concurrent grype processes
	Scheduler     bool          // queue due central targets every minute
	DBUpdateEvery time.Duration // how often to check for a new vulnerability DB
}

type Queue struct {
	db     *sql.DB
	client *river.Client[*sql.Tx]
	st     *store.Store
	log    *slog.Logger
}

// Open opens queue.db, migrates River's schema and builds the client; Start runs it.
func Open(ctx context.Context, cfg Config, st *store.Store, sc *scanner.Scanner, log *slog.Logger) (*Queue, error) {
	// River's SQLite driver needs a single connection: it runs maintenance
	// in parallel and would otherwise hit SQLITE_BUSY.
	db, err := sql.Open("sqlite", "file:"+cfg.Path+
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	drv := riversqlite.New(db)
	mig, err := rivermigrate.New(drv, nil)
	if err == nil {
		_, err = mig.Migrate(ctx, rivermigrate.DirectionUp, nil)
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate queue: %w", err)
	}

	q := &Queue{db: db, st: st, log: log}
	workers := river.NewWorkers()
	river.AddWorker(workers, &centralScanWorker{sc: sc})
	river.AddWorker(workers, &dbUpdateWorker{sc: sc})
	river.AddWorker(workers, &scheduleWorker{q: q})

	periodic := []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(cfg.DBUpdateEvery),
			func() (river.JobArgs, *river.InsertOpts) { return DBUpdateArgs{}, nil },
			&river.PeriodicJobOpts{ID: "db_update", RunOnStart: true}),
	}
	if cfg.Scheduler {
		periodic = append(periodic, river.NewPeriodicJob(river.PeriodicInterval(time.Minute),
			func() (river.JobArgs, *river.InsertOpts) { return ScheduleArgs{}, nil },
			&river.PeriodicJobOpts{ID: "schedule", RunOnStart: true}))
	}

	q.client, err = river.NewClient(drv, &river.Config{
		Logger: log.With("component", "jobs"),
		Queues: map[string]river.QueueConfig{
			QueueScan:  {MaxWorkers: max(cfg.ScanWorkers, 1), FetchPollInterval: pollInterval},
			QueueDB:    {MaxWorkers: 1, FetchPollInterval: time.Second},
			QueueMaint: {MaxWorkers: 1, FetchPollInterval: time.Second},
		},
		Workers:      workers,
		PeriodicJobs: periodic,
		ErrorHandler: &errorHandler{st: st, log: log},
		// Longer than any job's Timeout, so only jobs of a killed process are rescued.
		RescueStuckJobsAfter:        time.Hour,
		CompletedJobRetentionPeriod: 24 * time.Hour,
		DiscardedJobRetentionPeriod: 7 * 24 * time.Hour,
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return q, nil
}

func (q *Queue) Start(ctx context.Context) error { return q.client.Start(ctx) }

// Stop waits for running jobs until ctx ends, then cancels them; unfinished
// jobs run again after the next start.
func (q *Queue) Stop(ctx context.Context) error {
	err := q.client.Stop(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = q.client.StopAndCancel(cctx)
	}
	return errors.Join(err, q.db.Close())
}

// EnqueueCentral queues a scan of a central target; false if one is already pending.
func (q *Queue) EnqueueCentral(ctx context.Context, id int64) (bool, error) {
	res, err := q.client.Insert(ctx, CentralScanArgs{TargetID: id}, nil)
	if err != nil {
		return false, err
	}
	return !res.UniqueSkippedAsDuplicate, nil
}

// EnqueueDBUpdate queues a DB update; false if one is already pending.
func (q *Queue) EnqueueDBUpdate(ctx context.Context) (bool, error) {
	res, err := q.client.Insert(ctx, DBUpdateArgs{}, nil)
	if err != nil {
		return false, err
	}
	return !res.UniqueSkippedAsDuplicate, nil
}

// Stats counts jobs by state for the system page.
type Stats struct {
	Queued   int `json:"queued"`    // available, scheduled or waiting to retry
	Running  int `json:"running"`   //
	Failed24 int `json:"failed_24h"` // gave up in the last 24 hours
}

func (q *Queue) Stats(ctx context.Context) (Stats, error) {
	var s Stats
	err := q.db.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(state IN ('available','scheduled','retryable','pending')),0),
		COALESCE(SUM(state = 'running'),0),
		COALESCE(SUM(state = 'discarded' AND finalized_at > datetime('now','-1 day')),0)
		FROM river_job`).Scan(&s.Queued, &s.Running, &s.Failed24)
	return s, err
}

// errorHandler logs job failures; the workers record user-facing events.
type errorHandler struct {
	st  *store.Store
	log *slog.Logger
}

func (h *errorHandler) HandleError(ctx context.Context, job *rivertype.JobRow, err error) *river.ErrorHandlerResult {
	h.log.Warn("job failed", "kind", job.Kind, "id", job.ID, "attempt", job.Attempt, "max", job.MaxAttempts, "err", err)
	if job.Attempt >= job.MaxAttempts {
		_ = h.st.AddEvent(ctx, store.Event{Level: "error", Source: "system",
			Message: fmt.Sprintf("background job %s gave up after %d attempts: %v", job.Kind, job.Attempt, err)})
	}
	return nil
}

func (h *errorHandler) HandlePanic(ctx context.Context, job *rivertype.JobRow, v any, trace string) *river.ErrorHandlerResult {
	h.log.Error("job panicked", "kind", job.Kind, "id", job.ID, "panic", v, "trace", trace)
	return nil
}
