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
	"io"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riversqlite"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
	"github.com/robfig/cron/v3"
	_ "modernc.org/sqlite"

	"github.com/amanahlab/labwarden/server/internal/sboms"
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

	// At startup the DB is only checked when it is older than this, so a
	// restart does not download in the middle of the day.
	dbStartupMaxAge = 36 * time.Hour

	// Uploaded SBOMs nobody references are kept this long, well past the
	// lifetime of any job that might still read one.
	sbomGrace = 72 * time.Hour

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
	Path         string       // queue.db
	ScanWorkers  int          // concurrent grype processes
	Scheduler    bool         // queue due central targets every minute
	DBUpdateAt   string       // daily "HH:MM" in the server's time zone (TZ) to check for a new vulnerability DB
	SBOMs        *sboms.Files // uploaded SBOMs
	MaxQueued    int          // SubmitSBOM refuses work beyond this backlog
	MinFreeBytes uint64       // SubmitSBOM refuses uploads when the SBOM disk has less free
}

// ErrBusy means the server is not taking uploads right now; the agent keeps
// the SBOM in its spool and sends it again on its next run.
var ErrBusy = errors.New("server busy")

type Queue struct {
	cfg    Config
	db     *sql.DB
	client *river.Client[*sql.Tx]
	st     *store.Store
	sc     *scanner.Scanner
	sboms  *sboms.Files
	log    *slog.Logger
	daily  cron.Schedule // the DB update
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

	daily, err := DailyAt(cfg.DBUpdateAt)
	if err != nil {
		db.Close()
		return nil, err
	}
	q := &Queue{cfg: cfg, db: db, st: st, sc: sc, sboms: cfg.SBOMs, log: log, daily: daily}
	workers := river.NewWorkers()
	river.AddWorker(workers, &centralScanWorker{sc: sc})
	river.AddWorker(workers, &dbUpdateWorker{q: q})
	river.AddWorker(workers, &rematchWorker{q: q})
	river.AddWorker(workers, &sbomGCWorker{q: q})
	river.AddWorker(workers, &scheduleWorker{q: q})
	river.AddWorker(workers, &matchSBOMWorker{q: q})

	periodic := []*river.PeriodicJob{
		river.NewPeriodicJob(daily,
			func() (river.JobArgs, *river.InsertOpts) { return DBUpdateArgs{}, nil },
			&river.PeriodicJobOpts{ID: "db_update"}),
		river.NewPeriodicJob(river.PeriodicInterval(24*time.Hour),
			func() (river.JobArgs, *river.InsertOpts) { return SBOMGCArgs{}, nil },
			&river.PeriodicJobOpts{ID: "sbom_gc", RunOnStart: true}),
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

// DailyAt parses "HH:MM" into a schedule that fires once a day at that local
// time; TZ sets the zone.
func DailyAt(hhmm string) (cron.Schedule, error) {
	t, err := time.Parse("15:04", hhmm)
	if err != nil {
		return nil, fmt.Errorf("daily time %q: want HH:MM", hhmm)
	}
	return cron.ParseStandard(fmt.Sprintf("%d %d * * *", t.Minute(), t.Hour()))
}

// Start runs the workers. It also queues a DB update that only downloads
// when there is no DB yet or it missed a daily update.
func (q *Queue) Start(ctx context.Context) error {
	if err := q.client.Start(ctx); err != nil {
		return err
	}
	_, err := q.client.Insert(ctx, DBUpdateArgs{MaxAge: dbStartupMaxAge}, nil)
	return err
}

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

// EnqueueRematches queues a re-match of every live target with a stored
// SBOM; a target whose re-match is already pending is not queued twice.
func (q *Queue) EnqueueRematches(ctx context.Context) (int, error) {
	ids, err := q.st.LiveSBOMTargets(ctx)
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if _, err := q.client.Insert(ctx, RematchArgs{TargetID: id}, nil); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

// EnqueueDBUpdate queues a DB update; false if one is already pending.
func (q *Queue) EnqueueDBUpdate(ctx context.Context) (bool, error) {
	res, err := q.client.Insert(ctx, DBUpdateArgs{}, nil)
	if err != nil {
		return false, err
	}
	return !res.UniqueSkippedAsDuplicate, nil
}

// SubmitSBOM stores an uploaded SBOM and queues it for matching. It returns
// the job's ID, which is the pending job's when this upload is a retry.
func (q *Queue) SubmitSBOM(ctx context.Context, m store.IngestMeta, r io.Reader) (int64, error) {
	if q.sboms == nil {
		return 0, errors.New("sbom storage is not configured")
	}
	if q.cfg.MaxQueued > 0 {
		s, err := q.Stats(ctx)
		if err != nil {
			return 0, err
		}
		if s.Queued >= q.cfg.MaxQueued {
			return 0, fmt.Errorf("%w: %d jobs queued", ErrBusy, s.Queued)
		}
	}
	if free, err := q.sboms.Free(); err == nil && free < q.cfg.MinFreeBytes {
		return 0, fmt.Errorf("%w: %d MB free for SBOMs", ErrBusy, free>>20)
	}
	sha, size, err := q.sboms.Put(r)
	if err != nil {
		return 0, err
	}
	res, err := q.client.Insert(ctx, MatchSBOMArgs{SHA256: sha, Size: size, Host: m.Host, Target: m.Target,
		RunID: m.RunID, Meta: m}, nil)
	if err != nil {
		return 0, err
	}
	return res.Job.ID, nil
}

func (q *Queue) event(ctx context.Context, level string, m store.IngestMeta, msg string) {
	if err := q.st.AddEvent(ctx, store.Event{Level: level, Source: "scanner", Host: m.Host, RunID: m.RunID,
		Message: msg}); err != nil {
		q.log.Error("add event", "err", err)
	}
}

// Stats counts jobs by state for the system page.
type Stats struct {
	Queued       int    `json:"queued"` // available, scheduled or waiting to retry
	Running      int    `json:"running"`
	Failed24     int    `json:"failed_24h"` // gave up in the last 24 hours
	Rematching   int    `json:"rematching"` // re-matches queued or running
	LastRematch  string `json:"last_rematch,omitempty"` // within CompletedJobRetentionPeriod
	NextDBUpdate string `json:"next_db_update"`
}

func (q *Queue) Stats(ctx context.Context) (Stats, error) {
	s := Stats{NextDBUpdate: q.daily.Next(time.Now()).UTC().Format(time.RFC3339)}
	err := q.db.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(state IN ('available','scheduled','retryable','pending')),0),
		COALESCE(SUM(state = 'running'),0),
		COALESCE(SUM(state = 'discarded' AND finalized_at > datetime('now','-1 day')),0),
		COALESCE(SUM(kind = 'rematch' AND state IN ('available','scheduled','retryable','pending','running')),0),
		COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', MAX(CASE WHEN kind = 'rematch' AND state = 'completed' THEN finalized_at END)),'')
		FROM river_job`).Scan(&s.Queued, &s.Running, &s.Failed24, &s.Rematching, &s.LastRematch)
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
