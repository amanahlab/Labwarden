package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/amanahlab/labwarden/server/internal/registry"
	"github.com/amanahlab/labwarden/server/internal/store"
)

// ImageChecker asks registries about running images (*registry.Checker).
type ImageChecker interface {
	Check(ctx context.Context, repository string, tags []string) map[string]registry.Result
	Registries() []string
	Credentials() []string
}

// ErrImageChecksOff: LABWARDEN_IMAGE_CHECK=false.
var ErrImageChecksOff = errors.New("image update checks are turned off")

// The periodic sweep runs this often and queues the repositories whose last
// check is older than the interval, so a restart never re-checks everything.
// The slack keeps a repository checked just after one sweep from waiting a
// whole extra sweep.
const (
	imageSweep      = time.Hour
	imageSweepSlack = 10 * time.Minute
)

// ImageCheckArgs checks the running tags of one repository upstream.
type ImageCheckArgs struct {
	Repository string `json:"repository" river:"unique"`
}

func (ImageCheckArgs) Kind() string { return "image_check" }

func (ImageCheckArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueRegistry, MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

type imageCheckWorker struct {
	river.WorkerDefaults[ImageCheckArgs]
	q *Queue
}

// A repository makes one tag list call and one HEAD per running tag, each
// limited to 20 s.
func (w *imageCheckWorker) Timeout(*river.Job[ImageCheckArgs]) time.Duration { return 10 * time.Minute }

func (w *imageCheckWorker) Work(ctx context.Context, job *river.Job[ImageCheckArgs]) error {
	c := w.q.cfg.ImageChecker
	if c == nil {
		return nil
	}
	repo := job.Args.Repository
	tags, err := w.q.st.ImageTags(ctx, repo)
	if err != nil || len(tags) == 0 {
		return err // nothing runs it any more
	}
	// Registry trouble is recorded per tag, not retried: the next sweep
	// tries again, which is what a rate limit wants.
	results := c.Check(ctx, repo, tags)
	// A job that ran out of time still saves the tags it got an answer for;
	// the others stay due and wait for the next sweep instead of a retry
	// that would ask the same slow registry again.
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	for tag, r := range results {
		if err := w.q.st.SaveImageCheck(save, repo, tag, r); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		w.q.log.Warn("image check ran out of time", "repository", repo, "checked", len(results), "tags", len(tags))
	}
	return nil
}

// ImageCheckAllArgs queues a check of every running repository that is due;
// Force queues them all ("Check now").
type ImageCheckAllArgs struct {
	Force bool `json:"force" river:"unique"`
}

func (ImageCheckAllArgs) Kind() string { return "image_check_all" }

func (ImageCheckAllArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMaint, MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

type imageCheckAllWorker struct {
	river.WorkerDefaults[ImageCheckAllArgs]
	q *Queue
}

func (w *imageCheckAllWorker) Timeout(*river.Job[ImageCheckAllArgs]) time.Duration {
	return time.Minute
}

func (w *imageCheckAllWorker) Work(ctx context.Context, job *river.Job[ImageCheckAllArgs]) error {
	if w.q.cfg.ImageChecker == nil {
		return nil
	}
	if n, err := w.q.st.PruneImageChecks(ctx); err != nil {
		return err
	} else if n > 0 {
		w.q.log.Info("forgot upstream checks of images no longer running", "count", n)
	}
	before := ""
	if !job.Args.Force {
		before = time.Now().Add(-w.q.imageEvery() + imageSweepSlack).UTC().Format(time.RFC3339)
	}
	repos, err := w.q.st.DueImageRepositories(ctx, before)
	if err != nil {
		return err
	}
	for _, repo := range repos {
		if _, err := w.q.client.Insert(ctx, ImageCheckArgs{Repository: repo}, nil); err != nil {
			return err
		}
	}
	if job.Args.Force {
		w.q.event(ctx, "info", store.IngestMeta{}, fmt.Sprintf("checking %d image repositories for updates", len(repos)))
	}
	return nil
}

func (q *Queue) imageEvery() time.Duration {
	if q.cfg.ImageCheckEvery <= 0 {
		return 24 * time.Hour
	}
	return q.cfg.ImageCheckEvery
}

// ImageChecks reports the checker (nil when checks are off) and how often
// each repository is checked.
func (q *Queue) ImageChecks() (ImageChecker, time.Duration) {
	return q.cfg.ImageChecker, q.imageEvery()
}

// EnqueueImageCheckAll queues a check of every running repository now;
// false if one is already pending.
func (q *Queue) EnqueueImageCheckAll(ctx context.Context) (bool, error) {
	if q.cfg.ImageChecker == nil {
		return false, ErrImageChecksOff
	}
	res, err := q.client.Insert(ctx, ImageCheckAllArgs{Force: true}, nil)
	if err != nil {
		return false, err
	}
	return !res.UniqueSkippedAsDuplicate, nil
}

// EnqueueImageChecks queues the repositories running on host that were
// never checked, so a new image gets its status within minutes. Every check
// leaves a row, whatever its outcome, so this does not repeat.
func (q *Queue) EnqueueImageChecks(ctx context.Context, host string) (int, error) {
	if q.cfg.ImageChecker == nil {
		return 0, nil
	}
	repos, err := q.st.UncheckedImageRepositories(ctx, host)
	if err != nil {
		return 0, err
	}
	for _, repo := range repos {
		if _, err := q.client.Insert(ctx, ImageCheckArgs{Repository: repo}, nil); err != nil {
			return 0, err
		}
	}
	return len(repos), nil
}
