package jobs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amanahlab/labwarden/server/internal/sboms"
	"github.com/amanahlab/labwarden/server/internal/scanner"
	"github.com/amanahlab/labwarden/server/internal/store"
)

// fakeGrype has a current DB and answers every scan with the fixture report.
const fakeGrype = `#!/bin/sh
case "$1" in
version) echo '{"version":"0.0.0-fake"}' ;;
db) case "$2" in
  status) echo '{"schemaVersion":"v6","built":"2026-01-01T00:00:00Z","valid":true}' ;;
  check) echo '{"updateAvailable":false}' ;;
  esac ;;
*) cat "$FAKE_REPORT" ;;
esac
`

func setup(t *testing.T, withDB bool) (*Queue, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "grype")
	if !withDB {
		bin = filepath.Join(dir, "missing-grype")
	}
	if err := os.WriteFile(filepath.Join(dir, "grype"), []byte(fakeGrype), 0o755); err != nil {
		t.Fatal(err)
	}
	report, _ := filepath.Abs("../grype/testdata/alpine312.json")
	t.Setenv("FAKE_REPORT", report)
	t.Setenv("GRYPE_DB_CACHE_DIR", filepath.Join(dir, "db"))

	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sc := scanner.New(bin, st, log)
	sc.Init(context.Background())
	if err := sc.UpdateDB(context.Background()); err != nil { // finds the fake DB
		t.Fatal(err)
	}
	sb, err := sboms.New(filepath.Join(dir, "sboms"))
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(context.Background(), Config{Path: filepath.Join(dir, "queue.db"), ScanWorkers: 2,
		Scheduler: true, DBUpdateEvery: time.Hour, SBOMs: sb}, st, sc, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		q.Stop(ctx)
	})
	return q, st
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestCentralScanIsQueuedOnce(t *testing.T) {
	q, _ := setup(t, false)
	ctx := context.Background()
	for i, want := range []bool{true, false} {
		got, err := q.EnqueueCentral(ctx, 42)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("insert %d: queued=%v, want %v", i, got, want)
		}
	}
	s, err := q.Stats(ctx)
	if err != nil || s.Queued != 1 {
		t.Fatalf("stats = %+v, %v", s, err)
	}
}

func TestSchedulerScansDueCentralTargets(t *testing.T) {
	q, st := setup(t, true)
	ctx := context.Background()
	c, err := st.CreateCentralTarget(ctx, store.CentralTarget{Ref: "alpine:3.12", HostName: "reg", IntervalMin: 60})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "central scan through the queue", func() bool {
		got, err := st.GetCentralTarget(ctx, c.ID)
		return err == nil && got.LastStatus == "ok"
	})
	// Finished, so the next run of the same target is not a duplicate.
	waitFor(t, "job completion", func() bool { s, _ := q.Stats(ctx); return s.Queued == 0 && s.Running == 0 })
	if ok, err := q.EnqueueCentral(ctx, c.ID); err != nil || !ok {
		t.Fatalf("re-queue after completion: queued=%v err=%v", ok, err)
	}
}

func TestScansWaitForTheFirstDB(t *testing.T) {
	q, st := setup(t, false) // grype missing: no DB, so the scan snoozes instead of failing
	ctx := context.Background()
	c, err := st.CreateCentralTarget(ctx, store.CentralTarget{Ref: "alpine:3.12", HostName: "reg", IntervalMin: 60})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	waitFor(t, "snoozed scan", func() bool {
		err := q.db.QueryRowContext(ctx, `SELECT state FROM river_job WHERE kind='central_scan'`).Scan(&state)
		return err == nil && state == "scheduled"
	})
	if got, _ := st.GetCentralTarget(ctx, c.ID); got.LastStatus != "" {
		t.Fatalf("scan ran without a DB: %q", got.LastStatus)
	}
}

func TestSubmittedSBOMIsMatchedAndKept(t *testing.T) {
	q, st := setup(t, true)
	ctx := context.Background()
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	m := store.IngestMeta{Host: "vm1", Kind: "vm", Target: "/", RunID: "r1", Source: "agent"}
	if _, err := q.SubmitSBOM(ctx, m, strings.NewReader(`{"artifacts":[]}`)); err != nil {
		t.Fatal(err)
	}
	var targetID int64
	waitFor(t, "matched SBOM stored for its target", func() bool {
		ids, err := st.LiveSBOMTargets(ctx)
		if err != nil || len(ids) != 1 {
			return false
		}
		targetID = ids[0]
		return true
	})
	sha, got, err := st.TargetSBOM(ctx, targetID)
	if err != nil || len(sha) != 64 || got.Host != "vm1" || got.Target != "/" {
		t.Fatalf("target sbom = %q %+v %v", sha, got, err)
	}
}

func TestSubmitSBOMRefusesWhenTheDiskIsFull(t *testing.T) {
	q, _ := setup(t, true)
	q.cfg.MinFreeBytes = 1 << 62
	_, err := q.SubmitSBOM(context.Background(), store.IngestMeta{Host: "vm1"}, strings.NewReader("{}"))
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
}
