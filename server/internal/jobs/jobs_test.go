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

// fakeSyft catalogs every source as an empty image SBOM.
const fakeSyft = `#!/bin/sh
echo '{"artifacts":[],"source":{"type":"image"}}'
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
	if err := os.WriteFile(filepath.Join(dir, "syft"), []byte(fakeSyft), 0o755); err != nil {
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
	sb, err := sboms.New(filepath.Join(dir, "sboms"))
	if err != nil {
		t.Fatal(err)
	}
	sc := scanner.New(bin, filepath.Join(dir, "syft"), sb, st, log)
	sc.Init(context.Background())
	if _, err := sc.UpdateDB(context.Background(), 0); err != nil { // finds the fake DB
		t.Fatal(err)
	}
	q, err := Open(context.Background(), Config{Path: filepath.Join(dir, "queue.db"), ScanWorkers: 2,
		Scheduler: true, DBUpdateAt: "03:00", SBOMs: sb}, st, sc, log)
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
	// Its SBOM is kept, so a new DB re-matches it like an agent's.
	if ids, err := st.LiveSBOMTargets(ctx); err != nil || len(ids) != 1 {
		t.Fatalf("central target sboms = %v, %v; want one", ids, err)
	}
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

func TestRematchUsesTheStoredSBOMAndLeavesTheHostAlone(t *testing.T) {
	q, st := setup(t, true)
	ctx := context.Background()
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	m := store.IngestMeta{Host: "vm1", Kind: "vm", Target: "/", RunID: "r1", Source: "agent"}
	if _, err := q.SubmitSBOM(ctx, m, strings.NewReader(`{"artifacts":[]}`)); err != nil {
		t.Fatal(err)
	}
	scans := func() int {
		l, err := st.ListScans(ctx, store.ScanFilter{}, store.Page{})
		if err != nil {
			return -1
		}
		return l.Total
	}
	waitFor(t, "first match", func() bool { ids, _ := st.LiveSBOMTargets(ctx); return len(ids) == 1 })
	host := func() store.HostRow {
		l, err := st.ListHosts(ctx, store.HostFilter{}, store.Page{})
		if err != nil || len(l.Items) != 1 {
			t.Fatalf("hosts: %v %v", l, err)
		}
		return l.Items[0]
	}
	before := host()
	time.Sleep(1100 * time.Millisecond) // last_seen has second precision

	n, err := q.enqueueRematches(ctx)
	if err != nil || n != 1 {
		t.Fatalf("queued %d re-matches, err %v; want 1", n, err)
	}
	waitFor(t, "re-match scan", func() bool { return scans() == 2 })
	if after := host(); after.LastSeen != before.LastSeen {
		t.Fatalf("re-match moved last_seen from %s to %s", before.LastSeen, after.LastSeen)
	}
}

func TestDailyAt(t *testing.T) {
	sched, err := DailyAt("03:30")
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 11, 8, 4, 0, 0, 0, time.Local)
	if got, want := sched.Next(from), time.Date(2026, 11, 9, 3, 30, 0, 0, time.Local); !got.Equal(want) {
		t.Fatalf("next = %s, want %s", got, want)
	}
	for _, bad := range []string{"", "3", "25:00", "03:60", "* * * * *"} {
		if _, err := DailyAt(bad); err == nil {
			t.Errorf("DailyAt(%q) accepted", bad)
		}
	}
}
