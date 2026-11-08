package scanner

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amanahlab/labwarden/server/internal/store"
)

// fakeGrype logs each call as "<auto-update> <cache dir> <args>" and keeps the
// DB as a file holding its build date.
const fakeGrype = `#!/bin/sh
echo "$GRYPE_DB_AUTO_UPDATE $GRYPE_DB_CACHE_DIR $*" >>"$FAKE_DIR/calls"
db="$GRYPE_DB_CACHE_DIR/6/vulnerability.db"
case "$1" in
version) echo '{"version":"0.0.0-fake"}' ;;
db) case "$2" in
  status) [ -f "$db" ] || { echo '{"valid":false}'; exit 1; }
    printf '{"schemaVersion":"v6","built":"%s","valid":true}' "$(cat "$db")" ;;
  check) printf '{"updateAvailable":%s}' "$(cat "$FAKE_DIR/available")" ;;
  update) mkdir -p "$GRYPE_DB_CACHE_DIR/6" "$GRYPE_DB_CACHE_DIR/grype-db-download1"
    cat "$FAKE_DIR/next" >"$db"; rmdir "$GRYPE_DB_CACHE_DIR/grype-db-download1" ;;
  esac ;;
sbom:*) cat "$FAKE_DIR/report.json" ;;
esac
`

type fake struct {
	t     *testing.T
	dir   string // FAKE_DIR
	dbDir string
	s     *Scanner
}

func newFake(t *testing.T, liveDB string) *fake {
	t.Helper()
	f := &fake{t: t, dir: t.TempDir(), dbDir: filepath.Join(t.TempDir(), "grype-db")}
	bin := filepath.Join(f.dir, "grype")
	f.write("grype", fakeGrype)
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile("../grype/testdata/alpine312.json")
	if err != nil {
		t.Fatal(err)
	}
	f.write("report.json", string(report))
	f.write("available", "false")
	f.write("next", "2026-02-02T00:00:00Z")
	if liveDB != "" {
		if err := os.MkdirAll(filepath.Join(f.dbDir, "6"), 0o755); err != nil {
			t.Fatal(err)
		}
		f.writeAbs(filepath.Join(f.dbDir, "6", "vulnerability.db"), liveDB)
	}
	t.Setenv("FAKE_DIR", f.dir)
	t.Setenv("GRYPE_DB_CACHE_DIR", f.dbDir)

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f.s = New(bin, "syft-not-installed", nil, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.s.refreshVersion(context.Background())
	f.s.refreshDBStatus(context.Background())
	return f
}

func (f *fake) write(name, data string) { f.writeAbs(filepath.Join(f.dir, name), data) }

func (f *fake) writeAbs(path, data string) {
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fake) calls() []string {
	b, _ := os.ReadFile(filepath.Join(f.dir, "calls"))
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (f *fake) live() string {
	b, err := os.ReadFile(filepath.Join(f.dbDir, "6", "vulnerability.db"))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func TestScansNeverAutoUpdateTheDB(t *testing.T) {
	f := newFake(t, "2026-01-01T00:00:00Z")
	if _, err := f.s.grype(context.Background(), "sbom:/tmp/x.json"); err != nil {
		t.Fatal(err)
	}
	calls := f.calls()
	if want := "false " + f.dbDir + " sbom:/tmp/x.json -o json -q"; calls[len(calls)-1] != want {
		t.Fatalf("scan call = %q, want %q", calls[len(calls)-1], want)
	}
}

func TestScanWithoutDBFailsInsteadOfDownloading(t *testing.T) {
	f := newFake(t, "")
	_, err := f.s.grype(context.Background(), "sbom:/tmp/x.json")
	if err == nil || !strings.Contains(err.Error(), "not been downloaded") {
		t.Fatalf("err = %v", err)
	}
	for _, c := range f.calls() {
		if strings.Contains(c, "sbom:") {
			t.Fatalf("grype ran without a DB: %q", c)
		}
	}
}

func TestUpdateDBStagesSwapsAndCleansUp(t *testing.T) {
	f := newFake(t, "2026-01-01T00:00:00Z")
	for _, d := range []string{"grype-db-download123", "grype-db-download456/x", "6.old", stagingDir + "/6"} {
		if err := os.MkdirAll(filepath.Join(f.dbDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.write("available", "true")

	f.s.UpdateDB(context.Background(), 0)

	if got := f.live(); got != "2026-02-02T00:00:00Z" {
		t.Fatalf("live DB = %q, want the new one", got)
	}
	entries, _ := os.ReadDir(f.dbDir)
	if len(entries) != 1 || entries[0].Name() != "6" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("cache dir holds %v, want only 6", names)
	}
	var updates int
	for _, c := range f.calls() {
		if strings.HasSuffix(c, " db update") {
			updates++
			if want := "false " + filepath.Join(f.dbDir, stagingDir) + " db update"; c != want {
				t.Fatalf("update call = %q, want a download into staging", c)
			}
		}
	}
	if updates != 1 {
		t.Fatalf("%d downloads, want 1", updates)
	}
	if st := f.s.Status(); st.DBBuilt != "2026-02-02T00:00:00Z" || st.DBError != "" {
		t.Fatalf("status = %+v", st)
	}
}

func TestUpdateDBSkipsDownloadWhenCurrent(t *testing.T) {
	f := newFake(t, "2026-01-01T00:00:00Z")
	f.s.UpdateDB(context.Background(), 0)
	for _, c := range f.calls() {
		if strings.HasSuffix(c, " db update") {
			t.Fatalf("downloaded although the DB is current: %q", c)
		}
	}
	if f.live() != "2026-01-01T00:00:00Z" {
		t.Fatal("live DB changed")
	}
}

func TestUpdateDBDownloadsWhenMissing(t *testing.T) {
	f := newFake(t, "")
	f.s.UpdateDB(context.Background(), 0)
	if f.live() != "2026-02-02T00:00:00Z" || f.s.Status().DBBuilt == "" {
		t.Fatal("DB not downloaded on first start")
	}
	if _, err := f.s.grype(context.Background(), "sbom:/tmp/x.json"); err != nil {
		t.Fatalf("scan after first download: %v", err)
	}
}

func TestUpdateDBRunsOneAtATime(t *testing.T) {
	f := newFake(t, "2026-01-01T00:00:00Z")
	f.write("available", "true")
	f.s.updating.Store(true) // another update is running
	f.s.UpdateDB(context.Background(), 0)
	if f.live() != "2026-01-01T00:00:00Z" {
		t.Fatal("a second update ran concurrently")
	}
}

func TestSwapGivesUpRatherThanBlockingScans(t *testing.T) {
	f := newFake(t, "2026-01-01T00:00:00Z")
	staging := filepath.Join(f.dbDir, stagingDir)
	if err := os.MkdirAll(filepath.Join(staging, "6"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.s.dbLock.RLock() // a scan that runs past the update's deadline
	defer f.s.dbLock.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := f.s.swapDB(ctx, staging); err == nil {
		t.Fatal("swap succeeded while a scan held the DB")
	}
	if f.live() != "2026-01-01T00:00:00Z" {
		t.Fatal("live DB changed under a running scan")
	}
}

func TestUpdateDBMaxAgeSkipsARecentDB(t *testing.T) {
	recent := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	f := newFake(t, recent)
	f.write("available", "true")
	if updated, err := f.s.UpdateDB(context.Background(), 36*time.Hour); updated || err != nil {
		t.Fatalf("updated=%v err=%v; a DB built an hour ago is recent enough", updated, err)
	}
	for _, c := range f.calls() {
		if strings.Contains(c, " db check") || strings.Contains(c, " db update") {
			t.Fatalf("checked although the DB is recent: %q", c)
		}
	}
	if updated, err := f.s.UpdateDB(context.Background(), 0); !updated || err != nil {
		t.Fatalf("updated=%v err=%v; without maxAge the newer DB is taken", updated, err)
	}
}
