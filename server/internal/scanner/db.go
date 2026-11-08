package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The vulnerability DB is about 3.4 GB. Only updateDB downloads it: scans run
// grype with auto-update off, so they never start a download of their own.
// A new DB is downloaded into a staging dir next to the live one and swapped
// in with renames, so scans keep working during the download.

const stagingDir = ".staging"

// grypeDBDir is grype's cache dir: GRYPE_DB_CACHE_DIR, or grype's default.
func grypeDBDir() string {
	if d := os.Getenv("GRYPE_DB_CACHE_DIR"); d != "" {
		return d
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "grype", "db")
	}
	return filepath.Join(d, "grype", "db")
}

// grypeEnv is the environment for every grype process; dbDir overrides the cache dir.
func grypeEnv(dbDir string) []string {
	return append(os.Environ(),
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
		"GRYPE_DB_AUTO_UPDATE=false",
		"GRYPE_DB_CACHE_DIR="+dbDir)
}

type dbStatus struct {
	SchemaVersion string `json:"schemaVersion"`
	Built         string `json:"built"`
	Valid         bool   `json:"valid"`
}

func (s *Scanner) dbStatus(ctx context.Context, dbDir string) (dbStatus, error) {
	cmd := exec.CommandContext(ctx, s.bin, "db", "status", "-o", "json")
	cmd.Env = grypeEnv(dbDir)
	out, err := cmd.Output()
	var ds dbStatus
	if jerr := json.Unmarshal(out, &ds); jerr != nil && err == nil {
		err = jerr
	}
	return ds, err
}

// refreshDBStatus records the live DB's build date; empty when there is none yet.
func (s *Scanner) refreshDBStatus(ctx context.Context) {
	s.dbLock.RLock()
	ds, err := s.dbStatus(ctx, s.dbDir)
	s.dbLock.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || !ds.Valid {
		s.status.DBBuilt, s.status.DBSchema = "", ""
		return
	}
	s.status.DBBuilt, s.status.DBSchema = ds.Built, ds.SchemaVersion
}

// UpdateDB downloads a new DB if one is available and swaps it in, and
// reports whether it did. With maxAge > 0 it does nothing while the live DB
// was built less than maxAge ago. Only one runs at a time; a second call while
// one is running returns at once.
func (s *Scanner) UpdateDB(ctx context.Context, maxAge time.Duration) (bool, error) {
	if !s.Status().Available || !s.updating.CompareAndSwap(false, true) {
		return false, nil
	}
	defer s.updating.Store(false)
	s.refreshDBStatus(ctx) // decides between checking for an update and a first download
	if maxAge > 0 {
		if t, err := time.Parse(time.RFC3339, s.Status().DBBuilt); err == nil && time.Since(t) < maxAge {
			return false, nil
		}
	}
	built, err := s.downloadDB(ctx)
	s.mu.Lock()
	s.status.DBChecked = time.Now().UTC().Format(time.RFC3339)
	s.status.DBError = ""
	if err != nil {
		s.status.DBError = trim(err.Error(), 500)
	}
	s.mu.Unlock()
	if err != nil {
		s.event(ctx, "error", "", "grype DB update failed: "+trim(err.Error(), 1000))
		return false, err
	}
	s.refreshDBStatus(ctx)
	if built != "" {
		s.event(ctx, "info", "", "grype vulnerability DB updated (built "+built+")")
	}
	return built != "", nil
}

// downloadDB returns the new DB's build date, or "" when the live DB is current.
func (s *Scanner) downloadDB(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	staging := filepath.Join(s.dbDir, stagingDir)
	// Leftovers of downloads that were killed: grype never cleans these up.
	if err := removeStale(s.dbDir); err != nil {
		return "", err
	}
	if err := os.RemoveAll(staging); err != nil {
		return "", err
	}

	if !s.HasDB() {
		s.log.Info("no grype vulnerability DB yet; downloading", "dir", s.dbDir)
	} else {
		var chk struct {
			UpdateAvailable bool `json:"updateAvailable"`
		}
		cmd := exec.CommandContext(ctx, s.bin, "db", "check", "-o", "json")
		cmd.Env = grypeEnv(s.dbDir)
		out, err := cmd.Output()
		if jerr := json.Unmarshal(out, &chk); jerr != nil {
			return "", fmt.Errorf("grype db check: %v %v: %s", err, jerr, trim(string(out), 300))
		}
		if !chk.UpdateAvailable {
			return "", nil
		}
	}

	cmd := exec.CommandContext(ctx, s.bin, "db", "update")
	cmd.Env = grypeEnv(staging)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(staging)
		return "", fmt.Errorf("grype db update: %v: %s", err, trim(string(out), 1000))
	}
	ds, err := s.dbStatus(ctx, staging)
	if err != nil || !ds.Valid {
		_ = os.RemoveAll(staging)
		return "", fmt.Errorf("downloaded DB is not valid: %v", err)
	}
	if err := s.swapDB(ctx, staging); err != nil {
		return "", err
	}
	return ds.Built, nil
}

// swapDB moves each schema dir (e.g. "6") from staging into the live dir.
func (s *Scanner) swapDB(ctx context.Context, staging string) error {
	entries, err := os.ReadDir(staging)
	if err != nil {
		return err
	}
	// TryLock rather than Lock: a waiting Lock would hold up new scans until
	// every running one finished. The renames themselves take microseconds.
	for !s.dbLock.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	var old []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "grype-db-download") {
			continue
		}
		live := filepath.Join(s.dbDir, e.Name())
		prev := live + ".old"
		if err := os.Rename(live, prev); err == nil {
			old = append(old, prev)
		} else if !errors.Is(err, os.ErrNotExist) {
			s.dbLock.Unlock()
			return err
		}
		if err := os.Rename(filepath.Join(staging, e.Name()), live); err != nil {
			_ = os.Rename(prev, live)
			s.dbLock.Unlock()
			return err
		}
	}
	s.dbLock.Unlock()
	for _, p := range append(old, staging) {
		if err := os.RemoveAll(p); err != nil {
			s.log.Warn("remove old grype DB", "path", p, "err", err)
		}
	}
	return nil
}

// HasDB reports whether a vulnerability DB is ready for scans.
func (s *Scanner) HasDB() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status.DBBuilt != ""
}

// removeStale deletes download dirs left by killed grype runs and DBs a
// crashed swap left behind.
func removeStale(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(dir, 0o755)
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "grype-db-download") || strings.HasSuffix(e.Name(), ".old") {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
