// Command vulnx runs the VulnX dashboard server.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/coronas2k/vulnx/agent"
	"github.com/coronas2k/vulnx/server/internal/api"
	"github.com/coronas2k/vulnx/server/internal/notify"
	"github.com/coronas2k/vulnx/server/internal/scanner"
	"github.com/coronas2k/vulnx/server/internal/store"
	"github.com/coronas2k/vulnx/web"
)

var version = "dev"

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	dataDir := env("VULNX_DATA", "./data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dataDir, "vulnx.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if tok := os.Getenv("VULNX_INGEST_TOKEN"); tok != "" {
		if _, err := st.ImportToken(ctx, "bootstrap (VULNX_INGEST_TOKEN)", tok); err != nil {
			return err
		}
	}
	key, err := sessionKey(filepath.Join(dataDir, "session.key"))
	if err != nil {
		return err
	}
	adminPw := os.Getenv("VULNX_ADMIN_PASSWORD")
	if adminPw == "" {
		log.Warn("VULNX_ADMIN_PASSWORD is not set: the dashboard is open to anyone who can reach it")
	}
	maxMB, _ := strconv.ParseInt(env("VULNX_MAX_REPORT_MB", "256"), 10, 64)

	nt, err := notify.New(notify.Config{
		URL:         os.Getenv("VULNX_NOTIFY_URL"),
		Format:      env("VULNX_NOTIFY_FORMAT", "json"),
		MinSeverity: env("VULNX_NOTIFY_MIN_SEVERITY", "Critical"),
		KEV:         env("VULNX_NOTIFY_KEV", "true") == "true",
		PublicURL:   os.Getenv("VULNX_PUBLIC_URL"),
	}, st, log)
	if err != nil {
		return err
	}
	st.OnIngest(nt.Ingested)

	sc := scanner.New(env("VULNX_GRYPE_BIN", "grype"), st, log)
	go sc.Run(ctx, env("VULNX_SCHEDULER", "true") == "true", 6*time.Hour)
	go housekeeping(ctx, st, log)

	srv := api.New(api.Config{
		Version: version, AdminPassword: adminPw, SessionKey: key,
		CookieSecure: env("VULNX_COOKIE_SECURE", "false") == "true", MaxReportMB: maxMB,
	}, st, sc, nt, log, web.FS(), agent.FS)

	_ = st.AddEvent(ctx, store.Event{Level: "info", Source: "system", Message: "VulnX " + version + " started"})
	httpSrv := &http.Server{
		Addr:              env("VULNX_ADDR", ":8080"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // large reports over slow links
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", httpSrv.Addr, "version", version)
		errc <- httpSrv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdown)
}

// sessionKey loads or creates the HMAC key that signs admin sessions, so
// sessions survive restarts.
func sessionKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, os.WriteFile(path, b, 0o600)
}

// housekeeping keeps one trend point per day and bounds the event log.
func housekeeping(ctx context.Context, st *store.Store, log *slog.Logger) {
	keep, _ := strconv.Atoi(env("VULNX_EVENT_RETENTION", "50000"))
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if err := st.RefreshDaily(ctx); err != nil && ctx.Err() == nil {
			log.Error("refresh daily stats", "err", err)
		}
		if err := st.PruneEvents(ctx, keep); err != nil && ctx.Err() == nil {
			log.Error("prune events", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
