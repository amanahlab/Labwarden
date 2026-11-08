// Command labwarden runs the LabWarden dashboard server.
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
	_ "time/tzdata" // TZ works in images without zoneinfo

	"github.com/amanahlab/labwarden/agent"
	"github.com/amanahlab/labwarden/server/internal/api"
	"github.com/amanahlab/labwarden/server/internal/jobs"
	"github.com/amanahlab/labwarden/server/internal/notify"
	"github.com/amanahlab/labwarden/server/internal/sboms"
	"github.com/amanahlab/labwarden/server/internal/scanner"
	"github.com/amanahlab/labwarden/server/internal/store"
	"github.com/amanahlab/labwarden/web"
)

var version = "dev"

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	dataDir := env("LABWARDEN_DATA", "./data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dataDir, "labwarden.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if tok := os.Getenv("LABWARDEN_INGEST_TOKEN"); tok != "" {
		if err := st.ImportToken(ctx, "bootstrap (LABWARDEN_INGEST_TOKEN)", tok); err != nil {
			return err
		}
	}
	key, err := sessionKey(filepath.Join(dataDir, "session.key"))
	if err != nil {
		return err
	}
	adminPw := os.Getenv("LABWARDEN_ADMIN_PASSWORD")
	authOff := env("LABWARDEN_AUTH_DISABLED", "false") == "true"
	if err := api.CheckAuthConfig(adminPw, authOff); err != nil {
		return err
	}
	proxies, err := api.ParseTrustedProxies(os.Getenv("LABWARDEN_TRUSTED_PROXIES"))
	if err != nil {
		return err
	}
	maxMB, _ := strconv.ParseInt(env("LABWARDEN_MAX_REPORT_MB", "256"), 10, 64)

	nt, err := notify.New(notify.Config{
		URL:         os.Getenv("LABWARDEN_NOTIFY_URL"),
		Format:      env("LABWARDEN_NOTIFY_FORMAT", "json"),
		MinSeverity: env("LABWARDEN_NOTIFY_MIN_SEVERITY", "Critical"),
		KEV:         env("LABWARDEN_NOTIFY_KEV", "true") == "true",
		PublicURL:   os.Getenv("LABWARDEN_PUBLIC_URL"),
	}, st, log)
	if err != nil {
		return err
	}
	st.OnIngest(nt.Ingested)

	sb, err := sboms.New(filepath.Join(dataDir, "sboms"))
	if err != nil {
		return err
	}
	sc := scanner.New(env("LABWARDEN_GRYPE_BIN", "grype"), env("LABWARDEN_SYFT_BIN", "syft"), sb, st, log)
	sc.Init(ctx)
	workers, _ := strconv.Atoi(env("LABWARDEN_SCAN_WORKERS", "2"))
	maxQueued, _ := strconv.Atoi(env("LABWARDEN_QUEUE_MAX", "1000"))
	q, err := jobs.Open(ctx, jobs.Config{
		Path:         filepath.Join(dataDir, "queue.db"),
		ScanWorkers:  workers,
		Scheduler:    env("LABWARDEN_SCHEDULER", "true") == "true",
		DBUpdateAt:   env("LABWARDEN_DB_UPDATE_AT", "03:00"),
		SBOMs:        sb,
		MaxQueued:    maxQueued,
		MinFreeBytes: 1 << 30,
	}, st, sc, log)
	if err != nil {
		return err
	}
	if err := q.Start(ctx); err != nil {
		return err
	}
	defer func() {
		// Running scans get the grace period, then are cancelled and re-run after the next start.
		sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := q.Stop(sctx); err != nil {
			log.Error("stop jobs", "err", err)
		}
	}()
	go housekeeping(ctx, st, log, authOff)

	srv := api.New(api.Config{
		Version: version, AdminPassword: adminPw, SessionKey: key,
		CookieSecure: env("LABWARDEN_COOKIE_SECURE", "false") == "true", MaxReportMB: maxMB,
		TrustedProxies: proxies, PublicURL: os.Getenv("LABWARDEN_PUBLIC_URL"),
	}, st, sc, q, nt, log, web.FS(), agent.FS)

	_ = st.AddEvent(ctx, store.Event{Level: "info", Source: "system", Message: "LabWarden " + version + " started"})
	httpSrv := &http.Server{
		Addr:              env("LABWARDEN_ADDR", ":8080"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ReadTimeout:       5 * time.Minute, // large reports over slow links
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	certFile, keyFile := os.Getenv("LABWARDEN_TLS_CERT"), os.Getenv("LABWARDEN_TLS_KEY")
	if (certFile == "") != (keyFile == "") {
		return errors.New("set both LABWARDEN_TLS_CERT and LABWARDEN_TLS_KEY, or neither")
	}
	if certFile != "" {
		certs, err := newCertReloader(certFile, keyFile, log)
		if err != nil {
			return err
		}
		go certs.watch(ctx, time.Minute)
		httpSrv.TLSConfig = tlsConfig(certs)
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", httpSrv.Addr, "version", version, "tls", certFile != "")
		if certFile != "" {
			errc <- httpSrv.ListenAndServeTLS("", "")
			return
		}
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

// sessionKey loads or creates the key that fingerprints the admin password
// for sessions (see api.passwordFingerprint), so sessions survive restarts.
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

// housekeeping keeps one trend point per day, bounds the event log and drops
// ended sessions. With authentication off it says so every hour, so it is
// not forgotten.
func housekeeping(ctx context.Context, st *store.Store, log *slog.Logger, authOff bool) {
	keep, _ := strconv.Atoi(env("LABWARDEN_EVENT_RETENTION", "50000"))
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if authOff {
			log.Warn("LABWARDEN_AUTH_DISABLED=true: the dashboard is open to anyone who can reach it")
		}
		if err := st.RefreshDaily(ctx); err != nil && ctx.Err() == nil {
			log.Error("refresh daily stats", "err", err)
		}
		if err := st.PruneEvents(ctx, keep); err != nil && ctx.Err() == nil {
			log.Error("prune events", "err", err)
		}
		if err := st.PruneSessions(ctx, api.SessionIdleTimeout); err != nil && ctx.Err() == nil {
			log.Error("prune sessions", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
