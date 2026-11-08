package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// certReloader serves the certificate in certFile/keyFile and picks up a
// renewed pair on SIGHUP or when either file changes, without a restart.
// A pair that fails to load is logged and the current one stays in use.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger

	mu    sync.RWMutex
	cert  *tls.Certificate
	stamp string
}

func newCertReloader(certFile, keyFile string, log *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// stampOf identifies the current contents of the pair by size and mtime.
func (r *certReloader) stampOf() string {
	s := ""
	for _, f := range []string{r.certFile, r.keyFile} {
		if fi, err := os.Stat(f); err == nil {
			s += fmt.Sprintf("%d:%d;", fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return s
}

// reload loads the pair. A pair that fails is remembered too, so the watcher
// tries it again only once the files change (or on SIGHUP), not every tick.
func (r *certReloader) reload() error {
	stamp := r.stampOf()
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stamp = stamp
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	r.cert = &c
	return nil
}

func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// watch reloads on SIGHUP and when the files change (checked every interval).
func (r *certReloader) watch(ctx context.Context, interval time.Duration) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		case <-t.C:
			r.mu.RLock()
			same := r.stamp == r.stampOf()
			r.mu.RUnlock()
			if same {
				continue
			}
		}
		if err := r.reload(); err != nil {
			r.log.Error("TLS certificate reload failed, keeping the current one", "err", err)
			continue
		}
		r.log.Info("TLS certificate reloaded", "cert", r.certFile)
	}
}

// tlsConfig is the server TLS configuration: TLS 1.2 or newer with Go's
// default cipher suites, the certificate coming from r.
func tlsConfig(r *certReloader) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.getCertificate}
}

// healthcheck probes /healthz on the local listener, over TLS when it is on,
// for the image's HEALTHCHECK. It returns the process exit code.
func healthcheck() int {
	_, port, err := net.SplitHostPort(env("LABWARDEN_ADDR", ":8080"))
	if err != nil {
		return 1
	}
	scheme, client := "http", &http.Client{Timeout: 4 * time.Second}
	if os.Getenv("LABWARDEN_TLS_CERT") != "" {
		// Loopback to this very process: the name on the certificate is not
		// 127.0.0.1, and there is nothing in between to verify against.
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	resp, err := client.Get(scheme + "://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
