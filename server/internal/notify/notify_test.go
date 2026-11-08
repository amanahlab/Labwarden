package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amanahlab/labwarden/server/internal/grype"
	"github.com/amanahlab/labwarden/server/internal/store"
)

type hook struct {
	reqs chan *http.Request
	body chan []byte
}

func receiver(t *testing.T, status int) (*httptest.Server, *hook) {
	t.Helper()
	h := &hook{reqs: make(chan *http.Request, 4), body: make(chan []byte, 4)}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.reqs <- r
		h.body <- b
		w.WriteHeader(status)
	}))
	t.Cleanup(ts.Close)
	return ts, h
}

func setup(t *testing.T, cfg Config) (*Notifier, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	n, err := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	st.OnIngest(n.Ingested)
	return n, st
}

func report(t *testing.T) *grype.Report {
	t.Helper()
	f, err := os.Open("../grype/testdata/app-dir.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := grype.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func wait(t *testing.T, h *hook) (*http.Request, []byte) {
	t.Helper()
	select {
	case r := <-h.reqs:
		return r, <-h.body
	case <-time.After(5 * time.Second):
		t.Fatal("no webhook call")
		return nil, nil
	}
}

func TestAlertOnFirstScanThenQuietOnRepeat(t *testing.T) {
	ts, h := receiver(t, http.StatusNoContent)
	_, st := setup(t, Config{URL: ts.URL, MinSeverity: "Critical", KEV: true, PublicURL: "http://labwarden.lan/"})
	ctx := context.Background()
	meta := store.IngestMeta{Host: "vm-1", Kind: "vm"}

	if _, err := st.IngestReport(ctx, meta, report(t)); err != nil {
		t.Fatal(err)
	}
	r, b := wait(t, h)
	if r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("content type %q", r.Header.Get("Content-Type"))
	}
	var p struct {
		Title, Text, Content, Host, Link string
		Findings                         []store.NewFinding
	}
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p.Host != "vm-1" || len(p.Findings) == 0 || p.Text == "" || p.Content != p.Text || !strings.HasPrefix(p.Link, "http://labwarden.lan/hosts/") {
		t.Fatalf("payload: %s", b)
	}
	for _, f := range p.Findings {
		if f.Severity != "Critical" && !f.KEV {
			t.Fatalf("below threshold: %+v", f)
		}
	}

	// Same report again: nothing is new, so no alert.
	if _, err := st.IngestReport(ctx, meta, report(t)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.reqs:
		t.Fatal("alerted on a repeat scan")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestAlertingFiltersAndSuppresses(t *testing.T) {
	n, _ := setup(t, Config{MinSeverity: "High", KEV: true})
	found := []store.NewFinding{
		{VulnID: "CVE-1", Severity: "Medium"},
		{VulnID: "CVE-2", Severity: "High"},
		{VulnID: "CVE-3", Severity: "Low", KEV: true},
		{VulnID: "CVE-4", Severity: "Critical"},
		{VulnID: "CVE-4", Severity: "Critical"}, // same vuln in a second package
		{VulnID: "CVE-5", Severity: "Critical"},
	}
	got := n.Alerting(found, map[string]bool{"CVE-5": true})
	ids := []string{}
	for _, f := range got {
		ids = append(ids, f.VulnID)
	}
	if strings.Join(ids, ",") != "CVE-3,CVE-4,CVE-2" {
		t.Fatalf("got %v", ids)
	}
}

func TestTriageSuppressesAlert(t *testing.T) {
	ts, h := receiver(t, http.StatusOK)
	n, st := setup(t, Config{URL: ts.URL, MinSeverity: "Low"})
	ctx := context.Background()
	res, err := st.IngestReport(ctx, store.IngestMeta{Host: "vm-1"}, report(t))
	if err != nil {
		t.Fatal(err)
	}
	wait(t, h)
	for _, f := range res.NewFindings {
		if err := st.SetTriage(ctx, f.VulnID, 0, "ignored", ""); err != nil {
			t.Fatal(err)
		}
	}
	sup, err := st.SuppressedVulns(ctx, res.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if got := n.Alerting(res.NewFindings, sup); len(got) != 0 {
		t.Fatalf("ignored findings still alert: %v", got)
	}
	// A host-level decision overrides the global ignore.
	first := res.NewFindings[0].VulnID
	if err := st.SetTriage(ctx, first, res.HostID, "acknowledged", ""); err != nil {
		t.Fatal(err)
	}
	if sup, _ = st.SuppressedVulns(ctx, res.HostID); sup[first] {
		t.Fatal("host override ignored")
	}
}

func TestNtfyFormat(t *testing.T) {
	ts, h := receiver(t, http.StatusOK)
	n, _ := setup(t, Config{URL: ts.URL, Format: "ntfy", MinSeverity: "Critical", KEV: true})
	if err := n.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, b := wait(t, h)
	if r.Header.Get("Title") != "LabWarden test notification" || r.Header.Get("Priority") != "3" || !strings.Contains(string(b), "working") {
		t.Fatalf("headers %v body %q", r.Header, b)
	}
}

func TestErrorsHideURL(t *testing.T) {
	ts, _ := receiver(t, http.StatusForbidden)
	secret := ts.URL + "/hooks/s3cr3t-token"
	n, _ := setup(t, Config{URL: secret, MinSeverity: "Critical"})
	err := n.Test(context.Background())
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("err = %v", err)
	}
	// Unreachable host: net/http errors embed the URL unless stripped.
	n2, _ := setup(t, Config{URL: "http://127.0.0.1:1/hooks/s3cr3t-token", MinSeverity: "Critical"})
	if err := n2.Test(context.Background()); err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []Config{
		{Format: "xml", MinSeverity: "High"},
		{MinSeverity: "Negligible"},
		{URL: "ftp://x", MinSeverity: "High"},
	} {
		if _, err := New(cfg, nil, nil); err == nil {
			t.Errorf("accepted %+v", cfg)
		}
	}
	n, err := New(Config{}, nil, nil)
	if err != nil || n.Enabled() || n.cfg.MinSeverity != "Critical" || n.cfg.Format != "json" {
		t.Fatalf("defaults: %v %+v", err, n)
	}
}
