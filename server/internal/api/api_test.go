package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/amanahlab/labwarden/server/internal/grype"
	"github.com/amanahlab/labwarden/server/internal/jobs"
	"github.com/amanahlab/labwarden/server/internal/notify"
	"github.com/amanahlab/labwarden/server/internal/sboms"
	"github.com/amanahlab/labwarden/server/internal/scanner"
	"github.com/amanahlab/labwarden/server/internal/store"
)

const (
	testPassword  = "correct horse battery staple"
	testToken     = "vxe_test_token_0123456789abcdef" // enrollment token
	testMaxQueued = 3
)

func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	return newTestServerWith(t, nil)
}

// newTestServerWith lets a test adjust the server config before it starts.
func newTestServerWith(t *testing.T, configure func(*Config)) (*httptest.Server, *store.Store) {
	t.Helper()
	srv, st := newTestAPI(t, configure)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func newTestAPI(t *testing.T, configure func(*Config)) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "labwarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.ImportToken(context.Background(), "test", testToken); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	agentFS := fstest.MapFS{"install.sh": {Data: []byte("#!/bin/sh\n")}, "labwarden-agent.sh": {Data: []byte("#!/bin/sh\n")}}
	webFS := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>LabWarden</title>")}}
	nt, err := notify.New(notify.Config{MinSeverity: "Critical"}, st, log)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := sboms.New(filepath.Join(t.TempDir(), "sboms"))
	if err != nil {
		t.Fatal(err)
	}
	sc := scanner.New("grype-not-installed", "syft-not-installed", sb, st, log)
	// The queue is never started, so uploads stay queued: MaxQueued is reachable.
	q, err := jobs.Open(context.Background(), jobs.Config{Path: filepath.Join(t.TempDir(), "queue.db"),
		DBUpdateAt: "03:00", SBOMs: sb, MaxQueued: testMaxQueued}, st, sc, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Stop(context.Background()) })
	cfg := Config{Version: "test", AdminPassword: testPassword, SessionKey: bytes.Repeat([]byte("k"), 32)}
	if configure != nil {
		configure(&cfg)
	}
	return New(cfg, st, sc, q, nt, log, webFS, agentFS), st
}

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../grype/testdata/app-dir.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// enroll enrolls host with the test enrollment token and returns its credential.
func enroll(t *testing.T, st *store.Store, host string) string {
	t.Helper()
	cred, err := st.Enroll(context.Background(), testToken, host, "")
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// ingestFixture stores the test Grype report as target of host, as a match of an SBOM would.
func ingestFixture(t *testing.T, st *store.Store, host, target string) {
	t.Helper()
	rep, err := grype.Parse(bytes.NewReader(fixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.IngestReport(context.Background(), store.IngestMeta{Host: host, Kind: "vm", Target: target, RunID: "r1", Source: "agent"}, rep); err != nil {
		t.Fatal(err)
	}
}

func login(t *testing.T, ts *httptest.Server, password string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	b, _ := json.Marshal(map[string]string{"password": password})
	resp, err := c.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if password == testPassword && resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status %d", resp.StatusCode)
	}
	return c
}

func getJSON(t *testing.T, c *http.Client, url string, out any) int {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}

func TestIngestRequiresAgentCredential(t *testing.T) {
	ts, st := newTestServer(t)
	sbom := []byte(`{"artifacts":[],"source":{"type":"directory"}}`)
	for name, tok := range map[string]string{"missing": "", "wrong": "vxa_wrong_0000000000000000", "enrollment token": testToken} {
		if code, _ := postSBOM(t, ts, tok, "h1", "/", "r1", sbom, false); code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, code)
		}
	}
	cred := enroll(t, st, "h1")
	if code, _ := postSBOM(t, ts, cred, "h1", "/", "r1", sbom, false); code != http.StatusAccepted {
		t.Errorf("plain upload with the host's credential: status %d, want 202", code)
	}
	if code, _ := postSBOM(t, ts, cred, "", "/gz", "r1", sbom, true); code != http.StatusAccepted {
		t.Errorf("gzip upload without a host name: status %d, want 202", code)
	}
}

func TestFindingsByHostAndLocation(t *testing.T) {
	ts, st := newTestServer(t)
	ingestFixture(t, st, "plain-host", "/")
	ingestFixture(t, st, "gzip-host", "/")
	c := login(t, ts, testPassword)
	var byHost struct {
		Total int `json:"total"`
	}
	if code := getJSON(t, c, ts.URL+"/api/v1/findings/by-host", &byHost); code != http.StatusOK || byHost.Total != 2 {
		t.Fatalf("findings by host: status %d total %d, want 200 and 2", code, byHost.Total)
	}
	var byLoc struct {
		Total int `json:"total"`
		Items []struct {
			Location string `json:"location"`
			Total    int    `json:"total"`
			TargetID int64  `json:"target_id"`
		} `json:"items"`
	}
	if code := getJSON(t, c, ts.URL+"/api/v1/findings/by-location?sort=location&order=desc", &byLoc); code != http.StatusOK || byLoc.Total == 0 {
		t.Fatalf("findings by location: status %d total %d", code, byLoc.Total)
	}
	top := byLoc.Items[0]
	var drill struct {
		Total int `json:"total"`
	}
	q := url.Values{"location": {top.Location}, "target_id": {strconv.FormatInt(top.TargetID, 10)}}
	getJSON(t, c, ts.URL+"/api/v1/findings?"+q.Encode(), &drill)
	if top.Location == "" || drill.Total != top.Total {
		t.Fatalf("drill into %q: total %d, want %d", top.Location, drill.Total, top.Total)
	}
}

func TestUIRequiresSession(t *testing.T) {
	ts, _ := newTestServer(t)
	if code := getJSON(t, http.DefaultClient, ts.URL+"/api/v1/summary", nil); code != http.StatusUnauthorized {
		t.Fatalf("anonymous summary: status %d, want 401", code)
	}
	bad := login(t, ts, "wrong password")
	if code := getJSON(t, bad, ts.URL+"/api/v1/summary", nil); code != http.StatusUnauthorized {
		t.Fatalf("bad login summary: status %d, want 401", code)
	}
	// An agent token is not a UI credential.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/summary", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token on UI endpoint: status %d, want 401", resp.StatusCode)
	}
	good := login(t, ts, testPassword)
	if code := getJSON(t, good, ts.URL+"/api/v1/summary", nil); code != http.StatusOK {
		t.Fatalf("summary after login: status %d", code)
	}
}

func TestPublicEndpoints(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, p := range []string{"/healthz", "/install.sh", "/agent/labwarden-agent.sh", "/", "/hosts/42"} {
		if code := getJSON(t, http.DefaultClient, ts.URL+p, nil); code != http.StatusOK {
			t.Errorf("GET %s: status %d", p, code)
		}
	}
}

// Before login the server does not say which version it runs.
func TestVersionOnlyAfterLogin(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, p := range []string{"/healthz", "/api/v1/auth/me"} {
		var out map[string]any
		getJSON(t, http.DefaultClient, ts.URL+p, &out)
		if _, ok := out["version"]; ok {
			t.Errorf("GET %s without a session reveals the version", p)
		}
	}
	var me map[string]any
	getJSON(t, login(t, ts, testPassword), ts.URL+"/api/v1/auth/me", &me)
	if me["version"] != "test" {
		t.Errorf("/auth/me after login: version %v, want test", me["version"])
	}
}

func TestExportNeutralizesFormulas(t *testing.T) {
	ts, st := newTestServer(t)
	ingestFixture(t, st, "h1", "=HYPERLINK(1)")
	c := login(t, ts, testPassword)
	resp, err := c.Get(ts.URL + "/api/v1/vulnerabilities/export.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rows, err := csv.NewReader(resp.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("export has %d rows", len(rows))
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if strings.HasPrefix(cell, "=") {
				t.Fatalf("formula cell not neutralized: %q", cell)
			}
		}
		if row[2] != "'=HYPERLINK(1)" {
			t.Fatalf("target cell = %q", row[2])
		}
	}
}

func TestCSVRow(t *testing.T) {
	got := csvRow("=1+1", "+x", "-y", "@z", "plain", "")
	want := []string{"'=1+1", "'+x", "'-y", "'@z", "plain", ""}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cell %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMissingAssetIs404(t *testing.T) {
	ts, _ := newTestServer(t)
	res, err := http.Get(ts.URL + "/assets/Overview-old.js")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound || strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("missing asset: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	// Client routes still get the SPA.
	res, err = http.Get(ts.URL + "/hosts/1")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("client route: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
}

func postSBOM(t *testing.T, ts *httptest.Server, cred, host, target, run string, body []byte, gzipped bool) (int, map[string]any) {
	t.Helper()
	if gzipped {
		body = gz(t, body)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ingest/sbom?host="+host+"&kind=vm&run_id="+run+
		"&target="+url.QueryEscape(target), bytes.NewReader(body))
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	if gzipped {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestIngestSBOMQueuesWithBackpressure(t *testing.T) {
	ts, st := newTestServer(t)
	cred := enroll(t, st, "h1")
	uploadSBOM := func(t *testing.T, ts *httptest.Server, target, run string, body []byte) (int, map[string]any) {
		return postSBOM(t, ts, cred, "h1", target, run, body, true)
	}
	sbom := []byte(`{"artifacts":[],"source":{"type":"directory"}}`)
	start := time.Now()
	code, out := uploadSBOM(t, ts, "/a", "r1", sbom)
	if code != http.StatusAccepted || out["queued"] != true || out["job_id"] == nil {
		t.Fatalf("status %d, body %v", code, out)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("upload took %s; it should only queue", d)
	}
	// A retry of the same run and target is the same job, not a second one.
	if _, again := uploadSBOM(t, ts, "/a", "r1", sbom); again["job_id"] != out["job_id"] {
		t.Fatalf("retry got job %v, want %v", again["job_id"], out["job_id"])
	}
	for i := 1; i < testMaxQueued; i++ {
		if code, _ := uploadSBOM(t, ts, fmt.Sprintf("/t%d", i), "r1", sbom); code != http.StatusAccepted {
			t.Fatalf("upload %d: status %d", i, code)
		}
	}
	if code, _ := uploadSBOM(t, ts, "/over", "r1", sbom); code != http.StatusServiceUnavailable {
		t.Fatalf("over the backlog limit: status %d, want 503", code)
	}
	if code, _ := uploadSBOM(t, ts, "/empty", "r1", nil); code != http.StatusBadRequest && code != http.StatusServiceUnavailable {
		t.Fatalf("empty sbom: status %d", code)
	}
}

func TestCapReaderFailsInsteadOfTruncating(t *testing.T) {
	r := &capReader{r: strings.NewReader("0123456789"), n: 5}
	_, err := io.ReadAll(r)
	var mbe *http.MaxBytesError
	if !errors.As(err, &mbe) {
		t.Fatalf("err = %v, want MaxBytesError", err)
	}
	got, err := io.ReadAll(&capReader{r: strings.NewReader("01234"), n: 5})
	if err != nil || string(got) != "01234" {
		t.Fatalf("at the limit: %q, %v", got, err)
	}
}

func TestUpdateDBNowIsQueuedOnce(t *testing.T) {
	ts, _ := newTestServer(t)
	post := func(c *http.Client, path string) int {
		resp, err := c.Post(ts.URL+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(http.DefaultClient, "/api/v1/db/update"); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: status %d, want 401", code)
	}
	c := login(t, ts, testPassword)
	for i, want := range []int{http.StatusAccepted, http.StatusConflict} {
		if code := post(c, "/api/v1/db/update"); code != want {
			t.Fatalf("request %d: status %d, want %d", i, code, want)
		}
	}
	for i, want := range []int{http.StatusAccepted, http.StatusConflict} {
		if code := post(c, "/api/v1/rematch"); code != want {
			t.Fatalf("rematch %d: status %d, want %d", i, code, want)
		}
	}
	var sys struct {
		Queue struct {
			NextDBUpdate string `json:"next_db_update"`
		} `json:"queue"`
	}
	if code := getJSON(t, c, ts.URL+"/api/v1/system", &sys); code != http.StatusOK || sys.Queue.NextDBUpdate == "" {
		t.Fatalf("system: status %d, next_db_update %q", code, sys.Queue.NextDBUpdate)
	}
}
