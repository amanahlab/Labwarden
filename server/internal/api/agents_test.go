package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/amanahlab/labwarden/agent"
	"github.com/amanahlab/labwarden/server/internal/store"
)

func postAgent(t *testing.T, ts *httptest.Server, tok, path, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
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

func TestEnrollOverHTTP(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := postAgent(t, ts, testToken, "/api/v1/ingest/enroll", `{"host":"vm-1"}`)
	cred, _ := out["credential"].(string)
	if code != http.StatusCreated || len(cred) < 40 || out["host"] != "vm-1" {
		t.Fatalf("enroll: status %d, body %v", code, out)
	}
	if code, _ := postAgent(t, ts, testToken, "/api/v1/ingest/enroll", `{"host":"vm-1"}`); code != http.StatusConflict {
		t.Errorf("second enrollment of the same host: status %d, want 409", code)
	}
	if code, _ := postAgent(t, ts, "vxe_not_a_token_0000000000", "/api/v1/ingest/enroll", `{"host":"vm-2"}`); code != http.StatusUnauthorized {
		t.Errorf("unknown enrollment token: status %d, want 401", code)
	}
	if code, _ := postAgent(t, ts, testToken, "/api/v1/ingest/enroll", `{"host":"-bad host"}`); code != http.StatusBadRequest {
		t.Errorf("bad host name: status %d, want 400", code)
	}
	// The credential cannot enroll further hosts.
	if code, _ := postAgent(t, ts, cred, "/api/v1/ingest/enroll", `{"host":"vm-3"}`); code != http.StatusUnauthorized {
		t.Errorf("credential used to enroll: status %d, want 401", code)
	}
	run := `{"host":"vm-1","run_id":"r1","status":"started"}`
	if code, _ := postAgent(t, ts, cred, "/api/v1/ingest/run", run); code != http.StatusAccepted {
		t.Errorf("run with the host's credential: status %d, want 202", code)
	}
}

// A credential speaks only for its own host: it cannot retire another host's
// targets, write its events or upload in its name.
func TestCredentialIsBoundToItsHost(t *testing.T) {
	ts, st := newTestServer(t)
	ingestFixture(t, st, "victim", "/srv")
	enroll(t, st, "victim")
	attacker := enroll(t, st, "attacker")

	for path, body := range map[string]string{
		"/api/v1/ingest/run":   `{"host":"victim","run_id":"r1","status":"ok","targets":[]}`,
		"/api/v1/ingest/event": `{"host":"victim","level":"error","message":"forged","run_id":"r1"}`,
	} {
		if code, _ := postAgent(t, ts, attacker, path, body); code != http.StatusForbidden {
			t.Errorf("%s as another host: status %d, want 403", path, code)
		}
	}
	if code, _ := postSBOM(t, ts, attacker, "victim", "/", "r1", []byte(`{"artifacts":[]}`), false); code != http.StatusForbidden {
		t.Errorf("sbom as another host: status %d, want 403", code)
	}

	c := login(t, ts, testPassword)
	var hosts struct {
		Items []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	getJSON(t, c, ts.URL+"/api/v1/hosts?q=victim", &hosts)
	if len(hosts.Items) != 1 {
		t.Fatalf("hosts = %+v", hosts.Items)
	}
	targets, err := st.HostTargets(context.Background(), hosts.Items[0].ID)
	if err != nil || len(targets) != 1 || targets[0].RetiredAt != "" {
		t.Fatalf("victim targets after the attempt = %+v, %v; want one active", targets, err)
	}
}

func TestIngestReportIsGone(t *testing.T) {
	ts, st := newTestServer(t)
	cred := enroll(t, st, "h1")
	if code, _ := postAgent(t, ts, cred, "/api/v1/ingest/report?host=h1", `{}`); code != http.StatusNotFound {
		t.Fatalf("/ingest/report: status %d, want 404", code)
	}
}

func TestAgentCannotReportCentralKind(t *testing.T) {
	ts, st := newTestServer(t)
	cred := enroll(t, st, "h1")
	if code, _ := postAgent(t, ts, cred, "/api/v1/ingest/run", `{"host":"h1","kind":"central","run_id":"r1","status":"started"}`); code != http.StatusBadRequest {
		t.Fatalf("kind central: status %d, want 400", code)
	}
}

// Guessing agent tokens gets a client locked out, and only one event per
// client reaches the event log.
func TestBadAgentTokensAreLimited(t *testing.T) {
	ts, st := newTestServer(t)
	last := 0
	for range 8 {
		last, _ = postAgent(t, ts, "vxa_guess_00000000000000000", "/api/v1/ingest/run", `{"host":"h1","run_id":"r1","status":"started"}`)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after repeated bad tokens: status %d, want 429", last)
	}
	if code, _ := postAgent(t, ts, testToken, "/api/v1/ingest/enroll", `{"host":"h1"}`); code != http.StatusTooManyRequests {
		t.Fatalf("enroll while locked out: status %d, want 429", code)
	}
	ev, err := st.ListEvents(context.Background(), store.EventFilter{Q: "rejected agent request"}, store.Page{Size: 50})
	if err != nil || len(ev.Items) != 1 {
		t.Fatalf("rejected-agent events = %d, %v; want 1", len(ev.Items), err)
	}
}

func TestResetCredential(t *testing.T) {
	ts, st := newTestServer(t)
	cred := enroll(t, st, "h1")
	if code, _ := postAgent(t, ts, cred, "/api/v1/ingest/run", `{"host":"h1","run_id":"r1","status":"started"}`); code != http.StatusAccepted {
		t.Fatalf("run: status %d", code)
	}
	c := login(t, ts, testPassword)
	var hosts struct {
		Items []struct {
			ID int64 `json:"id"`
		} `json:"items"`
	}
	getJSON(t, c, ts.URL+"/api/v1/hosts?q=h1", &hosts)
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/hosts/"+strconv.FormatInt(hosts.Items[0].ID, 10)+"/credential", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset: status %d", resp.StatusCode)
	}
	if code, _ := postAgent(t, ts, cred, "/api/v1/ingest/run", `{"host":"h1","run_id":"r2","status":"started"}`); code != http.StatusUnauthorized {
		t.Fatalf("old credential after reset: status %d, want 401", code)
	}
	if code, _ := postAgent(t, ts, testToken, "/api/v1/ingest/enroll", `{"host":"h1"}`); code != http.StatusCreated {
		t.Fatalf("enroll again after reset: status %d, want 201", code)
	}
}

func TestCreateEnrollmentToken(t *testing.T) {
	ts, _ := newTestServer(t)
	c := login(t, ts, testPassword)
	post := func(body string) (int, map[string]any) {
		resp, err := c.Post(ts.URL+"/api/v1/tokens", "application/json", bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	code, out := post(`{"name":"lab"}`)
	tok, _ := out["token"].(map[string]any)
	if code != http.StatusCreated || tok["expires_at"] == "" {
		t.Fatalf("default token: status %d, body %v; want 201 and a 24 h expiry", code, out)
	}
	if code, out := post(`{"name":"forever","ttl_hours":0,"max_uses":2}`); code != http.StatusCreated ||
		out["token"].(map[string]any)["expires_at"] != "" || out["token"].(map[string]any)["max_uses"] != float64(2) {
		t.Fatalf("non-expiring token: status %d, body %v", code, out)
	}
	if code, _ := post(`{"name":"x","ttl_hours":-1}`); code != http.StatusBadRequest {
		t.Fatalf("negative ttl: status %d, want 400", code)
	}
}

// The served installer carries the checksum of the served agent script, and
// /system reports the installer's own checksum.
func TestInstallerCarriesAgentChecksum(t *testing.T) {
	files := loadAgentFiles(agent.FS, slog.New(slog.DiscardHandler))
	if len(files.install) == 0 || len(files.agent) == 0 {
		t.Fatal("agent scripts not loaded")
	}
	if bytes.Contains(files.install, []byte(agentSumPlaceholder)) {
		t.Fatal("served install.sh still has the checksum placeholder")
	}
	sum := sha256.Sum256(files.agent)
	if !bytes.Contains(files.install, []byte("AGENT_SHA256="+hex.EncodeToString(sum[:])+"\n")) {
		t.Fatal("served install.sh does not carry the agent script's SHA-256")
	}
	isum := sha256.Sum256(files.install)
	if files.installSum != hex.EncodeToString(isum[:]) {
		t.Fatalf("installSum = %q, want the SHA-256 of the served install.sh", files.installSum)
	}
}
