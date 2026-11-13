package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/amanahlab/labwarden/server/internal/store"
)

var (
	imgA = "sha256:" + strings.Repeat("a", 64)
	imgB = "sha256:" + strings.Repeat("b", 64)
)

func runWithImages(images string) string {
	return `{"host":"docker-1","kind":"docker","run_id":"r1","status":"ok","targets":[],"images":` + images + `}`
}

func TestRunReportsRunningImages(t *testing.T) {
	ts, st := newTestServer(t)
	cred := enroll(t, st, "docker-1")
	images := fmt.Sprintf(`[
		{"container":"/web","ref":"nginx:1.27@%[1]s","image_id":"%[2]s","repo_digests":["nginx@%[1]s"],"created":"2026-03-01T10:00:00.123456789Z"},
		{"container":"/app","ref":"myapp","image_id":"%[2]s","repo_digests":[],"created":"1970-01-01T00:00:00Z"},
		{"container":"/by-id","ref":"%[2]s","image_id":"%[2]s"},
		{"container":"/bad-ref","ref":"Not A Ref","image_id":"%[2]s"},
		{"container":"/bad-id","ref":"nginx","image_id":"sha256:short"},
		{"container":"","ref":"nginx","image_id":"%[2]s"}
	]`, imgA, imgB)
	if code, out := postAgent(t, ts, cred, "/api/v1/ingest/run", runWithImages(images)); code != http.StatusAccepted {
		t.Fatalf("run with images: status %d, %v", code, out)
	}

	var list store.List[store.ImageRow]
	c := login(t, ts, testPassword)
	if code := getJSON(t, c, ts.URL+"/api/v1/images?sort=name&order=asc", &list); code != http.StatusOK {
		t.Fatalf("list images: status %d", code)
	}
	if list.Total != 3 {
		t.Fatalf("total = %d, want 3 valid containers: %+v", list.Total, list.Items)
	}
	got := map[string]store.ImageRow{}
	for _, r := range list.Items {
		got[r.Hosts[0].Containers[0]] = r
	}
	web := got["web"]
	if web.Name != "nginx" || web.Tag != "1.27" || web.PinnedDigest != imgA || web.Digest != imgA ||
		web.ImageCreated != "2026-03-01T10:00:00Z" || web.Status != "unchecked" {
		t.Errorf("web = %+v", web)
	}
	if app := got["app"]; app.Status != "local" || app.ImageCreated != "" {
		t.Errorf("app (local build, epoch timestamp) = %+v", app)
	}
	if byID := got["by-id"]; byID.Repository != "" || byID.Name != strings.Repeat("b", 12) || byID.Status != "local" {
		t.Errorf("by-id = %+v", byID)
	}

	var regs []string
	if getJSON(t, c, ts.URL+"/api/v1/images/registries", &regs); len(regs) != 1 || regs[0] != "docker.io" {
		t.Errorf("registries = %v", regs)
	}
	var hosts []store.ImageHostOption
	if getJSON(t, c, ts.URL+"/api/v1/images/hosts", &hosts); len(hosts) != 1 || hosts[0].Name != "docker-1" || hosts[0].ID == 0 {
		t.Errorf("hosts = %v", hosts)
	}

	// An older agent sends no list: what is stored stays.
	old := `{"host":"docker-1","kind":"docker","run_id":"r2","status":"ok","targets":[]}`
	if code, _ := postAgent(t, ts, cred, "/api/v1/ingest/run", old); code != http.StatusAccepted {
		t.Fatalf("run without images: status %d", code)
	}
	getJSON(t, c, ts.URL+"/api/v1/images", &list)
	if list.Total != 3 {
		t.Errorf("run without images changed the inventory: total %d", list.Total)
	}
	// An empty list means nothing runs any more.
	if code, _ := postAgent(t, ts, cred, "/api/v1/ingest/run", runWithImages(`[]`)); code != http.StatusAccepted {
		t.Fatalf("run with no containers: status %d", code)
	}
	getJSON(t, c, ts.URL+"/api/v1/images", &list)
	if list.Total != 0 {
		t.Errorf("empty list kept %d images", list.Total)
	}
}

func TestRunImagesLimits(t *testing.T) {
	ts, st := newTestServer(t)
	cred := enroll(t, st, "docker-1")
	many := make([]imageIn, maxImages+1)
	for i := range many {
		many[i] = imageIn{Container: fmt.Sprint("c", i), Ref: "nginx", ImageID: imgA}
	}
	b, _ := json.Marshal(many)
	if code, _ := postAgent(t, ts, cred, "/api/v1/ingest/run", runWithImages(string(b))); code != http.StatusBadRequest {
		t.Errorf("%d images: status %d, want 400", len(many), code)
	}
	// A credential cannot report another host's containers.
	enroll(t, st, "victim")
	body := strings.Replace(runWithImages(`[]`), `"docker-1"`, `"victim"`, 1)
	if code, _ := postAgent(t, ts, cred, "/api/v1/ingest/run", body); code != http.StatusForbidden {
		t.Errorf("images for another host: status %d, want 403", code)
	}
}
