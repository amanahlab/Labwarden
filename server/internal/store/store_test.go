package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/amanahlab/labwarden/server/internal/grype"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func fixture(t *testing.T, name string) *grype.Report {
	t.Helper()
	f, err := os.Open("../grype/testdata/" + name)
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

func TestIngestAndQuery(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	img := fixture(t, "alpine312.json")
	dir := fixture(t, "app-dir.json")

	r1, err := s.IngestReport(ctx, IngestMeta{Host: "vm-1", Kind: "vm", Group: "lab", IntervalSec: 3600}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Findings == 0 || r1.New != 0 {
		t.Fatalf("first ingest: %+v", r1)
	}
	if _, err := s.IngestReport(ctx, IngestMeta{Host: "docker-1", Kind: "docker", Group: "lab"}, img); err != nil {
		t.Fatal(err)
	}
	// Re-ingesting the same report creates a new scan with no new/fixed findings.
	r2, err := s.IngestReport(ctx, IngestMeta{Host: "vm-1", Kind: "vm"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if r2.New != 0 || r2.Fixed != 0 || r2.TargetID != r1.TargetID {
		t.Fatalf("re-ingest: %+v", r2)
	}

	sum, err := s.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Hosts != 2 || sum.Targets != 2 || sum.Findings.Total != r1.Findings+len(mustFindings(img)) {
		t.Fatalf("summary: hosts=%d targets=%d findings=%d", sum.Hosts, sum.Targets, sum.Findings.Total)
	}
	if sum.Unique.Critical == 0 || len(sum.TopVulns) == 0 || len(sum.TopHosts) != 2 {
		t.Fatalf("summary content: %+v", sum.Unique)
	}

	vl, err := s.ListVulns(ctx, FindingFilter{Q: "lodash"}, Page{Size: 5, Sort: "cvss"})
	if err != nil {
		t.Fatal(err)
	}
	if vl.Total == 0 || len(vl.Items) > 5 {
		t.Fatalf("vuln search: total=%d items=%d", vl.Total, len(vl.Items))
	}
	// Unknown sort keys are ignored rather than interpolated.
	if _, err := s.ListVulns(ctx, FindingFilter{}, Page{Sort: "id; DROP TABLE hosts"}); err != nil {
		t.Fatal(err)
	}

	hosts, err := s.ListHosts(ctx, HostFilter{Group: "lab"}, Page{Sort: "critical"})
	if err != nil || hosts.Total != 2 {
		t.Fatalf("hosts: %v %+v", err, hosts)
	}
	if hosts.Items[0].Status != "ok" {
		t.Fatalf("fresh host status = %q", hosts.Items[0].Status)
	}

	// Ignoring a vuln removes it from active counts.
	before := sum.Findings.Total
	if err := s.SetTriage(ctx, "CVE-2022-37434", 0, "ignored", "test"); err != nil {
		t.Fatal(err)
	}
	sum2, _ := s.Summary(ctx)
	if sum2.Findings.Total >= before {
		t.Fatalf("ignore did not reduce active findings: %d -> %d", before, sum2.Findings.Total)
	}

	// Completing a run with a target list retires targets the agent no longer has.
	retired, err := s.CompleteRun(ctx, IngestMeta{Host: "docker-1"}, "ok", []string{"something-else"})
	if err != nil || retired != 1 {
		t.Fatalf("retire: %d %v", retired, err)
	}
	sum3, _ := s.Summary(ctx)
	if sum3.Targets != 1 {
		t.Fatalf("targets after retire = %d", sum3.Targets)
	}
	// nil = no list sent: nothing is retired.
	if retired, err := s.CompleteRun(ctx, IngestMeta{Host: "vm-1"}, "ok", nil); err != nil || retired != 0 {
		t.Fatalf("nil target list retired %d (%v)", retired, err)
	}
	// An empty list = the host has no targets left.
	if retired, err := s.CompleteRun(ctx, IngestMeta{Host: "vm-1"}, "ok", []string{}); err != nil || retired != 1 {
		t.Fatalf("empty target list retired %d (%v), want 1", retired, err)
	}

	trends, err := s.Trends(ctx, 30)
	if err != nil || len(trends) != 1 {
		t.Fatalf("trends: %v %v", trends, err)
	}
}

func mustFindings(rep *grype.Report) []grype.Finding {
	_, f := grype.Normalize(rep)
	return f
}

func TestTokens(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	tok, plain, err := s.CreateToken(ctx, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := s.VerifyToken(ctx, plain); !ok || name != "lab" {
		t.Fatal("token did not verify")
	}
	if _, ok := s.VerifyToken(ctx, plain+"x"); ok {
		t.Fatal("wrong token verified")
	}
	if err := s.DeleteToken(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.VerifyToken(ctx, plain); ok {
		t.Fatal("deleted token verified")
	}
}

func TestTargetSBOMs(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	m := IngestMeta{Host: "vm-1", Kind: "vm", Target: "/", RunID: "r1"}
	res, err := s.IngestReport(ctx, m, fixture(t, "app-dir.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.TargetSBOM(ctx, res.TargetID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no sbom yet: err = %v", err)
	}
	for _, sha := range []string{"aaa", "bbb"} { // the second upload replaces the first
		if err := s.SetTargetSBOM(ctx, res.TargetID, sha, 10, m); err != nil {
			t.Fatal(err)
		}
	}
	sha, got, err := s.TargetSBOM(ctx, res.TargetID)
	if err != nil || sha != "bbb" || got != m {
		t.Fatalf("TargetSBOM = %q %+v %v", sha, got, err)
	}
	if refs, _ := s.SBOMRefs(ctx); len(refs) != 1 || !refs["bbb"] {
		t.Fatalf("refs = %v", refs)
	}
	if ids, _ := s.LiveSBOMTargets(ctx); len(ids) != 1 || ids[0] != res.TargetID {
		t.Fatalf("live = %v", ids)
	}
	if _, err := s.CompleteRun(ctx, m, "ok", []string{}); err != nil { // retires the target
		t.Fatal(err)
	}
	if ids, _ := s.LiveSBOMTargets(ctx); len(ids) != 0 {
		t.Fatalf("retired target still live: %v", ids)
	}
}
