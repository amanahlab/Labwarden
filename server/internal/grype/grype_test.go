package grype

import (
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, name string) *Report {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestParseImageReport(t *testing.T) {
	rep := load(t, "alpine312.json")
	if got := rep.TargetName(); got != "alpine:3.12" {
		t.Errorf("TargetName = %q", got)
	}
	if got := rep.TargetType(); got != "image" {
		t.Errorf("TargetType = %q", got)
	}
	if !strings.HasPrefix(rep.DistroString(), "alpine 3.12") {
		t.Errorf("distro = %q", rep.DistroString())
	}
	if rep.DBBuilt() == "" || rep.Descriptor.Version == "" {
		t.Errorf("descriptor not parsed: %+v", rep.Descriptor)
	}

	vulns, findings := Normalize(rep)
	if len(findings) == 0 || len(vulns) == 0 {
		t.Fatal("no findings")
	}
	if len(vulns) > len(findings) {
		t.Errorf("catalog (%d) larger than findings (%d)", len(vulns), len(findings))
	}
	v, ok := vulns["CVE-2022-37434"]
	if !ok {
		t.Fatal("expected CVE-2022-37434 (zlib)")
	}
	if v.Severity != "Critical" || v.CVSSScore < 9 {
		t.Errorf("zlib vuln = %+v", v)
	}
	// The alpine record has no description; it must be filled from NVD.
	if v.Description == "" {
		t.Error("description not filled from related vulnerability")
	}
	for _, f := range findings {
		switch f.FixState {
		case "fixed", "not-fixed", "wont-fix", "unknown":
		default:
			t.Errorf("unexpected fix state %q", f.FixState)
		}
		if SeverityRank(f.Severity) == 0 && f.Severity != "Unknown" {
			t.Errorf("unexpected severity %q", f.Severity)
		}
	}
}

func TestParseDirectoryReport(t *testing.T) {
	rep := load(t, "app-dir.json")
	if rep.TargetType() != "filesystem" || rep.TargetName() != "/scan" {
		t.Errorf("target = %s %s", rep.TargetType(), rep.TargetName())
	}
	vulns, findings := Normalize(rep)
	pkgs := map[string]bool{}
	for _, f := range findings {
		pkgs[f.PkgType+"/"+f.PkgName] = true
	}
	for _, want := range []string{"python/django", "npm/lodash", "npm/minimist"} {
		if !pkgs[want] {
			t.Errorf("missing findings for %s", want)
		}
	}
	aliased := 0
	for _, v := range vulns {
		if strings.HasPrefix(v.ID, "GHSA-") && len(v.Aliases) > 0 {
			aliased++
		}
	}
	if aliased == 0 {
		t.Error("expected GHSA records to carry CVE aliases")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "{}", `{"descriptor":{"name":"trivy"}}`, "not json"} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) succeeded", in)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{"CRITICAL": "Critical", "moderate": "Medium", "": "Unknown", "weird": "Unknown"}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMergeKeepsOnlyWebLinks(t *testing.T) {
	var cat Vuln
	merge(&cat, Vulnerability{DataSource: "javascript:alert(1)", URLs: []string{
		"https://nvd.nist.gov/vuln/detail/CVE-1", "javascript:alert(1)", "data:text/html,x", "HTTP://example.com/a", "ftp://x",
	}}, true)
	if cat.DataSource != "" {
		t.Errorf("DataSource = %q, want it dropped", cat.DataSource)
	}
	want := []string{"https://nvd.nist.gov/vuln/detail/CVE-1", "HTTP://example.com/a"}
	if strings.Join(cat.URLs, " ") != strings.Join(want, " ") {
		t.Errorf("URLs = %v, want %v", cat.URLs, want)
	}
}
