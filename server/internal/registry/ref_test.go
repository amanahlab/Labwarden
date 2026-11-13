package registry

import (
	"errors"
	"strings"
	"testing"
)

var d1 = "sha256:" + strings.Repeat("a", 64)
var d2 = "sha256:" + strings.Repeat("b", 64)

func TestParseRef(t *testing.T) {
	cases := []struct {
		in   string
		want Ref
	}{
		{"nginx", Ref{"docker.io", "docker.io/library/nginx", "latest", ""}},
		{"nginx:1.27-alpine", Ref{"docker.io", "docker.io/library/nginx", "1.27-alpine", ""}},
		{"docker.io/grafana/grafana:11.2.0", Ref{"docker.io", "docker.io/grafana/grafana", "11.2.0", ""}},
		{"ghcr.io/x/y:1.2@" + d1, Ref{"ghcr.io", "ghcr.io/x/y", "1.2", d1}},
		{"ghcr.io/x/y@" + d1, Ref{"ghcr.io", "ghcr.io/x/y", "", d1}},
		{"localhost:5000/app", Ref{"localhost:5000", "localhost:5000/app", "latest", ""}},
		{"localhost:5000/app@" + d1, Ref{"localhost:5000", "localhost:5000/app", "", d1}},
		{"registry.lan:5000/team/app:v2", Ref{"registry.lan:5000", "registry.lan:5000/team/app", "v2", ""}},
	}
	for _, c := range cases {
		got, err := ParseRef(c.in)
		if err != nil {
			t.Errorf("ParseRef(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseRef(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"", "sha256:" + strings.Repeat("a", 64), "nginx@sha256:short", "nginx@md5:abc", "Nginx", "a b"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) accepted", bad)
		}
	}
}

func TestParseRefImageID(t *testing.T) {
	for _, id := range []string{d1, strings.Repeat("a", 64)} {
		if _, err := ParseRef(id); !errors.Is(err, ErrImageID) {
			t.Errorf("ParseRef(%q) = %v, want ErrImageID", id, err)
		}
	}
}

func TestRepoDigest(t *testing.T) {
	rds := []string{"mirror.lan/library/nginx@" + d2, "nginx@" + d1, "garbage"}
	if got := RepoDigest("docker.io/library/nginx", rds); got != d1 {
		t.Errorf("short form: got %q", got)
	}
	if got := RepoDigest("ghcr.io/x/y", rds); got != "" {
		t.Errorf("other repository: got %q", got)
	}
	if got := RepoDigest("docker.io/library/nginx", nil); got != "" {
		t.Errorf("no digests: got %q", got)
	}
}

func TestShortName(t *testing.T) {
	for in, want := range map[string]string{
		"docker.io/library/nginx":   "nginx",
		"docker.io/grafana/grafana": "grafana/grafana",
		"ghcr.io/x/y":               "ghcr.io/x/y",
	} {
		if got := ShortName(in); got != want {
			t.Errorf("ShortName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidDigest(t *testing.T) {
	if !ValidDigest(d1) {
		t.Error("sha256 digest rejected")
	}
	for _, bad := range []string{"", "sha256:abc", "sha512:" + strings.Repeat("a", 128), strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64)} {
		if ValidDigest(bad) {
			t.Errorf("ValidDigest(%q) accepted", bad)
		}
	}
}
