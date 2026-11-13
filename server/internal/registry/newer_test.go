package registry

import "testing"

func TestNewer(t *testing.T) {
	nginx := []string{"latest", "stable", "mainline", "alpine", "1", "1.27", "1.29", "1.27.3", "1.27.4", "1.27.5", "1.28.0", "1.29.1",
		"1.27.3-alpine", "1.27.5-alpine", "1.29.1-alpine", "1.29.1-alpine-slim", "1.30.0-rc1", "1.29.1-perl"}
	cases := []struct {
		name, current   string
		tags            []string
		newest, inMajor string
	}{
		{"patch and minor", "1.27.3", nginx, "1.29.1", "1.29.1"},
		{"suffix keeps its family", "1.27.3-alpine", nginx, "1.29.1-alpine", "1.29.1-alpine"},
		{"two parts compare with two parts", "1.27", nginx, "1.29", "1.29"},
		{"newest already", "1.29.1", nginx, "", ""},
		{"pre-releases are left out", "1.29.1", append(nginx, "1.29.2-rc1", "1.30.0-beta"), "", ""},
		{"floating tag", "latest", nginx, "", ""},
		{"word tag", "alpine", nginx, "", ""},
		{"major", "16.4", []string{"15.9", "16.4", "16.6", "17.2", "17", "16"}, "17.2", "16.6"},
		{"one number", "16", []string{"15", "16", "17", "16.6"}, "17", ""},
		{"v prefix stays apart", "v2.1.0", []string{"2.9.0", "v2.3.0", "v3.0.1", "v3.0.1-rc1"}, "v3.0.1", "v2.3.0"},
		{"word prefix", "jammy-20240101", []string{"jammy-20240501", "noble-20250101", "20250101"}, "jammy-20240501", ""},
		{"linuxserver build", "1.27.3-ls245", []string{"1.27.3-ls246", "1.27.4-ls250", "1.27.4", "version-1.27.9"}, "1.27.4-ls250", "1.27.4-ls250"},
		{"linuxserver version prefix", "version-1.27.3", []string{"version-1.27.9", "1.27.9"}, "version-1.27.9", "version-1.27.9"},
		{"alpine release in the suffix", "3.12-alpine3.20", []string{"3.12-alpine3.21", "3.13-alpine3.21", "3.13-alpine"}, "3.13-alpine3.21", "3.13-alpine3.21"},
		{"commit hash suffix", "1.2.3-ab12cd", []string{"1.2.4-ff00aa", "1.2.4-ab12cd"}, "1.2.4-ab12cd", "1.2.4-ab12cd"},
		{"git sha tag", "sha-1a2b3c4", []string{"sha-9a2b3c4"}, "", ""},
		{"huge number", "1.2", []string{"99999999999999999999999.0"}, "", ""},
		{"numbers compare as numbers", "1.9.0", []string{"1.10.0", "1.8.12"}, "1.10.0", "1.10.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			newest, inMajor := Newer(c.current, c.tags)
			if newest != c.newest || inMajor != c.inMajor {
				t.Errorf("Newer(%q) = %q, %q; want %q, %q", c.current, newest, inMajor, c.newest, c.inMajor)
			}
		})
	}
}

func TestVersioned(t *testing.T) {
	for tag, want := range map[string]bool{"1.27": true, "v2": true, "16-alpine": true, "latest": false, "stable-alpine": false, "sha-1a2b": false} {
		if got := Versioned(tag); got != want {
			t.Errorf("Versioned(%q) = %v", tag, got)
		}
	}
}
