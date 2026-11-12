package store

import (
	"context"
	"strings"
	"testing"
)

func TestReplaceHostImagesAndList(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	for _, h := range []string{"docker-1", "docker-2"} {
		if _, err := s.Heartbeat(ctx, IngestMeta{Host: h, Kind: "docker"}); err != nil {
			t.Fatal(err)
		}
	}
	id := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	nginx := ContainerImage{Ref: "nginx:1.27", Registry: "docker.io", Repository: "docker.io/library/nginx", Tag: "1.27",
		ImageID: id("1"), RepoDigest: id("a"), ImageCreated: "2026-01-02T03:04:05Z"}
	web1, web2 := nginx, nginx
	web1.Container, web2.Container = "web", "web-2"
	local := ContainerImage{Container: "app", Ref: "myapp", Registry: "docker.io", Repository: "docker.io/library/myapp", Tag: "latest", ImageID: id("2")}
	pinned := ContainerImage{Container: "proxy", Ref: "ghcr.io/x/proxy@" + id("c"), Registry: "ghcr.io", Repository: "ghcr.io/x/proxy",
		PinnedDigest: id("c"), ImageID: id("3"), RepoDigest: id("c")}
	if err := s.ReplaceHostImages(ctx, "docker-1", []ContainerImage{web1, web2, local, pinned}); err != nil {
		t.Fatal(err)
	}
	web3 := nginx
	web3.Container, web3.ImageID = "edge", id("4") // another platform, same pulled digest
	if err := s.ReplaceHostImages(ctx, "docker-2", []ContainerImage{web3}); err != nil {
		t.Fatal(err)
	}

	all, err := s.ListImages(ctx, ImageFilter{}, Page{Sort: "name", Order: "asc"})
	if err != nil {
		t.Fatal(err)
	}
	if all.Total != 3 {
		t.Fatalf("total = %d, want 3 (nginx across both hosts, myapp, proxy): %+v", all.Total, all.Items)
	}
	byName := map[string]ImageRow{}
	for _, r := range all.Items {
		byName[r.Name] = r
	}
	n := byName["nginx"]
	if n.Status != "unchecked" || n.Containers != 3 || len(n.Hosts) != 2 || n.ImageCreated != "2026-01-02T03:04:05Z" {
		t.Errorf("nginx row = %+v", n)
	}
	if len(n.Hosts[0].Containers)+len(n.Hosts[1].Containers) != 3 {
		t.Errorf("nginx containers = %+v", n.Hosts)
	}
	if byName["myapp"].Status != "local" {
		t.Errorf("myapp status = %q, want local", byName["myapp"].Status)
	}
	if p := byName["ghcr.io/x/proxy"]; p.Status != "pinned" || p.PinnedDigest != id("c") {
		t.Errorf("proxy row = %+v", p)
	}

	for _, c := range []struct {
		f    ImageFilter
		want int
	}{
		{ImageFilter{Status: "local"}, 1},
		{ImageFilter{Registry: "ghcr.io"}, 1},
		{ImageFilter{Q: "edge"}, 1},
		{ImageFilter{HostID: 2}, 1},
	} {
		got, err := s.ListImages(ctx, c.f, Page{})
		if err != nil || got.Total != c.want {
			t.Errorf("ListImages(%+v) total = %v (%v), want %d", c.f, got, err, c.want)
		}
	}
	// An unknown sort key falls back to the default instead of reaching SQL.
	if _, err := s.ListImages(ctx, ImageFilter{}, Page{Sort: "1; DROP TABLE hosts"}); err != nil {
		t.Errorf("unknown sort: %v", err)
	}

	// The next report replaces the list: stopped containers disappear.
	if err := s.ReplaceHostImages(ctx, "docker-1", []ContainerImage{web1}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListImages(ctx, ImageFilter{HostID: 1}, Page{}); got.Total != 1 || got.Items[0].Containers != 1 {
		t.Errorf("after replace: %+v", got)
	}
	if err := s.ReplaceHostImages(ctx, "docker-1", []ContainerImage{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListImages(ctx, ImageFilter{HostID: 1}, Page{}); got.Total != 0 {
		t.Errorf("empty report kept %d images", got.Total)
	}

	// Deleting a host drops its containers.
	if err := s.DeleteHost(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListImages(ctx, ImageFilter{}, Page{}); got.Total != 0 {
		t.Errorf("deleted host left %d images", got.Total)
	}
	if regs, err := s.ImageRegistries(ctx); err != nil || len(regs) != 0 {
		t.Errorf("registries = %v, %v", regs, err)
	}
}

func TestReplaceHostImagesUnknownHost(t *testing.T) {
	if err := openTest(t).ReplaceHostImages(context.Background(), "nobody", nil); err == nil {
		t.Error("unknown host accepted")
	}
}
