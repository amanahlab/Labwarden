package store

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/amanahlab/labwarden/server/internal/registry"
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
	if hosts, err := s.ImageHosts(ctx); err != nil || len(hosts) != 0 {
		t.Errorf("hosts = %v, %v", hosts, err)
	}
}

// The update age counts from the first upstream build after the running one,
// and a check that could not list the tags never claims "up to date".
func TestImageCheckHistoryAndListing(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Heartbeat(ctx, IngestMeta{Host: "docker-1", Kind: "docker"}); err != nil {
		t.Fatal(err)
	}
	id := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	const nginx, app, redis = "docker.io/library/nginx", "ghcr.io/x/app", "docker.io/library/redis"
	running := []ContainerImage{
		{Container: "web", Ref: "nginx:1.27", Registry: "docker.io", Repository: nginx, Tag: "1.27", ImageID: id("1"), RepoDigest: id("a")},
		{Container: "app", Ref: "ghcr.io/x/app:2.0.0", Registry: "ghcr.io", Repository: app, Tag: "2.0.0", ImageID: id("2"), RepoDigest: id("c")},
		{Container: "cache", Ref: "redis:7", Registry: "docker.io", Repository: redis, Tag: "7", ImageID: id("3"), RepoDigest: id("r")},
	}
	if err := s.ReplaceHostImages(ctx, "docker-1", running); err != nil {
		t.Fatal(err)
	}
	row := func(repo string) ImageRow {
		t.Helper()
		got, err := s.ListImages(ctx, ImageFilter{Q: strings.TrimPrefix(repo, "docker.io/library/")}, Page{Size: 100})
		if err != nil || len(got.Items) != 1 {
			t.Fatalf("row %s: %+v, %v", repo, got, err)
		}
		return got.Items[0]
	}
	save := func(repo, tag string, r registry.Result) {
		t.Helper()
		if err := s.SaveImageCheck(ctx, repo, tag, r); err != nil {
			t.Fatal(err)
		}
	}
	seen := func(digest, at string) {
		t.Helper()
		if _, err := s.w.ExecContext(ctx, `UPDATE image_upstream_digests SET first_seen=? WHERE digest=?`, at, digest); err != nil {
			t.Fatal(err)
		}
	}

	// Upstream moves a -> b -> c while the host runs a: the update is as old as b.
	save(nginx, "1.27", registry.Result{Outcome: registry.OK, Digest: id("a"), Listed: true})
	seen(id("a"), "2026-01-01T00:00:00Z")
	save(nginx, "1.27", registry.Result{Outcome: registry.OK, Digest: id("b"), Listed: true})
	seen(id("b"), "2026-02-01T00:00:00Z")
	save(nginx, "1.27", registry.Result{Outcome: registry.OK, Digest: id("c"), Listed: true})
	if r := row(nginx); !r.Drift || r.UpdateSince != "2026-02-01T00:00:00Z" {
		t.Errorf("a -> b -> c: %+v", r)
	}
	// Upstream never pointed at the running build: since the first check.
	save(redis, "7", registry.Result{Outcome: registry.OK, Digest: id("x"), Listed: true})
	seen(id("x"), "2026-03-01T00:00:00Z")
	save(redis, "7", registry.Result{Outcome: registry.OK, Digest: id("y"), Listed: true})
	if r := row(redis); !r.Drift || r.UpdateSince != "2026-03-01T00:00:00Z" {
		t.Errorf("never seen: %+v", r)
	}

	// The tag list failed on the first check: newer versions are unknown.
	unlisted := registry.Result{Outcome: registry.OK, Digest: id("c"), Error: "could not list tags: boom"}
	save(app, "2.0.0", unlisted)
	if r := row(app); r.Status != "error" || r.CheckError != unlisted.Error || r.UpstreamDigest != id("c") {
		t.Errorf("first check unlisted: %+v", r)
	}
	save(app, "2.0.0", registry.Result{Outcome: registry.OK, Digest: id("c"), Listed: true})
	if r := row(app); r.Status != "current" || r.CheckError != "" {
		t.Errorf("listed: %+v", r)
	}
	// Later list failures and rate limits keep the last good result, with a note.
	save(app, "2.0.0", unlisted)
	if r := row(app); r.Status != "current" || r.CheckError != unlisted.Error {
		t.Errorf("unlisted after listed: %+v", r)
	}
	save(app, "2.0.0", registry.Result{Outcome: registry.RateLimited, Error: "rate limited by the registry"})
	if r := row(app); r.Status != "current" || r.CheckError == "" {
		t.Errorf("rate limited after good: %+v", r)
	}

	// The history goes with the last container that runs the tag.
	if err := s.ReplaceHostImages(ctx, "docker-1", running[:1]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneImageChecks(ctx); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM image_upstream_digests WHERE repository <> ?`, nginx).Scan(&left); err != nil || left != 0 {
		t.Errorf("history left after prune: %d, %v", left, err)
	}
}

func TestReplaceHostImagesUnknownHost(t *testing.T) {
	if err := openTest(t).ReplaceHostImages(context.Background(), "nobody", nil); err == nil {
		t.Error("unknown host accepted")
	}
}

func TestImageChecks(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Heartbeat(ctx, IngestMeta{Host: "docker-1", Kind: "docker"}); err != nil {
		t.Fatal(err)
	}
	id := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	const nginx, app, gone = "docker.io/library/nginx", "ghcr.io/x/app", "ghcr.io/x/gone"
	imgs := []ContainerImage{
		{Container: "web", Ref: "nginx:1.27", Registry: "docker.io", Repository: nginx, Tag: "1.27", ImageID: id("1"), RepoDigest: id("a")},
		{Container: "app", Ref: "ghcr.io/x/app:2.0.0@" + id("c"), Registry: "ghcr.io", Repository: app, Tag: "2.0.0", PinnedDigest: id("c"), ImageID: id("2"), RepoDigest: id("c")},
		{Container: "old", Ref: "ghcr.io/x/gone:1", Registry: "ghcr.io", Repository: gone, Tag: "1", ImageID: id("3"), RepoDigest: id("d")},
		{Container: "local", Ref: "mine", Registry: "docker.io", Repository: "docker.io/library/mine", Tag: "latest", ImageID: id("4")},
		{Container: "bare", Ref: "ghcr.io/x/b@" + id("e"), Registry: "ghcr.io", Repository: "ghcr.io/x/b", PinnedDigest: id("e"), ImageID: id("5"), RepoDigest: id("e")},
	}
	if err := s.ReplaceHostImages(ctx, "docker-1", imgs); err != nil {
		t.Fatal(err)
	}
	row := func(repo string) ImageRow {
		t.Helper()
		got, err := s.ListImages(ctx, ImageFilter{}, Page{Size: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range got.Items {
			if r.Repository == repo {
				return r
			}
		}
		t.Fatalf("no row for %s", repo)
		return ImageRow{}
	}
	save := func(repo, tag string, r registry.Result) {
		t.Helper()
		if err := s.SaveImageCheck(ctx, repo, tag, r); err != nil {
			t.Fatal(err)
		}
	}
	strs := func(v []string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(v, ",")
	}

	// Local builds and bare digests are never checked.
	if got := strs(s.UncheckedImageRepositories(ctx, "docker-1")); got != strings.Join(slices.Sorted(slices.Values([]string{app, nginx, gone})), ",") {
		t.Errorf("unchecked = %s", got)
	}
	if got := strs(s.ImageTags(ctx, nginx)); got != "1.27" {
		t.Errorf("tags = %s", got)
	}

	save(nginx, "1.27", registry.Result{Outcome: registry.OK, Digest: id("a"), Listed: true})
	if r := row(nginx); r.Status != "current" || r.CheckedAt == "" || r.Drift || r.UpdateSince != "" {
		t.Errorf("current: %+v", r)
	}

	// The tag was pushed again.
	save(nginx, "1.27", registry.Result{Outcome: registry.OK, Digest: id("b"), Listed: true})
	if r := row(nginx); r.Status != "outdated" || !r.Drift || r.UpstreamDigest != id("b") || r.UpdateSince == "" {
		t.Errorf("drift: %+v", r)
	}
	if _, err := s.w.ExecContext(ctx, `UPDATE image_upstream_digests SET first_seen = CASE digest WHEN ? THEN '2025-12-01T00:00:00Z' ELSE '2026-01-01T00:00:00Z' END`, id("a")); err != nil {
		t.Fatal(err)
	}
	// A rate limit keeps the last good result and says why it is old.
	save(nginx, "1.27", registry.Result{Outcome: registry.RateLimited, Error: "rate limited by the registry"})
	if r := row(nginx); r.Status != "outdated" || r.CheckError == "" || r.UpstreamDigest != id("b") {
		t.Errorf("rate limited: %+v", r)
	}
	// The same digest again keeps its first-seen time; a newer tag is older
	// news only once it has been seen for longer.
	save(nginx, "1.27", registry.Result{Outcome: registry.OK, Digest: id("b"), Newest: "1.29", NewestInMajor: "", Listed: true})
	if r := row(nginx); r.UpdateSince != "2026-01-01T00:00:00Z" || r.NewestTag != "1.29" || r.CheckError != "" {
		t.Errorf("since: %+v", r)
	}

	// Pinned: the digest moving upstream is intended, a newer tag is not.
	save(app, "2.0.0", registry.Result{Outcome: registry.OK, Digest: id("f"), Listed: true})
	if r := row(app); r.Status != "current" || r.Drift {
		t.Errorf("pinned digest drift: %+v", r)
	}
	save(app, "2.0.0", registry.Result{Outcome: registry.OK, Digest: id("f"), Newest: "3.0.0", NewestInMajor: "2.1.0", Listed: true})
	if _, err := s.w.ExecContext(ctx, `UPDATE image_upstream SET newest_since='2026-02-01T00:00:00Z' WHERE repository=?`, app); err != nil {
		t.Fatal(err)
	}
	// The tag list could not be read this time: the newer tags stay.
	save(app, "2.0.0", registry.Result{Outcome: registry.OK, Digest: id("f")})
	if r := row(app); r.Status != "outdated" || r.NewestTag != "3.0.0" || r.NewestInMajor != "2.1.0" || r.UpdateSince != "2026-02-01T00:00:00Z" {
		t.Errorf("newer tag: %+v", r)
	}
	// Once current again, the time goes.
	save(app, "2.0.0", registry.Result{Outcome: registry.OK, Digest: id("f"), Listed: true})
	if r := row(app); r.Status != "current" || r.UpdateSince != "" {
		t.Errorf("current again: %+v", r)
	}

	save(gone, "1", registry.Result{Outcome: registry.NotFound, Error: "not found upstream, or it needs credentials"})
	if r := row(gone); r.Status != "not_found" || r.CheckError == "" {
		t.Errorf("not found: %+v", r)
	}
	save(gone, "1", registry.Result{Outcome: registry.Failed, Error: "boom"})
	if r := row(gone); r.Status != "error" {
		t.Errorf("error without data: %+v", r)
	}
	save(gone, "1", registry.Result{Outcome: registry.NotAllowed, Error: "not on the allowlist"})
	if r := row(gone); r.Status != "unchecked" || r.CheckError == "" {
		t.Errorf("not allowed: %+v", r)
	}
	if r := row("docker.io/library/mine"); r.Status != "local" || r.CheckedAt != "" {
		t.Errorf("local: %+v", r)
	}

	if got, err := s.ListImages(ctx, ImageFilter{Status: "outdated"}, Page{Sort: "checked"}); err != nil || got.Total != 1 {
		t.Errorf("outdated filter: %+v, %v", got, err)
	}
	if got := strs(s.UncheckedImageRepositories(ctx, "docker-1")); got != "" {
		t.Errorf("unchecked after checks = %s", got)
	}
	if got := strs(s.DueImageRepositories(ctx, "2000-01-01T00:00:00Z")); got != "" {
		t.Errorf("due long ago = %s", got)
	}
	if got := strs(s.DueImageRepositories(ctx, "")); got != strings.Join(slices.Sorted(slices.Values([]string{app, nginx, gone})), ",") {
		t.Errorf("due (all) = %s", got)
	}
	if last, err := s.LastImageCheck(ctx); err != nil || last == "" {
		t.Errorf("last check = %q, %v", last, err)
	}

	// gone stops running: its check is forgotten.
	if err := s.ReplaceHostImages(ctx, "docker-1", imgs[:2]); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PruneImageChecks(ctx); err != nil || n != 1 {
		t.Errorf("pruned %d, %v", n, err)
	}
}
