package jobs

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/amanahlab/labwarden/server/internal/registry"
	"github.com/amanahlab/labwarden/server/internal/store"
)

// fakeChecker says every tag is at digest "b", with 9.9 newer.
type fakeChecker struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeChecker) Check(_ context.Context, repo string, tags []string) map[string]registry.Result {
	f.mu.Lock()
	f.calls = append(f.calls, repo+":"+strings.Join(tags, ","))
	f.mu.Unlock()
	out := map[string]registry.Result{}
	for _, t := range tags {
		out[t] = registry.Result{Outcome: registry.OK, Digest: "sha256:" + strings.Repeat("b", 64), Newest: "9.9", Listed: true}
	}
	return out
}

func (f *fakeChecker) Registries() []string  { return registry.DefaultRegistries }
func (f *fakeChecker) Credentials() []string { return nil }

func (f *fakeChecker) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.calls...)
}

func runImages(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.Heartbeat(ctx, store.IngestMeta{Host: "docker-1", Kind: "docker"}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceHostImages(ctx, "docker-1", []store.ContainerImage{{Container: "web", Ref: "nginx:1.27", Registry: "docker.io",
		Repository: "docker.io/library/nginx", Tag: "1.27", ImageID: "sha256:" + strings.Repeat("1", 64), RepoDigest: "sha256:" + strings.Repeat("a", 64)}}); err != nil {
		t.Fatal(err)
	}
}

func TestImageChecks(t *testing.T) {
	fc := &fakeChecker{}
	q, st := setup(t, true, func(c *Config) { c.ImageChecker = fc })
	ctx := context.Background()
	runImages(t, st)
	if n, err := q.EnqueueImageChecks(ctx, "docker-1"); err != nil || n != 1 {
		t.Fatalf("EnqueueImageChecks = %d, %v", n, err)
	}
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the image check", func() bool {
		l, err := st.ListImages(ctx, store.ImageFilter{}, store.Page{})
		return err == nil && l.Total == 1 && l.Items[0].Status == "outdated"
	})
	if n, _ := q.EnqueueImageChecks(ctx, "docker-1"); n != 0 {
		t.Errorf("a checked repository was queued again (%d)", n)
	}
	// Checked just now: the start-up sweep and Check now differ only in Force.
	if ok, err := q.EnqueueImageCheckAll(ctx); err != nil || !ok {
		t.Fatalf("EnqueueImageCheckAll = %v, %v", ok, err)
	}
	waitFor(t, "the forced check", func() bool { return len(fc.seen()) >= 2 })
	for _, c := range fc.seen() {
		if c != "docker.io/library/nginx:1.27" {
			t.Errorf("checked %q", c)
		}
	}
}

func TestImageChecksOff(t *testing.T) {
	q, st := setup(t, true)
	ctx := context.Background()
	runImages(t, st)
	if n, err := q.EnqueueImageChecks(ctx, "docker-1"); err != nil || n != 0 {
		t.Errorf("EnqueueImageChecks = %d, %v", n, err)
	}
	if _, err := q.EnqueueImageCheckAll(ctx); !errors.Is(err, ErrImageChecksOff) {
		t.Errorf("EnqueueImageCheckAll: %v", err)
	}
	if c, _ := q.ImageChecks(); c != nil {
		t.Error("checker reported while off")
	}
}
