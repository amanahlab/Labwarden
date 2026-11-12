package registry

import (
	"context"
	"encoding/base64"
	"io"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// testRegistry runs ggcr's in-memory registry behind wrap and returns its
// host ("127.0.0.1:port"), which ggcr talks to over plain http.
func testRegistry(t *testing.T, wrap func(http.Handler) http.Handler) string {
	t.Helper()
	h := ggcrregistry.New(ggcrregistry.Logger(stdlog.New(io.Discard, "", 0)))
	if wrap != nil {
		h = wrap(h)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// push uploads a fresh random image as repo:tag and returns its digest.
func push(t *testing.T, host, repo, tag string, opts ...remote.Option) string {
	t.Helper()
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.NewTag(host + "/" + repo + ":" + tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img, opts...); err != nil {
		t.Fatal(err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d.String()
}

func checker(t *testing.T, o Options) *Checker {
	t.Helper()
	if o.Log == nil {
		o.Log = quiet
	}
	if o.Getenv == nil {
		o.Getenv = func(string) string { return "" }
	}
	c, err := NewChecker(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCheckDigestAndNewerTags(t *testing.T) {
	host := testRegistry(t, nil)
	running := push(t, host, "team/app", "1.0.0")
	push(t, host, "team/app", "1.1.0")
	push(t, host, "team/app", "2.0.0")
	push(t, host, "team/app", "2.1.0-rc1")
	latest := push(t, host, "team/app", "latest")

	c := checker(t, Options{Registries: []string{host}})
	got := c.Check(context.Background(), host+"/team/app", []string{"1.0.0", "latest"})
	want := map[string]Result{
		"1.0.0":  {Digest: running, Newest: "2.0.0", NewestInMajor: "1.1.0", Outcome: OK},
		"latest": {Digest: latest, Outcome: OK},
	}
	for tag, w := range want {
		if got[tag] != w {
			t.Errorf("%s: got %+v, want %+v", tag, got[tag], w)
		}
	}

	// The tag is pushed again: the upstream digest moves on.
	rebuilt := push(t, host, "team/app", "1.0.0")
	if got := c.Check(context.Background(), host+"/team/app", []string{"1.0.0"}); got["1.0.0"].Digest != rebuilt || rebuilt == running {
		t.Errorf("after re-push: got %+v, want digest %s", got["1.0.0"], rebuilt)
	}
}

func TestCheckNotFound(t *testing.T) {
	host := testRegistry(t, nil)
	push(t, host, "team/app", "1.0.0")
	c := checker(t, Options{Registries: []string{host}})
	got := c.Check(context.Background(), host+"/team/app", []string{"9.9.9"})
	if got["9.9.9"].Outcome != NotFound {
		t.Errorf("unknown tag: %+v", got["9.9.9"])
	}
	got = c.Check(context.Background(), host+"/team/nope", []string{"1.0.0", "latest"})
	if got["1.0.0"].Outcome != NotFound || got["latest"].Outcome != NotFound {
		t.Errorf("unknown repository: %+v", got)
	}
}

// counting answers every request itself and counts them.
func counting(n *atomic.Int32, h http.HandlerFunc) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h(w, r)
	}))
	return srv
}

func TestCheckNeverContactsDisallowedRegistry(t *testing.T) {
	var hits atomic.Int32
	srv := counting(&hits, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	c := checker(t, Options{})
	got := c.Check(context.Background(), host+"/team/app", []string{"1.0.0"})
	if got["1.0.0"].Outcome != NotAllowed {
		t.Errorf("got %+v", got["1.0.0"])
	}
	if hits.Load() != 0 {
		t.Errorf("the disallowed registry got %d requests", hits.Load())
	}
}

func TestCheckRefusesRedirectToDisallowedHost(t *testing.T) {
	var hits atomic.Int32
	internal := counting(&hits, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer internal.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer front.Close()
	host := strings.TrimPrefix(front.URL, "http://")

	c := checker(t, Options{Registries: []string{host}})
	got := c.Check(context.Background(), host+"/team/app", []string{"1.0.0"})
	if o := got["1.0.0"].Outcome; o == OK {
		t.Errorf("got %+v", got["1.0.0"])
	}
	if hits.Load() != 0 {
		t.Errorf("the redirect target got %d requests", hits.Load())
	}
}

func TestCheckStopsAtRateLimit(t *testing.T) {
	var heads atomic.Int32
	var limited atomic.Bool
	host := testRegistry(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limited.Load() && r.Method == http.MethodHead {
				heads.Add(1)
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			h.ServeHTTP(w, r)
		})
	})
	push(t, host, "team/app", "1.0.0")
	push(t, host, "team/app", "1.1.0")
	limited.Store(true)

	c := checker(t, Options{Registries: []string{host}})
	got := c.Check(context.Background(), host+"/team/app", []string{"1.0.0", "1.1.0"})
	for _, tag := range []string{"1.0.0", "1.1.0"} {
		if got[tag].Outcome != RateLimited {
			t.Errorf("%s: %+v", tag, got[tag])
		}
	}
	if heads.Load() != 1 {
		t.Errorf("%d HEAD requests, want 1: no retries, no further tags", heads.Load())
	}
}

func TestCheckSendsCredentials(t *testing.T) {
	const user, pass = "reader", "s3cret"
	host := testRegistry(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u, p, ok := r.BasicAuth(); !ok || u != user || p != pass {
				w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h.ServeHTTP(w, r)
		})
	})
	digest := push(t, host, "team/app", "1.0.0", remote.WithAuth(&authn.Basic{Username: user, Password: pass}))

	anon := checker(t, Options{Registries: []string{host}})
	if got := anon.Check(context.Background(), host+"/team/app", []string{"1.0.0"}); got["1.0.0"].Outcome != NotFound {
		t.Errorf("without credentials: %+v", got["1.0.0"])
	}

	env := map[string]string{"GRYPE_REGISTRY_AUTH_AUTHORITY": host, "SYFT_REGISTRY_AUTH_USERNAME": user, "GRYPE_REGISTRY_AUTH_PASSWORD": pass}
	c := checker(t, Options{Getenv: func(k string) string { return env[k] }})
	if !c.Allowed(host) {
		t.Fatal("a registry with credentials should be allowed")
	}
	if got := c.Check(context.Background(), host+"/team/app", []string{"1.0.0"}); got["1.0.0"].Digest != digest {
		t.Errorf("with credentials: %+v", got["1.0.0"])
	}
}

func TestDockerConfigInlineAuthsOnly(t *testing.T) {
	dir := t.TempDir()
	auth := base64.StdEncoding.EncodeToString([]byte("hubuser:hubpass"))
	cfg := `{"credsStore":"desktop","credHelpers":{"gcr.io":"gcloud"},"auths":{
		"https://index.docker.io/v1/":{"auth":"` + auth + `"},
		"Registry.Example:5000":{"username":"u","password":"p"},
		"quay.io":{}}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := checker(t, Options{DockerConfig: dir})

	if got := strings.Join(c.Credentials(), ","); got != "docker.io,registry.example:5000" {
		t.Errorf("Credentials() = %s", got)
	}
	if !c.Allowed("registry.example:5000") || c.Allowed("internal.lan") {
		t.Error("allowlist: credentials allow a registry, nothing else does")
	}
	for reg, want := range map[string]authn.AuthConfig{
		"docker.io":             {Username: "hubuser", Password: "hubpass"},
		"index.docker.io":       {Username: "hubuser", Password: "hubpass"},
		"registry.example:5000": {Username: "u", Password: "p"},
		"quay.io":               {},
		"gcr.io":                {}, // the helper is not run
	} {
		r, err := name.NewRegistry(reg)
		if err != nil {
			t.Fatal(err)
		}
		a, err := c.keys.Resolve(r)
		if err != nil {
			t.Fatalf("%s: %v", reg, err)
		}
		got, err := a.Authorization()
		if err != nil {
			t.Fatal(err)
		}
		if *got != want {
			t.Errorf("%s: got user %q", reg, got.Username)
		}
	}
}

func TestDockerConfigErrors(t *testing.T) {
	if _, err := NewChecker(Options{DockerConfig: t.TempDir(), Log: quiet}); err != nil {
		t.Errorf("a missing config.json is no error: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"auths":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChecker(Options{DockerConfig: dir, Log: quiet}); err == nil {
		t.Error("a broken config.json should stop the server")
	}
}

func TestCanonicalRegistry(t *testing.T) {
	for in, want := range map[string]string{
		"docker.io": "docker.io", "index.docker.io": "docker.io", "https://index.docker.io/v1/": "docker.io",
		"registry-1.docker.io": "docker.io", "GHCR.io": "ghcr.io", "localhost:5000": "localhost:5000", " quay.io ": "quay.io",
	} {
		if got := canonicalRegistry(in); got != want {
			t.Errorf("canonicalRegistry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyNeverLooksLikeAFailureForMissingImages(t *testing.T) {
	c := checker(t, Options{})
	// Not allowed is decided before any request.
	if got := c.Check(context.Background(), "internal.lan/app", []string{"1"}); got["1"].Outcome != NotAllowed {
		t.Errorf("got %+v", got["1"])
	}
	if got := c.Check(context.Background(), "not a name", []string{"1"}); got["1"].Outcome != Failed {
		t.Errorf("got %+v", got["1"])
	}
}
