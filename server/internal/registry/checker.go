package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/docker/cli/cli/config/configfile"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Outcome is how a check of one tag ended.
type Outcome string

const (
	OK          Outcome = "ok"
	NotFound    Outcome = "not_found"    // 401/403/404: gone, private, or needs credentials
	NotAllowed  Outcome = "not_allowed"  // the registry is not on the allowlist
	RateLimited Outcome = "rate_limited" // 429: try again next interval
	Failed      Outcome = "error"
)

// Result of checking one running tag against its registry.
type Result struct {
	Digest        string // what the tag points at upstream now
	Newest        string // newest tag of the same shape, if newer
	NewestInMajor string // newest tag in the running major version, if newer
	Listed        bool   // the Newest fields are known (the tag list was read, or the tag is no version)
	Outcome       Outcome
	Error         string // short, for people; never holds credentials
}

// DefaultRegistries are queried without further configuration. Image
// references come from agents, so anything else must be allowed by the
// operator: it stops a compromised agent from making the server call hosts
// on the internal network.
var DefaultRegistries = []string{"docker.io", "ghcr.io", "quay.io", "lscr.io", "gcr.io", "registry.k8s.io", "mcr.microsoft.com", "public.ecr.aws"}

// ErrNotAllowed: the request would have gone to a host off the allowlist.
var ErrNotAllowed = errors.New("registry is not on the allowlist")

// Options configure a Checker.
type Options struct {
	Registries   []string            // allowed on top of DefaultRegistries
	DockerConfig string              // directory holding config.json ("" = none)
	Getenv       func(string) string // SYFT_/GRYPE_REGISTRY_AUTH_*; nil = os.Getenv
	UserAgent    string              // e.g. labwarden/v0.3.0
	Timeout      time.Duration       // per registry call; 0 = 20 s
	Transport    http.RoundTripper   // nil = remote.DefaultTransport
	Log          *slog.Logger        // nil = slog.Default()
}

// Checker asks registries what a running tag points at now and which newer
// tags exist. It only sends HEAD requests for manifests (Docker Hub does not
// count those as pulls) and one tag list per repository.
type Checker struct {
	allow   map[string]bool
	creds   []string
	keys    authn.Keychain
	opts    []remote.Option
	timeout time.Duration
}

// NewChecker builds the allowlist and the keychain. Credentials come from
// SYFT_REGISTRY_AUTH_* (falling back per key to GRYPE_REGISTRY_AUTH_*, as
// for central scans) and from the inline "auths" of $DOCKER_CONFIG/config.json.
// Credential helpers are not in the image, so credsStore and credHelpers are
// ignored with a warning.
func NewChecker(o Options) (*Checker, error) {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.Transport == nil {
		o.Transport = remote.DefaultTransport
	}
	c := &Checker{allow: map[string]bool{}, timeout: o.Timeout}
	for _, r := range append(slices.Clone(DefaultRegistries), o.Registries...) {
		if r = canonicalRegistry(r); r != "" {
			c.allow[r] = true
		}
	}

	env := envKeychain(o.Getenv)
	file, err := fileKeychain(o.DockerConfig, o.Log)
	if err != nil {
		return nil, err
	}
	for r := range env {
		c.creds = append(c.creds, r)
	}
	for r := range file {
		if env[r] == nil {
			c.creds = append(c.creds, r)
		}
	}
	slices.Sort(c.creds)
	for _, r := range c.creds {
		c.allow[r] = true // credentials for a registry allow it
	}
	c.keys = authn.NewMultiKeychain(env, file)

	g := &guard{inner: o.Transport, allowed: c.Allowed, realms: map[string]bool{}}
	c.opts = []remote.Option{
		remote.WithAuthFromKeychain(c.keys),
		remote.WithTransport(g),
		remote.WithUserAgent(o.UserAgent),
		// Not 429: a rate limit waits for the next interval, not for a retry.
		remote.WithRetryStatusCodes(http.StatusRequestTimeout, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout),
	}
	return c, nil
}

// Allowed reports whether registry (a host, "docker.io" or "localhost:5000")
// may be queried.
func (c *Checker) Allowed(registry string) bool { return c.allow[canonicalRegistry(registry)] }

// Registries lists the allowed registries.
func (c *Checker) Registries() []string {
	out := make([]string, 0, len(c.allow))
	for r := range c.allow {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

// Credentials lists the registries that have credentials: host names only.
func (c *Checker) Credentials() []string { return slices.Clone(c.creds) }

// Check looks up the running tags of one repository (a normalised name such
// as docker.io/library/nginx). Every tag gets a Result.
func (c *Checker) Check(ctx context.Context, repository string, tags []string) map[string]Result {
	out := make(map[string]Result, len(tags))
	all := func(r Result) map[string]Result {
		for _, t := range tags {
			if _, done := out[t]; !done {
				out[t] = r
			}
		}
		return out
	}
	repo, err := name.NewRepository(repository)
	if err != nil {
		return all(Result{Outcome: Failed, Error: "not a repository name"})
	}
	if !c.Allowed(repo.RegistryStr()) {
		return all(Result{Outcome: NotAllowed, Error: fmt.Sprintf("%s is not on the registry allowlist", canonicalRegistry(repo.RegistryStr()))})
	}

	var list []string
	listed := false
	if slices.ContainsFunc(tags, Versioned) {
		cctx, cancel := context.WithTimeout(ctx, c.timeout)
		list, err = remote.List(repo, append(c.opts, remote.WithContext(cctx))...)
		cancel()
		if err != nil {
			if o, msg := classify(err); o == RateLimited {
				return all(Result{Outcome: o, Error: msg})
			}
		}
		listed = err == nil // else newer tags stay unknown; the digest check still runs
	}
	for _, tag := range tags {
		cctx, cancel := context.WithTimeout(ctx, c.timeout)
		desc, err := remote.Head(repo.Tag(tag), append(c.opts, remote.WithContext(cctx))...)
		cancel()
		if err != nil {
			o, msg := classify(err)
			out[tag] = Result{Outcome: o, Error: msg}
			if o == RateLimited {
				return all(out[tag])
			}
			continue
		}
		r := Result{Digest: desc.Digest.String(), Outcome: OK, Listed: listed || !Versioned(tag)}
		r.Newest, r.NewestInMajor = Newer(tag, list)
		out[tag] = r
	}
	return out
}

// classify turns a registry error into an outcome and a short message.
func classify(err error) (Outcome, string) {
	if errors.Is(err, ErrNotAllowed) {
		return NotAllowed, truncate(err.Error())
	}
	var te *transport.Error
	if errors.As(err, &te) {
		if te.StatusCode == http.StatusTooManyRequests || hasCode(te, transport.TooManyRequestsErrorCode) {
			return RateLimited, "rate limited by the registry"
		}
		// Registries answer 401 or 403 for a repository that does not exist,
		// so these read the same as a 404.
		switch te.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return NotFound, "not found upstream, or it needs credentials"
		}
		if hasCode(te, transport.NameUnknownErrorCode, transport.ManifestUnknownErrorCode, transport.DeniedErrorCode, transport.UnauthorizedErrorCode) {
			return NotFound, "not found upstream, or it needs credentials"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Failed, "the registry did not answer in time"
	}
	return Failed, truncate(err.Error())
}

func hasCode(te *transport.Error, codes ...transport.ErrorCode) bool {
	for _, d := range te.Errors {
		if slices.Contains(codes, d.Code) {
			return true
		}
	}
	return false
}

func truncate(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// canonicalRegistry is the allowlist key of a registry: lower case, no
// scheme or path, and Docker Hub's hosts all named docker.io.
func canonicalRegistry(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	s, _, _ = strings.Cut(s, "/")
	switch s {
	case "index.docker.io", "registry-1.docker.io":
		return "docker.io"
	}
	return s
}

// guard sends requests only to allowed registries and to the token servers
// they name. It sits under ggcr's client, so every redirect hop passes it.
type guard struct {
	inner   http.RoundTripper
	allowed func(string) bool
	mu      sync.Mutex
	realms  map[string]bool
}

var realmRe = regexp.MustCompile(`(?i)realm="([^"]+)"`)

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	host := strings.ToLower(req.URL.Host)
	g.mu.Lock()
	realm := g.realms[host]
	g.mu.Unlock()
	if !realm && !g.allowed(host) {
		return nil, fmt.Errorf("%w: %s", ErrNotAllowed, host)
	}
	resp, err := g.inner.RoundTrip(req)
	// An allowed registry's challenge names its token server (auth.docker.io
	// for Docker Hub): that host may be asked for a token.
	if err == nil && resp.StatusCode == http.StatusUnauthorized && !realm {
		for _, h := range resp.Header.Values("WWW-Authenticate") {
			if m := realmRe.FindStringSubmatch(h); m != nil {
				if u, err := url.Parse(m[1]); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
					g.mu.Lock()
					g.realms[strings.ToLower(u.Host)] = true
					g.mu.Unlock()
				}
			}
		}
	}
	return resp, err
}

// keychain maps a canonical registry to its credentials.
type keychain map[string]*authn.AuthConfig

func (k keychain) Resolve(r authn.Resource) (authn.Authenticator, error) {
	if cfg := k[canonicalRegistry(r.RegistryStr())]; cfg != nil {
		return authn.FromConfig(*cfg), nil
	}
	return authn.Anonymous, nil
}

// envKeychain reads the one registry credential central scans use:
// SYFT_REGISTRY_AUTH_{AUTHORITY,USERNAME,PASSWORD,TOKEN}, each falling back
// to its GRYPE_REGISTRY_AUTH_ twin.
func envKeychain(getenv func(string) string) keychain {
	get := func(k string) string {
		if v := getenv("SYFT_REGISTRY_AUTH_" + k); v != "" {
			return v
		}
		return getenv("GRYPE_REGISTRY_AUTH_" + k)
	}
	authority := canonicalRegistry(get("AUTHORITY"))
	cfg := authn.AuthConfig{Username: get("USERNAME"), Password: get("PASSWORD"), RegistryToken: get("TOKEN")}
	if authority == "" || (cfg.Username == "" && cfg.Password == "" && cfg.RegistryToken == "") {
		return keychain{}
	}
	return keychain{authority: &cfg}
}

// fileKeychain reads the inline "auths" of dir/config.json. A missing file
// means no credentials; a file that does not parse is an error.
func fileKeychain(dir string, log *slog.Logger) (keychain, error) {
	k := keychain{}
	if dir == "" {
		return k, nil
	}
	path := filepath.Join(dir, "config.json")
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		log.Warn("registry credentials: no config.json in DOCKER_CONFIG", "path", path)
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("registry credentials: %w", err)
	}
	defer f.Close()
	cf := configfile.New(path)
	if err := cf.LoadFromReader(f); err != nil {
		// The decoder's message can quote the file; keep it out of the log.
		return nil, fmt.Errorf("registry credentials: %s does not parse as a Docker config.json", path)
	}
	if cf.CredentialsStore != "" || len(cf.CredentialHelpers) > 0 {
		log.Warn("registry credentials: credsStore and credHelpers are ignored, only inline auths are read", "path", path)
	}
	for host, a := range cf.AuthConfigs {
		cfg := authn.AuthConfig{Username: a.Username, Password: a.Password, IdentityToken: a.IdentityToken, RegistryToken: a.RegistryToken}
		if r := canonicalRegistry(host); r != "" && (cfg.Username != "" || cfg.Password != "" || cfg.IdentityToken != "" || cfg.RegistryToken != "") {
			k[r] = &cfg
		}
	}
	return k, nil
}
