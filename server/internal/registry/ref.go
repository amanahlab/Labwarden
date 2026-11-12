// Package registry understands container image references and, in time,
// asks registries whether a running image is still current.
//
// References are parsed with github.com/distribution/reference, the parser
// Docker itself uses, so a name means here what it meant to the daemon.
package registry

import (
	"errors"
	"strings"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

// ErrImageID: the container was started from an image ID, which names no
// repository.
var ErrImageID = errors.New("an image ID, not a repository reference")

// Ref is a parsed, normalised image reference.
type Ref struct {
	Registry   string // docker.io, ghcr.io, …
	Repository string // full name: docker.io/library/nginx
	Tag        string // "" when the reference is a bare digest
	Digest     string // pinned digest of repo:tag@sha256:… or repo@sha256:…, else ""
}

// ParseRef normalises what a container was started from (docker's
// Config.Image): "nginx" becomes docker.io/library/nginx:latest. A tag next
// to a pinned digest is kept.
func ParseRef(s string) (Ref, error) {
	parsed, err := reference.ParseAnyReference(strings.TrimSpace(s))
	if err != nil {
		return Ref{}, err
	}
	named, ok := parsed.(reference.Named)
	if !ok {
		return Ref{}, ErrImageID
	}
	named = reference.TagNameOnly(named) // adds :latest only to a bare name
	r := Ref{Registry: reference.Domain(named), Repository: named.Name()}
	if t, ok := named.(reference.Tagged); ok {
		r.Tag = t.Tag()
	}
	if d, ok := named.(reference.Digested); ok {
		if !ValidDigest(d.Digest().String()) {
			return Ref{}, errors.New("only sha256 digests are supported")
		}
		r.Digest = d.Digest().String()
	}
	return r, nil
}

// ValidDigest accepts only a well-formed sha256 digest ("sha256:<64 hex>").
func ValidDigest(s string) bool {
	d, err := digest.Parse(s)
	return err == nil && d.Algorithm() == digest.SHA256
}

// RepoDigest picks, from docker's RepoDigests ("nginx@sha256:…"), the digest
// recorded for repository. "" means the image was not pulled from there
// (built locally, or pulled under another name).
func RepoDigest(repository string, repoDigests []string) string {
	for _, rd := range repoDigests {
		named, err := reference.ParseNormalizedNamed(strings.TrimSpace(rd))
		if err != nil || named.Name() != repository {
			continue
		}
		if d, ok := named.(reference.Digested); ok && ValidDigest(d.Digest().String()) {
			return d.Digest().String()
		}
	}
	return ""
}

// ShortName is how people write a repository ("nginx", "grafana/grafana",
// "ghcr.io/x/y"); repository must be a normalised name.
func ShortName(repository string) string {
	named, err := reference.ParseNormalizedNamed(repository)
	if err != nil {
		return repository
	}
	return reference.FamiliarName(named)
}
