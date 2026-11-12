package api

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/amanahlab/labwarden/server/internal/registry"
	"github.com/amanahlab/labwarden/server/internal/store"
)

// maxImages caps the containers one run may report; at about 400 bytes each
// it stays well inside decodeJSON's 1 MiB.
const maxImages = 1000

// imageIn is one running container in an agent's final run report.
type imageIn struct {
	Container   string   `json:"container"`
	Ref         string   `json:"ref"`
	ImageID     string   `json:"image_id"`
	RepoDigests []string `json:"repo_digests"`
	Created     string   `json:"created"`
}

// containerImages validates an agent's container list. Entries that make no
// sense are dropped (and counted) rather than failing the whole run, so one
// odd container cannot hide all the others.
func containerImages(in []imageIn) (out []store.ContainerImage, dropped int, err error) {
	if len(in) > maxImages {
		return nil, 0, fmt.Errorf("at most %d images per run", maxImages)
	}
	out = make([]store.ContainerImage, 0, len(in))
	seen := map[string]bool{}
	for _, c := range in {
		ci, ok := containerImage(c)
		if !ok || seen[ci.Container] {
			dropped++
			continue
		}
		seen[ci.Container] = true
		out = append(out, ci)
	}
	return out, dropped, nil
}

func containerImage(c imageIn) (store.ContainerImage, bool) {
	ci := store.ContainerImage{
		Container: strings.TrimPrefix(clean(c.Container, 256), "/"),
		Ref:       clean(c.Ref, 512),
		ImageID:   strings.TrimSpace(c.ImageID),
	}
	if ci.Container == "" || !registry.ValidDigest(ci.ImageID) {
		return ci, false
	}
	ref, err := registry.ParseRef(ci.Ref)
	switch {
	case errors.Is(err, registry.ErrImageID):
		// Started from an image ID: listed, but there is nothing to compare.
	case err != nil:
		return ci, false
	default:
		ci.Registry, ci.Repository, ci.Tag, ci.PinnedDigest = ref.Registry, ref.Repository, ref.Tag, ref.Digest
		if len(c.RepoDigests) > 64 {
			c.RepoDigests = c.RepoDigests[:64]
		}
		ci.RepoDigest = registry.RepoDigest(ref.Repository, c.RepoDigests)
	}
	ci.ImageCreated = buildTime(c.Created)
	return ci, true
}

// buildTime keeps a believable image build time. Reproducible builds stamp
// the epoch (SOURCE_DATE_EPOCH) and some daemons report the zero time; those
// are no age at all.
func buildTime(s string) string {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil || t.Year() < 2000 || t.After(time.Now().Add(24*time.Hour)) {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Server) listImages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ImageFilter{Q: strings.TrimSpace(q.Get("q")), HostID: qInt64(r, "host"), Registry: q.Get("registry")}
	if st := q.Get("status"); slices.Contains(store.ImageStatuses, st) {
		f.Status = st
	}
	out, err := s.st.ListImages(r.Context(), f, pageFrom(r))
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listImageRegistries(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ImageRegistries(r.Context())
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
