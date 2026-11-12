package store

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/amanahlab/labwarden/server/internal/registry"
)

// ContainerImage is one running container and the image it runs, as an agent
// reported it (validated and normalised by the API).
type ContainerImage struct {
	Container    string
	Ref          string
	Registry     string
	Repository   string
	Tag          string
	PinnedDigest string
	ImageID      string
	RepoDigest   string
	ImageCreated string // RFC 3339, "" = unknown
}

// ReplaceHostImages makes imgs the complete list of containers running on
// host: new ones are added, known ones refreshed, missing ones removed.
func (s *Store) ReplaceHostImages(ctx context.Context, host string, imgs []ContainerImage) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var hostID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE name=?`, host).Scan(&hostID); err != nil {
		return err
	}
	ts := now()
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO container_images(host_id, container, ref, registry, repository, tag, pinned_digest, image_id, repo_digest, image_created, first_seen, last_seen)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(host_id, container) DO UPDATE SET
		  ref=excluded.ref, registry=excluded.registry, repository=excluded.repository, tag=excluded.tag,
		  pinned_digest=excluded.pinned_digest, image_id=excluded.image_id, repo_digest=excluded.repo_digest,
		  image_created=excluded.image_created, last_seen=excluded.last_seen,
		  first_seen=CASE WHEN container_images.image_id = excluded.image_id THEN container_images.first_seen ELSE excluded.first_seen END`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, c := range imgs {
		if _, err := stmt.ExecContext(ctx, hostID, c.Container, c.Ref, c.Registry, c.Repository, c.Tag, c.PinnedDigest,
			c.ImageID, c.RepoDigest, c.ImageCreated, ts, ts); err != nil {
			return err
		}
	}
	// Everything not reported has stopped running.
	q := `DELETE FROM container_images WHERE host_id=?`
	args := []any{hostID}
	if len(imgs) > 0 {
		q += ` AND container NOT IN (` + strings.TrimSuffix(strings.Repeat("?,", len(imgs)), ",") + `)`
		for _, c := range imgs {
			args = append(args, c.Container)
		}
	}
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return err
	}
	return tx.Commit()
}

// ImageHost is a host running an image, with the containers that run it.
type ImageHost struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name"`
	Containers []string `json:"containers"`
}

// ImageRow is one image running somewhere: a repository and tag at one
// digest, across every host that runs it.
type ImageRow struct {
	Name         string      `json:"name"` // short form: nginx, ghcr.io/x/y
	Repository   string      `json:"repository"`
	Registry     string      `json:"registry"`
	Tag          string      `json:"tag"`
	Ref          string      `json:"ref"`
	PinnedDigest string      `json:"pinned_digest"`
	Digest       string      `json:"digest"` // the digest it was pulled at; "" = local build
	ImageID      string      `json:"image_id"`
	ImageCreated string      `json:"image_created"`
	Status       string      `json:"status"`
	Hosts        []ImageHost `json:"hosts"`
	Containers   int         `json:"containers"`
	FirstSeen    string      `json:"first_seen"`
	LastSeen     string      `json:"last_seen"`
}

// ImageStatuses are the values of ImageRow.Status. Upstream checks (current,
// outdated, error) come with the registry checker.
var ImageStatuses = []string{"local", "pinned", "unchecked"}

// imageStatusSQL works on the grouped columns of imageGroupSQL.
const imageStatusSQL = `CASE WHEN g.digest = '' THEN 'local' WHEN g.tag = '' THEN 'pinned' ELSE 'unchecked' END`

// imageGroupSQL groups containers into images. Local builds have no repo
// digest and are told apart by image ID. The %s takes the WHERE clause.
const imageGroupSQL = `SELECT ci.repository, ci.registry, ci.tag, ci.pinned_digest, ci.repo_digest AS digest,
	MIN(ci.ref) AS ref, MIN(ci.image_id) AS image_id, MIN(ci.image_created) AS image_created,
	COUNT(*) AS containers, COUNT(DISTINCT ci.host_id) AS hosts, MIN(ci.first_seen) AS first_seen, MAX(ci.last_seen) AS last_seen,
	json_group_array(json_object('id', h.id, 'name', h.name, 'container', ci.container)) AS members
	FROM container_images ci JOIN hosts h ON h.id = ci.host_id%s
	GROUP BY ci.repository, ci.tag, ci.pinned_digest, CASE WHEN ci.repo_digest = '' THEN ci.image_id ELSE ci.repo_digest END`

var imageSorts = map[string]string{
	"name":       "g.repository",
	"tag":        "g.tag",
	"hosts":      "g.hosts",
	"containers": "g.containers",
	"status":     "status",
	"created":    "g.image_created",
	"first_seen": "g.first_seen",
}

// ImageFilter narrows the Images page.
type ImageFilter struct {
	Q        string
	HostID   int64
	Registry string
	Status   string
}

func (s *Store) ListImages(ctx context.Context, f ImageFilter, p Page) (*List[ImageRow], error) {
	p.norm()
	var inner where
	if f.Q != "" {
		inner.add(`(ci.repository LIKE ? ESCAPE '\' OR ci.tag LIKE ? ESCAPE '\' OR ci.container LIKE ? ESCAPE '\' OR h.name LIKE ? ESCAPE '\')`,
			like(f.Q), like(f.Q), like(f.Q), like(f.Q))
	}
	if f.HostID > 0 {
		inner.add("ci.host_id = ?", f.HostID)
	}
	if f.Registry != "" {
		inner.add("ci.registry = ?", f.Registry)
	}
	var outer where
	if f.Status != "" {
		outer.add(imageStatusSQL+" = ?", f.Status)
	}
	from := ` FROM (` + strings.Replace(imageGroupSQL, "%s", inner.sql(), 1) + `) g` + outer.sql()
	args := append(append([]any{}, inner.args...), outer.args...)

	out := &List[ImageRow]{Items: []ImageRow{}, Page: p.Page, Size: p.Size}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*)`+from, args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	q := `SELECT g.repository, g.registry, g.tag, g.pinned_digest, g.digest, g.ref, g.image_id, g.image_created,
		` + imageStatusSQL + ` AS status, g.containers, g.first_seen, g.last_seen, g.members` +
		from + p.orderBy(imageSorts, "name", "g.repository, g.tag, g.digest")
	rows, err := s.r.QueryContext(ctx, q+p.limit(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ImageRow
		var members string
		if err := rows.Scan(&r.Repository, &r.Registry, &r.Tag, &r.PinnedDigest, &r.Digest, &r.Ref, &r.ImageID, &r.ImageCreated,
			&r.Status, &r.Containers, &r.FirstSeen, &r.LastSeen, &members); err != nil {
			return nil, err
		}
		r.Name = registry.ShortName(r.Repository)
		if r.Repository == "" { // started from an image ID
			r.Name = shortID(r.ImageID)
		}
		if r.Hosts, err = imageHosts(members); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, r)
	}
	return out, rows.Err()
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}

// imageHosts folds the per-container JSON of a group into hosts.
func imageHosts(members string) ([]ImageHost, error) {
	var ms []struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		Container string `json:"container"`
	}
	if err := json.Unmarshal([]byte(members), &ms); err != nil {
		return nil, err
	}
	var out []ImageHost
	idx := map[int64]int{}
	for _, m := range ms {
		i, ok := idx[m.ID]
		if !ok {
			i = len(out)
			idx[m.ID] = i
			out = append(out, ImageHost{ID: m.ID, Name: m.Name})
		}
		out[i].Containers = append(out[i].Containers, m.Container)
	}
	return out, nil
}

// ImageRegistries lists the registries of running images, for the filter.
func (s *Store) ImageRegistries(ctx context.Context) ([]string, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT DISTINCT registry FROM container_images WHERE registry <> '' ORDER BY registry`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
