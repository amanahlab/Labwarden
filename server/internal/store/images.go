package store

import (
	"context"
	"database/sql"
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

	// From the last registry check of repository:tag.
	UpstreamDigest string `json:"upstream_digest"`
	Drift          bool   `json:"drift"` // the tag points at another build upstream
	NewestTag      string `json:"newest_tag"`
	NewestInMajor  string `json:"newest_in_major"`
	CheckedAt      string `json:"checked_at"`
	CheckError     string `json:"check_error"`  // why the last check did not finish
	UpdateSince    string `json:"update_since"` // since when an update is available
}

// ImageStatuses are the values of ImageRow.Status.
var ImageStatuses = []string{"local", "pinned", "unchecked", "current", "outdated", "not_found", "error"}

// imageStatusSQL works on the grouped columns of imageGroupSQL (g) joined
// with image_upstream (u). A check that failed after an earlier good one
// keeps the earlier result; check_error says why it is old.
const imageStatusSQL = `CASE
	WHEN g.digest = '' THEN 'local'
	WHEN g.tag = '' THEN 'pinned'
	WHEN u.outcome IS NULL OR u.outcome = 'not_allowed' THEN 'unchecked'
	WHEN u.outcome = 'not_found' THEN 'not_found'
	WHEN u.digest = '' THEN 'error'
	WHEN u.newest_tag <> '' OR (g.pinned_digest = '' AND u.digest <> g.digest) THEN 'outdated'
	ELSE 'current' END`

// checkableImageSQL picks the containers (ci) whose image can be checked:
// pulled (or pinned) from a repository under a tag.
const checkableImageSQL = `ci.repository <> '' AND ci.tag <> '' AND (ci.repo_digest <> '' OR ci.pinned_digest <> '')`

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
	"checked":    "u.checked_at",
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
	from := ` FROM (` + strings.Replace(imageGroupSQL, "%s", inner.sql(), 1) + `) g
		LEFT JOIN image_upstream u ON u.repository = g.repository AND u.tag = g.tag` + outer.sql()
	args := append(append([]any{}, inner.args...), outer.args...)

	out := &List[ImageRow]{Items: []ImageRow{}, Page: p.Page, Size: p.Size}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*)`+from, args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	q := `SELECT g.repository, g.registry, g.tag, g.pinned_digest, g.digest, g.ref, g.image_id, g.image_created,
		` + imageStatusSQL + ` AS status, g.containers, g.first_seen, g.last_seen, g.members,
		COALESCE(u.digest, ''), COALESCE(u.digest_since, ''), COALESCE(u.newest_tag, ''), COALESCE(u.newest_in_major, ''),
		COALESCE(u.newest_since, ''), COALESCE(u.checked_at, ''), COALESCE(u.outcome, ''), COALESCE(u.error, '')` +
		from + p.orderBy(imageSorts, "name", "g.repository, g.tag, g.digest")
	rows, err := s.r.QueryContext(ctx, q+p.limit(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ImageRow
		var members, digestSince, newestSince, outcome string
		if err := rows.Scan(&r.Repository, &r.Registry, &r.Tag, &r.PinnedDigest, &r.Digest, &r.Ref, &r.ImageID, &r.ImageCreated,
			&r.Status, &r.Containers, &r.FirstSeen, &r.LastSeen, &members,
			&r.UpstreamDigest, &digestSince, &r.NewestTag, &r.NewestInMajor, &newestSince, &r.CheckedAt, &outcome, &r.CheckError); err != nil {
			return nil, err
		}
		r.upstream(digestSince, newestSince, outcome)
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

// upstream fills in what the row's status needs from the last check.
func (r *ImageRow) upstream(digestSince, newestSince, outcome string) {
	if r.Status == "local" || r.Status == "pinned" {
		r.UpstreamDigest, r.NewestTag, r.NewestInMajor, r.CheckedAt, r.CheckError = "", "", "", "", ""
		return
	}
	if outcome == string(registry.OK) {
		r.CheckError = ""
	}
	r.Drift = r.PinnedDigest == "" && r.UpstreamDigest != "" && r.UpstreamDigest != r.Digest
	// The update is as old as the oldest thing that makes the row outdated.
	if r.Drift {
		r.UpdateSince = digestSince
	}
	if r.NewestTag != "" && newestSince != "" && (r.UpdateSince == "" || newestSince < r.UpdateSince) {
		r.UpdateSince = newestSince
	}
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

// ImageTags lists the running tags of repository that can be checked.
func (s *Store) ImageTags(ctx context.Context, repository string) ([]string, error) {
	return s.strings(ctx, `SELECT DISTINCT ci.tag FROM container_images ci WHERE ci.repository = ? AND `+checkableImageSQL+` ORDER BY ci.tag`, repository)
}

// UncheckedImageRepositories lists the repositories running on host that
// have a tag never checked upstream.
func (s *Store) UncheckedImageRepositories(ctx context.Context, host string) ([]string, error) {
	return s.strings(ctx, `SELECT DISTINCT ci.repository FROM container_images ci JOIN hosts h ON h.id = ci.host_id
		WHERE h.name = ? AND `+checkableImageSQL+`
		  AND NOT EXISTS (SELECT 1 FROM image_upstream u WHERE u.repository = ci.repository AND u.tag = ci.tag)
		ORDER BY ci.repository`, host)
}

// DueImageRepositories lists the running repositories with a tag not
// checked since before (RFC 3339); before = "" lists them all.
func (s *Store) DueImageRepositories(ctx context.Context, before string) ([]string, error) {
	return s.strings(ctx, `SELECT DISTINCT ci.repository FROM container_images ci
		LEFT JOIN image_upstream u ON u.repository = ci.repository AND u.tag = ci.tag
		WHERE `+checkableImageSQL+` AND (? = '' OR u.checked_at IS NULL OR u.checked_at < ?)
		ORDER BY ci.repository`, before, before)
}

// SaveImageCheck records a registry check of repository:tag. The digest
// keeps its first-seen time until it changes; a newer tag keeps its time
// while one stays available. A failed check updates only the outcome, so the
// last good result stays on the page.
func (s *Store) SaveImageCheck(ctx context.Context, repository, tag string, r registry.Result) error {
	ts := now()
	if r.Outcome != registry.OK {
		_, err := s.w.ExecContext(ctx, `
			INSERT INTO image_upstream(repository, tag, outcome, error, checked_at) VALUES (?,?,?,?,?)
			ON CONFLICT(repository, tag) DO UPDATE SET outcome=excluded.outcome, error=excluded.error, checked_at=excluded.checked_at`,
			repository, tag, string(r.Outcome), r.Error, ts)
		return err
	}
	_, err := s.w.ExecContext(ctx, `
		INSERT INTO image_upstream(repository, tag, digest, digest_since, newest_tag, newest_in_major, newest_since, outcome, error, checked_at)
		VALUES (?1, ?2, ?3, ?4, ?5, ?6, CASE WHEN ?5 = '' THEN NULL ELSE ?4 END, 'ok', '', ?4)
		ON CONFLICT(repository, tag) DO UPDATE SET
		  digest_since = CASE WHEN image_upstream.digest = excluded.digest THEN image_upstream.digest_since ELSE excluded.digest_since END,
		  digest = excluded.digest,
		  newest_since = CASE WHEN NOT ?7 THEN image_upstream.newest_since
		                      WHEN excluded.newest_tag = '' THEN NULL
		                      ELSE COALESCE(image_upstream.newest_since, excluded.newest_since) END,
		  newest_tag = CASE WHEN ?7 THEN excluded.newest_tag ELSE image_upstream.newest_tag END,
		  newest_in_major = CASE WHEN ?7 THEN excluded.newest_in_major ELSE image_upstream.newest_in_major END,
		  outcome = 'ok', error = '', checked_at = excluded.checked_at`,
		repository, tag, r.Digest, ts, r.Newest, r.NewestInMajor, r.Listed)
	return err
}

// PruneImageChecks forgets the checks of tags no container runs any more.
func (s *Store) PruneImageChecks(ctx context.Context) (int64, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM image_upstream WHERE NOT EXISTS (
		SELECT 1 FROM container_images ci WHERE ci.repository = image_upstream.repository AND ci.tag = image_upstream.tag AND `+checkableImageSQL+`)`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// LastImageCheck is when a registry check last ran ("" = never).
func (s *Store) LastImageCheck(ctx context.Context) (string, error) {
	var t sql.NullString
	err := s.r.QueryRowContext(ctx, `SELECT MAX(checked_at) FROM image_upstream`).Scan(&t)
	return t.String, err
}

func (s *Store) strings(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
