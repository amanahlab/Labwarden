package store

// migrations are applied in order and never edited once released.
// Append new statements to the end.
var migrations = []string{
	`
CREATE TABLE hosts (
  id            INTEGER PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  kind          TEXT NOT NULL DEFAULT 'vm',      -- vm | docker | central
  grp           TEXT NOT NULL DEFAULT 'default',
  os            TEXT NOT NULL DEFAULT '',
  arch          TEXT NOT NULL DEFAULT '',
  ip            TEXT NOT NULL DEFAULT '',
  agent_version TEXT NOT NULL DEFAULT '',
  notes         TEXT NOT NULL DEFAULT '',
  interval_sec  INTEGER NOT NULL DEFAULT 0,      -- agent's declared scan interval
  first_seen    TEXT NOT NULL,
  last_seen     TEXT NOT NULL,
  last_run_status TEXT NOT NULL DEFAULT ''
);

CREATE TABLE targets (
  id             INTEGER PRIMARY KEY,
  host_id        INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  name           TEXT NOT NULL,
  type           TEXT NOT NULL,                  -- filesystem | image | sbom
  distro         TEXT NOT NULL DEFAULT '',
  latest_scan_id INTEGER,
  first_seen     TEXT NOT NULL,
  last_scanned   TEXT NOT NULL,
  retired_at     TEXT,
  UNIQUE(host_id, name)
);

CREATE TABLE scans (
  id            INTEGER PRIMARY KEY,
  target_id     INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  source        TEXT NOT NULL DEFAULT 'agent',   -- agent | server
  run_id        TEXT NOT NULL DEFAULT '',
  grype_version TEXT NOT NULL DEFAULT '',
  db_built      TEXT NOT NULL DEFAULT '',
  scanned_at    TEXT NOT NULL,
  received_at   TEXT NOT NULL,
  duration_ms   INTEGER NOT NULL DEFAULT 0,
  critical INTEGER NOT NULL DEFAULT 0,
  high     INTEGER NOT NULL DEFAULT 0,
  medium   INTEGER NOT NULL DEFAULT 0,
  low      INTEGER NOT NULL DEFAULT 0,
  negligible INTEGER NOT NULL DEFAULT 0,
  unknown  INTEGER NOT NULL DEFAULT 0,
  total    INTEGER NOT NULL DEFAULT 0,
  fixable  INTEGER NOT NULL DEFAULT 0,
  new_count   INTEGER NOT NULL DEFAULT 0,
  fixed_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX scans_target ON scans(target_id, id DESC);
CREATE INDEX scans_host ON scans(host_id, id DESC);

CREATE TABLE vulns (
  id          TEXT PRIMARY KEY,
  severity    TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  data_source TEXT NOT NULL DEFAULT '',
  namespace   TEXT NOT NULL DEFAULT '',
  urls        TEXT NOT NULL DEFAULT '[]',
  cvss_score  REAL NOT NULL DEFAULT 0,
  cvss_vector TEXT NOT NULL DEFAULT '',
  epss        REAL NOT NULL DEFAULT 0,
  epss_pct    REAL NOT NULL DEFAULT 0,
  kev         INTEGER NOT NULL DEFAULT 0,
  cwes        TEXT NOT NULL DEFAULT '',
  aliases     TEXT NOT NULL DEFAULT '',
  risk        REAL NOT NULL DEFAULT 0,
  first_seen  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE findings (
  id          INTEGER PRIMARY KEY,
  scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  vuln_id     TEXT NOT NULL,
  severity    TEXT NOT NULL,
  sev_rank    INTEGER NOT NULL,
  pkg_name    TEXT NOT NULL,
  pkg_version TEXT NOT NULL,
  pkg_type    TEXT NOT NULL,
  purl        TEXT NOT NULL DEFAULT '',
  location    TEXT NOT NULL DEFAULT '',
  fix_state   TEXT NOT NULL,
  fix_versions TEXT NOT NULL DEFAULT '',
  risk        REAL NOT NULL DEFAULT 0,
  epss        REAL NOT NULL DEFAULT 0,
  kev         INTEGER NOT NULL DEFAULT 0,
  cvss_score  REAL NOT NULL DEFAULT 0,
  first_seen  TEXT NOT NULL                       -- first time this vuln+pkg was seen on the target
);
CREATE INDEX findings_scan ON findings(scan_id);
CREATE INDEX findings_vuln ON findings(vuln_id);

CREATE TABLE triage (
  vuln_id    TEXT NOT NULL,
  host_id    INTEGER NOT NULL DEFAULT 0,         -- 0 = applies to every host
  status     TEXT NOT NULL,                      -- open | acknowledged | ignored | false_positive
  note       TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (vuln_id, host_id)
);

CREATE TABLE events (
  id      INTEGER PRIMARY KEY,
  ts      TEXT NOT NULL,
  level   TEXT NOT NULL,                         -- info | warn | error
  source  TEXT NOT NULL,                         -- agent | ingest | scanner | auth | system
  host    TEXT NOT NULL DEFAULT '',
  run_id  TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL
);
CREATE INDEX events_ts ON events(id DESC);

CREATE TABLE tokens (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  prefix     TEXT NOT NULL,
  hash       TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_used  TEXT
);

CREATE TABLE stats_daily (
  day        TEXT PRIMARY KEY,
  critical INTEGER NOT NULL, high INTEGER NOT NULL, medium INTEGER NOT NULL,
  low INTEGER NOT NULL, negligible INTEGER NOT NULL, unknown INTEGER NOT NULL,
  total INTEGER NOT NULL, fixable INTEGER NOT NULL, hosts INTEGER NOT NULL, kev INTEGER NOT NULL
);

CREATE TABLE central_targets (
  id         INTEGER PRIMARY KEY,
  ref        TEXT NOT NULL UNIQUE,               -- image reference, scanned via registry:
  host_name  TEXT NOT NULL,
  grp        TEXT NOT NULL DEFAULT 'central',
  interval_min INTEGER NOT NULL DEFAULT 1440,
  enabled    INTEGER NOT NULL DEFAULT 1,
  last_run   TEXT,
  last_status TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

-- Findings from the latest scan of every live target, with effective triage
-- status (host-specific triage wins over global).
CREATE VIEW current_findings AS
SELECT f.*, t.id AS target_id, t.name AS target_name, t.type AS target_type,
       h.id AS host_id, h.name AS host_name, h.grp AS grp, h.kind AS host_kind,
       COALESCE(th.status, tg.status, 'open') AS status
FROM findings f
JOIN targets t ON t.latest_scan_id = f.scan_id AND t.retired_at IS NULL
JOIN hosts h ON h.id = t.host_id
LEFT JOIN triage th ON th.vuln_id = f.vuln_id AND th.host_id = h.id
LEFT JOIN triage tg ON tg.vuln_id = f.vuln_id AND tg.host_id = 0;
`,
	// 2: the latest SBOM of each target, so a new vulnerability DB can be
	// matched against every host without waiting for its agent.
	`
CREATE TABLE target_sboms (
  target_id   INTEGER PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
  sha256      TEXT NOT NULL,                     -- file in <data>/sboms
  size_bytes  INTEGER NOT NULL,
  meta        TEXT NOT NULL,                     -- IngestMeta JSON to re-ingest with
  received_at TEXT NOT NULL
);
`,
	// 3: admin sessions, so they can be revoked. Only a hash of the session
	// ID is stored; pw_fp ties a session to the password it was opened with.
	`
CREATE TABLE sessions (
  id_hash    TEXT PRIMARY KEY,                   -- SHA-256 of the cookie value
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  ip         TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  pw_fp      TEXT NOT NULL                       -- HMAC of the admin password
);
CREATE INDEX sessions_expiry ON sessions(expires_at);
`,
	// 4: tokens become enrollment tokens (they can expire, be used up and be
	// revoked) and each enrolled host gets its own agent credential.
	`
ALTER TABLE tokens ADD COLUMN expires_at TEXT;
ALTER TABLE tokens ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 0;   -- 0 = unlimited
ALTER TABLE tokens ADD COLUMN uses INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tokens ADD COLUMN revoked_at TEXT;

CREATE TABLE agent_credentials (
  id          INTEGER PRIMARY KEY,
  host        TEXT NOT NULL,
  prefix      TEXT NOT NULL,
  hash        TEXT NOT NULL UNIQUE,                -- SHA-256 of the credential
  created_at  TEXT NOT NULL,
  last_used   TEXT,
  last_ip     TEXT NOT NULL DEFAULT '',
  enrolled_by INTEGER REFERENCES tokens(id) ON DELETE SET NULL,
  revoked_at  TEXT
);
CREATE UNIQUE INDEX agent_credentials_active_host ON agent_credentials(host) WHERE revoked_at IS NULL;
`,
	// 5: the containers running on each Docker host and the image each one
	// runs, as the agent last reported them, for the Images page.
	`
CREATE TABLE container_images (
  id            INTEGER PRIMARY KEY,
  host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  container     TEXT NOT NULL,
  ref           TEXT NOT NULL,                   -- what it was started from (Config.Image)
  registry      TEXT NOT NULL DEFAULT '',        -- docker.io, ghcr.io, … ('' = started from an image ID)
  repository    TEXT NOT NULL DEFAULT '',        -- normalised: docker.io/library/nginx
  tag           TEXT NOT NULL DEFAULT '',        -- '' for a bare digest
  pinned_digest TEXT NOT NULL DEFAULT '',        -- the digest of repo:tag@sha256:…
  image_id      TEXT NOT NULL,
  repo_digest   TEXT NOT NULL DEFAULT '',        -- digest pulled from repository ('' = local build)
  image_created TEXT NOT NULL DEFAULT '',        -- image build time ('' = unknown)
  first_seen    TEXT NOT NULL,
  last_seen     TEXT NOT NULL,
  UNIQUE(host_id, container)
);
CREATE INDEX container_images_repo ON container_images(repository, tag);
`,
	// 6: what each running repository:tag points at upstream, as the registry
	// checker last saw it. A failed check keeps the last good data.
	`
CREATE TABLE image_upstream (
  repository      TEXT NOT NULL,
  tag             TEXT NOT NULL,
  digest          TEXT NOT NULL DEFAULT '',      -- the tag's digest upstream ('' = never read)
  digest_since    TEXT,                          -- when that digest was first seen
  newest_tag      TEXT NOT NULL DEFAULT '',      -- newest tag of the same shape, if newer
  newest_in_major TEXT NOT NULL DEFAULT '',
  newest_since    TEXT,                          -- since when a newer tag exists
  outcome         TEXT NOT NULL,                 -- ok, not_found, not_allowed, rate_limited, error
  error           TEXT NOT NULL DEFAULT '',
  checked_at      TEXT NOT NULL,
  PRIMARY KEY(repository, tag)
);
`,
}
