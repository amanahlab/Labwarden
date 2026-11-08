# LabWarden

A homelab vulnerability dashboard. Agents on your VMs and Docker hosts catalog their packages with [Syft](https://github.com/anchore/syft) on a schedule and push the SBOMs to one central server. The server matches them with [Grype](https://github.com/anchore/grype) against the only copy of the vulnerability DB, tracks what is new or fixed, and shows everything in a web UI. When a new DB arrives each night, every stored SBOM is matched again.

- **Overview**: critical/high counts, known exploited (CISA KEV), fix availability, a 7/30/90-day trend, the riskiest hosts and the top vulnerabilities.
- **Vulnerabilities**: one row per CVE/GHSA or per package instance. Search, sort, filter by severity, KEV, fix state, triage status, group and ecosystem. Paginated, with CSV export.
- **Vulnerability detail**: description, references, CVSS, EPSS, risk, CWEs, affected packages, and triage (acknowledge, ignore, or mark as a false positive, globally or for one host).
- **Hosts**: health (healthy, stale, failing), grouped by group or kind, plus per-host findings, targets, scan history and logs.
- **Scans and Logs**: every report received, and every agent run, warning and error. Logs have a live tail.
- **Settings**: enrollment tokens, enrolled hosts, agent install snippets, central registry scans and system status.
- **Alerts**: a webhook (Slack, Discord, Mattermost, Gotify, ntfy or anything that takes JSON) when a scan finds new critical or known-exploited vulnerabilities.

## Quick start

Everything runs in Docker.

```bash
scripts/dev-env.sh                 # writes .env with a random admin password and bootstrap token
docker compose up -d --build       # http://localhost:8080 (password: grep LABWARDEN_ADMIN_PASSWORD .env)
```

Start the proving ground as well. It runs a deliberately vulnerable "VM" (Debian 12 with log4j 2.14.1, old Django and lodash manifests) and a Docker agent watching an outdated Alpine container:

```bash
docker compose --profile testbed up -d --build
scripts/e2e.sh                     # asserts the known CVEs, triage, central scans and retirement end to end
```

## Architecture

```
 VM (systemd timer / cron)          Docker host (agent container)        Dashboard container
 ┌──────────────────────┐           ┌──────────────────────────┐        ┌────────────────────────────┐
 │ labwarden-agent.sh   │           │ labwarden-agent.sh (loop)│        │ Go server (chi)            │
 │  syft dir:/   ───────┼── gzip ──▶│  syft docker:<image>  ───┼──────▶ │  /api/v1/ingest/* (cred)   │
 │  spool on failure    │   SBOM    │  via /var/run/docker.sock│        │  job queue (River, SQLite) │
 └──────────────────────┘           └──────────────────────────┘        │  grype sbom: + grype DB    │
                                                                        │  SQLite (WAL), SBOM files  │
                                                                        │  React UI (Chakra UI v3)   │
                                                                        └────────────────────────────┘
```

| Part | Tech |
|---|---|
| Server | Go 1.27, chi, modernc SQLite (pure Go, no CGO), single static binary with the UI embedded |
| UI | React 19, Vite, Chakra UI v3, TanStack Query, Recharts |
| Agent | POSIX `sh`, needs only `curl`, `gzip` and `syft` (pinned `v1.57.0`, bumped together with Grype) |
| Image | Alpine with the pinned Grype binary, non-root, health-checked |
| Jobs | [River](https://riverqueue.com) on its own SQLite file (`queue.db`): SBOM matching, central scans, re-matches, the daily DB update |

### How scans are scheduled

| Where | Mechanism |
|---|---|
| **VMs** | `install.sh` installs Syft, the agent and a **systemd timer** (`OnCalendar` every 6h, `RandomizedDelaySec=15m`, `Persistent=true` so missed runs catch up). Without systemd (Alpine, containers) it writes `/etc/cron.d/labwarden-agent` at a random minute. A lock prevents overlapping runs. |
| **Docker hosts** | The `labwarden-agent` container runs the agent, then sleeps `LABWARDEN_INTERVAL` seconds, in a loop. It lists running containers through the read-only Docker socket and catalogs each distinct image. If a tag was moved by a rebuild, it scans the image actually running. If that image was already deleted, it scans the container filesystem. `LABWARDEN_DOCKER_LABEL` limits scanning to labelled containers. |
| **Registry images** | Added in Settings. Every N minutes the server catalogs `registry:<ref>` with Syft, keeps the SBOM and matches it, with no agent involved. Like agent SBOMs, it is re-matched against each new DB. Private registries: set `SYFT_REGISTRY_AUTH_*` (or the older `GRYPE_REGISTRY_*`, which is passed on) on the server. |
| **Grype DB** | Only the server has it (about 3.4 GB). It checks for a new one once a day at `LABWARDEN_DB_UPDATE_AT`, downloads it next to the live copy and swaps it in, so there is never a second download and scans never wait. A new DB queues a re-match of every stored SBOM. Settings → System shows the build date, the next update and the last re-match, with **Update DB now** and **Re-match all now** buttons. Agents need no DB and no internet access. |

**Sizing.** Measured on 6 CPUs and 8 GB of RAM: the queue picks a job up within about 100 ms (p99) and handles about 300 jobs a second, so Grype is the limit. Matching an SBOM takes 1–2.5 s once the DB is in memory, with about 115 MB per Grype process. The first matches after a restart or a new DB take longer (up to about 25 s for a full VM) while the DB is read from disk. With `LABWARDEN_SCAN_WORKERS=2`, re-matching 500 targets takes about 10 minutes.

### How SBOMs and logs are shipped

0. On its first run the agent enrolls: `POST /api/v1/ingest/enroll {host}` with an **enrollment token** returns a **host credential** (`vxa_…`) bound to that host name. The agent keeps it in `/var/lib/labwarden/credential` (mode 0600) and sends it on every later request. A host that already has a credential cannot enroll again (`409`) until you reset it on its host page; a credential the server no longer knows (`401`) makes the agent re-enroll once.
1. `POST /api/v1/ingest/run` with `status=started` reports host facts (OS, arch, IP, agent version, interval).
2. For each target, the agent runs `syft -o syft-json`, gzips the output and sends `POST /api/v1/ingest/sbom?host=…&target=…` with `Content-Encoding: gzip`. The server stores the SBOM, answers `202 {queued, job_id}` at once and matches it on its job queue, usually within seconds; a retry of the same run and target is not matched twice. It answers `503` when the queue is backed up or less than 1 GB of disk is free. If the upload fails, the SBOM goes to a local spool (`/var/lib/labwarden/spool`, at most 20) and is re-sent on the next run.
   The server keeps the latest SBOM of every target, i.e. each host's full package list.
3. Warnings and errors go to `POST /api/v1/ingest/event` and show up under **Logs**. These include Syft failures and uploads that never arrive.
4. `POST /api/v1/ingest/run` with `status=ok|error` closes the run with the list of targets. On a successful run, targets the agent no longer reports (for example a removed container) are **retired** from the dashboard.

A host that misses more than 2.5× its reported interval is marked **stale**. A host whose last run ended in error is marked **failing**. All agent requests use `Authorization: Bearer <credential>`, and a credential speaks only for its own host: a request that names another host gets `403`. Enrollment tokens are created in Settings with an expiry (1 hour, 24 hours, 7 days or never) and an optional limit on uses; they can only enroll. Tokens and credentials are stored only as SHA-256 hashes. Repeated bad tokens from one address get `429`.

## Installing agents

Create an enrollment token in **Settings → Enrollment tokens**, then follow the snippets on that page. They are pre-filled with the dashboard URL. The token is only needed for the first run; revoking it later does not affect hosts that already enrolled.

**Upgrading to agent 3.0** breaks compatibility: the server no longer accepts ingest tokens on its ingest endpoints, and `/api/v1/ingest/report` is gone. Upgrade the server, then re-run `install.sh` on every VM and rebuild every Docker agent. Existing tokens keep working as enrollment tokens.

```bash
# Linux VM (systemd or cron)
curl -fsSL http://labwarden.lan:8080/install.sh | sudo LABWARDEN_URL=http://labwarden.lan:8080 LABWARDEN_TOKEN=<token> LABWARDEN_GROUP=homelab sh
# uninstall
curl -fsSL http://labwarden.lan:8080/install.sh | sudo sh -s -- --uninstall

# Docker host
docker build -t labwarden-agent agent/
docker run -d --name labwarden-agent --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock:ro -v labwarden-agent-db:/var/lib/labwarden \
  -e LABWARDEN_URL=http://labwarden.lan:8080 -e LABWARDEN_TOKEN=<token> -e LABWARDEN_HOST=$(hostname) labwarden-agent
```

Agent options (environment variables, or `/etc/labwarden/agent.env` on VMs):
- `LABWARDEN_HOST`, `LABWARDEN_GROUP`
- `LABWARDEN_SCAN_PATHS` (default `/`)
- `LABWARDEN_EXCLUDES`
- `LABWARDEN_SCAN_DOCKER` (`auto|true|false`)
- `LABWARDEN_DOCKER_LABEL`
- `LABWARDEN_INTERVAL`
- `LABWARDEN_SCHEDULE` (systemd `OnCalendar`)
- `LABWARDEN_CRON`

## Server configuration

| Variable | Default | |
|---|---|---|
| `LABWARDEN_ADMIN_PASSWORD` | *(required)* | Password for the web UI, at least 12 characters. The server will not start without it. Sessions end after 24 hours unused or 7 days in any case; changing the password, or **Settings → Sign out all sessions**, ends them all |
| `LABWARDEN_AUTH_DISABLED` | `false` | `true` runs the web UI without a password (only on a network you trust; logged every hour). Cannot be combined with a password |
| `LABWARDEN_INGEST_TOKEN` | | Optional bootstrap enrollment token (at least 16 characters, never expires). Imported once; revoking it in Settings sticks across restarts |
| `LABWARDEN_DATA` | `/data` | SQLite database, job queue (`queue.db`), stored SBOMs, session key, Grype DB |
| `LABWARDEN_ADDR` | `:8080` | |
| `LABWARDEN_COOKIE_SECURE` | `false` | `true` marks the session cookie `Secure` (with the `__Host-` prefix). Automatic when the request arrives over TLS, when a trusted proxy sends `X-Forwarded-Proto: https`, or when it is for the host of an `https://` `LABWARDEN_PUBLIC_URL` |
| `LABWARDEN_TRUSTED_PROXIES` | | Reverse proxies allowed to set `X-Forwarded-For` and `X-Forwarded-Proto`: IP addresses or CIDR ranges, comma-separated (e.g. `172.18.0.10`). List the proxy's own address, not its Docker network: a whole range such as `172.18.0.0/16` also covers Docker's gateway, which is where direct connections to a published port come from. Without it, the client address is the TCP peer, so login lockouts behind a proxy apply to the proxy as a whole |
| `LABWARDEN_MAX_REPORT_MB` | `256` | Maximum upload size in MB; a gzipped upload may decompress to at most 4 times that |
| `LABWARDEN_SCAN_WORKERS` | `2` | Grype processes run at once (about 115 MB each) |
| `LABWARDEN_QUEUE_MAX` | `1000` | Queued jobs above which SBOM uploads get `503` and stay in the agent's spool |
| `LABWARDEN_EVENT_RETENTION` | `50000` | Number of log events kept |
| `LABWARDEN_SCHEDULER` | `true` | Central registry scans |
| `LABWARDEN_DB_UPDATE_AT` | `03:00` | Daily time (`HH:MM`, in `TZ`) to check for a new Grype DB. After a new one, every stored SBOM is matched again, so new CVEs show up without an agent run. On start the DB is only checked when it is missing or older than 36 hours. |
| `TZ` | `UTC` | Time zone for `LABWARDEN_DB_UPDATE_AT`, e.g. `Europe/Amsterdam` |
| `LABWARDEN_NOTIFY_URL` | *(empty: off)* | Webhook for alerts. Never logged or shown in the UI. |
| `LABWARDEN_NOTIFY_FORMAT` | `json` | `json` posts `{title, text, content, message, host, target, link, findings}`. `ntfy` posts plain text with ntfy headers. |
| `LABWARDEN_NOTIFY_MIN_SEVERITY` | `Critical` | `Critical`, `High`, `Medium` or `Low` |
| `LABWARDEN_NOTIFY_KEV` | `true` | Also alert on known-exploited (CISA KEV) findings below that severity |
| `LABWARDEN_PUBLIC_URL` | | Dashboard URL, used for links in alerts. Browsers on this origin pass the cross-site request check even when a reverse proxy rewrites the `Host` header; without it, the proxy must pass `Host` through |

### Alerts

After each stored report, LabWarden compares the findings with the target's previous scan. It sends one message per report that lists the new findings at or above `LABWARDEN_NOTIFY_MIN_SEVERITY`, plus any new known-exploited ones. Each vulnerability appears once, KEV first, and the message shows at most 10. A target's first scan counts every finding as new. Vulnerabilities triaged as *ignored* or *false positive*, globally or for that host, do not alert. **Settings → System → Send test** checks the setup. A failed delivery shows up under **Logs**.

## Development

```bash
scripts/test.sh     # go vet + go test, web lint + typecheck + build, shellcheck (all in containers)
scripts/e2e.sh      # full stack + testbed
scripts/go.sh …     # any go command in the pinned toolchain container
scripts/npm.sh …    # any npm command for web/
```

> `testbed/` pins deliberately vulnerable software. Never reuse those images or versions anywhere else.

## License

LabWarden is licensed under the [GNU Affero General Public License v3.0](LICENSE).
