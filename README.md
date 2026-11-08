# VulnX

A homelab vulnerability dashboard. Agents on your VMs and Docker hosts run [Grype](https://github.com/anchore/grype) on a schedule and push the reports to one central server. The server stores them, tracks what is new or fixed, and shows everything in a web UI.

- **Overview**: critical/high counts, known exploited (CISA KEV), fix availability, a 7/30/90-day trend, the riskiest hosts and the top vulnerabilities.
- **Vulnerabilities**: one row per CVE/GHSA or per package instance. Search, sort, filter by severity, KEV, fix state, triage status, group and ecosystem. Paginated, with CSV export.
- **Vulnerability detail**: description, references, CVSS, EPSS, risk, CWEs, affected packages, and triage (acknowledge, ignore, or mark as a false positive, globally or for one host).
- **Hosts**: health (healthy, stale, failing), grouped by group or kind, plus per-host findings, targets, scan history and logs.
- **Scans and Logs**: every report received, and every agent run, warning and error. Logs have a live tail.
- **Settings**: ingest tokens, agent install snippets, central registry scans and system status.
- **Alerts**: a webhook (Slack, Discord, Mattermost, Gotify, ntfy or anything that takes JSON) when a scan finds new critical or known-exploited vulnerabilities.

## Quick start

Everything runs in Docker.

```bash
scripts/dev-env.sh                 # writes .env with a random admin password and bootstrap token
docker compose up -d --build       # http://localhost:8080 (password: grep VULNX_ADMIN_PASSWORD .env)
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
 │ vulnx-agent.sh       │           │ vulnx-agent.sh (loop)    │        │ Go server (chi)            │
 │  grype dir:/  ───────┼── gzip ──▶│  grype docker:<image> ───┼──────▶ │  /api/v1/ingest/* (token)  │
 │  spool on failure    │   JSON    │  via /var/run/docker.sock│        │  SQLite (WAL)              │
 └──────────────────────┘           └──────────────────────────┘        │  central grype: registry:  │
                                                                        │  React UI (Chakra UI v3)   │
                                                                        └────────────────────────────┘
```

| Part | Tech |
|---|---|
| Server | Go 1.27, chi, modernc SQLite (pure Go, no CGO), single static binary with the UI embedded |
| UI | React 19, Vite, Chakra UI v3, TanStack Query, Recharts |
| Agent | POSIX `sh`, needs only `curl`, `gzip` and `grype` |
| Image | Alpine with the pinned Grype binary, non-root, health-checked |

### How scans are scheduled

| Where | Mechanism |
|---|---|
| **VMs** | `install.sh` installs Grype, the agent and a **systemd timer** (`OnCalendar` every 6h, `RandomizedDelaySec=15m`, `Persistent=true` so missed runs catch up). Without systemd (Alpine, containers) it writes `/etc/cron.d/vulnx-agent` at a random minute. A lock prevents overlapping runs. |
| **Docker hosts** | The `vulnx-agent` container runs the agent, then sleeps `VULNX_INTERVAL` seconds, in a loop. It lists running containers through the read-only Docker socket and scans each distinct image. If a tag was moved by a rebuild, it scans the image actually running. If that image was already deleted, it scans the container filesystem. `VULNX_DOCKER_LABEL` limits scanning to labelled containers. |
| **Registry images** | Added in Settings. The server's scheduler scans `registry:<ref>` every N minutes, with no agent involved. |
| **Grype DB** | Each agent runs `grype db update` before scanning. The server updates its own DB every 6 hours. |

### How reports and logs are shipped

1. `POST /api/v1/ingest/run` with `status=started` reports host facts (OS, arch, IP, agent version, interval).
2. For each target, the agent runs `grype -o json`, gzips the output and sends `POST /api/v1/ingest/report?host=…&target=…` with `Content-Encoding: gzip`. If the upload fails, the report goes to a local spool (`/var/lib/vulnx/spool`, at most 20 reports) and is re-sent on the next run.
3. Warnings and errors go to `POST /api/v1/ingest/event` and show up under **Logs**. These include Grype failures, DB update problems and uploads that never arrive.
4. `POST /api/v1/ingest/run` with `status=ok|error` closes the run with the list of targets. On a successful run, targets the agent no longer reports (for example a removed container) are **retired** from the dashboard.

A host that misses more than 2.5× its reported interval is marked **stale**. A host whose last run ended in error is marked **failing**. All agent requests use `Authorization: Bearer <token>`. Tokens are created in Settings and stored only as SHA-256 hashes.

## Installing agents

Create a token in **Settings → Ingest tokens**, then follow the snippets on that page. They are pre-filled with the dashboard URL.

```bash
# Linux VM (systemd or cron)
curl -fsSL http://vulnx.lan:8080/install.sh | sudo VULNX_URL=http://vulnx.lan:8080 VULNX_TOKEN=<token> VULNX_GROUP=homelab sh
# uninstall
curl -fsSL http://vulnx.lan:8080/install.sh | sudo sh -s -- --uninstall

# Docker host
docker build -t vulnx-agent agent/
docker run -d --name vulnx-agent --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock:ro -v vulnx-agent-db:/var/lib/vulnx \
  -e VULNX_URL=http://vulnx.lan:8080 -e VULNX_TOKEN=<token> -e VULNX_HOST=$(hostname) vulnx-agent
```

Agent options (environment variables, or `/etc/vulnx/agent.env` on VMs):
- `VULNX_HOST`, `VULNX_GROUP`
- `VULNX_SCAN_PATHS` (default `/`)
- `VULNX_EXCLUDES`
- `VULNX_SCAN_DOCKER` (`auto|true|false`)
- `VULNX_DOCKER_LABEL`
- `VULNX_INTERVAL`
- `VULNX_SCHEDULE` (systemd `OnCalendar`)
- `VULNX_CRON`

## Server configuration

| Variable | Default | |
|---|---|---|
| `VULNX_ADMIN_PASSWORD` | *(empty: UI open)* | Password for the web UI. Always set it. |
| `VULNX_INGEST_TOKEN` | | Optional bootstrap ingest token (at least 16 characters) |
| `VULNX_DATA` | `/data` | SQLite database, session key, Grype DB |
| `VULNX_ADDR` | `:8080` | |
| `VULNX_COOKIE_SECURE` | `false` | Set to `true` behind HTTPS |
| `VULNX_MAX_REPORT_MB` | `256` | Maximum decompressed report size |
| `VULNX_EVENT_RETENTION` | `50000` | Number of log events kept |
| `VULNX_SCHEDULER` | `true` | Central registry scans and DB updates |
| `VULNX_NOTIFY_URL` | *(empty: off)* | Webhook for alerts. Never logged or shown in the UI. |
| `VULNX_NOTIFY_FORMAT` | `json` | `json` posts `{title, text, content, message, host, target, link, findings}`. `ntfy` posts plain text with ntfy headers. |
| `VULNX_NOTIFY_MIN_SEVERITY` | `Critical` | `Critical`, `High`, `Medium` or `Low` |
| `VULNX_NOTIFY_KEV` | `true` | Also alert on known-exploited (CISA KEV) findings below that severity |
| `VULNX_PUBLIC_URL` | | Dashboard URL used for links in alerts |

### Alerts

After each stored report, VulnX compares the findings with the target's previous scan. It sends one message per report that lists the new findings at or above `VULNX_NOTIFY_MIN_SEVERITY`, plus any new known-exploited ones. Each vulnerability appears once, KEV first, and the message shows at most 10. A target's first scan counts every finding as new. Vulnerabilities triaged as *ignored* or *false positive*, globally or for that host, do not alert. **Settings → System → Send test** checks the setup. A failed delivery shows up under **Logs**.

## Development

```bash
scripts/test.sh     # go vet + go test, web lint + typecheck + build, shellcheck (all in containers)
scripts/e2e.sh      # full stack + testbed
scripts/go.sh …     # any go command in the pinned toolchain container
scripts/npm.sh …    # any npm command for web/
```

> `testbed/` pins deliberately vulnerable software. Never reuse those images or versions anywhere else.
