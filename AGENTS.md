# AGENTS.md

LabWarden: a homelab vulnerability aggregation dashboard. Agents on VMs and Docker hosts run Syft and push SBOMs to a central Go server, which matches them with Grype on a job queue, stores the results in SQLite and serves a React (Chakra UI v3) dashboard. The Grype DB lives on the server only; a new one each night re-matches every stored SBOM. The server can also scan images centrally.

Project rules for coding agents. `CLAUDE.md` holds the same rules. Change both files together.

## Rules

1. **Code runs in Docker only.** Never run go, node or the app directly on the host. Use `scripts/go.sh`, `scripts/npm.sh`, `docker compose`.
2. **Never commit or push to `main`.** All work happens on a branch and reaches `main` only through a merged pull request. Use small conventional commits, each one building and passing `scripts/test.sh`.
3. **Never force-push**, on any branch. Never rewrite pushed history; update a branch by merging `main` into it.
4. No secrets in git. Tokens and passwords live in the gitignored `.env` (for development, generate it with `scripts/dev-env.sh`). Ingest tokens are stored hashed.
5. `testbed/` contains **deliberately vulnerable** packages. Never reuse its pins or images outside the testbed.
6. Pin tool versions (`GRYPE_VERSION` in the server Dockerfile, `SYFT_VERSION` in both Dockerfiles and `install.sh`, together with the Syft release SHA-256 sums pinned in `install.sh`, River in `go.mod`, govulncheck in `scripts/test.sh`). Shipped images (Dockerfiles, `docker-compose.yml`, `docker-compose.dev.yml`, the Settings snippets) are pinned by tag and multi-arch index digest (`docker buildx imagetools inspect`); update both together. Bump Grype and Syft together, deliberately. Our own images (`ghcr.io/amanahlab/labwarden`, `ghcr.io/amanahlab/labwarden-agent`) are published by `.github/workflows/release.yml`; after each release, a follow-up PR pins the new tag and index digest in `docker-compose.yml` (dashboard) and in the Settings snippets, `docs/setup/agent-docker.md` and `README.md` (agent).
7. Library APIs (Chakra v3, Recharts, chi, modernc sqlite, River) change often: check their current docs before writing against them.

## Layout

| Part | Where |
|---|---|
| Go server entrypoint | `server/cmd/labwarden` |
| Grype JSON parser (fixtures in `testdata/`) | `server/internal/grype` |
| SQLite store, schema, queries | `server/internal/store` |
| HTTP API (`/api/v1`), auth, ingest | `server/internal/api` |
| Scanner (runs the grype binary) and the single Grype DB | `server/internal/scanner` |
| Job queue (River on `queue.db`): SBOM matching, central scans, re-matches, DB update | `server/internal/jobs` |
| Stored SBOM files (content-addressed, gzipped) | `server/internal/sboms` |
| Webhook alerts for new findings | `server/internal/notify` |
| React UI (Vite, Chakra UI v3, TanStack Query), embedded into the binary | `web/` |
| Agent script, installer, Docker agent image | `agent/` |
| Proving ground (vulnerable "VM" + docker agent) | `testbed/` |
| End-user Compose file: published dashboard image, hardening | `docker-compose.yml` |
| Development override: source build and testbed, loaded through `COMPOSE_FILE` | `docker-compose.dev.yml` |
| Security model, how to report a vulnerability | `README.md` (Security model), `docs/security-architecture.md` (for users), `SECURITY.md` |
| Setup guides for users (Compose, agents, Caddy, nginx) | `docs/setup/` |
| Release: multi-arch (amd64 + arm64) images to GHCR on version tags | `.github/workflows/release.yml` |

## Build and test

```bash
scripts/test.sh          # go vet + go test + web typecheck/lint/build, all in containers
scripts/e2e.sh           # full stack + testbed, asserts known CVEs arrive in the dashboard
scripts/dev-env.sh       # .env with dev secrets and COMPOSE_FILE=docker-compose.yml:docker-compose.dev.yml
docker compose up -d --build   # dashboard built from source on http://localhost:8080
```

## Contracts

- Agents talk to the server only through `/api/v1/ingest/*`. `POST /ingest/enroll` trades an enrollment token for a host credential; every other ingest call sends `Authorization: Bearer <credential>` and may only speak for that host. Changing these endpoints or their query parameters means updating `agent/labwarden-agent.sh` and the README in the same commit.
- Schema changes are additive migrations appended in `server/internal/store/migrations.go`; never edit an applied migration.
