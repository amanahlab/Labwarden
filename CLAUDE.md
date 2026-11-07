# CLAUDE.md

VulnX: a homelab vulnerability aggregation dashboard. Agents on VMs and Docker hosts run Grype and push JSON reports to a central Go server, which stores them in SQLite and serves a React (Chakra UI v3) dashboard. The server can also scan images centrally.

Generic rules live in `~/.claude/CLAUDE.md`. This file adds the project rules.

## Rules

1. **Code runs in Docker only.** Never run go, node or the app directly on the host. Use `scripts/go.sh`, `scripts/npm.sh`, `docker compose`.
2. Solo repo: commit straight to `main`, small conventional commits, each one building and passing `scripts/test.sh`.
3. No secrets in git. Tokens and passwords live in the gitignored `.env` (generate with `scripts/dev-env.sh`). Ingest tokens are stored hashed.
4. `testbed/` contains **deliberately vulnerable** packages. Never reuse its pins or images outside the testbed.
5. Pin tool versions (`GRYPE_VERSION` in the Dockerfiles, base image tags). Bump deliberately.
6. Library APIs (Chakra v3, Recharts, chi, modernc sqlite) change often: check current docs with ctx7 before writing against them.

## Layout

| Part | Where |
|---|---|
| Go server entrypoint | `server/cmd/vulnx` |
| Grype JSON parser (fixtures in `testdata/`) | `server/internal/grype` |
| SQLite store, schema, queries | `server/internal/store` |
| HTTP API (`/api/v1`), auth, ingest | `server/internal/api` |
| Central scanner (runs the grype binary) | `server/internal/scanner` |
| React UI (Vite, Chakra UI v3, TanStack Query), embedded into the binary | `web/` |
| Agent script, installer, Docker agent image | `agent/` |
| Proving ground (vulnerable "VM" + docker agent) | `testbed/` |

## Build and test

```bash
scripts/test.sh          # go vet + go test + web typecheck/lint/build, all in containers
scripts/e2e.sh           # full stack + testbed, asserts known CVEs arrive in the dashboard
docker compose up -d --build   # dashboard on http://localhost:8080
```

## Contracts

- Agents talk to the server only through `/api/v1/ingest/*` with `Authorization: Bearer <token>`. Changing these endpoints or their query parameters means updating `agent/vulnx-agent.sh` and the README in the same commit.
- Schema changes are additive migrations appended in `server/internal/store/migrations.go`; never edit an applied migration.
