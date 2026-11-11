#!/usr/bin/env sh
# Unit tests and static checks, all inside containers.
# Usage: scripts/test.sh [go|web|vuln|shell]...   (no argument: every section)
# CI runs the sections as parallel jobs.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

check_go() {
  echo "== go vet / test"
  scripts/go.sh vet ./...
  scripts/go.sh test -count=1 ./...
}

check_web() {
  echo "== web lint / build"
  [ -d web/node_modules ] || scripts/npm.sh ci --no-audit --no-fund
  scripts/npm.sh run lint
  scripts/npm.sh run build
}

check_vuln() {
  echo "== known vulnerabilities in dependencies"
  scripts/go.sh run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./... # pinned; bump deliberately
  scripts/npm.sh audit --omit=dev --audit-level=high # reads the lockfile only
}

check_shell() {
  echo "== shell"
  docker run --rm -v "$ROOT:/mnt:ro" -w /mnt koalaman/shellcheck:stable -s sh -S warning \
    agent/labwarden-agent.sh agent/install.sh agent/docker/entrypoint.sh testbed/vm/entrypoint.sh scripts/*.sh
  for img in alpine:3.22 debian:12-slim; do
    docker run --rm -v "$ROOT:/mnt:ro" "$img" sh /mnt/scripts/agent-selftest.sh >/dev/null ||
      { docker run --rm -v "$ROOT:/mnt:ro" "$img" sh /mnt/scripts/agent-selftest.sh | grep -v '^ok'; exit 1; }
  done
  echo "agent and installer self-test passed (busybox, debian)"
}

[ $# -gt 0 ] || set -- go web vuln shell
for section; do
  case "$section" in
    go | web | vuln | shell) ;;
    *) echo "usage: scripts/test.sh [go|web|vuln|shell]..." >&2; exit 2 ;;
  esac
done
for section; do "check_$section"; done
echo "all checks passed"
