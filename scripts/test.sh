#!/usr/bin/env sh
# Unit tests and static checks, all inside containers.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
echo "== go vet / test"
scripts/go.sh vet ./...
scripts/go.sh test -count=1 ./...
echo "== web lint / build"
[ -d web/node_modules ] || scripts/npm.sh ci --no-audit --no-fund
scripts/npm.sh run lint
scripts/npm.sh run build
echo "== shell"
docker run --rm -v "$ROOT:/mnt:ro" -w /mnt koalaman/shellcheck:stable -s sh -S warning \
  agent/labwarden-agent.sh agent/install.sh agent/docker/entrypoint.sh testbed/vm/entrypoint.sh scripts/*.sh
for img in alpine:3.22 debian:12-slim; do
  docker run --rm -v "$ROOT:/mnt:ro" "$img" sh /mnt/scripts/agent-selftest.sh >/dev/null ||
    { docker run --rm -v "$ROOT:/mnt:ro" "$img" sh /mnt/scripts/agent-selftest.sh | grep -v '^ok'; exit 1; }
done
echo "agent and installer self-test passed (busybox, debian)"
echo "all checks passed"
