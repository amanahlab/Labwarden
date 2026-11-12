#!/usr/bin/env sh
# Screenshots of the dashboard for visual review: every route, light and dark,
# at three widths, written to screenshots/<name>/ (gitignored).
# Usage: scripts/screenshots.sh [name] [routes]
#   name    folder under screenshots/ (default: current), e.g. before, after
#   routes  comma-separated subset, e.g. overview,hosts (default: all)
#
# The working tree is built as labwarden:shots and served with no network, no
# scheduler and no login, from a throwaway COPY of the findings in the dev
# stack's data volume (LABWARDEN_SHOTS_SOURCE, default labwarden_labwarden-data).
# That volume is mounted read-only; without it the pages show their empty states.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=${1:-current}
ROUTES=${2:-}
OUT="$ROOT/screenshots/$NAME"
SRC=${LABWARDEN_SHOTS_SOURCE:-labwarden_labwarden-data}
VIEW=labwarden-shots
DATA=labwarden-shots-data
# Playwright's image holds the browsers only; the npm package of the same
# version is installed once into the labwarden-playwright volume.
PW_VERSION=1.65.0
PW_IMAGE=mcr.microsoft.com/playwright:v1.65.0-noble@sha256:9beb546099e11f52d62e505537914870e01a67e0e6b00ae41da4775324e73dbe

# Removes only what this script created.
cleanup() {
  docker rm -f "$VIEW" >/dev/null 2>&1 || true
  docker volume rm "$DATA" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 1' INT TERM

echo "== build labwarden:shots"
docker build -q -t labwarden:shots "$ROOT" >/dev/null

cleanup
docker volume create "$DATA" >/dev/null
if docker volume inspect "$SRC" >/dev/null 2>&1; then
  echo "== copy findings from $SRC"
  docker run --rm -v "$SRC:/src:ro" -v "$DATA:/dst" alpine:3.22 sh -c '
    for f in /src/labwarden.db*; do [ -e "$f" ] && cp -a "$f" /dst/; done
    [ -d /src/sboms ] && cp -a /src/sboms /dst/
    chown -R 10001:10001 /dst'
else
  echo "== no volume $SRC: empty dashboard"
  docker run --rm -v "$DATA:/dst" alpine:3.22 chown 10001:10001 /dst
fi

docker run -d --name "$VIEW" --network none -v "$DATA:/data" \
  -e LABWARDEN_SCHEDULER=false -e LABWARDEN_AUTH_DISABLED=true labwarden:shots >/dev/null

docker run --rm -v labwarden-playwright:/pw -w /pw -e PW_VERSION="$PW_VERSION" "$PW_IMAGE" sh -c '
  grep -qs "\"version\": \"$PW_VERSION\"" node_modules/playwright/package.json ||
    npm install --no-audit --no-fund --no-save "playwright@$PW_VERSION" >/dev/null'

echo "== screenshots -> screenshots/$NAME"
mkdir -p "$OUT"
docker run --rm --network "container:$VIEW" --ipc=host \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v labwarden-playwright:/pw:ro -e NODE_PATH=/pw/node_modules \
  -v "$ROOT/scripts/screenshots.cjs:/screenshots.cjs:ro" -v "$OUT:/out" \
  -e ROUTES="$ROUTES" "$PW_IMAGE" node /screenshots.cjs
