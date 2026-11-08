#!/usr/bin/env sh
# Run an npm command for web/ inside the pinned node container.
# Usage: scripts/npm.sh run build
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
exec docker run --rm \
  -v "$ROOT/web:/web" -w /web \
  -v labwarden-npm-cache:/root/.npm \
  node:24-alpine npm "$@"
