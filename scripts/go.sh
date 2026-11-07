#!/usr/bin/env sh
# Run a go command inside the pinned toolchain container.
# Usage: scripts/go.sh test ./...
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
exec docker run --rm \
  -v "$ROOT:/src" -w /src \
  -v vulnx-gomod:/go/pkg/mod -v vulnx-gocache:/root/.cache/go-build \
  -e CGO_ENABLED=0 \
  golang:1.27-alpine go "$@"
