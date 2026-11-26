#!/usr/bin/env sh
# Run a go command inside the pinned toolchain container.
# Usage: scripts/go.sh test ./...
# The image is the Dockerfile's server stage image (tag@index digest): tests and
# govulncheck must see the Go that builds the release. Bump both together.
# The module and build caches are named volumes; CI sets LABWARDEN_GOMODCACHE
# and LABWARDEN_GOCACHE to directories it saves between runs (-modcacherw lets
# it read and restore the module cache).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
exec docker run --rm \
  -v "$ROOT:/src" -w /src \
  -v "${LABWARDEN_GOMODCACHE:-labwarden-gomod}:/go/pkg/mod" \
  -v "${LABWARDEN_GOCACHE:-labwarden-gocache}:/root/.cache/go-build" \
  -e CGO_ENABLED=0 -e GOFLAGS=-modcacherw \
  golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 go "$@"
