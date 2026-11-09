# LabWarden dashboard: React UI + Go server + grype (matching) and syft
# (cataloging central images). Bump both together with the agent's SYFT_VERSION.
# Images are pinned by tag and by the digest of their multi-arch index
# (docker buildx imagetools inspect <image>).
# Multi-arch: the web and server stages run on the build platform (the UI does
# not depend on the architecture, Go cross-compiles); grype, syft and alpine
# are pulled per target platform.
ARG GRYPE_VERSION=v0.121.2
ARG GRYPE_DIGEST=sha256:6a36234da13f9faa327306ac0b3dab3405cfa2b4eb20c8f904125a8707863913
ARG SYFT_VERSION=v1.57.0
ARG SYFT_DIGEST=sha256:3c70e6d5979364cefdc22b51617a78fd264574d3bd6b4f84a351204147025e2a

FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# release.yml passes the agent image it just published (tag@index digest), so the
# Settings snippets of a release name its own agent. Empty: the pin in Settings.tsx.
ARG AGENT_IMAGE=
RUN case "$AGENT_IMAGE" in \
      ""|ghcr.io/amanahlab/labwarden-agent:*@sha256:*) ;; \
      *) echo "AGENT_IMAGE must be ghcr.io/amanahlab/labwarden-agent:<tag>@sha256:<digest>" >&2; exit 1 ;; \
    esac \
    && VITE_AGENT_IMAGE="$AGENT_IMAGE" npm run build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS server
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY server/ server/
COPY agent/ agent/
COPY web/embed.go web/
COPY --from=web /web/dist web/dist
ARG VERSION=dev
# Declared late so the layers above are shared by every target platform.
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/labwarden ./server/cmd/labwarden

FROM anchore/grype:${GRYPE_VERSION}@${GRYPE_DIGEST} AS grype
FROM anchore/syft:${SYFT_VERSION}@${SYFT_DIGEST} AS syft

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 labwarden && adduser -S -u 10001 -G labwarden -h /data labwarden \
 && mkdir -p /data && chown labwarden:labwarden /data
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=server /out/labwarden /usr/local/bin/labwarden
# TMPDIR on the volume: Grype DB downloads and central image pulls are large,
# and the root filesystem can then be read-only with only a small /tmp.
ENV LABWARDEN_DATA=/data \
    LABWARDEN_ADDR=:8080 \
    TMPDIR=/data/tmp \
    GRYPE_DB_CACHE_DIR=/data/grype-db \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    SYFT_CHECK_FOR_APP_UPDATE=false
USER labwarden
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/usr/local/bin/labwarden", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/labwarden"]
