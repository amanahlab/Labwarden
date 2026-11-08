# LabWarden dashboard: React UI + Go server + grype (matching) and syft
# (cataloging central images). Bump both together with the agent's SYFT_VERSION.
ARG GRYPE_VERSION=v0.121.2
ARG SYFT_VERSION=v1.57.0

FROM node:24-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS server
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY server/ server/
COPY agent/ agent/
COPY web/embed.go web/
COPY --from=web /web/dist web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/labwarden ./server/cmd/labwarden

FROM anchore/grype:${GRYPE_VERSION} AS grype
FROM anchore/syft:${SYFT_VERSION} AS syft

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 labwarden && adduser -S -u 10001 -G labwarden -h /data labwarden \
 && mkdir -p /data && chown labwarden:labwarden /data
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=server /out/labwarden /usr/local/bin/labwarden
ENV LABWARDEN_DATA=/data \
    LABWARDEN_ADDR=:8080 \
    GRYPE_DB_CACHE_DIR=/data/grype-db \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    SYFT_CHECK_FOR_APP_UPDATE=false
USER labwarden
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/usr/local/bin/labwarden", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/labwarden"]
