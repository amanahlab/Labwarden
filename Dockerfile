# VulnX dashboard: React UI + Go server + grype for central scans.
ARG GRYPE_VERSION=v0.121.2

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
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/vulnx ./server/cmd/vulnx

FROM anchore/grype:${GRYPE_VERSION} AS grype

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 vulnx && adduser -S -u 10001 -G vulnx -h /data vulnx \
 && mkdir -p /data && chown vulnx:vulnx /data
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=server /out/vulnx /usr/local/bin/vulnx
ENV VULNX_DATA=/data \
    VULNX_ADDR=:8080 \
    GRYPE_DB_CACHE_DIR=/data/grype-db \
    GRYPE_CHECK_FOR_APP_UPDATE=false
USER vulnx
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/vulnx"]
