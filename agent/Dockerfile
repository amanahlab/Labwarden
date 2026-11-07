# VulnX Docker agent: scans the images of running containers through the
# Docker socket every VULNX_INTERVAL seconds and pushes the reports.
ARG GRYPE_VERSION=v0.121.2
FROM anchore/grype:${GRYPE_VERSION} AS grype

FROM alpine:3.22
RUN apk add --no-cache ca-certificates curl jq gzip tzdata
COPY --from=grype /grype /usr/local/bin/grype
COPY vulnx-agent.sh /usr/local/bin/vulnx-agent
COPY docker/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod 755 /usr/local/bin/vulnx-agent /usr/local/bin/entrypoint
ENV VULNX_SCAN_PATHS="" \
    VULNX_SCAN_DOCKER=true \
    VULNX_KIND=docker \
    VULNX_INTERVAL=21600 \
    VULNX_SPOOL=/var/lib/vulnx/spool \
    GRYPE_DB_CACHE_DIR=/var/lib/vulnx/grype-db
VOLUME /var/lib/vulnx
ENTRYPOINT ["/usr/local/bin/entrypoint"]
