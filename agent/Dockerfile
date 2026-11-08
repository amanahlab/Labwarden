# LabWarden Docker agent: scans the images of running containers through the
# Docker socket every LABWARDEN_INTERVAL seconds and pushes the reports.
ARG GRYPE_VERSION=v0.121.2
FROM anchore/grype:${GRYPE_VERSION} AS grype

FROM alpine:3.22
RUN apk add --no-cache ca-certificates curl jq gzip tzdata
COPY --from=grype /grype /usr/local/bin/grype
COPY labwarden-agent.sh /usr/local/bin/labwarden-agent
COPY docker/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod 755 /usr/local/bin/labwarden-agent /usr/local/bin/entrypoint
ENV LABWARDEN_SCAN_PATHS="" \
    LABWARDEN_SCAN_DOCKER=true \
    LABWARDEN_KIND=docker \
    LABWARDEN_INTERVAL=21600 \
    LABWARDEN_SPOOL=/var/lib/labwarden/spool \
    GRYPE_DB_CACHE_DIR=/var/lib/labwarden/grype-db
VOLUME /var/lib/labwarden
ENTRYPOINT ["/usr/local/bin/entrypoint"]
