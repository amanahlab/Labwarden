# LabWarden Docker agent: catalogs the images of running containers through the
# Docker socket every LABWARDEN_INTERVAL seconds and pushes the SBOMs.
# Bump SYFT_VERSION together with the server's GRYPE_VERSION.
ARG SYFT_VERSION=v1.57.0
FROM anchore/syft:${SYFT_VERSION} AS syft

FROM alpine:3.22
RUN apk add --no-cache ca-certificates curl jq gzip tzdata
COPY --from=syft /syft /usr/local/bin/syft
COPY labwarden-agent.sh /usr/local/bin/labwarden-agent
COPY docker/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod 755 /usr/local/bin/labwarden-agent /usr/local/bin/entrypoint
ENV LABWARDEN_SCAN_PATHS="" \
    LABWARDEN_SCAN_DOCKER=true \
    LABWARDEN_KIND=docker \
    LABWARDEN_INTERVAL=21600 \
    LABWARDEN_SPOOL=/var/lib/labwarden/spool
VOLUME /var/lib/labwarden
ENTRYPOINT ["/usr/local/bin/entrypoint"]
