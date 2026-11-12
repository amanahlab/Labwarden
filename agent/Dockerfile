# LabWarden Docker agent: catalogs the images of running containers through the
# Docker socket every LABWARDEN_INTERVAL seconds and pushes the SBOMs.
# Bump SYFT_VERSION (and its digest) together with the server's GRYPE_VERSION.
ARG SYFT_VERSION=v1.57.0
ARG SYFT_DIGEST=sha256:3c70e6d5979364cefdc22b51617a78fd264574d3bd6b4f84a351204147025e2a
FROM anchore/syft:${SYFT_VERSION}@${SYFT_DIGEST} AS syft

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache ca-certificates curl jq gzip tzdata
COPY --from=syft /syft /usr/local/bin/syft
COPY labwarden-agent.sh /usr/local/bin/labwarden-agent
COPY docker/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod 755 /usr/local/bin/labwarden-agent /usr/local/bin/entrypoint
ENV LABWARDEN_SCAN_PATHS="" \
    LABWARDEN_SCAN_DOCKER=true \
    LABWARDEN_KIND=docker \
    LABWARDEN_INTERVAL=21600 \
    LABWARDEN_SPOOL=/var/lib/labwarden/spool \
    TMPDIR=/var/lib/labwarden/tmp \
    XDG_CACHE_HOME=/var/lib/labwarden/cache
# Image exports and syft's layer extraction go to TMPDIR, on the state volume,
# so the container can run with a read-only root filesystem.
VOLUME /var/lib/labwarden
ENTRYPOINT ["/usr/local/bin/entrypoint"]
