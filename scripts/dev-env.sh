#!/usr/bin/env sh
# Create .env with random credentials for development. Never prints the secrets.
# .env also sets COMPOSE_FILE, so plain `docker compose` builds from source and
# knows the testbed (docker-compose.dev.yml). env_file passes that line into the
# container as well, which is harmless.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ENV="$ROOT/.env"
DEV_FILES=COMPOSE_FILE=docker-compose.yml:docker-compose.dev.yml
if [ -f "$ENV" ] && [ "${1:-}" != "--force" ]; then
  # An .env from before the compose split lacks the line: without it, compose
  # would pull the published image and --profile testbed would match nothing.
  if ! grep -q '^COMPOSE_FILE=' "$ENV"; then
    [ -z "$(tail -c 1 "$ENV")" ] || echo >>"$ENV"
    echo "$DEV_FILES" >>"$ENV"
    echo "added $DEV_FILES to $ENV"
  fi
  echo ".env already exists (use --force to regenerate)"
  exit 0
fi
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }
umask 077
cat >"$ENV" <<EOT
LABWARDEN_ADMIN_PASSWORD=$(rand 24)
LABWARDEN_INGEST_TOKEN=vxe_$(rand 40)
LABWARDEN_PORT=8080
$DEV_FILES
EOT
echo "wrote $ENV (admin password: grep LABWARDEN_ADMIN_PASSWORD .env)"
