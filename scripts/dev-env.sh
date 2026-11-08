#!/usr/bin/env sh
# Create .env with random credentials. Never prints the secrets.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ENV="$ROOT/.env"
if [ -f "$ENV" ] && [ "${1:-}" != "--force" ]; then
  echo ".env already exists (use --force to regenerate)"
  exit 0
fi
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }
umask 077
cat >"$ENV" <<EOT
LABWARDEN_ADMIN_PASSWORD=$(rand 24)
LABWARDEN_INGEST_TOKEN=vxe_$(rand 40)
LABWARDEN_PORT=8080
EOT
echo "wrote $ENV (admin password: grep LABWARDEN_ADMIN_PASSWORD .env)"
