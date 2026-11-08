#!/bin/sh
set -eu
: "${LABWARDEN_URL:?}" "${LABWARDEN_TOKEN:?}"
echo "testbed-vm: waiting for $LABWARDEN_URL"
until curl -fsS "$LABWARDEN_URL/healthz" >/dev/null 2>&1; do sleep 2; done
if [ ! -x /usr/local/bin/labwarden-agent ]; then
	curl -fsSL "$LABWARDEN_URL/install.sh" | sh
fi
touch /var/log/labwarden-agent.log
tail -F /var/log/labwarden-agent.log &
exec cron -f
