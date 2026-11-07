#!/bin/sh
set -eu
: "${VULNX_URL:?}" "${VULNX_TOKEN:?}"
echo "testbed-vm: waiting for $VULNX_URL"
until curl -fsS "$VULNX_URL/healthz" >/dev/null 2>&1; do sleep 2; done
if [ ! -x /usr/local/bin/vulnx-agent ]; then
	curl -fsSL "$VULNX_URL/install.sh" | sh
fi
touch /var/log/vulnx-agent.log
tail -F /var/log/vulnx-agent.log &
exec cron -f
