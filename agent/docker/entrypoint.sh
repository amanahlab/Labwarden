#!/bin/sh
# Run the agent now and then every VULNX_INTERVAL seconds. Failures are
# reported to the dashboard by the agent itself; the loop keeps going.
set -u
interval=${VULNX_INTERVAL:-21600}
trap 'exit 0' TERM INT
while :; do
	/usr/local/bin/vulnx-agent || true
	sleep "$interval" &
	wait $!
done
