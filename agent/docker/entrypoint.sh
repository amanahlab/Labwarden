#!/bin/sh
# Run the agent now and then every LABWARDEN_INTERVAL seconds. Failures are
# reported to the dashboard by the agent itself; the loop keeps going.
set -u
interval=${LABWARDEN_INTERVAL:-21600}
trap 'exit 0' TERM INT
# Agents before 2.0 kept their own 3+ GB copy of the Grype DB in the state volume.
if [ -d /var/lib/labwarden/grype-db ]; then
	rm -rf /var/lib/labwarden/grype-db && echo "removed the old local grype DB (/var/lib/labwarden/grype-db)"
fi
while :; do
	/usr/local/bin/labwarden-agent || true
	sleep "$interval" &
	wait $!
done
