#!/bin/sh
# VulnX agent installer. Served by the dashboard at /install.sh.
#
#   curl -fsSL http://vulnx.lan:8080/install.sh | sudo VULNX_URL=http://vulnx.lan:8080 VULNX_TOKEN=vx_... sh
#
# Optional: VULNX_HOST, VULNX_GROUP, VULNX_SCAN_PATHS, VULNX_SCAN_DOCKER,
#           VULNX_SCHEDULE (systemd OnCalendar, default every 6h),
#           VULNX_CRON (cron expression used when systemd is absent),
#           VULNX_INTERVAL (seconds; must match the schedule, default 21600),
#           GRYPE_VERSION (default pinned below), VULNX_RUN_NOW=0 to skip the first scan.
# Uninstall: curl -fsSL .../install.sh | sudo sh -s -- --uninstall
set -eu

GRYPE_VERSION=${GRYPE_VERSION:-v0.121.2}
BIN=/usr/local/bin/vulnx-agent
CONF_DIR=/etc/vulnx
UNIT_DIR=/etc/systemd/system

say() { printf 'vulnx: %s\n' "$*"; }
die() { printf 'vulnx: error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

has_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

if [ "${1:-}" = "--uninstall" ]; then
	if has_systemd; then
		systemctl disable --now vulnx-agent.timer 2>/dev/null || true
		rm -f "$UNIT_DIR/vulnx-agent.service" "$UNIT_DIR/vulnx-agent.timer"
		systemctl daemon-reload
	fi
	rm -f /etc/cron.d/vulnx-agent "$BIN"
	rm -rf "$CONF_DIR"
	say "agent removed (grype and /var/lib/vulnx were left in place)"
	exit 0
fi

: "${VULNX_URL:?set VULNX_URL to the dashboard URL}"
: "${VULNX_TOKEN:?set VULNX_TOKEN to an ingest token from Settings}"
VULNX_URL=${VULNX_URL%/}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v gzip >/dev/null 2>&1 || die "gzip is required"

# 1. grype
if command -v grype >/dev/null 2>&1; then
	say "grype already installed: $(grype version 2>/dev/null | awk '/^Version:/{print $2}')"
else
	say "installing grype $GRYPE_VERSION"
	curl -fsSL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin "$GRYPE_VERSION"
fi

# 2. agent script, from the dashboard so it always matches the server
curl -fsSL "$VULNX_URL/agent/vulnx-agent.sh" -o "$BIN.tmp"
head -n1 "$BIN.tmp" | grep -q '^#!/bin/sh' || die "downloaded agent does not look like a script"
chmod 755 "$BIN.tmp" && mv "$BIN.tmp" "$BIN"
say "agent installed at $BIN"

# 3. configuration (contains the token: root-only)
mkdir -p "$CONF_DIR" /var/lib/vulnx/grype-db
chmod 700 "$CONF_DIR" /var/lib/vulnx
umask 077
{
	printf "VULNX_URL='%s'\n" "$VULNX_URL"
	printf "VULNX_TOKEN='%s'\n" "$VULNX_TOKEN"
	[ -n "${VULNX_HOST:-}" ] && printf "VULNX_HOST='%s'\n" "$VULNX_HOST"
	printf "VULNX_GROUP='%s'\n" "${VULNX_GROUP:-default}"
	[ -n "${VULNX_SCAN_PATHS+x}" ] && printf "VULNX_SCAN_PATHS='%s'\n" "$VULNX_SCAN_PATHS"
	printf "VULNX_SCAN_DOCKER='%s'\n" "${VULNX_SCAN_DOCKER:-auto}"
	printf "VULNX_INTERVAL='%s'\n" "${VULNX_INTERVAL:-21600}"
	printf "GRYPE_DB_CACHE_DIR='/var/lib/vulnx/grype-db'\n"
	printf "PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'\n"
} >"$CONF_DIR/agent.env"
umask 022
say "configuration written to $CONF_DIR/agent.env"

# 4. schedule
if has_systemd; then
	cat >"$UNIT_DIR/vulnx-agent.service" <<'EOF'
[Unit]
Description=VulnX vulnerability scan (grype)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vulnx-agent
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=2h
EOF
	cat >"$UNIT_DIR/vulnx-agent.timer" <<EOF
[Unit]
Description=Run the VulnX scan on a schedule

[Timer]
OnCalendar=${VULNX_SCHEDULE:-*-*-* 00/6:00:00}
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
EOF
	systemctl daemon-reload
	systemctl enable --now vulnx-agent.timer
	say "systemd timer enabled: $(systemctl list-timers vulnx-agent.timer --no-legend 2>/dev/null | head -n1)"
	[ "${VULNX_RUN_NOW:-1}" = "1" ] && systemctl start --no-block vulnx-agent.service && say "first scan started: journalctl -u vulnx-agent -f"
else
	minute=$(awk 'BEGIN{srand(); print int(rand()*60)}')
	cron=${VULNX_CRON:-"$minute */6 * * *"}
	if [ -d /etc/cron.d ]; then
		printf 'SHELL=/bin/sh\n%s root %s >>/var/log/vulnx-agent.log 2>&1\n' "$cron" "$BIN" >/etc/cron.d/vulnx-agent
		chmod 644 /etc/cron.d/vulnx-agent
	else
		(crontab -l 2>/dev/null | grep -v vulnx-agent; printf '%s %s >>/var/log/vulnx-agent.log 2>&1\n' "$cron" "$BIN") | crontab -
	fi
	say "cron schedule installed: $cron (log: /var/log/vulnx-agent.log)"
	[ "${VULNX_RUN_NOW:-1}" = "1" ] && (nohup "$BIN" >>/var/log/vulnx-agent.log 2>&1 &) && say "first scan started in the background"
fi
say "done. The host appears in the dashboard after its first scan."
