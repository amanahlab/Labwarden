#!/bin/sh
# LabWarden agent installer. Served by the dashboard at /install.sh.
#
#   curl -fsSL http://labwarden.lan:8080/install.sh | sudo LABWARDEN_URL=http://labwarden.lan:8080 LABWARDEN_TOKEN=vx_... sh
#
# Optional: LABWARDEN_HOST, LABWARDEN_GROUP, LABWARDEN_SCAN_PATHS, LABWARDEN_SCAN_DOCKER,
#           LABWARDEN_SCHEDULE (systemd OnCalendar, default every 6h),
#           LABWARDEN_CRON (cron expression used when systemd is absent),
#           LABWARDEN_INTERVAL (seconds; must match the schedule, default 21600),
#           SYFT_VERSION (default pinned below), LABWARDEN_RUN_NOW=0 to skip the first scan.
# Uninstall: curl -fsSL .../install.sh | sudo sh -s -- --uninstall
set -eu

# Bump together with the server's GRYPE_VERSION.
SYFT_VERSION=${SYFT_VERSION:-v1.57.0}
BIN=/usr/local/bin/labwarden-agent
CONF_DIR=/etc/labwarden
UNIT_DIR=/etc/systemd/system

say() { printf 'labwarden: %s\n' "$*"; }
die() { printf 'labwarden: error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

has_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

if [ "${1:-}" = "--uninstall" ]; then
	if has_systemd; then
		systemctl disable --now labwarden-agent.timer 2>/dev/null || true
		rm -f "$UNIT_DIR/labwarden-agent.service" "$UNIT_DIR/labwarden-agent.timer"
		systemctl daemon-reload
	fi
	rm -f /etc/cron.d/labwarden-agent "$BIN"
	rm -rf "$CONF_DIR"
	say "agent removed (syft and /var/lib/labwarden were left in place)"
	exit 0
fi

: "${LABWARDEN_URL:?set LABWARDEN_URL to the dashboard URL}"
: "${LABWARDEN_TOKEN:?set LABWARDEN_TOKEN to an ingest token from Settings}"
LABWARDEN_URL=${LABWARDEN_URL%/}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v gzip >/dev/null 2>&1 || die "gzip is required"

# 1. syft (the dashboard holds the vulnerability DB; agents only catalog packages)
if command -v syft >/dev/null 2>&1 && [ "v$(syft version 2>/dev/null | awk '/^Version:/{print $2}')" = "$SYFT_VERSION" ]; then
	say "syft $SYFT_VERSION already installed"
else
	say "installing syft $SYFT_VERSION"
	curl -fsSL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin "$SYFT_VERSION"
fi
# Agents before 2.0 kept their own 3+ GB copy of the Grype DB here.
if [ -d /var/lib/labwarden/grype-db ]; then
	rm -rf /var/lib/labwarden/grype-db
	say "removed the old local grype DB (/var/lib/labwarden/grype-db)"
fi

# 2. agent script, from the dashboard so it always matches the server
curl -fsSL "$LABWARDEN_URL/agent/labwarden-agent.sh" -o "$BIN.tmp"
head -n1 "$BIN.tmp" | grep -q '^#!/bin/sh' || die "downloaded agent does not look like a script"
chmod 755 "$BIN.tmp" && mv "$BIN.tmp" "$BIN"
say "agent installed at $BIN"

# 3. configuration (contains the token: root-only)
mkdir -p "$CONF_DIR" /var/lib/labwarden
chmod 700 "$CONF_DIR" /var/lib/labwarden
umask 077
{
	printf "LABWARDEN_URL='%s'\n" "$LABWARDEN_URL"
	printf "LABWARDEN_TOKEN='%s'\n" "$LABWARDEN_TOKEN"
	[ -n "${LABWARDEN_HOST:-}" ] && printf "LABWARDEN_HOST='%s'\n" "$LABWARDEN_HOST"
	printf "LABWARDEN_GROUP='%s'\n" "${LABWARDEN_GROUP:-default}"
	[ -n "${LABWARDEN_SCAN_PATHS+x}" ] && printf "LABWARDEN_SCAN_PATHS='%s'\n" "$LABWARDEN_SCAN_PATHS"
	printf "LABWARDEN_SCAN_DOCKER='%s'\n" "${LABWARDEN_SCAN_DOCKER:-auto}"
	printf "LABWARDEN_INTERVAL='%s'\n" "${LABWARDEN_INTERVAL:-21600}"
	printf "PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'\n"
} >"$CONF_DIR/agent.env"
umask 022
say "configuration written to $CONF_DIR/agent.env"

# 4. schedule
if has_systemd; then
	cat >"$UNIT_DIR/labwarden-agent.service" <<'EOF'
[Unit]
Description=LabWarden vulnerability scan (syft)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/labwarden-agent
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=2h
EOF
	cat >"$UNIT_DIR/labwarden-agent.timer" <<EOF
[Unit]
Description=Run the LabWarden scan on a schedule

[Timer]
OnCalendar=${LABWARDEN_SCHEDULE:-*-*-* 00/6:00:00}
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
EOF
	systemctl daemon-reload
	systemctl enable --now labwarden-agent.timer
	say "systemd timer enabled: $(systemctl list-timers labwarden-agent.timer --no-legend 2>/dev/null | head -n1)"
	[ "${LABWARDEN_RUN_NOW:-1}" = "1" ] && systemctl start --no-block labwarden-agent.service && say "first scan started: journalctl -u labwarden-agent -f"
else
	minute=$(awk 'BEGIN{srand(); print int(rand()*60)}')
	cron=${LABWARDEN_CRON:-"$minute */6 * * *"}
	if [ -d /etc/cron.d ]; then
		printf 'SHELL=/bin/sh\n%s root %s >>/var/log/labwarden-agent.log 2>&1\n' "$cron" "$BIN" >/etc/cron.d/labwarden-agent
		chmod 644 /etc/cron.d/labwarden-agent
	else
		(crontab -l 2>/dev/null | grep -v labwarden-agent; printf '%s %s >>/var/log/labwarden-agent.log 2>&1\n' "$cron" "$BIN") | crontab -
	fi
	say "cron schedule installed: $cron (log: /var/log/labwarden-agent.log)"
	[ "${LABWARDEN_RUN_NOW:-1}" = "1" ] && (nohup "$BIN" >>/var/log/labwarden-agent.log 2>&1 &) && say "first scan started in the background"
fi
say "done. The host appears in the dashboard after its first scan."
