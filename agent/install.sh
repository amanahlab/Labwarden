#!/bin/sh
# LabWarden agent installer. Served by the dashboard at /install.sh.
#
#   curl -fsSL -o lw-install.sh https://labwarden.lan:8443/install.sh
#   echo "<sha256 from Settings>  lw-install.sh" | sha256sum -c
#   sudo LABWARDEN_URL=https://labwarden.lan:8443 LABWARDEN_TOKEN=vxe_... sh lw-install.sh
#
# Optional: LABWARDEN_CA_FILE (PEM CA to trust for the dashboard; copied to
#           /etc/labwarden/ca.pem), LABWARDEN_DOCKER_URL (tcp://host:port of a
#           read-only Docker socket proxy),
#           LABWARDEN_HOST, LABWARDEN_GROUP, LABWARDEN_SCAN_PATHS, LABWARDEN_SCAN_DOCKER,
#           LABWARDEN_SCHEDULE (systemd OnCalendar, default every 6h),
#           LABWARDEN_CRON (cron expression used when systemd is absent),
#           LABWARDEN_INTERVAL (seconds; must match the schedule, default 21600),
#           LABWARDEN_RUN_NOW=0 to skip the first scan.
# Uninstall: sudo sh lw-install.sh --uninstall
set -eu

# Bump together with the server's GRYPE_VERSION, and update both checksums
# from syft_<version>_checksums.txt of the release.
SYFT_VERSION=v1.57.0
SYFT_SHA256_amd64=9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704
SYFT_SHA256_arm64=410cbfa0ae0f63246bc0057843760b1de2833cd23919e025e368fd7681308cdb
# The dashboard fills this in with the SHA-256 of the agent script it serves.
AGENT_SHA256=@AGENT_SHA256@
BIN=/usr/local/bin/labwarden-agent
CONF_DIR=/etc/labwarden
UNIT_DIR=/etc/systemd/system

say() { printf 'labwarden: %s\n' "$*"; }
die() { printf 'labwarden: error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

# shq <value>: the value as one single-quoted shell word.
shq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# has_ctrl <value>: true if it contains a control character (newline included).
has_ctrl() { [ "$(printf '%s' "$1" | wc -c)" -ne "$(printf '%s' "$1" | tr -d '\000-\037\177' | wc -c)" ]; }

# matches <value> <extended regex>: the whole value, which has no control characters.
matches() { ! has_ctrl "$1" && printf '%s' "$1" | grep -Eq "^($2)\$"; }

# plain_http_remote <url>: true for http:// to anything but this machine.
plain_http_remote() {
	case "$1" in http://*) ;; *) return 1 ;; esac
	_h=${1#http://}
	_h=${_h%%/*}
	case "$_h" in localhost | localhost:* | 127.* | "[::1]" | "[::1]:"*) return 1 ;; esac
}

# validate: refuse any setting that could break out of agent.env, the cron
# line or the systemd unit.
validate() {
	matches "$LABWARDEN_URL" 'https?://[]A-Za-z0-9.:[_-]+(/[A-Za-z0-9._~/-]*)?' ||
		die "LABWARDEN_URL must be an http(s) URL such as http://labwarden.lan:8080"
	matches "$LABWARDEN_TOKEN" '[A-Za-z0-9_-]{16,255}' || die "LABWARDEN_TOKEN does not look like an enrollment token"
	[ -z "${LABWARDEN_HOST:-}" ] || matches "$LABWARDEN_HOST" '[A-Za-z0-9][A-Za-z0-9._-]{0,127}' ||
		die "LABWARDEN_HOST may only contain letters, digits, '.', '_' and '-'"
	matches "${LABWARDEN_GROUP:-default}" '.{1,64}' || die "LABWARDEN_GROUP must be 1-64 characters without control characters"
	! has_ctrl "${LABWARDEN_SCAN_PATHS:-}" || die "LABWARDEN_SCAN_PATHS must not contain control characters"
	matches "${LABWARDEN_SCAN_DOCKER:-auto}" 'auto|true|false' || die "LABWARDEN_SCAN_DOCKER must be auto, true or false"
	matches "${LABWARDEN_INTERVAL:-21600}" '[0-9]{1,7}' || die "LABWARDEN_INTERVAL must be a number of seconds"
	[ -z "${LABWARDEN_SCHEDULE:-}" ] || matches "$LABWARDEN_SCHEDULE" '[A-Za-z0-9*:/,. ~-]{1,100}' ||
		die "LABWARDEN_SCHEDULE must be a systemd OnCalendar expression"
	[ -z "${LABWARDEN_CRON:-}" ] || matches "$LABWARDEN_CRON" '[0-9*/,-]+( [0-9*/,-]+){4}' ||
		die "LABWARDEN_CRON must be five cron fields of digits and * / , -"
	[ -z "${LABWARDEN_DOCKER_URL:-}" ] || matches "$LABWARDEN_DOCKER_URL" 'tcp://[]A-Za-z0-9.:[_-]+' ||
		die "LABWARDEN_DOCKER_URL must look like tcp://socket-proxy:2375"
	[ -z "${LABWARDEN_CA_FILE:-}" ] || { ! has_ctrl "$LABWARDEN_CA_FILE" && [ -r "$LABWARDEN_CA_FILE" ]; } ||
		die "LABWARDEN_CA_FILE must be a readable PEM file"
}

# fetch <url> <file>: from the dashboard, never following a redirect elsewhere.
fetch() {
	if [ -n "${LABWARDEN_CA_FILE:-}" ]; then
		curl -fsS --proto =http,https --cacert "$LABWARDEN_CA_FILE" --max-time 120 -o "$2" "$1"
	else
		curl -fsS --proto =http,https --max-time 120 -o "$2" "$1"
	fi
}

# verify <file> <sha256>
verify() { [ "$(sha256sum "$1" | awk '{print $1}')" = "$2" ]; }

[ "${LABWARDEN_INSTALL_SELFTEST:-}" = 1 ] && return 0 2>/dev/null # scripts/test.sh sources the helpers above

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
: "${LABWARDEN_TOKEN:?set LABWARDEN_TOKEN to an enrollment token from Settings}"
LABWARDEN_URL=${LABWARDEN_URL%/}
validate
if plain_http_remote "$LABWARDEN_URL"; then
	say "warning: $LABWARDEN_URL is plain http; the enrollment token, the host credential and the SBOMs"
	say "warning: will cross the network unencrypted. Serve the dashboard over https (README: Security model)."
fi

for c in curl gzip sha256sum tar; do command -v "$c" >/dev/null 2>&1 || die "$c is required"; done
matches "$AGENT_SHA256" '[0-9a-f]{64}' || die "download install.sh from the dashboard; this copy carries no agent checksum"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# 1. syft (the dashboard holds the vulnerability DB; agents only catalog packages)
if command -v syft >/dev/null 2>&1 && [ "v$(syft version 2>/dev/null | awk '/^Version:/{print $2}')" = "$SYFT_VERSION" ]; then
	say "syft $SYFT_VERSION already installed"
else
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 sum=$SYFT_SHA256_amd64 ;;
	aarch64 | arm64) arch=arm64 sum=$SYFT_SHA256_arm64 ;;
	*) die "no pinned syft build for $(uname -m)" ;;
	esac
	say "installing syft $SYFT_VERSION ($arch)"
	tarball="syft_${SYFT_VERSION#v}_linux_${arch}.tar.gz"
	# GitHub answers with a redirect to its download host; https only.
	curl -fsSL --proto =https --max-time 300 -o "$TMP/$tarball" "https://github.com/anchore/syft/releases/download/$SYFT_VERSION/$tarball" ||
		die "could not download syft"
	verify "$TMP/$tarball" "$sum" || die "syft download does not match its pinned SHA-256; not installing it"
	tar -xzof "$TMP/$tarball" -C "$TMP" syft
	install -m 755 "$TMP/syft" /usr/local/bin/syft
fi
# Agents before 2.0 kept their own 3+ GB copy of the Grype DB here.
if [ -d /var/lib/labwarden/grype-db ]; then
	rm -rf /var/lib/labwarden/grype-db
	say "removed the old local grype DB (/var/lib/labwarden/grype-db)"
fi

# 2. agent script, from the dashboard so it always matches the server
fetch "$LABWARDEN_URL/agent/labwarden-agent.sh" "$TMP/agent" || die "could not download the agent from $LABWARDEN_URL"
verify "$TMP/agent" "$AGENT_SHA256" || die "the agent script does not match the checksum in this installer; not installing it"
install -m 755 "$TMP/agent" "$BIN"
say "agent installed at $BIN"

# 3. configuration (contains the enrollment token: root-only). The agent enrolls
#    on its first run and keeps its own credential in /var/lib/labwarden.
mkdir -p "$CONF_DIR" /var/lib/labwarden
chmod 700 "$CONF_DIR" /var/lib/labwarden
if [ -n "${LABWARDEN_CA_FILE:-}" ]; then
	[ "$LABWARDEN_CA_FILE" = "$CONF_DIR/ca.pem" ] || cp "$LABWARDEN_CA_FILE" "$CONF_DIR/ca.pem" || die "could not copy $LABWARDEN_CA_FILE"
	chown 0:0 "$CONF_DIR/ca.pem"
	chmod 644 "$CONF_DIR/ca.pem"
fi
umask 077
{
	printf 'LABWARDEN_URL=%s\n' "$(shq "$LABWARDEN_URL")"
	printf 'LABWARDEN_TOKEN=%s\n' "$(shq "$LABWARDEN_TOKEN")"
	[ -n "${LABWARDEN_HOST:-}" ] && printf 'LABWARDEN_HOST=%s\n' "$(shq "$LABWARDEN_HOST")"
	printf 'LABWARDEN_GROUP=%s\n' "$(shq "${LABWARDEN_GROUP:-default}")"
	[ -n "${LABWARDEN_SCAN_PATHS+x}" ] && printf 'LABWARDEN_SCAN_PATHS=%s\n' "$(shq "$LABWARDEN_SCAN_PATHS")"
	printf 'LABWARDEN_SCAN_DOCKER=%s\n' "$(shq "${LABWARDEN_SCAN_DOCKER:-auto}")"
	printf 'LABWARDEN_INTERVAL=%s\n' "$(shq "${LABWARDEN_INTERVAL:-21600}")"
	[ -n "${LABWARDEN_CA_FILE:-}" ] && printf 'LABWARDEN_CA_FILE=%s\n' "$(shq "$CONF_DIR/ca.pem")"
	[ -n "${LABWARDEN_DOCKER_URL:-}" ] && printf 'LABWARDEN_DOCKER_URL=%s\n' "$(shq "$LABWARDEN_DOCKER_URL")"
	printf "PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'\n"
} >"$CONF_DIR/agent.env"
chown 0:0 "$CONF_DIR/agent.env"
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
# Root is needed to read every file and the Docker socket, nothing more:
# read-only everywhere except the agent's state, no privilege gain.
# CAP_DAC_OVERRIDE lets it unpack a container filesystem with read-only
# directories into its private /tmp.
Environment=XDG_CACHE_HOME=/var/lib/labwarden/cache
ReadWritePaths=/var/lib/labwarden
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
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
