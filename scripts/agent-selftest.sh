#!/bin/sh
# Checks the input validation of agent/install.sh and the escaping helpers of
# agent/labwarden-agent.sh. scripts/test.sh runs it in busybox and debian
# containers with the repository mounted at /mnt.
set -eu
cd /mnt
fails=0
check() { # check <description> <expected exit: 0|1> <command...>
	_d=$1 _want=$2
	shift 2
	if ("$@") >/dev/null 2>&1; then _got=0; else _got=1; fi
	if [ "$_got" = "$_want" ]; then echo "ok   $_d"; else echo "FAIL $_d" && fails=$((fails + 1)); fi
}

LABWARDEN_INSTALL_SELFTEST=1
. agent/install.sh
set +e

nl='
'
good() {
	LABWARDEN_URL=http://labwarden.lan:8080 LABWARDEN_TOKEN=vxe_0123456789abcdef0123
	LABWARDEN_HOST='' LABWARDEN_GROUP='' LABWARDEN_CRON='' LABWARDEN_SCHEDULE='' LABWARDEN_SCAN_PATHS='' LABWARDEN_INTERVAL=''
	LABWARDEN_SCAN_DOCKER='' LABWARDEN_DOCKER_URL='' LABWARDEN_CA_FILE=''
}
with() { good && eval "$1" && validate; } # with <assignments>: validate a good config changed by them
check "good settings pass" 0 with ':'
check "https URL and IPv6 host pass" 0 with 'LABWARDEN_URL=https://[fd00::1]:8443/labwarden'
check "a group with a quote passes (it is quoted)" 0 with "LABWARDEN_GROUP=\"bob's lab\""
check "cron with five fields passes" 0 with 'LABWARDEN_CRON="5 */6 * * 1-5"'
check "systemd calendar passes" 0 with 'LABWARDEN_SCHEDULE="*-*-* 00/6:00:00"'
check "ftp URL fails" 1 with 'LABWARDEN_URL=ftp://x'
check "URL with a quote fails" 1 with "LABWARDEN_URL=\"http://x/'\""
check "URL with a space fails" 1 with 'LABWARDEN_URL="http://x y"'
check "token with a quote fails" 1 with "LABWARDEN_TOKEN=\"vxe_0123456789abcdef'x\""
check "short token fails" 1 with 'LABWARDEN_TOKEN=vxe_1'
check "host name with a slash fails" 1 with 'LABWARDEN_HOST=a/b'
check "group with a newline fails" 1 with 'LABWARDEN_GROUP="a${nl}b"'
check "cron with a newline fails" 1 with 'LABWARDEN_CRON="5 * * * *${nl}* * * * * root sh"'
check "cron with a command fails" 1 with 'LABWARDEN_CRON="5 * * * * root"'
check "systemd calendar with a newline fails" 1 with 'LABWARDEN_SCHEDULE="daily${nl}ExecStart=/bin/sh"'
check "interval with letters fails" 1 with 'LABWARDEN_INTERVAL=6h'
check "scan docker yes fails" 1 with 'LABWARDEN_SCAN_DOCKER=yes'
check "socket proxy URL passes" 0 with 'LABWARDEN_DOCKER_URL=tcp://socket-proxy:2375'
check "http socket proxy URL fails" 1 with 'LABWARDEN_DOCKER_URL=http://socket-proxy:2375'
check "socket proxy URL with a path fails" 1 with 'LABWARDEN_DOCKER_URL=tcp://x:2375/../v1'
check "readable CA file passes" 0 with 'LABWARDEN_CA_FILE=/etc/hostname'
check "missing CA file fails" 1 with 'LABWARDEN_CA_FILE=/nonexistent.pem'
check "plain http to a LAN host warns" 0 plain_http_remote http://labwarden.lan:8080
check "plain http to loopback does not warn" 1 plain_http_remote http://127.0.0.1:8080/x
check "plain http to [::1] does not warn" 1 plain_http_remote 'http://[::1]:8080'
check "https does not warn" 1 plain_http_remote https://labwarden.lan
check "shq survives quotes" 0 sh -c ". /dev/stdin; [ \"\$v\" = \"a'b \\\$(id)\" ]" <<EOT
v=$(shq "a'b \$(id)")
EOT

eval "$(sed -n '/^json_str()/,/^}/p; /^printable()/,/^}/p; /^auth_header()/,/^}/p; /^docker_url_ok()/,/^}/p' agent/labwarden-agent.sh)"
check "agent: socket proxy URL passes" 0 docker_url_ok tcp://socket-proxy:2375
check "agent: socket proxy IPv6 URL passes" 0 docker_url_ok 'tcp://[fd00::2]:2375'
check "agent: socket proxy URL with a path fails" 1 docker_url_ok tcp://x:2375/v1
check "agent: socket proxy URL with a space fails" 1 docker_url_ok 'tcp://x 2375'
check "agent: empty socket proxy host fails" 1 docker_url_ok tcp://
check "agent: unix URL fails" 1 docker_url_ok unix:///var/run/docker.sock
esc=$(printf '\033')
check "json_str drops control characters" 0 test "$(json_str "a${esc}[31m\"b\\")" = '"a[31m\"b\\"'
check "json_str turns newlines into spaces" 0 test "$(json_str "a${nl}b")" = '"a b"'
tmp=$(mktemp -d)
check "auth_header writes a header" 0 sh -c "$(sed -n '/^auth_header()/,/^}/p' agent/labwarden-agent.sh)
auth_header vxa_ok $tmp/h && [ \"\$(cat $tmp/h)\" = 'Authorization: Bearer vxa_ok' ]"
check "auth_header refuses a newline" 1 auth_header "vxa_ok${nl}X-Evil: 1" "$tmp/h2"
check "auth_header refuses an empty secret" 1 auth_header "" "$tmp/h3"
rm -rf "$tmp"

# host_os reads /etc/os-release of this throwaway container.
eval "$(sed -n '/^os_release()/,/^}/p; /^host_os()/,/^}/p' agent/labwarden-agent.sh)"
cp /etc/os-release /tmp/os-release.orig
printf 'NAME="Plain OS"\nPRETTY_NAME="Plain OS 1 (x)"\n' >/etc/os-release
check "host_os reads PRETTY_NAME" 0 test "$(host_os)" = "Plain OS 1 (x)"
printf "NAME='Plain OS'\nID=plain\n" >/etc/os-release
check "host_os falls back to NAME" 0 test "$(host_os)" = "Plain OS"
printf 'PRETTY_NAME="$(id)"\n' >/etc/os-release
check "host_os never runs os-release" 0 test "$(host_os)" = '$(id)'
cp /tmp/os-release.orig /etc/os-release

# docker_inventory over the docker CLI (no jq): every container, even two on
# one image, and an image that cannot be inspected still lists its container.
eval "$(sed -n '/^docker_inventory()/,/^}/p' agent/labwarden-agent.sh)"
WORK=$(mktemp -d)
export LABWARDEN_DOCKER_LABEL=''
mkdir "$WORK/bin"
cat >"$WORK/bin/docker" <<'EOT'
#!/bin/sh
case "$1 $2" in
"ps -q") printf 'c1\nc2\n' ;;
"inspect --format")
	case "$3" in
	*container*) printf '"container":"/%s","ref":"nginx:1.27","image_id":"sha256:%s"' "$4" "$4" ;;
	*) printf 'sha256:%s\n' "$4" ;;
	esac ;;
"image inspect")
	[ "$5" = sha256:c1 ] || exit 1
	printf '"repo_digests":["nginx@sha256:d"],"created":"2026-03-01T10:00:00Z"' ;;
*) exit 1 ;;
esac
EOT
chmod +x "$WORK/bin/docker"
want='[{"container":"/c1","ref":"nginx:1.27","image_id":"sha256:c1","repo_digests":["nginx@sha256:d"],"created":"2026-03-01T10:00:00Z"},{"container":"/c2","ref":"nginx:1.27","image_id":"sha256:c2","repo_digests":[],"created":""}]'
check "docker_inventory lists every container" 0 test "$(PATH="$WORK/bin" docker_inventory)" = "$want"
check "docker_inventory fails without docker or jq" 1 sh -c "PATH=/nonexistent; $(sed -n '/^docker_inventory()/,/^}/p' agent/labwarden-agent.sh)
docker_inventory"
rm -rf "$WORK"

# A restarted container often hands the new run the pid of the run that was
# killed holding the lock; exec keeps $$, so the lock names the agent itself.
check "a lock holding the agent's own pid is stale" 0 sh -c '
	mkdir -p /tmp/lws/agent.lock && rm -f /tmp/lws/out
	sh -c "echo \$\$ >/tmp/lws/agent.lock/pid && LABWARDEN_STATE=/tmp/lws LABWARDEN_URL=http://127.0.0.1:9 \
		LABWARDEN_TOKEN=vxe_0123456789abcdef0123 ENV_FILE=/nonexistent exec sh agent/labwarden-agent.sh" >/tmp/lws/out 2>&1
	grep -q "removing stale lock" /tmp/lws/out'

[ "$fails" -eq 0 ] || { echo "$fails check(s) failed" && exit 1; }
