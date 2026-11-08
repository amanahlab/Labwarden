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
	LABWARDEN_SCAN_DOCKER=''
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
check "shq survives quotes" 0 sh -c ". /dev/stdin; [ \"\$v\" = \"a'b \\\$(id)\" ]" <<EOT
v=$(shq "a'b \$(id)")
EOT

eval "$(sed -n '/^json_str()/,/^}/p; /^printable()/,/^}/p; /^auth_header()/,/^}/p' agent/labwarden-agent.sh)"
esc=$(printf '\033')
check "json_str drops control characters" 0 test "$(json_str "a${esc}[31m\"b\\")" = '"a[31m\"b\\"'
check "json_str turns newlines into spaces" 0 test "$(json_str "a${nl}b")" = '"a b"'
tmp=$(mktemp -d)
check "auth_header writes a header" 0 sh -c "$(sed -n '/^auth_header()/,/^}/p' agent/labwarden-agent.sh)
auth_header vxa_ok $tmp/h && [ \"\$(cat $tmp/h)\" = 'Authorization: Bearer vxa_ok' ]"
check "auth_header refuses a newline" 1 auth_header "vxa_ok${nl}X-Evil: 1" "$tmp/h2"
check "auth_header refuses an empty secret" 1 auth_header "" "$tmp/h3"
rm -rf "$tmp"

[ "$fails" -eq 0 ] || { echo "$fails check(s) failed" && exit 1; }
