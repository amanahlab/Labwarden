#!/bin/sh
# LabWarden agent: catalogs the packages on this machine with Syft and pushes the
# SBOMs to a LabWarden dashboard, which matches them against its vulnerability DB. Scans the root filesystem (VM mode) and/or every image used by a
# running container (Docker mode). Logs to stdout and to the dashboard.
#
# Configuration comes from the environment, optionally loaded from
# /etc/labwarden/agent.env (see install.sh):
#   LABWARDEN_URL          dashboard base URL (required), e.g. http://labwarden.lan:8080
#   LABWARDEN_TOKEN        enrollment token from Settings; needed until this host has
#                          enrolled, after which it uses its own credential
#   LABWARDEN_HOST         host name shown in the dashboard (default: hostname)
#   LABWARDEN_GROUP        host group (default: default)
#   LABWARDEN_KIND         vm | docker (default: docker when scanning containers, else vm)
#   LABWARDEN_SCAN_PATHS   space-separated directories to scan (default: /; empty disables)
#   LABWARDEN_SCAN_DOCKER  auto | true | false (default: auto = if a Docker socket is reachable)
#   LABWARDEN_DOCKER_SOCK  Docker socket path (default: /var/run/docker.sock)
#   LABWARDEN_DOCKER_LABEL only scan containers with this label, e.g. labwarden.scan=true
#   LABWARDEN_EXCLUDES     space-separated syft --exclude globs for directory scans
#   LABWARDEN_INTERVAL     seconds between runs, reported so the dashboard can flag silent hosts
#   LABWARDEN_STATE        directory for the host credential (default: /var/lib/labwarden)
#   LABWARDEN_SPOOL        directory for SBOMs that failed to upload (default: $LABWARDEN_STATE/spool)
set -u

AGENT_VERSION="3.0.0"

# The configuration is sourced as shell code, so only a file that nobody else
# can have written is trusted: owned by root (or this user), not group- or
# world-writable.
ENV_FILE=/etc/labwarden/agent.env
if [ -f "$ENV_FILE" ]; then
	_perm=$(ls -ln "$ENV_FILE" | awk '{print $1}') _owner=$(ls -ln "$ENV_FILE" | awk '{print $3}')
	case "$_perm" in ?????w* | ????????w*) echo "refusing $ENV_FILE: it is group- or world-writable" >&2 && exit 1 ;; esac
	case "$_owner" in 0 | "$(id -u)") ;; *) echo "refusing $ENV_FILE: it is not owned by root" >&2 && exit 1 ;; esac
	set -a
	# shellcheck disable=SC1090
	. "$ENV_FILE"
	set +a
fi

: "${LABWARDEN_URL:?LABWARDEN_URL is required}"
LABWARDEN_TOKEN=${LABWARDEN_TOKEN:-}
LABWARDEN_URL=${LABWARDEN_URL%/}
LABWARDEN_HOST=${LABWARDEN_HOST:-$(hostname 2>/dev/null || cat /etc/hostname)}
LABWARDEN_GROUP=${LABWARDEN_GROUP:-default}
LABWARDEN_SCAN_PATHS=${LABWARDEN_SCAN_PATHS-/}
LABWARDEN_SCAN_DOCKER=${LABWARDEN_SCAN_DOCKER:-auto}
LABWARDEN_DOCKER_SOCK=${LABWARDEN_DOCKER_SOCK:-/var/run/docker.sock}
LABWARDEN_DOCKER_LABEL=${LABWARDEN_DOCKER_LABEL:-}
LABWARDEN_EXCLUDES=${LABWARDEN_EXCLUDES-./proc/** ./sys/** ./dev/** ./run/** ./tmp/** ./var/lib/docker/** ./var/lib/containerd/** ./var/lib/labwarden/** ./snap/** ./mnt/** ./media/**}
LABWARDEN_INTERVAL=${LABWARDEN_INTERVAL:-21600}
LABWARDEN_STATE=${LABWARDEN_STATE:-/var/lib/labwarden}
LABWARDEN_SPOOL=${LABWARDEN_SPOOL:-$LABWARDEN_STATE/spool}
CRED_FILE="$LABWARDEN_STATE/credential"
CRED=""
SYFT=${SYFT:-syft}
export SYFT_CHECK_FOR_APP_UPDATE=false

RUN_ID="$(date +%s)-$$"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/labwarden.XXXXXX") || exit 1
LOCK="$LABWARDEN_STATE/agent.lock"
trap 'rm -rf "$WORK"' EXIT INT TERM
(umask 077 && : >"$WORK/auth.hdr") # no credential yet: no Authorization header

log() { printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2"; }

# JSON string escaping for the few values we embed by hand. Control
# characters other than newline and tab are dropped, those two become spaces.
json_str() {
	printf '%s' "$1" | tr '\n\t' '  ' | tr -d '\000-\037\177' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/; s/$/"/'
}

# printable <file>: up to 300 bytes of a server answer, safe to log.
printable() {
	head -c 300 "$1" 2>/dev/null | tr '\n\t' '  ' | tr -d '\000-\037\177'
}

# Secrets go to curl in a header file, never on its command line, where any
# local user could read them. Only [A-Za-z0-9_-] passes, so nothing can be
# injected into the header.
auth_header() { # auth_header <secret> <file>
	case "$1" in "" | *[!A-Za-z0-9_-]*) return 1 ;; esac
	(umask 077 && printf 'Authorization: Bearer %s\n' "$1" >"$2")
}

urlenc() {
	printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n' | sed 's/\(..\)/%\1/g'
}

api() { # api <path> <content-type> <body-file> [extra curl args]
	_path=$1 _ctype=$2 _file=$3
	shift 3
	curl -fsS --proto =http,https --retry 3 --retry-delay 5 --max-time 120 \
		-H "@$WORK/auth.hdr" -H "Content-Type: ${_ctype}" -H "User-Agent: labwarden-agent/${AGENT_VERSION}" \
		--data-binary "@${_file}" "$@" "${LABWARDEN_URL}${_path}"
}

# event <level> <message>: log locally and ship to the dashboard (best effort).
event() {
	log "$1" "$2"
	printf '{"host":%s,"level":%s,"run_id":%s,"message":%s}' \
		"$(json_str "$LABWARDEN_HOST")" "$(json_str "$1")" "$(json_str "$RUN_ID")" "$(json_str "$2")" >"$WORK/event.json"
	api /api/v1/ingest/event application/json "$WORK/event.json" -o /dev/null 2>/dev/null || true
}

# The host credential: the dashboard hands it out once, at enrollment, and
# binds it to LABWARDEN_HOST. A credential stored for another host name (the
# machine was renamed) is not used.
load_credential() {
	CRED=""
	[ -f "$CRED_FILE" ] && [ "$(cat "$CRED_FILE.host" 2>/dev/null)" = "$LABWARDEN_HOST" ] || return 1
	CRED=$(cat "$CRED_FILE")
	auth_header "$CRED" "$WORK/auth.hdr" || { CRED="" && return 1; }
}

# enroll: trade LABWARDEN_TOKEN for this host's credential.
enroll() {
	if [ -z "$LABWARDEN_TOKEN" ]; then
		log error "this host is not enrolled and LABWARDEN_TOKEN is not set; re-run install.sh with an enrollment token from Settings"
		return 1
	fi
	if ! auth_header "$LABWARDEN_TOKEN" "$WORK/enroll.hdr"; then
		log error "LABWARDEN_TOKEN is not a valid enrollment token"
		return 1
	fi
	# The dashboard hands out a credential only once: make sure it can be kept.
	mkdir -p "$LABWARDEN_STATE" && chmod 700 "$LABWARDEN_STATE" && (umask 077 && : >"$CRED_FILE.tmp") ||
		{ log error "cannot write the credential to $LABWARDEN_STATE; not enrolling" && return 1; }
	printf '{"host":%s}' "$(json_str "$LABWARDEN_HOST")" >"$WORK/enroll.json"
	: >"$WORK/enrolled.json"
	_code=$(curl -sS --proto =http,https --max-time 60 -H "@$WORK/enroll.hdr" -H "Content-Type: application/json" \
		-H "User-Agent: labwarden-agent/${AGENT_VERSION}" --data-binary "@$WORK/enroll.json" \
		-o "$WORK/enrolled.json" -w '%{http_code}' "${LABWARDEN_URL}/api/v1/ingest/enroll")
	case "$_code" in
	201) ;;
	401) log error "enrollment refused: the token is unknown, revoked, expired or used up; create a new one in Settings and re-run install.sh" && return 1 ;;
	409) log error "$LABWARDEN_HOST is already enrolled; reset its agent credential on the host's page in the dashboard" && return 1 ;;
	*) log error "enrollment failed (HTTP ${_code:-none}); will try again on the next run" && return 1 ;;
	esac
	_cred=$(sed -n 's/.*"credential":"\([A-Za-z0-9_]*\)".*/\1/p' "$WORK/enrolled.json")
	auth_header "$_cred" "$WORK/auth.hdr" || { log error "enrollment answer carried no credential" && return 1; }
	mkdir -p "$LABWARDEN_STATE" && chmod 700 "$LABWARDEN_STATE"
	(umask 077 && printf '%s' "$_cred" >"$CRED_FILE.tmp" && printf '%s' "$LABWARDEN_HOST" >"$CRED_FILE.host") &&
		mv "$CRED_FILE.tmp" "$CRED_FILE" || { log error "could not store the credential in $CRED_FILE" && return 1; }
	CRED=$_cred
	log info "enrolled $LABWARDEN_HOST with the dashboard"
}

host_os() {
	# Read, never sourced: os-release is data, not a script.
	if [ -r /etc/os-release ]; then
		sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n1 | sed 's/^["'"'"']//; s/["'"'"']$//'
	else
		uname -s
	fi
}

host_ip() {
	(hostname -I 2>/dev/null || ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1) | awk '{print $1; exit}'
}

run_status() { # run_status <started|ok|error> <message> [targets-json-array]
	printf '{"host":%s,"kind":%s,"group":%s,"os":%s,"arch":%s,"ip":%s,"agent_version":%s,"interval":%s,"run_id":%s,"status":%s,"message":%s,"targets":%s}' \
		"$(json_str "$LABWARDEN_HOST")" "$(json_str "$KIND")" "$(json_str "$LABWARDEN_GROUP")" "$(json_str "$(host_os)")" \
		"$(json_str "$(uname -m)")" "$(json_str "$(host_ip)")" "$(json_str "$AGENT_VERSION")" "$LABWARDEN_INTERVAL" \
		"$(json_str "$RUN_ID")" "$(json_str "$1")" "$(json_str "$2")" "${3:-[]}" >"$WORK/run.json"
	_code=$(api /api/v1/ingest/run application/json "$WORK/run.json" -o /dev/null -w '%{http_code}')
}

docker_enabled() {
	case "$LABWARDEN_SCAN_DOCKER" in
	true) return 0 ;;
	false) return 1 ;;
	esac
	[ -S "$LABWARDEN_DOCKER_SOCK" ]
}

docker_api() { # docker_api <path> [curl args]: Docker Engine API over the socket
	_p=$1
	shift
	curl -fsS --unix-socket "$LABWARDEN_DOCKER_SOCK" "$@" "http://localhost$_p"
}

# One line per distinct running image: "<image-id> <container-id> <name>". The
# name is the image the container was started from, so it stays stable when a
# tag moves.
docker_images() {
	if command -v jq >/dev/null 2>&1; then
		_filter=""
		[ -n "$LABWARDEN_DOCKER_LABEL" ] && _filter="?filters=$(urlenc "{\"label\":[$(json_str "$LABWARDEN_DOCKER_LABEL")]}")"
		docker_api "/containers/json$_filter" | jq -r '.[].Id' | while read -r _c; do
			docker_api "/containers/$_c/json" | jq -r '.Image + " " + .Id + " " + .Config.Image'
		done
	elif command -v docker >/dev/null 2>&1; then
		if [ -n "$LABWARDEN_DOCKER_LABEL" ]; then
			DOCKER_HOST="unix://$LABWARDEN_DOCKER_SOCK" docker ps -q --filter "label=$LABWARDEN_DOCKER_LABEL"
		else
			DOCKER_HOST="unix://$LABWARDEN_DOCKER_SOCK" docker ps -q
		fi | while read -r _c; do
			DOCKER_HOST="unix://$LABWARDEN_DOCKER_SOCK" docker inspect --format '{{.Image}} {{.Id}} {{.Config.Image}}' "$_c" </dev/null
		done
	else
		event error "docker scanning needs jq or the docker CLI"
		return 1
	fi | sort -u -k1,1
}

image_id_of() { # image_id_of <name>: current image ID behind a tag
	if command -v jq >/dev/null 2>&1; then
		docker_api "/images/$1/json" 2>/dev/null | jq -r '.Id'
	else
		DOCKER_HOST="unix://$LABWARDEN_DOCKER_SOCK" docker image inspect --format '{{.Id}}' "$1" </dev/null 2>/dev/null
	fi
}

save_image() { # save_image <image-id> <file>
	if command -v jq >/dev/null 2>&1; then
		docker_api "/images/$1/get" -o "$2"
	else
		DOCKER_HOST="unix://$LABWARDEN_DOCKER_SOCK" docker save -o "$2" "$1" </dev/null
	fi
}

export_container() { # export_container <container-id> <dir>: unpack its filesystem
	mkdir -p "$2"
	if command -v jq >/dev/null 2>&1; then
		docker_api "/containers/$1/export" | tar -xof - -C "$2" 2>/dev/null
	else
		DOCKER_HOST="unix://$LABWARDEN_DOCKER_SOCK" docker export "$1" </dev/null | tar -xof - -C "$2" 2>/dev/null
	fi
	[ -d "$2/etc" ] || [ -d "$2/usr" ]
}

# scan_image <image-id> <container-id> <name>. In order of preference:
#  1. by tag, when it still points at the running image;
#  2. an export of the image, when the tag moved but the image still exists;
#  3. the container's filesystem, when the image itself is gone (rebuilt and
#     removed while the container kept running).
scan_image() {
	if [ "$(image_id_of "$3")" = "$1" ]; then
		scan "docker:$3" "$3"
		return
	fi
	if save_image "$1" "$WORK/image.tar" 2>/dev/null; then
		log info "$3 no longer points at the running image; scanning an export of ${1#sha256:}"
		scan "docker-archive:$WORK/image.tar" "$3"
		_rc=$?
		rm -f "$WORK/image.tar"
		return $_rc
	fi
	rm -f "$WORK/image.tar"
	log info "image of $3 was removed while its container runs; scanning the container filesystem"
	if ! export_container "$2" "$WORK/rootfs"; then
		event error "could not export container ${2%"${2#????????????}"} ($3)"
		rm -rf "$WORK/rootfs"
		return 1
	fi
	_ex=$LABWARDEN_EXCLUDES
	LABWARDEN_EXCLUDES=""
	scan "dir:$WORK/rootfs" "$3"
	_rc=$?
	LABWARDEN_EXCLUDES=$_ex
	rm -rf "$WORK/rootfs"
	return $_rc
}

query_for() { # query_for <target-name> <duration-ms>
	printf 'host=%s&kind=%s&group=%s&os=%s&arch=%s&ip=%s&agent_version=%s&interval=%s&run_id=%s&target=%s&duration_ms=%s' \
		"$(urlenc "$LABWARDEN_HOST")" "$KIND" "$(urlenc "$LABWARDEN_GROUP")" "$(urlenc "$(host_os)")" "$(uname -m)" \
		"$(urlenc "$(host_ip)")" "$AGENT_VERSION" "$LABWARDEN_INTERVAL" "$RUN_ID" "$(urlenc "$1")" "$2"
}

# upload <gz-file> <query>: the server answers 202 and matches it in
# the background. Returns 2 when the server rejects the upload itself (bad, too
# large, or for another host), which no retry can fix; 1 for anything worth
# retrying later.
upload() {
	: >"$WORK/resp.json" # curl -f writes no body on an error; never report the last success
	_code=$(api "/api/v1/ingest/sbom?$2" application/json "$1" -H "Content-Encoding: gzip" \
		-o "$WORK/resp.json" -w '%{http_code}') && return 0
	case "$_code" in 400 | 403 | 413 | 415 | 422) return 2 ;; esac
	return 1
}

rejected() { # rejected <what>: why the server refused the last upload
	_body=$(printable "$WORK/resp.json")
	printf 'rejected %s (HTTP %s%s)' "$1" "$_code" "${_body:+: $_body}"
}

# Re-send SBOMs that failed to upload on an earlier run.
flush_spool() {
	[ -d "$LABWARDEN_SPOOL" ] || return 0
	for f in "$LABWARDEN_SPOOL"/*.sbom.gz; do
		[ -f "$f" ] || continue
		_base=${f%.sbom.gz}
		if upload "$f" "$(cat "$_base.query")" 2>/dev/null; then
			rm -f "$f" "$_base.query"
			event info "uploaded spooled SBOM $(basename "$f")"
		elif [ $? -eq 2 ]; then
			rm -f "$f" "$_base.query" # would block every newer spooled upload forever
			event error "dashboard $(rejected "spooled SBOM $(basename "$f")"); dropped it"
		else
			log warn "dashboard unreachable or busy; keeping spooled uploads"
			return 0
		fi
	done
}

spool() { # spool <gz-file> <query>
	mkdir -p "$LABWARDEN_SPOOL" && chmod 700 "$LABWARDEN_SPOOL"
	_name="$LABWARDEN_SPOOL/$(date +%s)-$$-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
	cp "$1" "$_name.sbom.gz" && printf '%s' "$2" >"$_name.query"
	# keep the spool bounded
	ls -1t "$LABWARDEN_SPOOL"/*.gz 2>/dev/null | tail -n +21 | while read -r old; do rm -f "$old" "${old%.*.gz}.query"; done
}

# scan <syft-source> <target-name>
scan() {
	_src=$1 _name=$2
	log info "cataloging $_name"
	_start=$(date +%s)
	set -f # keep exclude globs literal
	_excl=""
	case "$_src" in dir:*) for e in $LABWARDEN_EXCLUDES; do _excl="$_excl --exclude $e"; done ;; esac
	# shellcheck disable=SC2086
	if ! "$SYFT" scan "$_src" -o syft-json -q $_excl >"$WORK/sbom.json" 2>"$WORK/syft.err"; then
		set +f
		event error "syft failed on $_name: $(tail -c 800 "$WORK/syft.err")"
		return 1
	fi
	set +f
	_dur=$((($(date +%s) - _start) * 1000))
	gzip -c "$WORK/sbom.json" >"$WORK/sbom.json.gz"
	_q=$(query_for "$_name" "$_dur")
	if upload "$WORK/sbom.json.gz" "$_q" 2>"$WORK/curl.err"; then
		log info "uploaded $_name: $(printable "$WORK/resp.json")"
	elif [ $? -eq 2 ]; then
		event error "dashboard $(rejected "the SBOM of $_name")"
		return 1
	else
		spool "$WORK/sbom.json.gz" "$_q"
		log error "upload of $_name failed ($(printable "$WORK/curl.err")); SBOM spooled for the next run"
		return 1
	fi
}

main() {
	(umask 077 && mkdir -p "$LABWARDEN_STATE") || { log error "cannot create $LABWARDEN_STATE" && exit 1; }
	if ! mkdir "$LOCK" 2>/dev/null; then
		# A run killed without its trap (SIGKILL, power loss, a stopped
		# container) leaves the lock behind; take it over if its owner is gone.
		_pid=$(cat "$LOCK/pid" 2>/dev/null)
		if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null &&
			{ [ ! -r "/proc/$_pid/cmdline" ] || grep -q labwarden-agent "/proc/$_pid/cmdline"; }; then
			log warn "another labwarden-agent run is in progress; exiting"
			exit 0
		fi
		log warn "removing stale lock left by pid ${_pid:-unknown}"
		rm -rf "$LOCK"
		mkdir "$LOCK" 2>/dev/null || { log warn "another labwarden-agent run took the lock; exiting"; exit 0; }
	fi
	printf '%s\n' "$$" >"$LOCK/pid"
	trap 'rm -rf "$WORK" "$LOCK"' EXIT INT TERM

	KIND=${LABWARDEN_KIND:-}
	if [ -z "$KIND" ]; then
		if docker_enabled; then KIND=docker; else KIND=vm; fi
	fi
	load_credential || enroll || log warn "not enrolled with the dashboard; SBOMs will be spooled"

	if ! command -v "$SYFT" >/dev/null 2>&1; then
		log error "syft not found (SYFT=$SYFT)"
		run_status error "syft is not installed on this host; re-run install.sh" 2>/dev/null
		exit 1
	fi

	_t0=$(date +%s)
	_started="scan run started (agent $AGENT_VERSION, $($SYFT version 2>/dev/null | awk '/^Version:/{print "syft " $2}'))"
	run_status started "$_started"
	# A credential that was reset, or a dashboard rebuilt from scratch: enroll again, once.
	if [ "$_code" = 401 ] && [ -n "$CRED" ]; then
		log warn "the dashboard no longer accepts this host's credential; enrolling again"
		rm -f "$CRED_FILE" "$CRED_FILE.host" "$WORK/auth.hdr"
		CRED=""
		enroll && run_status started "$_started"
	fi
	[ "$_code" = 202 ] || log warn "dashboard at $LABWARDEN_URL did not accept the run (HTTP ${_code:-none}); SBOMs will be spooled"
	flush_spool

	failed=0
	scanned=0
	targets=""
	add_target() { targets="$targets$(json_str "$1"),"; }

	for p in $LABWARDEN_SCAN_PATHS; do
		add_target "$p"
		if scan "dir:$p" "$p"; then scanned=$((scanned + 1)); else failed=$((failed + 1)); fi
	done

	if docker_enabled; then
		if docker_images >"$WORK/images.txt"; then
			while read -r id cid name; do
				[ -n "$id" ] || continue
				case "$name" in "" | sha256:*) name=$(printf '%.12s' "${id#sha256:}") ;; esac
				add_target "$name"
				if scan_image "$id" "$cid" "$name"; then scanned=$((scanned + 1)); else failed=$((failed + 1)); fi
			done <"$WORK/images.txt"
		else
			event error "could not list containers via $LABWARDEN_DOCKER_SOCK"
			failed=$((failed + 1))
		fi
	fi

	msg="scanned $scanned target(s) in $(($(date +%s) - _t0))s"
	if [ "$failed" -gt 0 ]; then
		msg="$msg, $failed failed"
		run_status error "$msg" "[${targets%,}]" || log error "could not report run status"
		log error "$msg"
		exit 1
	fi
	run_status ok "$msg" "[${targets%,}]" || log error "could not report run status"
	log info "$msg"
}

main "$@"
