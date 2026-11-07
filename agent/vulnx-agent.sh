#!/bin/sh
# VulnX agent: runs Grype on this machine and pushes the reports to a VulnX
# dashboard. Scans the root filesystem (VM mode) and/or every image used by a
# running container (Docker mode). Logs to stdout and to the dashboard.
#
# Configuration comes from the environment, optionally loaded from
# /etc/vulnx/agent.env (see install.sh):
#   VULNX_URL          dashboard base URL (required), e.g. http://vulnx.lan:8080
#   VULNX_TOKEN        ingest token (required)
#   VULNX_HOST         host name shown in the dashboard (default: hostname)
#   VULNX_GROUP        host group (default: default)
#   VULNX_KIND         vm | docker (default: docker when scanning containers, else vm)
#   VULNX_SCAN_PATHS   space-separated directories to scan (default: /; empty disables)
#   VULNX_SCAN_DOCKER  auto | true | false (default: auto = if a Docker socket is reachable)
#   VULNX_DOCKER_SOCK  Docker socket path (default: /var/run/docker.sock)
#   VULNX_DOCKER_LABEL only scan containers with this label, e.g. vulnx.scan=true
#   VULNX_EXCLUDES     space-separated grype --exclude globs for directory scans
#   VULNX_INTERVAL     seconds between runs, reported so the dashboard can flag silent hosts
#   VULNX_SPOOL        directory for reports that failed to upload (default: /var/lib/vulnx/spool)
#   GRYPE_DB_CACHE_DIR where grype keeps its vulnerability DB
set -u

AGENT_VERSION="1.0.0"

if [ -f /etc/vulnx/agent.env ]; then set -a; . /etc/vulnx/agent.env; set +a; fi

: "${VULNX_URL:?VULNX_URL is required}"
: "${VULNX_TOKEN:?VULNX_TOKEN is required}"
VULNX_URL=${VULNX_URL%/}
VULNX_HOST=${VULNX_HOST:-$(hostname 2>/dev/null || cat /etc/hostname)}
VULNX_GROUP=${VULNX_GROUP:-default}
VULNX_SCAN_PATHS=${VULNX_SCAN_PATHS-/}
VULNX_SCAN_DOCKER=${VULNX_SCAN_DOCKER:-auto}
VULNX_DOCKER_SOCK=${VULNX_DOCKER_SOCK:-/var/run/docker.sock}
VULNX_DOCKER_LABEL=${VULNX_DOCKER_LABEL:-}
VULNX_EXCLUDES=${VULNX_EXCLUDES-./proc/** ./sys/** ./dev/** ./run/** ./tmp/** ./var/lib/docker/** ./var/lib/containerd/** ./var/lib/vulnx/** ./snap/** ./mnt/** ./media/**}
VULNX_INTERVAL=${VULNX_INTERVAL:-21600}
VULNX_SPOOL=${VULNX_SPOOL:-/var/lib/vulnx/spool}
GRYPE=${GRYPE:-grype}
export GRYPE_CHECK_FOR_APP_UPDATE=false

RUN_ID="$(date +%s)-$$"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vulnx.XXXXXX") || exit 1
LOCK="${TMPDIR:-/tmp}/vulnx-agent.lock"
trap 'rm -rf "$WORK"' EXIT INT TERM

log() { printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2"; }

# JSON string escaping for the few values we embed by hand.
json_str() {
	printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n\t\r' '   ' | sed 's/^/"/; s/$/"/'
}

urlenc() {
	printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n' | sed 's/\(..\)/%\1/g'
}

api() { # api <path> <content-type> <body-file> [extra curl args]
	_path=$1 _ctype=$2 _file=$3
	shift 3
	curl -fsS --retry 3 --retry-delay 5 --max-time 600 \
		-H "Authorization: Bearer ${VULNX_TOKEN}" -H "Content-Type: ${_ctype}" -H "User-Agent: vulnx-agent/${AGENT_VERSION}" \
		--data-binary "@${_file}" "$@" "${VULNX_URL}${_path}"
}

# event <level> <message>: log locally and ship to the dashboard (best effort).
event() {
	log "$1" "$2"
	printf '{"host":%s,"level":%s,"run_id":%s,"message":%s}' \
		"$(json_str "$VULNX_HOST")" "$(json_str "$1")" "$(json_str "$RUN_ID")" "$(json_str "$2")" >"$WORK/event.json"
	api /api/v1/ingest/event application/json "$WORK/event.json" -o /dev/null 2>/dev/null || true
}

host_os() {
	if [ -r /etc/os-release ]; then
		(. /etc/os-release && printf '%s' "${PRETTY_NAME:-$NAME}")
	else
		uname -s
	fi
}

host_ip() {
	(hostname -I 2>/dev/null || ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1) | awk '{print $1; exit}'
}

run_status() { # run_status <started|ok|error> <message> [targets-json-array]
	printf '{"host":%s,"kind":%s,"group":%s,"os":%s,"arch":%s,"ip":%s,"agent_version":%s,"interval":%s,"run_id":%s,"status":%s,"message":%s,"targets":%s}' \
		"$(json_str "$VULNX_HOST")" "$(json_str "$KIND")" "$(json_str "$VULNX_GROUP")" "$(json_str "$(host_os)")" \
		"$(json_str "$(uname -m)")" "$(json_str "$(host_ip)")" "$(json_str "$AGENT_VERSION")" "$VULNX_INTERVAL" \
		"$(json_str "$RUN_ID")" "$(json_str "$1")" "$(json_str "$2")" "${3:-[]}" >"$WORK/run.json"
	api /api/v1/ingest/run application/json "$WORK/run.json" -o /dev/null
}

docker_enabled() {
	case "$VULNX_SCAN_DOCKER" in
	true) return 0 ;;
	false) return 1 ;;
	esac
	[ -S "$VULNX_DOCKER_SOCK" ]
}

docker_api() { # docker_api <path> [curl args]: Docker Engine API over the socket
	_p=$1
	shift
	curl -fsS --unix-socket "$VULNX_DOCKER_SOCK" "$@" "http://localhost$_p"
}

# One line per distinct running image: "<image-id> <container-id> <name>". The
# name is the image the container was started from, so it stays stable when a
# tag moves.
docker_images() {
	if command -v jq >/dev/null 2>&1; then
		_filter=""
		[ -n "$VULNX_DOCKER_LABEL" ] && _filter="?filters=$(urlenc "{\"label\":[$(json_str "$VULNX_DOCKER_LABEL")]}")"
		docker_api "/containers/json$_filter" | jq -r '.[].Id' | while read -r _c; do
			docker_api "/containers/$_c/json" | jq -r '.Image + " " + .Id + " " + .Config.Image'
		done
	elif command -v docker >/dev/null 2>&1; then
		if [ -n "$VULNX_DOCKER_LABEL" ]; then
			DOCKER_HOST="unix://$VULNX_DOCKER_SOCK" docker ps -q --filter "label=$VULNX_DOCKER_LABEL"
		else
			DOCKER_HOST="unix://$VULNX_DOCKER_SOCK" docker ps -q
		fi | while read -r _c; do
			DOCKER_HOST="unix://$VULNX_DOCKER_SOCK" docker inspect --format '{{.Image}} {{.Id}} {{.Config.Image}}' "$_c" </dev/null
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
		DOCKER_HOST="unix://$VULNX_DOCKER_SOCK" docker image inspect --format '{{.Id}}' "$1" </dev/null 2>/dev/null
	fi
}

save_image() { # save_image <image-id> <file>
	if command -v jq >/dev/null 2>&1; then
		docker_api "/images/$1/get" -o "$2"
	else
		DOCKER_HOST="unix://$VULNX_DOCKER_SOCK" docker save -o "$2" "$1" </dev/null
	fi
}

export_container() { # export_container <container-id> <dir>: unpack its filesystem
	mkdir -p "$2"
	if command -v jq >/dev/null 2>&1; then
		docker_api "/containers/$1/export" | tar -xf - -C "$2" 2>/dev/null
	else
		DOCKER_HOST="unix://$VULNX_DOCKER_SOCK" docker export "$1" </dev/null | tar -xf - -C "$2" 2>/dev/null
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
	_ex=$VULNX_EXCLUDES
	VULNX_EXCLUDES=""
	scan "dir:$WORK/rootfs" "$3"
	_rc=$?
	VULNX_EXCLUDES=$_ex
	rm -rf "$WORK/rootfs"
	return $_rc
}

query_for() { # query_for <target-name> <duration-ms>
	printf 'host=%s&kind=%s&group=%s&os=%s&arch=%s&ip=%s&agent_version=%s&interval=%s&run_id=%s&target=%s&duration_ms=%s' \
		"$(urlenc "$VULNX_HOST")" "$KIND" "$(urlenc "$VULNX_GROUP")" "$(urlenc "$(host_os)")" "$(uname -m)" \
		"$(urlenc "$(host_ip)")" "$AGENT_VERSION" "$VULNX_INTERVAL" "$RUN_ID" "$(urlenc "$1")" "$2"
}

upload() { # upload <gz-file> <query>
	api "/api/v1/ingest/report?$2" application/json "$1" -H "Content-Encoding: gzip" -o "$WORK/resp.json"
}

# Re-send reports that failed to upload on an earlier run.
flush_spool() {
	[ -d "$VULNX_SPOOL" ] || return 0
	for f in "$VULNX_SPOOL"/*.json.gz; do
		[ -f "$f" ] || continue
		if upload "$f" "$(cat "${f%.json.gz}.query")" 2>/dev/null; then
			rm -f "$f" "${f%.json.gz}.query"
			event info "uploaded spooled report $(basename "$f")"
		else
			log warn "dashboard still unreachable; keeping spooled reports"
			return 0
		fi
	done
}

spool() { # spool <gz-file> <query>
	mkdir -p "$VULNX_SPOOL" && chmod 700 "$VULNX_SPOOL"
	_name="$VULNX_SPOOL/$(date +%s)-$$-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
	cp "$1" "$_name.json.gz" && printf '%s' "$2" >"$_name.query"
	# keep the spool bounded
	ls -1t "$VULNX_SPOOL"/*.json.gz 2>/dev/null | tail -n +21 | while read -r old; do rm -f "$old" "${old%.json.gz}.query"; done
}

# scan <grype-source> <target-name>
scan() {
	_src=$1 _name=$2
	log info "scanning $_name"
	_start=$(date +%s)
	set -f # keep exclude globs literal
	_excl=""
	case "$_src" in dir:*) for e in $VULNX_EXCLUDES; do _excl="$_excl --exclude $e"; done ;; esac
	# shellcheck disable=SC2086
	if ! "$GRYPE" "$_src" -o json $_excl >"$WORK/report.json" 2>"$WORK/grype.err"; then
		set +f
		event error "grype failed on $_name: $(tail -c 800 "$WORK/grype.err")"
		return 1
	fi
	set +f
	_dur=$((($(date +%s) - _start) * 1000))
	gzip -c "$WORK/report.json" >"$WORK/report.json.gz"
	_q=$(query_for "$_name" "$_dur")
	if upload "$WORK/report.json.gz" "$_q" 2>"$WORK/curl.err"; then
		log info "uploaded $_name: $(cat "$WORK/resp.json")"
	else
		spool "$WORK/report.json.gz" "$_q"
		log error "upload of $_name failed ($(cat "$WORK/curl.err")); report spooled for the next run"
		return 1
	fi
}

main() {
	if ! mkdir "$LOCK" 2>/dev/null; then
		log warn "another vulnx-agent run is in progress; exiting"
		exit 0
	fi
	trap 'rm -rf "$WORK"; rmdir "$LOCK" 2>/dev/null' EXIT INT TERM

	KIND=${VULNX_KIND:-}
	if [ -z "$KIND" ]; then
		if docker_enabled; then KIND=docker; else KIND=vm; fi
	fi

	if ! command -v "$GRYPE" >/dev/null 2>&1; then
		log error "grype not found (GRYPE=$GRYPE)"
		run_status error "grype is not installed on this host" 2>/dev/null
		exit 1
	fi

	_t0=$(date +%s)
	run_status started "scan run started (agent $AGENT_VERSION, $($GRYPE version 2>/dev/null | awk '/^Version:/{print "grype " $2}'))" ||
		log warn "dashboard unreachable at $VULNX_URL; reports will be spooled"
	flush_spool

	if ! "$GRYPE" db update -q >"$WORK/db.log" 2>&1; then
		event warn "grype DB update failed, scanning with the cached DB: $(tail -c 500 "$WORK/db.log")"
	fi

	failed=0
	scanned=0
	targets=""
	add_target() { targets="$targets$(json_str "$1"),"; }

	for p in $VULNX_SCAN_PATHS; do
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
			event error "could not list containers via $VULNX_DOCKER_SOCK"
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
