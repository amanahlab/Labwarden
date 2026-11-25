#!/bin/sh
# Measures what the agent's Syft run costs a host: wall time, CPU, memory and
# temp space for each (target x Syft setting x CPU limit), each in its own
# throwaway container so every run has its own cgroup. Rerun it when bumping
# Syft or changing how the agent calls it.
#
# Usage: scripts/agent-bench.sh
#   BENCH_IMAGES    images to catalog as the Docker agent does (default: a few
#                   large homelab images and the testbed workload)
#   BENCH_DIRS      directory targets, as the Linux agent scans /: "testbed-vm"
#                   (the testbed VM's filesystem) and/or "host" (this machine's /,
#                   read-only) (default: testbed-vm)
#   BENCH_VARIANTS  space-separated name[:VAR=value[,VAR=value...]] Syft settings
#   BENCH_CPUS      space-separated CPU limits, 0 = none (default: "0 2")
#   BENCH_OUT       results directory (default: bench/, gitignored)
# Prints one tab-separated row per run and keeps every SBOM for a findings diff.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

IMAGES=${BENCH_IMAGES-python:3.13 node:24 postgres:17 homeassistant/home-assistant:stable labwarden-testbed-workload:latest}
DIRS=${BENCH_DIRS-testbed-vm}
VARIANTS=${BENCH_VARIANTS:-default p1:SYFT_PARALLELISM=1 p2:SYFT_PARALLELISM=2 p4:SYFT_PARALLELISM=4 nofiles:SYFT_FILE_METADATA_SELECTION=none}
CPUS=${BENCH_CPUS:-0 2}
OUT=${BENCH_OUT:-$ROOT/bench}
AGENT=labwarden-agent:bench
# The agent's default excludes for a scan of /.
EXCLUDES='./proc/** ./sys/** ./dev/** ./run/** ./tmp/** ./var/lib/docker/** ./var/lib/containerd/** ./var/lib/labwarden/** ./snap/** ./mnt/** ./media/**'

mkdir -p "$OUT/img" "$OUT/sbom"
docker build -q -t "$AGENT" agent >/dev/null

# Runs inside the agent image: syft on $SRC, sampling its peak RSS. Prints
# "wall_s cpu_s rss_mb cgroup_peak_mb sbom_kb sbom_gz_kb rc".
# shellcheck disable=SC2016
MEASURE='
read -r u0 _ </proc/uptime
c0=$(sed -n "s/^usage_usec //p" /sys/fs/cgroup/cpu.stat)
set -f
excl=""
case "$SRC" in dir:*) for e in $EXCLUDES; do excl="$excl --exclude $e"; done ;; esac
syft scan "$SRC" -o syft-json -q $excl >/out/sbom.json 2>/out/syft.err &
pid=$!
hwm=0
while [ -r /proc/$pid/status ]; do
	while read -r k v _; do [ "$k" = VmHWM: ] && [ "$v" -gt "$hwm" ] && hwm=$v; done </proc/$pid/status 2>/dev/null || :
	sleep 0.1
done
wait $pid && rc=0 || rc=$?
read -r u1 _ </proc/uptime
c1=$(sed -n "s/^usage_usec //p" /sys/fs/cgroup/cpu.stat)
peak=$(cat /sys/fs/cgroup/memory.peak)
echo "$u0 $u1 $c0 $c1 $hwm $peak $(wc -c </out/sbom.json) $(gzip -c /out/sbom.json | wc -c) $rc" |
	awk "{printf \"%.1f %.1f %d %d %d %d %d\n\", \$2-\$1, (\$4-\$3)/1e6, \$5/1024, \$6/1048576, \$7/1024, \$8/1024, \$9}"
'

# measure <target> <syft-source> <variant> <cpus> [docker run args]
measure() {
	_t=$1 _src=$2 _v=$3 _c=$4
	shift 4
	_name=${_v%%:*} _envs=""
	case "$_v" in *:*) _envs=$(printf '%s' "${_v#*:}" | tr ',' ' ') ;; esac
	_lim=""
	[ "$_c" = 0 ] || _lim="--cpus $_c"
	_tmp=labwarden-bench-tmp-$$
	_run="$OUT/run"
	rm -rf "$_run" && mkdir -p "$_run"
	docker volume create "$_tmp" >/dev/null
	# A sidecar samples the temp volume, so du's own CPU stays out of the run's cgroup.
	_side=$(docker run -d -v "$_tmp:/t:ro" alpine:3.24 sh -c 'while :; do du -sk /t; sleep 1; done')
	_set=""
	for e in $_envs; do _set="$_set -e $e"; done
	# shellcheck disable=SC2086
	_row=$(docker run --rm $_lim $_set "$@" -e SRC="$_src" -e EXCLUDES="$EXCLUDES" \
		-e TMPDIR=/t -e SYFT_CHECK_FOR_APP_UPDATE=false -v "$_tmp:/t" -v "$_run:/out" \
		--entrypoint sh "$AGENT" -c "$MEASURE") || _row="- - - - - - fail"
	_tp=$(docker logs "$_side" 2>/dev/null | awk '$1 > m {m = $1} END {print int(m / 1024)}')
	docker rm -f "$_side" >/dev/null
	docker volume rm -f "$_tmp" >/dev/null
	[ -s "$_run/sbom.json" ] && mv "$_run/sbom.json" "$OUT/sbom/$(printf '%s' "$_t" | tr '/:' '__').$_name.cpu$_c.json"
	[ -s "$_run/syft.err" ] && { echo "syft stderr for $_t ($_name):" >&2; tail -c 400 "$_run/syft.err" >&2; }
	# shellcheck disable=SC2086
	set -- $_row
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$_t" "$_name" "$_c" "$1" "$2" "$3" "$4" "$_tp" "$5" "$6" "$7" | tee -a "$RESULTS"
}

RESULTS="$OUT/results-$(date -u +%Y%m%dT%H%M%SZ).tsv"
{
	echo "# host: $(nproc) CPUs, $(awk '/MemTotal/{printf "%d MB", $2/1024}' /proc/meminfo); syft: $(docker run --rm --entrypoint syft "$AGENT" version | awk '/^Version:/{print $2}')"
	printf 'target\tvariant\tcpus\twall_s\tcpu_s\trss_mb\tcgroup_peak_mb\ttmp_peak_mb\tsbom_kb\tsbom_gz_kb\trc\n'
} | tee "$RESULTS"

for img in $IMAGES; do
	docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null
	echo "# $img = $(docker image inspect --format '{{.Id}} {{join .RepoDigests " "}}' "$img")" | tee -a "$RESULTS"
	tar="$OUT/img/$(printf '%s' "$img" | tr '/:' '__').tar"
	[ -s "$tar" ] || docker save -o "$tar" "$img"
	for c in $CPUS; do
		for v in $VARIANTS; do
			measure "$img" "docker-archive:/img/$(basename "$tar")" "$v" "$c" -v "$OUT/img:/img:ro"
		done
	done
done

for d in $DIRS; do
	case "$d" in
	host) src=dir:/host args="-v /:/host:ro" ;;
	testbed-vm)
		docker build -q -t labwarden-bench-vm testbed/vm >/dev/null
		vol=labwarden-bench-rootfs
		if ! docker run --rm -v "$vol:/r" alpine:3.24 test -d /r/testbed-vm; then
			cid=$(docker create labwarden-bench-vm)
			docker export "$cid" | docker run --rm -i -v "$vol:/r" alpine:3.24 sh -c 'mkdir -p /r/testbed-vm && tar -xf - -C /r/testbed-vm'
			docker rm "$cid" >/dev/null
		fi
		src=dir:/r/testbed-vm args="-v $vol:/r:ro"
		;;
	*) echo "unknown BENCH_DIRS entry: $d" >&2 && exit 2 ;;
	esac
	for c in $CPUS; do
		for v in $VARIANTS; do
			# shellcheck disable=SC2086
			measure "$d" "$src" "$v" "$c" $args
		done
	done
done
echo "results: $RESULTS"
