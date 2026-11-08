#!/usr/bin/env sh
# End-to-end check: start the dashboard and the testbed, wait for both agents
# to report, then assert known vulnerabilities, triage, central scanning and
# retirement of a container that disappears. Never prints secrets.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
[ -f .env ] || scripts/dev-env.sh
set -a; . ./.env; set +a
URL="http://localhost:${LABWARDEN_PORT:-8080}"
JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok   $*"; }
api() { curl -fsS -b "$JAR" -c "$JAR" "$@"; }
jqr() { docker run --rm -i ghcr.io/jqlang/jq:1.8.1 "$@"; }
wait_for() { # wait_for <seconds> <description> <command...>
  _t=$1 _d=$2; shift 2
  while ! "$@" >/dev/null 2>&1; do
    _t=$((_t - 5)); [ "$_t" -gt 0 ] || fail "timed out waiting for $_d"
    sleep 5
  done
  pass "$_d"
}

echo "== starting stack"
docker compose --profile testbed up -d --build --quiet-pull >/dev/null
wait_for 120 "dashboard healthy" curl -fsS "$URL/healthz"

printf '{"password":"%s"}' "$LABWARDEN_ADMIN_PASSWORD" | api -o /dev/null -H 'Content-Type: application/json' --data-binary @- "$URL/api/v1/auth/login" ||
  fail "login"
pass "admin login"

host_id() { api "$URL/api/v1/hosts?q=$1" | jqr -e --arg n "$1" '.items[] | select(.name == $n and .total > 0) | .id'; }
wait_for 900 "testbed-vm reported findings" host_id testbed-vm
# Don't wait for the 15-minute loop: run the docker agent now (a no-op if a run is in progress).
docker compose --profile testbed exec -T testbed-docker-agent labwarden-agent >/dev/null 2>&1 || true
wait_for 900 "testbed-docker reported findings" host_id testbed-docker

has_vuln() { # has_vuln <query> <jq filter on items>
  api "$URL/api/v1/vulnerabilities?q=$1&status=all&size=100" | jqr -e "[.items[] | $2] | any" >/dev/null || fail "expected $1 ($2)"
  pass "found $1"
}
has_vuln CVE-2021-44228 '.kev and .severity == "Critical"'
has_vuln django '.packages == "django"'
has_vuln lodash '.packages == "lodash"'
has_vuln log4j-core '.packages == "log4j-core"'
api "$URL/api/v1/findings?pkg_type=apk&size=1" | jqr -e '.total > 0' >/dev/null || fail "no apk findings from the docker agent"
pass "docker image findings (apk)"

echo "== triage"
VID=$(api "$URL/api/v1/vulnerabilities?q=CVE-2021-44228" | jqr -r '.items[0].id')
api -o /dev/null -X PUT -H 'Content-Type: application/json' -d '{"host_id":0,"status":"acknowledged","note":"e2e"}' "$URL/api/v1/vulnerabilities/$VID/triage"
api "$URL/api/v1/vulnerabilities/$VID" | jqr -e '.vulnerability.status == "acknowledged"' >/dev/null || fail "triage not applied"
api -o /dev/null -X PUT -H 'Content-Type: application/json' -d '{"host_id":0,"status":"open","note":""}' "$URL/api/v1/vulnerabilities/$VID/triage"
pass "triage round trip on $VID"

echo "== central registry scan"
CID=$(api -H 'Content-Type: application/json' -d '{"ref":"alpine:3.12","host_name":"e2e-registry","group":"e2e","interval_min":1440}' "$URL/api/v1/central-targets" | jqr -r '.id')
central_ok() { api "$URL/api/v1/central-targets" | jqr -e --argjson id "$CID" '.[] | select(.id == $id) | .last_status == "ok"'; }
wait_for 600 "central scan of alpine:3.12" central_ok
api -o /dev/null -X DELETE "$URL/api/v1/central-targets/$CID"
api -o /dev/null -X DELETE "$URL/api/v1/hosts/$(host_id e2e-registry)"
pass "central scan target and its host cleaned up"

echo "== stale agent lock"
# A run killed mid-scan (e.g. the container was stopped) leaves its lock behind.
docker compose --profile testbed exec -T testbed-docker-agent \
  sh -c 'mkdir -p /tmp/labwarden-agent.lock && echo 999999 >/tmp/labwarden-agent.lock/pid'
docker compose --profile testbed exec -T testbed-docker-agent labwarden-agent 2>&1 | grep -q "removing stale lock" ||
  fail "agent did not take over a stale lock"
docker compose --profile testbed exec -T testbed-docker-agent test ! -e /tmp/labwarden-agent.lock ||
  fail "agent left its lock behind"
pass "agent recovers from a stale lock"

echo "== retirement of a removed container"
DID=$(host_id testbed-docker)
run_agent() { docker compose --profile testbed exec -T testbed-docker-agent labwarden-agent >/dev/null 2>&1; }
workload_retired() { # workload_retired <true|false>: runs the agent once, then checks
  run_agent || return 1
  api "$URL/api/v1/hosts/$DID" | jqr -e --argjson want "$1" \
    '[.targets[] | select(.name == "labwarden-testbed-workload:latest") | .retired_at != ""] | (length > 0 and all == $want)'
}
docker compose --profile testbed stop testbed-workload >/dev/null
wait_for 300 "workload image retired after it stopped running" workload_retired true
docker compose --profile testbed start testbed-workload >/dev/null
wait_for 300 "workload image back after it started again" workload_retired false

echo "== logs"
api "$URL/api/v1/events?source=agent&size=1" | jqr -e '.total > 0' >/dev/null || fail "no agent events"
pass "agent events recorded"
echo "e2e passed"
