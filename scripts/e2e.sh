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
JAR=$(mktemp) JAR2=$(mktemp); trap 'rm -f "$JAR" "$JAR2"' EXIT

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

echo "== agents send SBOMs, the server matches them"
# The VM keeps the agent it installed first; re-running install.sh is how a real host upgrades.
docker compose --profile testbed exec -T testbed-vm sh -c 'curl -fsSL "$LABWARDEN_URL/install.sh" | LABWARDEN_RUN_NOW=0 sh' >/dev/null ||
  fail "upgrade of the testbed-vm agent"
pass "testbed-vm agent upgraded with install.sh"
matched_since() { # matched_since <host> <time>: a server-side match received after <time>
  api "$URL/api/v1/scans?q=$1&source=server&size=50" |
    jqr -e --arg h "$1" --arg t "$2" '[.items[] | select(.host_name == $h and .received_at >= $t)] | length > 0'
}
agent_matched_within() { # agent_matched_within <seconds> <service:host>: run the agent, wait for its match
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  out=$(docker compose --profile testbed exec -T "${2%%:*}" labwarden-agent 2>&1) || true
  case "$out" in
  *"another labwarden-agent run"*) wait_for 900 "${2#*:} SBOM matched (scheduled run)" matched_since "${2#*:}" "$since" ;;
  *"uploaded "*) wait_for "$1" "${2#*:} SBOM matched within $1 s of upload" matched_since "${2#*:}" "$since" ;;
  *) printf '%s\n' "$out" | tail -n 20 >&2; fail "${2#*:} agent run uploaded nothing" ;;
  esac
}
# Right after a (re)start grype pages its 3.4 GB DB in from disk, so the first
# matches are slow (up to ~25 s for the VM); the 15 s bound is for a warm server.
agent_matched_within 120 testbed-vm:testbed-vm
agent_matched_within 120 testbed-docker-agent:testbed-docker
agent_matched_within 15 testbed-vm:testbed-vm
wait_for 60 "testbed-vm reported findings" host_id testbed-vm
wait_for 60 "testbed-docker reported findings" host_id testbed-docker

echo "== agent credentials"
# Tokens and credentials go to curl on stdin (-H @-), never on a command line.
code=$(printf 'Authorization: Bearer %s\n' "$LABWARDEN_INGEST_TOKEN" |
  curl -sS -o /dev/null -w '%{http_code}' -H @- -H 'Content-Type: application/json' -d '{"host":"testbed-vm"}' "$URL/api/v1/ingest/enroll")
[ "$code" = 409 ] || fail "second enrollment of testbed-vm: status $code, want 409"
pass "an enrolled host cannot enroll again"
vm_post() { # vm_post <path> <json>: POST from testbed-vm with its own credential, print the status
  docker compose --profile testbed exec -T testbed-vm sh -c \
    'printf "Authorization: Bearer %s\n" "$(cat /var/lib/labwarden/credential)" |
      curl -sS -o /dev/null -w "%{http_code}" -H @- -H "Content-Type: application/json" -d "$2" "$LABWARDEN_URL$1"' sh "$1" "$2"
}
code=$(vm_post /api/v1/ingest/run '{"host":"testbed-docker","run_id":"e2e","status":"ok","targets":[]}')
[ "$code" = 403 ] || fail "testbed-vm credential posting as testbed-docker: status $code, want 403"
pass "a credential only speaks for its own host"
code=$(vm_post /api/v1/ingest/report '{}')
[ "$code" = 404 ] || fail "/ingest/report: status $code, want 404"
pass "/ingest/report is gone"
# Secrets never reach a command line, where any local user could read them.
argv_since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker compose --profile testbed exec -T testbed-vm sh -c '
  b=Bear; e=vx; labwarden-agent >/tmp/argv-run.log 2>&1 & pid=$!; seen=0
  while kill -0 "$pid" 2>/dev/null; do
    ps -eo args >/tmp/argv.txt
    grep -q -e "${b}er " -e "${e}a_" -e "${e}e_" /tmp/argv.txt && seen=1
    sleep 0.2
  done
  grep -q "uploaded " /tmp/argv-run.log || { echo "the agent run uploaded nothing" >&2; exit 2; }
  exit $seen' || fail "a token or credential appeared on a command line during an agent run (or the run uploaded nothing)"
pass "no token or credential on any command line during an agent run"
# Let that run's match land, so it cannot move last_seen in the re-match check.
wait_for 120 "testbed-vm argv-check run matched" matched_since testbed-vm "$argv_since"

echo "== re-match without an agent run"
last_seen() { api "$URL/api/v1/hosts?q=$1" | jqr -r --arg n "$1" '.items[] | select(.name == $n) | .last_seen'; }
vm_seen=$(last_seen testbed-vm)
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
api -X POST "$URL/api/v1/rematch" | jqr -e '.queued' >/dev/null || fail "re-match not queued"
wait_for 120 "testbed-vm re-matched" matched_since testbed-vm "$since"
wait_for 120 "testbed-docker re-matched" matched_since testbed-docker "$since"
[ "$(last_seen testbed-vm)" = "$vm_seen" ] || fail "re-match moved testbed-vm's last_seen"
pass "re-match left last_seen alone"

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
  sh -c 'mkdir -p /var/lib/labwarden/agent.lock && echo 999999 >/var/lib/labwarden/agent.lock/pid'
# Capture first: grep -q would close the pipe early and kill the run before its cleanup trap.
out=$(docker compose --profile testbed exec -T testbed-docker-agent labwarden-agent 2>&1) || true
printf '%s\n' "$out" | grep -q "removing stale lock" || fail "agent did not take over a stale lock"
docker compose --profile testbed exec -T testbed-docker-agent test ! -e /var/lib/labwarden/agent.lock ||
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

echo "== one vulnerability DB"
for svc in testbed-vm testbed-docker-agent; do
  docker compose --profile testbed exec -T "$svc" test ! -e /var/lib/labwarden/grype-db || fail "$svc still has a local grype DB"
done
pass "agents keep no grype DB"
dbdirs=$(docker compose exec -T labwarden sh -c 'ls -A /data/grype-db')
[ "$dbdirs" = "6" ] || fail "server grype-db holds: $(echo $dbdirs)"
pass "server holds exactly one grype DB (no download leftovers)"
code=$(curl -sS -o /dev/null -w '%{http_code}' -b "$JAR" -X POST "$URL/api/v1/db/update")
case "$code" in 202 | 409) pass "Update DB now accepted ($code)" ;; *) fail "Update DB now: status $code" ;; esac

echo "== logs"
api "$URL/api/v1/events?source=agent&size=1" | jqr -e '.total > 0' >/dev/null || fail "no agent events"
pass "agent events recorded"

echo "== admin auth"
code=$(curl -sS -o /dev/null -w '%{http_code}' -b "$JAR" -X POST -H 'Origin: https://evil.example' "$URL/api/v1/db/update")
[ "$code" = 403 ] || fail "cross-site POST: status $code, want 403"
pass "cross-site POST refused"
printf '{"password":"%s"}' "$LABWARDEN_ADMIN_PASSWORD" |
  curl -fsS -o /dev/null -c "$JAR2" -H 'Content-Type: application/json' --data-binary @- "$URL/api/v1/auth/login" || fail "second login"
curl -fsS -o /dev/null -b "$JAR2" -X POST "$URL/api/v1/auth/logout" || fail "logout"
code=$(curl -sS -o /dev/null -w '%{http_code}' -b "$JAR2" "$URL/api/v1/summary")
[ "$code" = 401 ] || fail "session cookie replayed after logout: status $code, want 401"
pass "logout ends the session on the server"
# Last: this locks the e2e client out of logging in for a while.
i=0 code=
while [ $i -lt 10 ]; do
  i=$((i + 1))
  code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H "X-Forwarded-For: 198.51.100.$i" \
    --data-binary '{"password":"wrong"}' "$URL/api/v1/auth/login")
done
[ "$code" = 429 ] || fail "bad logins with a new X-Forwarded-For each time: last status $code, want 429"
pass "login lockout ignores a forged X-Forwarded-For"
echo "e2e passed"
