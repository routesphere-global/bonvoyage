#!/bin/sh
set -eu
export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
output=''
service='bonvoyage.service'
interface=''
metrics_url='http://127.0.0.1:9090/metrics'
load_host=''
upstream_host_a=''
upstream_host_b=''
direct_support=''
snapshot_file='/etc/bonvoyage/snapshot.pb'
credential_file=''
load_repository='/home/ubuntu/RouteSphere-BonVoyage'

fail() { echo "phase5-native-sample: $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --service) service="$2"; shift 2 ;;
    --interface) interface="$2"; shift 2 ;;
    --metrics-url) metrics_url="$2"; shift 2 ;;
    --load-host) load_host="$2"; shift 2 ;;
    --upstream-host-a) upstream_host_a="$2"; shift 2 ;;
    --upstream-host-b) upstream_host_b="$2"; shift 2 ;;
    --direct-support) direct_support="$2"; shift 2 ;;
    --load-repository) load_repository="$2"; shift 2 ;;
    --snapshot-file) snapshot_file="$2"; shift 2 ;;
    --credential-file) credential_file="$2"; shift 2 ;;
    --) shift; break ;;
    *) fail "unknown option: $1" ;;
  esac
done
[ -n "$output" ] && [ -n "$load_host" ] && [ -n "$upstream_host_a" ] &&
  [ -n "$upstream_host_b" ] && [ -d "$direct_support" ] && [ "$#" -gt 0 ] ||
  fail 'usage: --output DIR --load-host HOST --upstream-host-a HOST --upstream-host-b HOST --direct-support DIR [--load-repository DIR] -- CLIENT ARG...'
[ "$load_host" != "$upstream_host_a" ] && [ "$load_host" != "$upstream_host_b" ] &&
  [ "$upstream_host_a" != "$upstream_host_b" ] ||
  fail 'support roles must be separate hosts'
[ -f "$snapshot_file" ] || fail "snapshot missing: $snapshot_file"
[ -z "$credential_file" ] || [ -f "$credential_file" ] ||
  fail "credential file missing: $credential_file"
case "$load_repository" in /*) ;; *) fail 'load repository must be absolute' ;; esac
[ ! -e "$output" ] || fail "output already exists: $output"
for tool in cmp git jq perf python3 sha256sum ssh; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
[ -z "$(git -C "$repo" status --porcelain)" ] || fail 'clean source required'
(cd "$direct_support" && sha256sum -c checksums.sha256 >/dev/null) ||
  fail 'direct-support checksum verification failed'
[ "$(cat "$direct_support/source-commit.txt")" = "$(git -C "$repo" rev-parse HEAD)" ] ||
  fail 'direct-support harness commit differs from native capture'
[ "$(cat "$direct_support/client-exit-code.txt")" = '0' ] ||
  fail 'direct-support client failed'
umask 077
mkdir -p "$output"
git -C "$repo" rev-parse HEAD >"$output/source-commit.txt"
sha256sum "$script_dir/phase5-oha-lanes.mjs" | awk '{print $1}' \
  >"$output/expected-runner-sha256.txt"
sha256sum "$snapshot_file" | awk '{print $1}' >"$output/snapshot-sha256.txt"
if [ -n "$credential_file" ]; then
  sha256sum "$credential_file" | awk '{print $1}' >"$output/credential-sha256.txt"
else
  printf '%s\n' null >"$output/credential-sha256.txt"
fi
cp "$direct_support/direct-upstream.oha.json" "$output/direct-upstream.oha.json"
for name in source-commit.txt expected-runner-sha256.txt client-exit-code.txt \
  client.stderr loadgen-host.txt upstream-a-host.txt upstream-b-host.txt \
  loadgen-proc-before.txt loadgen-proc-after.txt \
  upstream-a-proc-before.txt upstream-a-proc-after.txt \
  upstream-b-proc-before.txt upstream-b-proc-after.txt \
  loadgen-source-commit-before.txt loadgen-source-commit-after.txt \
  loadgen-source-status-before.txt loadgen-source-status-after.txt \
  loadgen-runner-sha256-before.txt loadgen-runner-sha256-after.txt; do
  cp "$direct_support/$name" "$output/direct-$name"
done
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$load_host" hostname \
  >"$output/gateway-loadgen-host.txt"
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$upstream_host_a" hostname \
  >"$output/gateway-upstream-a-host.txt"
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$upstream_host_b" hostname \
  >"$output/gateway-upstream-b-host.txt"

if ! cmp -s "$output/direct-loadgen-host.txt" "$output/gateway-loadgen-host.txt" ||
  ! cmp -s "$output/direct-upstream-a-host.txt" "$output/gateway-upstream-a-host.txt" ||
  ! cmp -s "$output/direct-upstream-b-host.txt" "$output/gateway-upstream-b-host.txt"; then
  fail 'direct-support hosts differ from native capture hosts'
fi

support_cpu() {
  stage="$1"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$load_host" cat /proc/stat \
    >"$output/gateway-loadgen-proc-$stage.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$upstream_host_a" cat /proc/stat \
    >"$output/gateway-upstream-a-proc-$stage.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$upstream_host_b" cat /proc/stat \
    >"$output/gateway-upstream-b-proc-$stage.txt"
}

load_source() {
  stage="$1"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$load_host" \
    git -C "$load_repository" rev-parse HEAD \
    >"$output/gateway-loadgen-source-commit-$stage.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$load_host" \
    git -C "$load_repository" status --porcelain \
    >"$output/gateway-loadgen-source-status-$stage.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$load_host" \
    sha256sum "$load_repository/benchmarks/scripts/phase5-oha-lanes.mjs" |
    awk '{print $1}' >"$output/gateway-loadgen-runner-sha256-$stage.txt"
}

validate_load_source() {
  expected_commit="$(cat "$output/source-commit.txt")"
  expected_runner="$(cat "$output/expected-runner-sha256.txt")"
  for stage in before after; do
    [ "$(cat "$output/gateway-loadgen-source-commit-$stage.txt")" = \
      "$expected_commit" ] || fail "load-generator source commit differs at $stage"
    [ ! -s "$output/gateway-loadgen-source-status-$stage.txt" ] ||
      fail "load-generator source was dirty at $stage"
    [ "$(cat "$output/gateway-loadgen-runner-sha256-$stage.txt")" = \
      "$expected_runner" ] || fail "load-generator runner differs at $stage"
  done
  cmp -s "$output/gateway-loadgen-source-commit-before.txt" \
    "$output/gateway-loadgen-source-commit-after.txt" ||
    fail 'load-generator source changed during native capture'
  cmp -s "$output/gateway-loadgen-runner-sha256-before.txt" \
    "$output/gateway-loadgen-runner-sha256-after.txt" ||
    fail 'load-generator runner changed during native capture'
}

seal() {
  (
    cd "$output"
    manifest="$(mktemp "${TMPDIR:-/tmp}/bonvoyage-perf01-checksums.XXXXXX")"
    find . -type f ! -name checksums.sha256 | LC_ALL=C sort |
      while IFS= read -r file; do sha256sum "$file"; done >"$manifest"
    mv "$manifest" checksums.sha256
    sha256sum -c checksums.sha256 >/dev/null
  )
}

capture() {
  stage="$1"
  set -- python3 -B "$script_dir/queue_attribution.py" capture \
    --output "$output/$stage" --service "$service" \
    --metrics-url "$metrics_url" --repository "$repo"
  if [ -n "$interface" ]; then set -- "$@" --interface "$interface"; fi
  "$@"
  pid="$(jq -er '.process.pid' "$output/$stage/snapshot.json")"
  rss_kib="$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")"
  [ -n "$rss_kib" ] || fail "cannot read RSS for PID $pid"
  fds="$(find "/proc/$pid/fd" -maxdepth 1 -type l | wc -l | tr -d ' ')"
  jq -n --argjson rss_bytes "$((rss_kib * 1024))" --argjson fd "$fds" \
    --argjson pid "$pid" --argjson start_ticks \
    "$(jq -er '.process.start_ticks' "$output/$stage/snapshot.json")" \
    --argjson restart_count \
    "$(jq -er '.process.restarts' "$output/$stage/snapshot.json")" \
    '{rss_bytes: $rss_bytes, fd: $fd, pid: $pid,
      start_ticks: $start_ticks, restart_count: $restart_count}' \
    >"$output/$stage-resource.json"
}

load_source before
support_cpu before
capture before
pid="$(jq -er '.process.pid' "$output/before/snapshot.json")"
# Keep the capacity pass free of perf tracepoint overhead. The second,
# matched-rate pass supplies attribution but does not set the RPS verdict.
set +e
"$@" >"$output/oha.json" 2>"$output/client.stderr"
client_status="$?"
set -e
capture after
support_cpu after
python3 -B "$script_dir/queue_attribution.py" analyze \
  --before "$output/before" --after "$output/after" \
  --output "$output/attribution.json"
printf '%s\n' "$client_status" >"$output/client-exit-code.txt"
if [ "$client_status" -ne 0 ]; then
  load_source after
  validate_load_source
  seal
  fail "client exited $client_status; checksum-bound partial evidence retained in $output"
fi
set +e
perf stat -x , -e cycles,instructions,cache-misses,raw_syscalls:sys_enter \
  -p "$pid" -o "$output/perf.csv" -- "$@" \
  >"$output/diagnostic.oha.json" 2>"$output/diagnostic.stderr"
diagnostic_status="$?"
set -e
capture diagnostic-after
load_source after
validate_load_source
printf '%s\n' "$diagnostic_status" >"$output/diagnostic-exit-code.txt"
seal
[ "$diagnostic_status" -eq 0 ] ||
  fail "diagnostic client exited $diagnostic_status; evidence retained in $output"
echo "CAPTURE_DIR=$output"
