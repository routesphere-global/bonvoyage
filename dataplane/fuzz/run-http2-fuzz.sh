#!/bin/sh
set -eu

evidence_dir="${BONVOYAGE_FUZZ_EVIDENCE_DIR:-/evidence}"
seconds="${BONVOYAGE_HTTP2_FUZZ_SECONDS:-30}"

case "$seconds" in
  ''|*[!0-9]*)
    echo "BONVOYAGE_HTTP2_FUZZ_SECONDS must be an integer" >&2
    exit 2
    ;;
esac
if [ "$seconds" -lt 1 ] || [ "$seconds" -gt 600 ]; then
  echo "BONVOYAGE_HTTP2_FUZZ_SECONDS must be between 1 and 600" >&2
  exit 2
fi

mkdir -p \
  "$evidence_dir/artifacts/server" \
  "$evidence_dir/artifacts/client" \
  "$evidence_dir/corpus"
cp /opt/bonvoyage-http2-fuzz/corpus/* "$evidence_dir/corpus/"

{
  printf 'started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'duration_seconds_per_target=%s\n' "$seconds"
  printf 'target_count=2\n'
  printf 'network_access=disabled\n'
  printf 'input_max_bytes=65536\n'
  printf 'rss_limit_mb=2048\n'
  printf 'malloc_limit_mb=512\n'
  printf 'timeout_seconds_per_input=5\n'
  clang++-18 --version | sed -n '1p'
  dpkg-query -W -f='clang_package=${Package} ${Version}\n' clang-18
} > "$evidence_dir/fuzz-environment.txt"

set +e
ASAN_OPTIONS='abort_on_error=1:allocator_may_return_null=0:detect_leaks=1:halt_on_error=1:symbolize=1' \
UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
  /usr/src/bonvoyage/build/protocol-fuzz/bonvoyage-http2-session-fuzz \
    "$evidence_dir/corpus" \
    -artifact_prefix="$evidence_dir/artifacts/server/" \
    -dict=/opt/bonvoyage-http2-fuzz/http2.dict \
    -max_len=65536 \
    -max_total_time="$seconds" \
    -timeout=5 \
    -rss_limit_mb=2048 \
    -malloc_limit_mb=512 \
    -seed=1 \
    -reload=0 \
    -reduce_inputs=1 \
    -use_value_profile=1 \
    -print_final_stats=1 \
    > "$evidence_dir/server-fuzzer.log" 2>&1
server_fuzzer_status=$?
ASAN_OPTIONS='abort_on_error=1:allocator_may_return_null=0:detect_leaks=1:halt_on_error=1:symbolize=1' \
UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
  /usr/src/bonvoyage/build/protocol-fuzz/bonvoyage-http2-client-session-fuzz \
    "$evidence_dir/corpus" \
    -artifact_prefix="$evidence_dir/artifacts/client/" \
    -dict=/opt/bonvoyage-http2-fuzz/http2.dict \
    -max_len=65536 \
    -max_total_time="$seconds" \
    -timeout=5 \
    -rss_limit_mb=2048 \
    -malloc_limit_mb=512 \
    -seed=1 \
    -reload=0 \
    -reduce_inputs=1 \
    -use_value_profile=1 \
    -print_final_stats=1 \
    > "$evidence_dir/client-fuzzer.log" 2>&1
client_fuzzer_status=$?
set -e

artifact_count="$(find "$evidence_dir/artifacts" -type f | wc -l | tr -d ' ')"
server_executed_units="$(
  sed -n 's/^stat::number_of_executed_units: *//p' \
    "$evidence_dir/server-fuzzer.log" | tail -n 1
)"
server_executed_units="${server_executed_units:-unknown}"
client_executed_units="$(
  sed -n 's/^stat::number_of_executed_units: *//p' \
    "$evidence_dir/client-fuzzer.log" | tail -n 1
)"
client_executed_units="${client_executed_units:-unknown}"

result=PASS
fuzzer_status=0
if [ "$server_fuzzer_status" -ne 0 ] \
    || [ "$client_fuzzer_status" -ne 0 ] \
    || [ "$artifact_count" -ne 0 ]; then
  result=FAIL
  fuzzer_status=1
fi

{
  printf 'result=%s\n' "$result"
  printf 'fuzzer_exit_status=%s\n' "$fuzzer_status"
  printf 'server_fuzzer_exit_status=%s\n' "$server_fuzzer_status"
  printf 'client_fuzzer_exit_status=%s\n' "$client_fuzzer_status"
  printf 'crash_artifacts=%s\n' "$artifact_count"
  printf 'server_executed_units=%s\n' "$server_executed_units"
  printf 'client_executed_units=%s\n' "$client_executed_units"
  printf 'finished_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$evidence_dir/summary.txt"

checksum_lines="$(
  cd "$evidence_dir"
  find . -type f ! -name SHA256SUMS -print \
    | LC_ALL=C sort \
    | while IFS= read -r file; do sha256sum "$file"; done
)"
printf '%s\n' "$checksum_lines" > "$evidence_dir/SHA256SUMS"

cat "$evidence_dir/summary.txt"
if [ "$result" != PASS ]; then
  tail -n 80 "$evidence_dir/server-fuzzer.log" >&2
  tail -n 80 "$evidence_dir/client-fuzzer.log" >&2
  exit 1
fi
