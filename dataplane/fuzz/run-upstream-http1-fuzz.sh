#!/bin/sh
set -eu

evidence_dir="${BONVOYAGE_FUZZ_EVIDENCE_DIR:-/evidence}"
seconds="${BONVOYAGE_UPSTREAM_HTTP1_FUZZ_SECONDS:-30}"

case "$seconds" in
  ''|*[!0-9]*)
    echo "BONVOYAGE_UPSTREAM_HTTP1_FUZZ_SECONDS must be an integer" >&2
    exit 2
    ;;
esac
if [ "$seconds" -lt 1 ] || [ "$seconds" -gt 600 ]; then
  echo "BONVOYAGE_UPSTREAM_HTTP1_FUZZ_SECONDS must be between 1 and 600" >&2
  exit 2
fi

mkdir -p "$evidence_dir/artifacts" "$evidence_dir/corpus"
cp /opt/bonvoyage-upstream-http1-fuzz/corpus/* "$evidence_dir/corpus/"

{
  printf 'started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'duration_seconds=%s\n' "$seconds"
  printf 'network_access=disabled\n'
  printf 'input_max_bytes=65536\n'
  printf 'response_head_limit_bytes=32768\n'
  printf 'response_header_field_limit=128\n'
  printf 'rss_limit_mb=2048\n'
  printf 'malloc_limit_mb=512\n'
  printf 'timeout_seconds_per_input=5\n'
  clang++-18 --version | sed -n '1p'
  dpkg-query -W -f='clang_package=${Package} ${Version}\n' clang-18
} > "$evidence_dir/fuzz-environment.txt"

set +e
ASAN_OPTIONS='abort_on_error=1:allocator_may_return_null=0:detect_leaks=1:halt_on_error=1:symbolize=1' \
UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
  /usr/src/bonvoyage/build/protocol-fuzz/bonvoyage-upstream-response-head-fuzz \
    "$evidence_dir/corpus" \
    -artifact_prefix="$evidence_dir/artifacts/" \
    -dict=/opt/bonvoyage-upstream-http1-fuzz/http1.dict \
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
    > "$evidence_dir/fuzzer.log" 2>&1
fuzzer_status=$?
set -e

artifact_count="$(find "$evidence_dir/artifacts" -type f | wc -l | tr -d ' ')"
executed_units="$(
  sed -n 's/^stat::number_of_executed_units: *//p' \
    "$evidence_dir/fuzzer.log" | tail -n 1
)"
executed_units="${executed_units:-unknown}"

result=PASS
if [ "$fuzzer_status" -ne 0 ] || [ "$artifact_count" -ne 0 ]; then
  result=FAIL
fi

{
  printf 'result=%s\n' "$result"
  printf 'fuzzer_exit_status=%s\n' "$fuzzer_status"
  printf 'crash_artifacts=%s\n' "$artifact_count"
  printf 'executed_units=%s\n' "$executed_units"
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
  tail -n 80 "$evidence_dir/fuzzer.log" >&2
  exit 1
fi
