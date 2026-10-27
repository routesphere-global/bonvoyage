#!/bin/sh
set -eu

compose_file="${BONVOYAGE_COMPOSE_FILE:-deploy/compose/local.yml}"
gateway_url="${BONVOYAGE_GATEWAY_URL:-http://127.0.0.1:8080}"
admin_url="${BONVOYAGE_ADMIN_URL:-http://127.0.0.1:9901}"
metrics_url="${BONVOYAGE_METRICS_URL:-http://127.0.0.1:9090}"
requests_per_route="${BONVOYAGE_VERIFY_REQUESTS_PER_ROUTE:-25}"
request_timeout="${BONVOYAGE_VERIFY_REQUEST_TIMEOUT_SECONDS:-10}"

fail() {
  echo "local deployment verification failed: $*" >&2
  exit 1
}

case "$requests_per_route" in
  ''|*[!0-9]*)
    echo "BONVOYAGE_VERIFY_REQUESTS_PER_ROUTE must be a positive integer" >&2
    exit 2
    ;;
esac
[ "$requests_per_route" -gt 0 ] || {
  echo "BONVOYAGE_VERIFY_REQUESTS_PER_ROUTE must be greater than zero" >&2
  exit 2
}

case "$request_timeout" in
  ''|*[!0-9]*)
    echo "BONVOYAGE_VERIFY_REQUEST_TIMEOUT_SECONDS must be a positive integer" >&2
    exit 2
    ;;
esac
[ "$request_timeout" -gt 0 ] || {
  echo "BONVOYAGE_VERIFY_REQUEST_TIMEOUT_SECONDS must be greater than zero" >&2
  exit 2
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v docker >/dev/null 2>&1 || fail "Docker with Compose v2 is required"
[ -f "$compose_file" ] || fail "Compose file not found: $compose_file"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-local-verification.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

compose() {
  docker compose -f "$compose_file" "$@"
}

service_id() {
  compose ps --all --quiet "$1" | sed -n '1p'
}

inspect_value() {
  docker inspect --format "$2" "$1"
}

require_equal() {
  actual="$1"
  expected="$2"
  label="$3"
  [ "$actual" = "$expected" ] ||
    fail "$label: expected '$expected', received '$actual'"
}

fetch_exact() {
  url="$1"
  expected="$2"
  label="$3"
  output="$4"
  curl --fail --silent --show-error --max-time "$request_timeout" \
    "$url" >"$output" || fail "$label request failed"
  actual="$(cat "$output")"
  require_equal "$actual" "$expected" "$label body"
}

capture_metrics() {
  output="$1"
  curl --fail --silent --show-error --max-time "$request_timeout" \
    "$metrics_url/metrics" >"$output" || fail "metrics request failed"
}

metric_sum() {
  file="$1"
  name="$2"
  awk -v metric="$name" '
    $1 == metric || index($1, metric "{") == 1 {
      found = 1
      sum += $2
    }
    END {
      if (!found) {
        exit 2
      }
      printf "%.0f\n", sum
    }
  ' "$file" || fail "required metric is absent: $name"
}

gateway_id="$(service_id bonvoyage)"
upstream_id="$(service_id upstream)"
compiler_id="$(service_id snapshot-compiler)"
[ -n "$gateway_id" ] || fail "bonvoyage container was not found"
[ -n "$upstream_id" ] || fail "upstream container was not found"
[ -n "$compiler_id" ] || fail "snapshot-compiler container was not found"

require_equal "$(inspect_value "$gateway_id" '{{.State.Status}}')" running \
  "bonvoyage container state"
require_equal "$(inspect_value "$gateway_id" '{{.RestartCount}}')" 0 \
  "bonvoyage restart count"
require_equal "$(inspect_value "$upstream_id" '{{.State.Status}}')" running \
  "upstream container state"
require_equal "$(inspect_value "$upstream_id" '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}')" healthy \
  "upstream health"
require_equal "$(inspect_value "$upstream_id" '{{.RestartCount}}')" 0 \
  "upstream restart count"
require_equal "$(inspect_value "$compiler_id" '{{.State.Status}}')" exited \
  "snapshot-compiler container state"
require_equal "$(inspect_value "$compiler_id" '{{.State.ExitCode}}')" 0 \
  "snapshot-compiler exit code"
require_equal "$(inspect_value "$compiler_id" '{{.RestartCount}}')" 0 \
  "snapshot-compiler restart count"

fetch_exact "$gateway_url/bonvoyage/ready" ready "fixed route" \
  "$tmp_dir/fixed-initial.body"
fetch_exact "$gateway_url/healthz" ok "proxied route" \
  "$tmp_dir/proxied-initial.body"
fetch_exact "$admin_url/health/ready" '{"status":"ok"}' "admin readiness" \
  "$tmp_dir/admin.body"

capture_metrics "$tmp_dir/metrics-before.txt"
require_equal "$(metric_sum "$tmp_dir/metrics-before.txt" \
  bonvoyage_bonvoyage_gateway_ready)" 1 "gateway readiness metric"
require_equal "$(metric_sum "$tmp_dir/metrics-before.txt" \
  bonvoyage_bonvoyage_gateway_configured_clusters)" 1 "configured clusters"
require_equal "$(metric_sum "$tmp_dir/metrics-before.txt" \
  bonvoyage_bonvoyage_gateway_configured_endpoints)" 1 "configured endpoints"
require_equal "$(metric_sum "$tmp_dir/metrics-before.txt" \
  bonvoyage_bonvoyage_gateway_configured_listeners)" 1 "configured listeners"
require_equal "$(metric_sum "$tmp_dir/metrics-before.txt" \
  bonvoyage_bonvoyage_gateway_configured_routes)" 2 "configured routes"

requests_before="$(metric_sum "$tmp_dir/metrics-before.txt" \
  bonvoyage_bonvoyage_gateway_requests_total)"
responses_before="$(metric_sum "$tmp_dir/metrics-before.txt" \
  bonvoyage_bonvoyage_gateway_responses_2xx_total)"
upstream_before="$(metric_sum "$tmp_dir/metrics-before.txt" \
  bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total)"

i=0
while [ "$i" -lt "$requests_per_route" ]; do
  fetch_exact "$gateway_url/bonvoyage/ready" ready "fixed route" \
    "$tmp_dir/fixed.body"
  fetch_exact "$gateway_url/healthz" ok "proxied route" \
    "$tmp_dir/proxied.body"
  i=$((i + 1))
done

capture_metrics "$tmp_dir/metrics-after.txt"
requests_after="$(metric_sum "$tmp_dir/metrics-after.txt" \
  bonvoyage_bonvoyage_gateway_requests_total)"
responses_after="$(metric_sum "$tmp_dir/metrics-after.txt" \
  bonvoyage_bonvoyage_gateway_responses_2xx_total)"
upstream_after="$(metric_sum "$tmp_dir/metrics-after.txt" \
  bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total)"
expected_request_delta=$((requests_per_route * 2))

require_equal "$((requests_after - requests_before))" "$expected_request_delta" \
  "request counter delta"
require_equal "$((responses_after - responses_before))" "$expected_request_delta" \
  "2xx response counter delta"
require_equal "$((upstream_after - upstream_before))" "$requests_per_route" \
  "upstream selection counter delta"

for metric in \
  bonvoyage_bonvoyage_gateway_responses_4xx_total \
  bonvoyage_bonvoyage_gateway_responses_5xx_total \
  bonvoyage_bonvoyage_gateway_route_misses_total \
  bonvoyage_bonvoyage_gateway_request_timeouts_total \
  bonvoyage_bonvoyage_gateway_overload_rejections_total \
  bonvoyage_bonvoyage_gateway_upstream_failures_total \
  bonvoyage_memory_malloc_failed \
  bonvoyage_reactor_abandoned_failed_futures \
  bonvoyage_stall_detector_reported
do
  require_equal "$(metric_sum "$tmp_dir/metrics-after.txt" "$metric")" 0 "$metric"
done

require_equal "$(service_id bonvoyage)" "$gateway_id" \
  "bonvoyage container identity"
require_equal "$(service_id upstream)" "$upstream_id" \
  "upstream container identity"
require_equal "$(inspect_value "$gateway_id" '{{.State.Status}}')" running \
  "bonvoyage final container state"
require_equal "$(inspect_value "$gateway_id" '{{.RestartCount}}')" 0 \
  "bonvoyage final restart count"
require_equal "$(inspect_value "$upstream_id" '{{.State.Status}}')" running \
  "upstream final container state"
require_equal "$(inspect_value "$upstream_id" '{{.RestartCount}}')" 0 \
  "upstream final restart count"

printf '%s\n' \
  "status=pass" \
  "fixed_requests=$requests_per_route" \
  "proxied_requests=$requests_per_route" \
  "request_delta=$expected_request_delta" \
  "response_2xx_delta=$expected_request_delta" \
  "upstream_selection_delta=$requests_per_route" \
  "configured_routes=2" \
  "container_restarts=0" \
  "runtime_error_counters=0"
