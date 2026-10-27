#!/bin/sh
set -eu

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="load-balancing-smoke-$timestamp"
suffix="$$"
network="bonvoyage-load-balancing-$suffix"
volume="bonvoyage-load-balancing-snapshot-$suffix"
gateway="bonvoyage-load-balancing-gateway-$suffix"
upstream_a="bonvoyage-load-balancing-upstream-a-$suffix"
upstream_b="bonvoyage-load-balancing-upstream-b-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-load-balancing.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_LOAD_BALANCING_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

cleanup() {
  status="$?"
  if [ -d "$stage_dir" ]; then
    docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1 || true
    docker logs "$upstream_a" >"$stage_dir/upstream-a.log" 2>&1 || true
    docker logs "$upstream_b" >"$stage_dir/upstream-b.log" 2>&1 || true
  fi
  if [ "$status" -ne 0 ]; then
    echo "load-balancing smoke failed; temporary evidence: $stage_dir" >&2
    if [ -f "$stage_dir/gateway.log" ]; then
      cat "$stage_dir/gateway.log" >&2
    fi
  fi
  docker rm --force "$gateway" "$upstream_a" "$upstream_b" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  fi
  return "$status"
}
trap cleanup EXIT INT TERM

for command_name in date docker git mktemp uname; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name is required" >&2
    exit 1
  }
done

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null

docker run --rm --platform "$platform" \
  --volume "$PWD/tests/fixtures/phase3-load-balancing.yaml:/etc/bonvoyage/load-balancing.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/load-balancing.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$upstream_a" \
  --network "$network" --network-alias upstream-a \
  --env BONVOYAGE_UPSTREAM_ID=a "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$upstream_b" \
  --network "$network" --network-alias upstream-b \
  --env BONVOYAGE_UPSTREAM_ID=b "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test \
  --volume "$volume:/snapshot:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned >/dev/null

attempt=0
until docker exec "$upstream_a" python -c \
  'import urllib.request; assert urllib.request.urlopen("http://bonvoyage-load-balancing-gateway-'"$suffix"':9901/health/ready", timeout=1).status == 200' \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "BonVoyage load-balancing listener did not become ready" >&2
    exit 1
  fi
  sleep 1
done

docker exec "$upstream_a" python -c '
import collections
import concurrent.futures
import http.client
import json
import time
import urllib.error
import urllib.request

gateway = "http://bonvoyage-load-balancing-gateway-'"$suffix"':8080"

def request(path, expected_status=200):
    value = urllib.request.Request(
        gateway + path,
        headers={"Host": "api.example.test"},
    )
    try:
        with urllib.request.urlopen(value, timeout=10) as response:
            status = response.status
            body = response.read().decode()
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read().decode()
    assert status == expected_status, (path, status, body)
    return body

def metric_total(suffix):
    metrics = urllib.request.urlopen(
        "http://bonvoyage-load-balancing-gateway-'"$suffix"':9090/metrics",
        timeout=10,
    ).read().decode()
    value = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0].endswith(suffix):
            value += float(raw)
    return value

round_robin = [request("/identity/round-robin").strip() for _ in range(8)]
assert collections.Counter(round_robin) == {"a": 6, "b": 2}, round_robin

random_results = [request("/identity/random").strip() for _ in range(400)]
random_counts = collections.Counter(random_results)
assert set(random_counts) == {"a", "b"}, random_counts
assert 260 <= random_counts["a"] <= 340, random_counts

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    first = executor.submit(request, "/slow-identity/500")
    time.sleep(0.1)
    second = executor.submit(request, "/slow-identity/500")
    least_request = [first.result().strip(), second.result().strip()]
assert least_request == ["a", "b"], least_request

passive = [
    {"status": 502, "body": request("/identity/passive", 502)},
    {"status": 200, "body": request("/identity/passive", 200)},
]
time.sleep(0.6)
passive.extend([
    {"status": 502, "body": request("/identity/passive", 502)},
    {"status": 200, "body": request("/identity/passive", 200)},
])
assert passive[1]["body"] == "b\n" and passive[3]["body"] == "b\n", passive

all_ejected = [
    {"status": 502, "body": request("/identity/all-ejected", 502)},
    {"status": 502, "body": request("/identity/all-ejected", 502)},
    {"status": 503, "body": request("/identity/all-ejected", 503)},
]
assert json.loads(all_ejected[2]["body"])["error"]["code"] == "no_healthy_upstream"

passive_failures_before = metric_total("upstream_passive_failures_total")
try:
    request("/chunked-truncated/16")
except (http.client.IncompleteRead, http.client.RemoteDisconnected,
        ConnectionResetError, urllib.error.URLError):
    pass
else:
    raise AssertionError("truncated post-head response unexpectedly completed")
passive_failures_after = metric_total("upstream_passive_failures_total")
assert passive_failures_after == passive_failures_before, (
    passive_failures_before, passive_failures_after
)
post_head_recovery = request("/identity/post-head").strip()
assert post_head_recovery == "a", post_head_recovery

print(json.dumps({
    "weighted_round_robin": {
        "requests": len(round_robin),
        "sequence": round_robin,
        "counts": collections.Counter(round_robin),
    },
    "weighted_random": {
        "requests": len(random_results),
        "counts": random_counts,
    },
    "least_request": {
        "overlapping_sequence": least_request,
    },
    "passive_ejection": passive,
    "all_ejected": all_ejected,
    "post_head_failure": {
        "passive_failures_before": passive_failures_before,
        "passive_failures_after": passive_failures_after,
        "next_request_upstream": post_head_recovery,
    },
}, indent=2, sort_keys=True))
' >"$stage_dir/functional-results.json"

docker exec "$upstream_a" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-load-balancing-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode(), end="")
' >"$stage_dir/metrics.prom"

docker exec "$upstream_a" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://bonvoyage-load-balancing-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode()

def total(suffix):
    value = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        name = name.split("{", 1)[0]
        if name.endswith(suffix):
            value += float(raw)
    return value

assert total("upstream_endpoint_selections_total") >= 418
assert total("upstream_passive_failures_total") >= 4
assert total("upstream_passive_ejections_total") >= 4
assert total("upstream_passive_reactivations_total") >= 1
assert total("upstream_no_eligible_endpoints_total") >= 1
assert total("active_upstream_requests") == 0
print("load-balancing and passive-health metrics passed")
' >"$stage_dir/metrics-validation.txt"

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
docker logs "$gateway" >"$stage_dir/gateway.log" 2>&1
docker logs "$upstream_a" >"$stage_dir/upstream-a.log" 2>&1
docker logs "$upstream_b" >"$stage_dir/upstream-b.log" 2>&1

source_commit="$(git rev-parse HEAD)"
if [ -z "$(git status --porcelain)" ]; then
  source_dirty=false
else
  source_dirty=true
fi
runtime_image_id="$(docker image inspect "$image" --format '{{.Id}}')"
cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
host=$(uname -s) $(uname -r) $(uname -m)
platform=$platform
runtime_image=$image
runtime_image_id=$runtime_image_id
gateway_shards=1
weighted_round_robin_requests=8
weighted_random_requests=400
least_request_overlapping_requests=2
passive_ejection_attempts=4
all_ejected_attempts=3
post_head_failure_attempts=1
post_head_recovery_attempts=1
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<EOF
# Phase 3 load-balancing and passive-health evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live one-shard gateway exercised weighted round robin, weighted random, weighted least request under overlapping requests, passive pre-response failure circuits, a failed half-open recovery probe, and fail-closed behavior after every endpoint was opened. The same immutable snapshot compiler and shard-local upstream pools used by the product path were exercised.

Client cancellation and failures after a valid upstream response head are excluded from passive transport-failure accounting. HTTP status codes alone do not mark an endpoint unhealthy. Active probes, DNS refresh, retry policy, and cross-shard health aggregation remain separately owned features.

\`functional-results.json\` contains the deterministic assertions. Metrics, logs, image identity, source checksums, and evidence checksums preserve the supporting record.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/runtime/endpoint_selector.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/endpoint_selector.cc
dataplane/src/gateway.cc
dataplane/src/runtime_snapshot.cc
deploy/docker/upstream/server.py
scripts/phase3-load-balancing-smoke.sh
tests/fixtures/phase3-load-balancing.yaml
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md compiler.txt functional-results.json \
    gateway.inspect.json gateway.log metadata.txt metrics-validation.txt \
    metrics.prom runtime-image.inspect.json source-checksums.sha256 \
    upstream-a.log upstream-b.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-load-balancing-smoke.txt.tmp"
mv "$output_root/current-load-balancing-smoke.txt.tmp" \
  "$output_root/current-load-balancing-smoke.txt"

printf 'Load-balancing integration passed: %s\n' "$output_dir"
cat "$output_dir/metrics-validation.txt"
