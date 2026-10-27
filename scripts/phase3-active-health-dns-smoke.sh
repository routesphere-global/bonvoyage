#!/bin/sh
set -eu

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="active-health-dns-smoke-$timestamp"
suffix="$$"
network="bonvoyage-active-health-dns-$suffix"
volume="bonvoyage-active-health-dns-snapshot-$suffix"
gateway="bonvoyage-active-health-dns-gateway-$suffix"
client="bonvoyage-active-health-dns-client-$suffix"
upstream_a="bonvoyage-active-health-dns-upstream-a-$suffix"
upstream_b="bonvoyage-active-health-dns-upstream-b-$suffix"
padding="bonvoyage-active-health-dns-padding-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-active-health-dns.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_ACTIVE_HEALTH_DNS_EVIDENCE_ROOT:-benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

container_logs() {
  container_name="$1"
  destination="$2"
  if docker inspect "$container_name" >/dev/null 2>&1; then
    docker logs "$container_name" >"$destination" 2>&1 || true
  fi
}

cleanup() {
  status="$?"
  if [ -d "$stage_dir" ]; then
    container_logs "$gateway" "$stage_dir/gateway.log"
    container_logs "$client" "$stage_dir/client.log"
    container_logs "$upstream_a" "$stage_dir/upstream-a.log"
    container_logs "$upstream_b" "$stage_dir/upstream-b.log"
    container_logs "$padding" "$stage_dir/padding.log"
  fi
  if [ "$status" -ne 0 ]; then
    echo "active-health and DNS smoke failed; temporary evidence: $stage_dir" >&2
    if [ -f "$stage_dir/gateway.log" ]; then
      cat "$stage_dir/gateway.log" >&2
    fi
  fi
  docker rm --force "$gateway" "$client" "$upstream_a" "$upstream_b" \
    "$padding" >/dev/null 2>&1 || true
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
  --volume "$PWD/tests/fixtures/phase3-active-health-dns.yaml:/etc/bonvoyage/active-health-dns.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/active-health-dns.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$stage_dir/compiler.txt"

docker run --detach --platform "$platform" --name "$client" \
  --network "$network" --env BONVOYAGE_UPSTREAM_ID=client \
  "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$upstream_a" \
  --network "$network" --network-alias maintenance-upstream \
  --env BONVOYAGE_UPSTREAM_ID=a "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test \
  --volume "$volume:/snapshot:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 2 --memory 512M --overprovisioned >/dev/null

attempt=0
until docker exec "$client" python -c \
  'import urllib.request; assert urllib.request.urlopen("http://bonvoyage-active-health-dns-gateway-'"$suffix"':9901/health/ready", timeout=1).status == 200' \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "BonVoyage active-health listener did not become ready" >&2
    exit 1
  fi
  sleep 1
done

docker exec "$client" python -c '
import json
import urllib.request

request = urllib.request.Request(
    "http://bonvoyage-active-health-dns-gateway-'"$suffix"':8080/identity",
    headers={"Host": "api.example.test"},
)
with urllib.request.urlopen(request, timeout=5) as response:
    body = response.read().decode()
    assert response.status == 200 and body == "a\n", (response.status, body)
print(json.dumps({"status": 200, "upstream": body.strip()}, sort_keys=True))
' >"$stage_dir/initial-response.json"

container_logs "$upstream_a" "$stage_dir/upstream-a.log"
docker rm --force "$upstream_a" >/dev/null

docker exec "$client" python -c '
import json
import time
import urllib.error
import urllib.request

url = "http://bonvoyage-active-health-dns-gateway-'"$suffix"':8080/identity"
events = []
started = time.monotonic()
deadline = started + 25
while time.monotonic() < deadline:
    request = urllib.request.Request(url, headers={"Host": "api.example.test"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = response.status
            body = response.read().decode()
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read().decode()
    except urllib.error.URLError as error:
        status = 0
        body = str(error.reason)
    events.append({"elapsed_ms": round((time.monotonic() - started) * 1000),
                   "status": status, "body": body.strip()})
    if status == 503:
        parsed = json.loads(body)
        assert parsed["error"]["code"] == "no_healthy_upstream", parsed
        break
    time.sleep(0.25)
else:
    raise AssertionError(("gateway did not fail closed", events))
print(json.dumps({"transition": events,
                  "unavailable_after_ms": events[-1]["elapsed_ms"]},
                 indent=2, sort_keys=True))
' >"$stage_dir/outage-transition.json"

docker exec "$client" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-active-health-dns-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/unavailable-metrics.prom"

docker exec "$client" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://bonvoyage-active-health-dns-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode()

def values(suffix):
    result = []
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0].endswith(suffix):
            result.append(float(raw))
    return result

assert sum(values("active_unhealthy_endpoints")) == 2, values("active_unhealthy_endpoints")
assert sum(values("active_health_failures_total")) >= 2
assert sum(values("active_health_state_changes_total")) >= 1
assert sum(values("dns_refresh_failures_total")) >= 1
nonzero_coordinators = [value for value in values("active_health_checks_total") if value > 0]
assert len(nonzero_coordinators) == 1, nonzero_coordinators
print("two-shard fail-closed state and shard-zero coordinator metrics passed")
' >"$stage_dir/unavailable-metrics-validation.txt"

# Occupy the removed container address so the replacement must receive a new
# address and the test proves DNS publication rather than same-IP recovery.
docker run --detach --platform "$platform" --name "$padding" \
  --network "$network" --env BONVOYAGE_UPSTREAM_ID=padding \
  "$upstream_image" >/dev/null
docker run --detach --platform "$platform" --name "$upstream_b" \
  --network "$network" --network-alias maintenance-upstream \
  --env BONVOYAGE_UPSTREAM_ID=b "$upstream_image" >/dev/null

docker exec "$client" python -c '
import json
import time
import urllib.error
import urllib.request

url = "http://bonvoyage-active-health-dns-gateway-'"$suffix"':8080/identity"
events = []
started = time.monotonic()
deadline = started + 30
while time.monotonic() < deadline:
    request = urllib.request.Request(url, headers={"Host": "api.example.test"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = response.status
            body = response.read().decode()
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read().decode()
    except urllib.error.URLError as error:
        status = 0
        body = str(error.reason)
    events.append({"elapsed_ms": round((time.monotonic() - started) * 1000),
                   "status": status, "body": body.strip()})
    if status == 200 and body == "b\n":
        break
    time.sleep(0.25)
else:
    raise AssertionError(("gateway did not recover on replacement address", events))
print(json.dumps({"transition": events,
                  "recovered_after_ms": events[-1]["elapsed_ms"],
                  "replacement_upstream": events[-1]["body"]},
                 indent=2, sort_keys=True))
' >"$stage_dir/recovery-transition.json"

docker exec "$client" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-active-health-dns-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$stage_dir/final-metrics.prom"

docker exec "$client" python -c '
import urllib.request

metrics = urllib.request.urlopen(
    "http://bonvoyage-active-health-dns-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode()

def values(suffix):
    result = []
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0].endswith(suffix):
            result.append(float(raw))
    return result

def total(suffix):
    return sum(values(suffix))

assert total("active_health_checks_total") >= 4
assert total("active_health_successes_total") >= 2
assert total("active_health_failures_total") >= 2
assert total("active_health_state_changes_total") >= 2
assert total("active_health_publish_failures_total") == 0
assert total("active_health_cycle_overruns_total") == 0
assert total("dns_refresh_attempts_total") >= 2
assert total("dns_refresh_successes_total") >= 1
assert total("dns_refresh_failures_total") >= 1
assert total("dns_address_changes_total") >= 1
assert total("dns_publish_failures_total") == 0
assert total("dns_refresh_cycle_overruns_total") == 0
assert total("upstream_no_eligible_endpoints_total") >= 1
assert total("active_unhealthy_endpoints") == 0
assert total("active_upstream_requests") == 0
nonzero_coordinators = [value for value in values("active_health_checks_total") if value > 0]
assert len(nonzero_coordinators) == 1, nonzero_coordinators
print("active-health hysteresis, DNS address change, and no-restart recovery metrics passed")
' >"$stage_dir/final-metrics-validation.txt"

docker stop --time 15 "$gateway" >/dev/null
gateway_exit_code="$(docker inspect "$gateway" --format '{{.State.ExitCode}}')"
test "$gateway_exit_code" -eq 0
printf 'graceful maintenance shutdown passed: exit_code=%s\n' \
  "$gateway_exit_code" >"$stage_dir/shutdown-validation.txt"

docker image inspect "$image" >"$stage_dir/runtime-image.inspect.json"
docker inspect "$gateway" >"$stage_dir/gateway.inspect.json"
container_logs "$gateway" "$stage_dir/gateway.log"
container_logs "$client" "$stage_dir/client.log"
container_logs "$upstream_b" "$stage_dir/upstream-b.log"
container_logs "$padding" "$stage_dir/padding.log"

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
gateway_shards=2
maintenance_coordinator_shard=0
active_health_interval_ms=1000
active_health_timeout_ms=500
healthy_threshold=2
unhealthy_threshold=2
dns_refresh_interval_ms=1000
dns_resolve_timeout_ms=500
graceful_stop_exit_code=$gateway_exit_code
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
EOF

cat >"$stage_dir/README.md" <<'EOF'
# Phase 3 active-health and DNS-refresh evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, or competitive claims.

The live two-shard gateway began on controlled upstream A, excluded it after two failed coordinator probes, returned a bounded `503 no_healthy_upstream` while every shard had the endpoint excluded, accepted a new DNS address, and recovered on controlled upstream B after two successful probes. The gateway process was not restarted.

The removed address was deliberately occupied before upstream B started. Recovery therefore required an observed DNS address change. Metrics also require exactly one shard with nonzero maintenance probe counters, zero publication failures, and zero unhealthy endpoints after recovery.

After recovery, the harness sent the normal termination signal and required the two maintenance loops, resolver, pools, and shards to stop with process exit code zero.

`initial-response.json`, `outage-transition.json`, and `recovery-transition.json` preserve the client-visible sequence. The two metric snapshots, validations, runtime identity, source checksums, logs, and evidence checksums preserve the supporting record.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
api/gen/go/bonvoyage/v1/config.pb.go
api/proto/bonvoyage/v1/config.proto
config/schemas/bonvoyage-config.schema.json
control-plane/internal/snapshot/snapshot.go
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/runtime/endpoint_maintenance.hh
dataplane/include/bonvoyage/runtime/endpoint_selector.hh
dataplane/include/bonvoyage/runtime/gateway.hh
dataplane/include/bonvoyage/runtime/runtime_snapshot.hh
dataplane/src/endpoint_maintenance.cc
dataplane/src/endpoint_selector.cc
dataplane/src/gateway.cc
dataplane/src/main.cc
dataplane/src/runtime_snapshot.cc
deploy/docker/upstream/server.py
scripts/phase3-active-health-dns-smoke.sh
tests/fixtures/phase3-active-health-dns.yaml
EOF
while IFS= read -r source_file; do
  hash_file "$source_file"
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

(
  cd "$stage_dir"
  for evidence_file in README.md client.log compiler.txt final-metrics-validation.txt \
    final-metrics.prom gateway.inspect.json gateway.log initial-response.json \
    metadata.txt outage-transition.json padding.log recovery-transition.json \
    runtime-image.inspect.json shutdown-validation.txt source-checksums.sha256 unavailable-metrics-validation.txt \
    unavailable-metrics.prom upstream-a.log upstream-b.log; do
    hash_file "$evidence_file"
  done >checksums.sha256
)

mkdir -p "$output_root"
test ! -e "$output_dir"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-active-health-dns-smoke.txt.tmp"
mv "$output_root/current-active-health-dns-smoke.txt.tmp" \
  "$output_root/current-active-health-dns-smoke.txt"

printf 'Active-health and DNS-refresh integration passed: %s\n' "$output_dir"
cat "$output_dir/unavailable-metrics-validation.txt"
cat "$output_dir/final-metrics-validation.txt"
