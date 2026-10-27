#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
# shellcheck disable=SC1091
. "$repo/scripts/test-fixture-secrets.sh"

platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
gateway_image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
suffix="$$-$(date -u +%Y%m%dT%H%M%SZ)"
network="bonvoyage-perf03-$suffix"
snapshot_volume="bonvoyage-perf03-snapshot-$suffix"
secrets_volume="bonvoyage-perf03-secrets-$suffix"
gateway="bonvoyage-perf03-gateway-$suffix"
upstream="bonvoyage-perf03-upstream-$suffix"
work="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-perf03.XXXXXX")"

fail() {
  echo "phase5-response-path-diagnostics: $*" >&2
  exit 1
}

cleanup() {
  status="$?"
  set +e
  if [ "$status" -ne 0 ] && docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >"$work/gateway.log" 2>&1
  fi
  docker rm --force "$gateway" "$upstream" >/dev/null 2>&1
  docker network rm "$network" >/dev/null 2>&1
  docker volume rm "$snapshot_volume" >/dev/null 2>&1
  bv_remove_fixture_secrets "$secrets_volume" "$work" >/dev/null 2>&1
  if [ "$status" -eq 0 ]; then
    rm -rf "$work"
  else
    echo "partial diagnostic evidence retained: $work" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for tool in docker jq mktemp openssl python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool required"
done

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj '/CN=BonVoyage PERF-03 CA' -keyout "$work/ca-key.pem" \
  -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=api.example.test' -keyout "$work/server-key.pem" \
  -out "$work/server.csr" >/dev/null 2>&1
printf '%s\n' \
  'subjectAltName=DNS:api.example.test' \
  'extendedKeyUsage=serverAuth' \
  'keyUsage=digitalSignature,keyEncipherment' >"$work/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work/server.csr" \
  -CA "$work/ca.pem" -CAkey "$work/ca-key.pem" -CAcreateserial \
  -extfile "$work/server-ext.cnf" -out "$work/server-chain.pem" \
  >/dev/null 2>&1
chmod 600 "$work"/*-key.pem

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file "$repo/deploy/docker/control-plane/Dockerfile" "$repo" >/dev/null
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file "$repo/deploy/docker/upstream/Dockerfile" \
  "$repo/deploy/docker/upstream" >/dev/null
docker network create "$network" >/dev/null
docker volume create "$snapshot_volume" >/dev/null
docker run --rm --pull never --platform "$platform" --user 0:0 \
  --network none --volume "$snapshot_volume:/output" --entrypoint python \
  "$upstream_image" -c \
  'import os; os.chmod("/output", 0o700); os.chown("/output", 65532, 65532)' \
  >/dev/null
bv_stage_fixture_secrets "$secrets_volume" "$work" "$upstream_image" \
  "$platform" server-chain.pem server-key.pem

docker run --rm --pull never --platform "$platform" \
  --volume "$repo/tests/fixtures/phase3-routing.yaml:/config/input.yaml:ro" \
  --volume "$snapshot_volume:/output" "$compiler_image" \
  -input /config/input.yaml -output /output/snapshot.pb \
  >"$work/compiler.log"

docker run --detach --pull never --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  --env BONVOYAGE_UPSTREAM_ID=upstream "$upstream_image" >/dev/null

start_gateway() {
  diagnostics="$1"
  diagnostic_argument=''
  if [ "$diagnostics" = enabled ]; then
    diagnostic_argument='--response-path-diagnostics'
  fi
  # Word splitting is intentional for the optional flag, which is either empty
  # or exactly one argument.
  # shellcheck disable=SC2086
  docker run --detach --pull never --platform "$platform" --name "$gateway" \
    --network "$network" --network-alias gateway \
    --network-alias api.example.test \
    --volume "$snapshot_volume:/snapshot:ro" \
    --volume "$secrets_volume:/etc/bonvoyage/secrets:ro" \
    "$gateway_image" --snapshot /snapshot/snapshot.pb \
    --secrets-directory /etc/bonvoyage/secrets \
    --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
    --smp 1 --memory 384M --overprovisioned $diagnostic_argument >/dev/null
  bv_wait_gateway_ready "$gateway" "$upstream" \
    "http://$gateway:9901/health/ready"
}

proxy_requests() {
  repetitions="$1"
  docker exec "$upstream" python -c '
import sys
import urllib.request

gateway = "http://bonvoyage-perf03-gateway-'"$suffix"':8080"
paths = ["/payload/256", "/payload/16384", "/chunked/1024"]
for _ in range(int(sys.argv[1])):
    for path in paths:
        request = urllib.request.Request(
            gateway + path, headers={"Host": "api.example.test"}
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read()
            assert response.status == 200, (path, response.status)
            expected = int(path.rsplit("/", 1)[1])
            assert len(body) == expected, (path, len(body), expected)
' "$repetitions"
}

excluded_requests() {
  label="$1"
  docker exec "$upstream" python -c '
import urllib.request

request = urllib.request.Request(
    "http://bonvoyage-perf03-gateway-'"$suffix"':8080/routing/baseline",
    headers={"Host": "api.example.test"},
)
for _ in range(3):
    with urllib.request.urlopen(request, timeout=10) as response:
        assert response.status == 200
        assert response.read() == b"baseline\n"
'
  docker run --rm --pull never --platform "$platform" --network "$network" \
    --volume "$work/ca.pem:/tls/ca.pem:ro" "$oha_image" \
    -n 3 -c 1 -p 1 --no-tui --no-color --output-format json \
    --http-version 2 --disable-compression --cacert /tls/ca.pem \
    https://api.example.test:8443/payload/256 >"$work/$label-http2.oha.json"
  jq -e '.statusCodeDistribution == {"200": 3} and
    (.errorDistribution | length) == 0' "$work/$label-http2.oha.json" \
    >/dev/null || fail "$label HTTP/2 exclusion probe failed"
}

capture_metrics() {
  destination="$1"
  docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-perf03-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$destination"
}

validate_metrics() {
  mode="$1"
  metrics="$2"
  python3 - "$mode" "$metrics" <<'PY'
import sys

mode, path = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    metrics = source.read()

prefix = "bonvoyage_bonvoyage_gateway_"

def total(suffix):
    value = 0.0
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        name, raw = line.split(None, 1)
        if name.split("{", 1)[0] == prefix + suffix:
            value += float(raw)
    return value

counter_names = (
    "response_path_completed_responses_total",
    "response_path_write_operations_total",
    "response_path_write_bytes_total",
    "response_path_flush_operations_total",
    "response_path_flush_wait_operations_total",
    "response_path_flush_wait_nanoseconds_total",
    "response_path_handoff_observations_total",
    "response_path_handoff_nanoseconds_total",
)

if mode == "disabled":
    assert total("response_path_diagnostics_enabled") == 0
    assert all(total(name) == 0 for name in counter_names)
    print("default-off diagnostics remained inert under live traffic")
    raise SystemExit(0)

expected_responses = 6
minimum_body_bytes = 2 * (256 + 16384 + 1024)
completed = total("response_path_completed_responses_total")
writes = total("response_path_write_operations_total")
write_bytes = total("response_path_write_bytes_total")
flushes = total("response_path_flush_operations_total")
flush_waits = total("response_path_flush_wait_operations_total")
handoffs = total("response_path_handoff_observations_total")

assert total("response_path_diagnostics_enabled") == 1
assert completed == expected_responses, completed
assert handoffs == expected_responses, handoffs
assert flushes == expected_responses, flushes
assert writes >= expected_responses * 2, writes
assert write_bytes >= minimum_body_bytes, write_bytes
assert 0 <= flush_waits <= flushes, (flush_waits, flushes)
assert total("response_path_flush_wait_nanoseconds_total") >= 0
assert total("response_path_handoff_nanoseconds_total") >= 0
print(
    "opt-in diagnostics passed: "
    f"completed={completed:.0f} writes={writes:.0f} "
    f"logical_bytes={write_bytes:.0f} flushes={flushes:.0f} "
    f"flush_waits={flush_waits:.0f}"
)
PY
}

start_gateway disabled
proxy_requests 1
excluded_requests disabled
capture_metrics "$work/disabled.prom"
validate_metrics disabled "$work/disabled.prom"

docker rm --force "$gateway" >/dev/null
start_gateway enabled
proxy_requests 2
excluded_requests enabled
capture_metrics "$work/enabled.prom"
validate_metrics enabled "$work/enabled.prom"

echo 'PERF-03 response-path diagnostics smoke passed'
