#!/bin/sh
set -eu

umask 077

script_dir="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
repo_root="$(CDPATH='' cd "$script_dir/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
fixture="$repo_root/tests/fixtures/phase3-otlp-tracing.yaml"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="otlp-tracing-$timestamp"
suffix="$$"
network="bonvoyage-otlp-$suffix"
volume="bonvoyage-otlp-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-otlp-gateway-$suffix"
upstream="bonvoyage-otlp-upstream-$suffix"
collector="bonvoyage-otlp-collector-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-otlp.XXXXXX")"
stage_dir="$work_dir/evidence"
output_root="${BONVOYAGE_OTLP_EVIDENCE_ROOT:-$repo_root/benchmarks/results/verification}"
output_dir="$output_root/$run_id"
mkdir -p "$stage_dir"

checksum_tool=""

fail() {
  message="$1"
  printf 'phase3-otlp-tracing: %s\n' "$message" >&2
  if [ -d "$stage_dir" ]; then
    printf '%s\n' "$message" >"$stage_dir/failure.txt"
  fi
  exit 1
}

capture_container() {
  container_name="$1"
  label="$2"
  if docker inspect "$container_name" >/dev/null 2>&1; then
    docker inspect "$container_name" >"$stage_dir/$label.inspect.json" \
      2>&1 || true
    docker logs "$container_name" >"$stage_dir/$label.log" 2>&1 || true
  fi
}

write_checksums() {
  (
    cd "$stage_dir" || exit 1
    find . -type f ! -name checksums.sha256 \
      ! -name checksums.sha256.tmp -print | LC_ALL=C sort \
      >"$work_dir/checksum-files.txt"
    while IFS= read -r path; do
      path="${path#./}"
      if [ "$checksum_tool" = sha256sum ]; then
        sha256sum "$path"
      else
        shasum -a 256 "$path"
      fi
    done <"$work_dir/checksum-files.txt" >checksums.sha256.tmp
    mv checksums.sha256.tmp checksums.sha256
    if [ "$checksum_tool" = sha256sum ]; then
      sha256sum --check --quiet checksums.sha256
    else
      shasum -a 256 --check --quiet checksums.sha256
    fi
  )
}

cleanup() {
  status="$?"
  trap - EXIT INT TERM
  set +e
  if [ -d "$stage_dir" ]; then
    capture_container "$gateway" gateway
    capture_container "$upstream" upstream
    capture_container "$collector" collector
    if [ "$status" -ne 0 ]; then
      printf 'outcome=FAIL\nexit_code=%s\n' "$status" \
        >"$stage_dir/run-status.env"
      write_checksums >/dev/null 2>&1 || true
      printf 'Temporary evidence retained at %s\n' "$stage_dir" >&2
      sed -n '1,240p' "$stage_dir/gateway.log" >&2 || true
      sed -n '1,160p' "$stage_dir/collector.log" >&2 || true
    fi
  fi
  docker rm --force "$gateway" "$upstream" "$collector" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  if [ "$status" -eq 0 ]; then
    rm -rf "$work_dir"
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command_name in date docker find git grep mktemp openssl python3 sed sleep; do
  command -v "$command_name" >/dev/null 2>&1 \
    || fail "required command is unavailable: $command_name"
done
if command -v sha256sum >/dev/null 2>&1; then
  checksum_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  checksum_tool=shasum
else
  fail "either sha256sum or shasum is required"
fi

[ -f "$fixture" ] || fail "OTLP fixture is missing: $fixture"
[ -f "$script_dir/phase3-otlp-collector.py" ] \
  || fail "controlled OTLP collector is missing"
[ -f "$script_dir/phase3-trace-upstream.py" ] \
  || fail "controlled trace upstream is missing"
[ -f "$script_dir/phase3-otlp-tracing-client.py" ] \
  || fail "controlled trace client is missing"
case "$oha_image" in
  *@sha256:*) ;;
  *) fail "BONVOYAGE_OHA_IMAGE must use an immutable sha256 digest" ;;
esac
[ ! -e "$output_dir" ] \
  || fail "evidence directory already exists: $output_dir"

docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage OTLP Test CA" \
  -keyout "$work_dir/ca-key.pem" -out "$work_dir/ca.pem" \
  >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=api.example.test" \
  -keyout "$work_dir/server-key.pem" -out "$work_dir/server.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  "subjectAltName=DNS:api.example.test" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=digitalSignature,keyEncipherment" \
  >"$work_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/server.csr" \
  -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca-key.pem" -CAcreateserial \
  -extfile "$work_dir/server-ext.cnf" -out "$work_dir/server-chain.pem" \
  >/dev/null 2>&1
chmod 600 "$work_dir"/*-key.pem

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile . \
  >"$stage_dir/compiler-image-build.log" 2>&1 \
  || fail "snapshot compiler image build failed"
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream \
  >"$stage_dir/upstream-image-build.log" 2>&1 \
  || fail "controlled upstream image build failed"
if ! docker image inspect "$oha_image" >/dev/null 2>&1; then
  docker pull --platform "$platform" "$oha_image" \
    >"$stage_dir/oha-image-pull.log" 2>&1 \
    || fail "pinned oha image is unavailable"
fi

dataplane_image_id="$(docker image inspect --format '{{.Id}}' "$image")" \
  || fail "dataplane image is unavailable: $image"
compiler_image_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")"
upstream_image_id="$(docker image inspect --format '{{.Id}}' "$upstream_image")"
oha_image_id="$(docker image inspect --format '{{.Id}}' "$oha_image")"
docker image inspect "$dataplane_image_id" "$compiler_image_id" \
  "$upstream_image_id" "$oha_image_id" >"$stage_dir/images.inspect.json"

docker network create --internal "$network" >/dev/null \
  || fail "could not create isolated Docker network"
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem \
  || fail "could not stage private gateway secrets"
docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$fixture:/etc/bonvoyage/otlp.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" "$compiler_image_id" \
  -input /etc/bonvoyage/otlp.yaml \
  -output /var/lib/bonvoyage/snapshot.pb \
  >"$stage_dir/snapshot-compiler.log" 2>&1 \
  || fail "OTLP snapshot compilation failed"

docker run --detach --platform "$platform" --name "$collector" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --network-alias collector --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --entrypoint python --env PYTHONDONTWRITEBYTECODE=1 \
  --env BONVOYAGE_EVIDENCE_DIR=/evidence \
  --volume "$script_dir/phase3-otlp-collector.py:/collector.py:ro" \
  --volume "$stage_dir:/evidence" "$upstream_image_id" \
  -B /collector.py >/dev/null \
  || fail "could not start controlled OTLP collector"
docker run --detach --platform "$platform" --name "$upstream" \
  --user "$(id -u):$(id -g)" \
  --network "$network" --network-alias upstream --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --entrypoint python --env PYTHONDONTWRITEBYTECODE=1 \
  --volume "$script_dir/phase3-trace-upstream.py:/trace-upstream.py:ro" \
  --volume "$script_dir/phase3-otlp-tracing-client.py:/trace-client.py:ro" \
  "$upstream_image_id" -B /trace-upstream.py >/dev/null \
  || fail "could not start controlled trace upstream"
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test --dns-search . --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$dataplane_image_id" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --otlp-traces-endpoint http://collector:4318/v1/traces \
  --otlp-traces-allow-insecure \
  --otlp-traces-queue-capacity 8 \
  --otlp-traces-max-batch-spans 2 \
  --otlp-traces-max-batch-bytes 65536 \
  --otlp-traces-flush-interval-ms 50 \
  --otlp-traces-request-timeout-ms 500 \
  --otlp-traces-sample-every 1 \
  --otlp-traces-max-retries 1 \
  --otlp-traces-retry-initial-backoff-ms 20 \
  --otlp-traces-retry-max-backoff-ms 20 \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=info \
  --logger-log-level bonvoyage-otlp-traces=info >/dev/null \
  || fail "could not start traced BonVoyage dataplane"

wait_for_url() {
  url="$1"
  label="$2"
  attempt=0
  until docker exec "$upstream" python -c \
    'import sys, urllib.request; assert urllib.request.urlopen(sys.argv[1], timeout=1).status == 200' \
    "$url" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 40 ] || fail "$label did not become ready"
    sleep 1
  done
}

capture_url() {
  url="$1"
  output="$2"
  docker exec "$upstream" python -c '
import sys
import urllib.request
sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1], timeout=5).read())
' "$url" >"$stage_dir/$output"
}

wait_for_metric() {
  metric="$1"
  comparison="$2"
  threshold="$3"
  label="$4"
  attempt=0
  until docker exec "$upstream" python -c '
import sys
import urllib.request

text = urllib.request.urlopen(sys.argv[1], timeout=2).read().decode()
name, comparison, threshold = sys.argv[2], sys.argv[3], float(sys.argv[4])
value = sum(
    float(line.split()[-1])
    for line in text.splitlines()
    if line.startswith(name + "{") or line.startswith(name + " ")
)
assert (value >= threshold) if comparison == "ge" else (value == threshold), value
' http://api.example.test:9090/metrics "$metric" "$comparison" "$threshold" \
    >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 100 ] || fail "$label did not reach its expected value"
    sleep 0.1
  done
}

wait_for_url http://upstream:8081/healthz "controlled upstream"
wait_for_url http://collector:4318/healthz "controlled OTLP collector"
bv_wait_gateway_ready "$gateway" "$upstream" http://api.example.test:9901/health/ready

docker inspect "$gateway" >"$stage_dir/gateway-before.inspect.json"
capture_url http://api.example.test:9901/config/active active-snapshot.json
capture_url http://api.example.test:9090/metrics metrics-baseline.prom

docker exec "$upstream" python -B /trace-client.py failure "$gateway" \
  --count 64 >"$stage_dir/http1-failure-load.json" \
  || fail "requests failed while the OTLP collector rejected exports"

metric_prefix=bonvoyage_bonvoyage_gateway_
wait_for_metric "${metric_prefix}otlp_trace_export_failures_total" ge 1 \
  "OTLP failure counter"
wait_for_metric "${metric_prefix}otlp_trace_retry_exhaustions_total" ge 1 \
  "OTLP retry exhaustion counter"
wait_for_metric "${metric_prefix}otlp_trace_queue_overflows_total" ge 1 \
  "OTLP queue overflow counter"
wait_for_metric "${metric_prefix}otlp_trace_exporter_healthy" eq 0 \
  "OTLP unhealthy gauge"
capture_url http://api.example.test:9090/metrics metrics-failure.prom

docker exec "$upstream" python -c '
import urllib.request
request = urllib.request.Request("http://collector:4318/recover", data=b"", method="POST")
with urllib.request.urlopen(request, timeout=5) as response:
    assert response.status == 200
' >"$stage_dir/collector-recovery.txt" \
  || fail "controlled OTLP collector did not enter recovery mode"

docker exec "$upstream" python -B /trace-client.py recovery "$gateway" \
  >"$stage_dir/http1-recovery.json" \
  || fail "HTTP/1 trace propagation or recovery checks failed"

docker run --rm --platform "$platform" --network "$network" \
  --user "$(id -u):$(id -g)" \
  --volume "$work_dir:/tls:ro" "$oha_image_id" \
  -n 4 -c 1 -p 4 --no-tui --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  -H 'traceparent: 00-33333333333333333333333333333333-4444444444444444-01' \
  -H 'tracestate: vendor=h2-trace-state-do-not-export' \
  -H 'baggage: h2-private-baggage-do-not-export=value' \
  -H 'x-private-header: h2-private-header-do-not-export' \
  'https://api.example.test:8443/h2-private-path-do-not-export?token=h2-private-query-do-not-export' \
  >"$stage_dir/http2-recovery.oha.json" \
  || fail "TLS HTTP/2 trace propagation failed"

wait_for_metric "${metric_prefix}otlp_trace_exporter_healthy" eq 1 \
  "OTLP healthy gauge"
wait_for_metric "${metric_prefix}otlp_trace_exporter_recoveries_total" ge 1 \
  "OTLP recovery counter"
wait_for_metric "${metric_prefix}otlp_trace_spans_exported_total" ge 8 \
  "OTLP exported span counter"
wait_for_metric "${metric_prefix}otlp_trace_queue_depth" eq 0 \
  "OTLP queue drain"

capture_url http://api.example.test:9090/metrics metrics-final.prom
capture_url http://collector:4318/observations collector-observations.json
capture_url http://upstream:8081/observations upstream-observations.json
docker inspect "$gateway" >"$stage_dir/gateway-after.inspect.json"
capture_container "$gateway" gateway
capture_container "$upstream" upstream
capture_container "$collector" collector

python3 - "$stage_dir" >"$stage_dir/validation.txt" <<'PY'
import glob
import json
import os
import re
import sys

root = sys.argv[1]
prefix = "bonvoyage_bonvoyage_gateway_"


def load(name):
    with open(os.path.join(root, name), encoding="utf-8") as source:
        return json.load(source)


def metric_totals(name):
    text = open(os.path.join(root, name), encoding="utf-8").read()
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key = line.split("{", 1)[0].split()[0]
        result[key] = result.get(key, 0.0) + float(line.split()[-1])
    return result


def read_varint(data, offset):
    value = 0
    shift = 0
    while True:
        assert offset < len(data), "truncated protobuf varint"
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
        assert shift <= 63, "oversized protobuf varint"


def fields(data):
    offset = 0
    while offset < len(data):
        key, offset = read_varint(data, offset)
        number, wire = key >> 3, key & 7
        assert number > 0
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire == 1:
            assert offset + 8 <= len(data)
            value, offset = data[offset : offset + 8], offset + 8
        elif wire == 2:
            length, offset = read_varint(data, offset)
            assert offset + length <= len(data)
            value, offset = data[offset : offset + length], offset + length
        elif wire == 5:
            assert offset + 4 <= len(data)
            value, offset = data[offset : offset + 4], offset + 4
        else:
            raise AssertionError(f"unsupported protobuf wire type {wire}")
        yield number, wire, value


def extract_spans(payload):
    spans = []
    for number, wire, resource_spans in fields(payload):
        if number != 1 or wire != 2:
            continue
        for resource_number, resource_wire, scope_spans in fields(resource_spans):
            if resource_number != 2 or resource_wire != 2:
                continue
            for scope_number, scope_wire, span in fields(scope_spans):
                if scope_number == 2 and scope_wire == 2:
                    values = {}
                    attributes = []
                    for span_number, span_wire, value in fields(span):
                        values.setdefault(span_number, []).append((span_wire, value))
                        if span_number == 9 and span_wire == 2:
                            key = None
                            for kv_number, kv_wire, kv_value in fields(value):
                                if kv_number == 1 and kv_wire == 2:
                                    key = kv_value.decode("utf-8")
                            attributes.append(key)
                    spans.append({"attributes": attributes, "fields": values})
    return spans


baseline = metric_totals("metrics-baseline.prom")
failed = metric_totals("metrics-failure.prom")
final = metric_totals("metrics-final.prom")
failure_load = load("http1-failure-load.json")
http1 = load("http1-recovery.json")
http2 = load("http2-recovery.oha.json")
collector = load("collector-observations.json")
upstream = load("upstream-observations.json")
before = load("gateway-before.inspect.json")[0]
after = load("gateway-after.inspect.json")[0]

assert failure_load == {"requests": 64, "status_counts": {"200": 64}}
assert http1["valid_remote_parent_status"] == 200
assert http1["invalid_traceparent_status"] == 200
assert http1["propagation_limit_status"] == 431
assert http1["post_limit_recovery_status"] == 200
assert http2["summary"]["successRate"] == 1, http2
assert http2["statusCodeDistribution"].get("200") == 4, http2

def total(metrics, suffix):
    return metrics.get(prefix + suffix, 0.0)


assert total(baseline, "otlp_traces_enabled") == 1
assert total(failed, "otlp_trace_exporter_healthy") == 0
assert total(failed, "otlp_trace_export_failures_total") >= 1
assert total(failed, "otlp_trace_export_retries_total") >= 1
assert total(failed, "otlp_trace_retry_exhaustions_total") >= 1
assert total(failed, "otlp_trace_queue_overflows_total") >= 1
assert total(final, "otlp_trace_exporter_healthy") == 1
assert total(final, "otlp_trace_exporter_recoveries_total") >= 1
assert total(final, "otlp_trace_queue_depth") == 0
assert total(final, "otlp_trace_invalid_traceparents_total") >= 1
assert total(final, "otlp_trace_remote_parents_total") >= 5
assert total(final, "otlp_trace_propagation_limit_rejections_total") == 1
assert total(final, "otlp_trace_partial_success_responses_total") == 0
assert total(final, "requests_total") == 72
assert total(final, "responses_2xx_total") == 71
assert total(final, "responses_4xx_total") == 1
assert total(final, "otlp_trace_spans_started_total") == 72
assert total(final, "otlp_trace_spans_sampled_total") == 72
assert total(final, "otlp_trace_spans_sampled_out_total") == 0
assert (
    total(final, "otlp_trace_spans_exported_total")
    + total(final, "otlp_trace_spans_dropped_total")
) == 72

assert before["Id"] == after["Id"]
assert before["State"]["Pid"] == after["State"]["Pid"]
assert before["State"]["StartedAt"] == after["State"]["StartedAt"]
assert after["State"]["Running"] is True

assert collector["attempts"] >= 2
assert collector["rejected"] >= 1
assert collector["accepted"] >= 1
assert all(
    item["content_type"] == "application/x-protobuf"
    for item in collector["observations"]
)
assert all(
    item["connection_header"].lower() == "close"
    for item in collector["observations"]
)
assert len({item["connection_id"] for item in collector["observations"]}) == len(
    collector["observations"]
)

payload_paths = sorted(glob.glob(os.path.join(root, "otlp-payload-*.bin")))
assert len(payload_paths) == collector["accepted"]
payloads = [open(path, "rb").read() for path in payload_paths]
assert all(payloads)
assert sum(len(payload) for payload in payloads) == total(
    final, "otlp_trace_bytes_exported_total"
)
spans = [span for payload in payloads for span in extract_spans(payload)]
assert len(spans) == total(final, "otlp_trace_spans_exported_total")

allowed_attributes = {
    "bonvoyage.action",
    "bonvoyage.cluster",
    "bonvoyage.completion",
    "bonvoyage.listener",
    "bonvoyage.route",
    "bonvoyage.shard",
    "bonvoyage.snapshot.generation",
    "http.request.body.size",
    "http.request.method",
    "http.response.body.size",
    "http.response.status_code",
    "network.protocol.name",
    "network.protocol.version",
    "rpc.system",
}
h1_trace = bytes.fromhex("11" * 16)
h1_parent = bytes.fromhex("22" * 8)
h2_trace = bytes.fromhex("33" * 16)
h2_parent = bytes.fromhex("44" * 8)
h1_remote = 0
h2_remote = 0
for span in spans:
    values = span["fields"]
    assert values[1][0][0] == 2 and len(values[1][0][1]) == 16
    assert values[2][0][0] == 2 and len(values[2][0][1]) == 8
    assert 3 not in values, "tracestate unexpectedly entered an OTLP span"
    assert set(span["attributes"]) <= allowed_attributes
    trace_id = values[1][0][1]
    parent_id = values.get(4, [(None, b"")])[0][1]
    if trace_id == h1_trace:
        assert parent_id == h1_parent
        h1_remote += 1
    if trace_id == h2_trace:
        assert parent_id == h2_parent
        h2_remote += 1
assert h1_remote == 1
assert h2_remote == 4

raw_payload = b"".join(payloads).lower()
for marker in (
    b"private-path-do-not-export",
    b"private-query-do-not-export",
    b"private-auth-do-not-export",
    b"private-baggage-do-not-export",
    b"private-cookie-do-not-export",
    b"trace-state-do-not-export",
    b"private-header-do-not-export",
    b"api.example.test",
    b"authorization",
    b"cookie",
    b"baggage",
    b"tracestate",
):
    assert marker not in raw_payload, marker

traceparent_pattern = re.compile(
    r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$"
)
observations = upstream["observations"]
assert upstream["requests"] == 71
assert not any(item["path"] == "/propagation-limit" for item in observations)

h1_items = [
    item for item in observations
    if item["path"].startswith("/private-path-do-not-export?")
]
assert len(h1_items) == 1
h1_headers = h1_items[0]["headers"]
h1_match = traceparent_pattern.fullmatch(h1_headers["traceparent"])
assert h1_match and h1_match.group(1) == "11" * 16
assert h1_match.group(2) != "22" * 8
assert "baggage" not in h1_headers and "tracestate" not in h1_headers
assert h1_headers["authorization"] == "Bearer private-auth-do-not-export"
assert h1_headers["cookie"] == "session=private-cookie-do-not-export"

h2_items = [
    item for item in observations
    if item["path"].startswith("/h2-private-path-do-not-export?")
]
assert len(h2_items) == 4
for item in h2_items:
    headers = item["headers"]
    match = traceparent_pattern.fullmatch(headers["traceparent"])
    assert match and match.group(1) == "33" * 16
    assert match.group(2) != "44" * 8
    assert "baggage" not in headers and "tracestate" not in headers

invalid = [item for item in observations if item["path"] == "/invalid-context"]
assert len(invalid) == 1
assert traceparent_pattern.fullmatch(invalid[0]["headers"]["traceparent"])
assert "not-a-valid-traceparent" not in invalid[0]["headers"]["traceparent"]

summary = {
    "classification": "local-engineering",
    "collector": {
        "accepted_batches": collector["accepted"],
        "attempts": collector["attempts"],
        "rejected_attempts": collector["rejected"],
    },
    "gateway_process_unchanged": True,
    "http1_failure_requests": 64,
    "http2_recovery_requests": 4,
    "marketing_use_authorized": False,
    "metrics": {
        key.removeprefix(prefix): int(value)
        for key, value in sorted(final.items())
        if key.startswith(prefix + "otlp_trace")
    },
    "otlp_payload_bytes": sum(len(payload) for payload in payloads),
    "privacy_markers_exported": [],
    "propagation": {
        "http1_remote_parent_spans": h1_remote,
        "http2_remote_parent_spans": h2_remote,
        "invalid_traceparent_replaced": True,
        "tracestate_and_baggage_forwarded": False,
    },
    "publishable": False,
    "result": "PASS",
    "spans_parsed": len(spans),
    "upstream_requests": upstream["requests"],
}
with open(os.path.join(root, "summary.json"), "w", encoding="utf-8") as output:
    json.dump(summary, output, indent=2, sort_keys=True)
    output.write("\n")
print("bounded OTLP failure isolation, recovery, propagation, and privacy gate passed")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

source_commit="$(git rev-parse HEAD)"
if [ -z "$(git status --porcelain)" ]; then
  source_dirty=false
else
  source_dirty=true
fi
git status --short >"$stage_dir/git-status.txt"
git diff --no-ext-diff --binary >"$stage_dir/source-diff.patch"
cat >"$stage_dir/metadata.txt" <<EOF
captured_at_utc=$timestamp
run_id=$run_id
source_commit=$source_commit
source_dirty=$source_dirty
platform=$platform
dataplane_image=$image
dataplane_image_id=$dataplane_image_id
compiler_image_id=$compiler_image_id
upstream_image_id=$upstream_image_id
oha_image=$oha_image
oha_image_id=$oha_image_id
gateway_shards=1
otlp_transport=http1-protobuf
otlp_endpoint_scheme=http
otlp_queue_capacity_per_shard=8
otlp_max_batch_spans=2
otlp_max_batch_bytes=65536
otlp_sample_every=1
otlp_max_retries=1
evidence_class=local-engineering
publishable=false
marketing_use_authorized=false
performance_claim_authorized=false
EOF

cat >"$stage_dir/README.md" <<'EOF'
# Phase 3 bounded OTLP tracing evidence

**LOCAL ENGINEERING EVIDENCE - NON-PUBLISHABLE.** This run is not authorized for marketing, customer-facing, performance, or competitive claims.

One unchanged single-shard BonVoyage process continued serving HTTP/1.1 requests while a controlled OTLP/HTTP collector returned `503`, exposed bounded drop and retry-exhaustion counters, and recovered after the collector returned valid protobuf `200` responses. The same process then propagated canonical W3C `traceparent` context over HTTP/1.1 and TLS HTTP/2, replaced invalid context, stripped `tracestate` and `baggage`, enforced the final forwarded-header byte ceiling, exported only the approved low-cardinality span schema, and drained its bounded queue.

`summary.json` is the machine-readable decision record. Raw metrics, parsed collector and upstream observations, accepted OTLP protobuf payloads, HTTP client outputs, container and image inspection, logs, source diff, source identity, and checksums are retained beside it.
EOF

cat >"$stage_dir/source-files.txt" <<'EOF'
Makefile
control-plane/internal/snapshot/snapshot.go
control-plane/internal/snapshot/snapshot_test.go
dataplane/CMakeLists.txt
dataplane/include/bonvoyage/runtime/gateway.hh
dataplane/include/bonvoyage/runtime/trace_context.hh
dataplane/include/bonvoyage/runtime/trace_exporter.hh
dataplane/src/gateway.cc
dataplane/src/main.cc
dataplane/src/runtime_snapshot.cc
dataplane/src/trace_context.cc
dataplane/src/trace_exporter.cc
dataplane/tests/runtime_snapshot_test.cc
dataplane/tests/trace_context_test.cc
dataplane/tests/trace_exporter_runtime_test.cc
deploy/docker/bonvoyage/Dockerfile
scripts/phase3-otlp-collector.py
scripts/phase3-otlp-tracing-client.py
scripts/phase3-otlp-tracing-smoke.sh
scripts/test-fixture-secrets.sh
scripts/phase3-trace-upstream.py
security/dependencies/opentelemetry-proto-1.11.0.json
tests/fixtures/phase3-otlp-tracing.yaml
third_party/opentelemetry-proto/LICENSE
third_party/opentelemetry-proto/opentelemetry/proto/collector/trace/v1/trace_service.proto
third_party/opentelemetry-proto/opentelemetry/proto/common/v1/common.proto
third_party/opentelemetry-proto/opentelemetry/proto/resource/v1/resource.proto
third_party/opentelemetry-proto/opentelemetry/proto/trace/v1/trace.proto
EOF
while IFS= read -r source_file; do
  [ -f "$source_file" ] || fail "source evidence file is missing: $source_file"
  if [ "$checksum_tool" = sha256sum ]; then
    sha256sum "$source_file"
  else
    shasum -a 256 "$source_file"
  fi
done <"$stage_dir/source-files.txt" >"$stage_dir/source-checksums.sha256"
rm "$stage_dir/source-files.txt"

printf 'outcome=PASS\nexit_code=0\n' >"$stage_dir/run-status.env"
write_checksums || fail "evidence checksum verification failed"
mkdir -p "$output_root"
mv "$stage_dir" "$output_dir"
printf '%s\n' "$run_id" >"$output_root/current-otlp-tracing.txt.tmp"
mv "$output_root/current-otlp-tracing.txt.tmp" \
  "$output_root/current-otlp-tracing.txt"

printf 'Phase 3 OTLP tracing qualification passed: %s\n' "$output_dir"
cat "$output_dir/summary.json"
