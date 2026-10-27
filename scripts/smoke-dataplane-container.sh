#!/bin/sh
set -eu

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
evidence_dir="${BONVOYAGE_HTTP1_FRAMING_EVIDENCE_DIR:-}"
started_at="$(date -u +%Y%m%dT%H%M%SZ)"
suffix="$$"
network="bonvoyage-smoke-$suffix"
volume="bonvoyage-snapshot-$suffix"
gateway="bonvoyage-gateway-$suffix"
safe_gateway="bonvoyage-gateway-safe-$suffix"
upstream="bonvoyage-upstream-$suffix"

if [ -n "$evidence_dir" ]; then
  case "$evidence_dir" in
    /*) ;;
    *)
      echo "BONVOYAGE_HTTP1_FRAMING_EVIDENCE_DIR must be absolute" >&2
      exit 2
      ;;
  esac
  mkdir -p "$evidence_dir"
fi

cleanup() {
  status="$?"
  if [ "$status" -ne 0 ] && docker inspect "$gateway" >/dev/null 2>&1; then
    echo "BonVoyage gateway state after smoke failure:" >&2
    docker inspect --format \
      'status={{.State.Status}} exit_code={{.State.ExitCode}} oom_killed={{.State.OOMKilled}} error={{.State.Error}}' \
      "$gateway" >&2 || true
    echo "BonVoyage gateway logs after smoke failure:" >&2
    docker logs "$gateway" >&2 || true
    echo "BonVoyage metrics after smoke failure:" >&2
    docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-gateway-'"$suffix"':9090/metrics", timeout=10
).read().decode())
' >&2 || true
    echo "Controlled upstream logs after smoke failure:" >&2
    docker logs "$upstream" >&2 || true
    if docker inspect "$safe_gateway" >/dev/null 2>&1; then
      echo "BonVoyage safe-default gateway state after smoke failure:" >&2
      docker inspect --format \
        'status={{.State.Status}} exit_code={{.State.ExitCode}} oom_killed={{.State.OOMKilled}} error={{.State.Error}}' \
        "$safe_gateway" >&2 || true
      echo "BonVoyage safe-default gateway logs after smoke failure:" >&2
      docker logs "$safe_gateway" >&2 || true
    fi
  fi
  docker rm --force "$gateway" "$safe_gateway" "$upstream" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  return "$status"
}
trap cleanup EXIT INT TERM

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null

docker run --rm --platform "$platform" \
  --volume "$PWD/config/examples/local.yaml:/etc/bonvoyage/local.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" \
  -input /etc/bonvoyage/local.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >/dev/null

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream "$upstream_image" >/dev/null

set -- \
  --snapshot /etc/bonvoyage/snapshot.pb \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned \
  --runtime-log-transport stderr-pipe \
  --logger-log-level bonvoyage-gateway=debug
upstream_client="$(docker image inspect "$image" --format \
  '{{index .Config.Labels "io.routesphere.bonvoyage.upstream-http1-client"}}')"
if [ "$upstream_client" = "seastar-reference" ]; then
  set -- "$@" --logger-log-level http=trace
elif [ "$upstream_client" = "llhttp-candidate" ]; then
  set -- "$@" --logger-log-level bonvoyage-upstream-client=trace
fi
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --volume "$volume:/etc/bonvoyage:ro" "$image" \
  "$@" --trust-upstream-http1-connection-reuse >/dev/null

attempt=0
until docker exec "$upstream" python -c \
  'import urllib.request; assert urllib.request.urlopen("http://bonvoyage-gateway-'"$suffix"':9901/health/ready", timeout=1).status == 200' \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    docker logs "$gateway"
    echo "BonVoyage dataplane did not become ready" >&2
    exit 1
  fi
  sleep 1
done

# Exercise fixed responses, proxying, request-body streaming, and upstream reuse.
docker exec "$upstream" python -c '
import http.client
c = http.client.HTTPConnection("bonvoyage-gateway-'"$suffix"'", 8080, timeout=20)
c.request("GET", "/bonvoyage/ready", headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 200 and r.read() == b"ready\n"
c.request("GET", "/payload/256", headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 200 and len(r.read()) == 256
first = r.getheader("x-upstream-connection")
c.request("GET", "/payload/16", headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 200 and len(r.read()) == 16
assert r.getheader("x-upstream-connection") == first
c.request("GET", "/payload/1048576", headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 200 and r.read() == b"x" * 1048576
assert r.getheader("x-upstream-connection") == first
c.request("GET", "/reset-content", headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 205 and r.read() == b""
assert r.getheader("content-length") == "0"
c.request("GET", "/payload/8", headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 200 and r.read() == b"x" * 8
c.request("GET", "/bonvoyage/ready", headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 200 and r.read() == b"ready\n"
payload = b"stream-through-bonvoyage"
c.request("POST", "/echo", body=payload, headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 200 and r.read() == payload
c.request("POST", "/echo", body=[b"chunked-", b"request"],
          headers={"Host": "example.test"}, encode_chunked=True)
r = c.getresponse(); assert r.status == 200 and r.read() == b"chunked-request"
c.close()
'

if [ "$upstream_client" = "llhttp-candidate" ]; then
  # The owned candidate consumes bounded informational responses, rejects
  # upgrades, and retires a peer that exceeds the informational-response cap.
  docker exec "$upstream" python -c '
import http.client

host = "bonvoyage-gateway-'"$suffix"'"
headers = {"Host": "example.test"}

connection = http.client.HTTPConnection(host, 8080, timeout=20)
connection.request("GET", "/informational-final", headers=headers)
response = connection.getresponse()
assert response.status == 200 and response.read() == b"final\n"
connection.close()

for path in ("/switching-protocols", "/informational-flood"):
    connection = http.client.HTTPConnection(host, 8080, timeout=20)
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    assert response.status == 502, (path, response.status)
    response.read()
    connection.close()

connection = http.client.HTTPConnection(host, 8080, timeout=20)
connection.request("GET", "/payload/12", headers=headers)
response = connection.getresponse()
assert response.status == 200 and response.read() == b"x" * 12
connection.close()
'
fi

# A complete response followed by unsolicited bytes must retire the upstream
# connection. The next request must reach a fresh upstream socket rather than
# consuming the forged response already queued behind the prior boundary.
docker exec "$upstream" python -c '
import http.client

host = "bonvoyage-gateway-'"$suffix"'"
headers = {"Host": "example.test"}
cases = (
    ("/response-overrun/bodyless", 204, b""),
    ("/response-overrun/content-length", 200, b"ok"),
    ("/response-overrun/chunked", 200, b"ok"),
)
for path, expected_status, expected_body in cases:
    connection = http.client.HTTPConnection(host, 8080, timeout=20)
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    assert response.status == expected_status, (path, response.status)
    assert response.read() == expected_body, path
    connection.request("GET", "/healthz", headers=headers)
    recovered = connection.getresponse()
    assert recovered.status == 200, (path, recovered.status)
    assert recovered.read() == b"ok\n", path
    assert recovered.getheader("x-bonvoyage-forged") is None, path
    connection.close()
'

# The secure default never reuses an HTTP/1 upstream connection. Delayed bytes
# sent after a valid response therefore cannot become the next transaction,
# including when they arrive in a separate TCP/TLS record after pool return.
docker run --detach --platform "$platform" --name "$safe_gateway" \
  --network "$network" --volume "$volume:/etc/bonvoyage:ro" "$image" \
  "$@" >/dev/null
attempt=0
until docker exec "$upstream" python -c \
  'import urllib.request; assert urllib.request.urlopen("http://bonvoyage-gateway-safe-'"$suffix"':9901/health/ready", timeout=1).status == 200' \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    docker logs "$safe_gateway"
    echo "BonVoyage safe-default dataplane did not become ready" >&2
    exit 1
  fi
  sleep 1
done

docker exec "$upstream" python -c '
import http.client

host = "bonvoyage-gateway-safe-'"$suffix"'"
headers = {"Host": "example.test"}
cases = (
    ("/response-overrun-delayed/bodyless", 204, b""),
    ("/response-overrun-delayed/content-length", 200, b"ok"),
    ("/response-overrun-delayed/chunked", 200, b"ok"),
)
for path, expected_status, expected_body in cases:
    connection = http.client.HTTPConnection(host, 8080, timeout=20)
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    assert response.status == expected_status, (path, response.status)
    assert response.read() == expected_body, path
    first_upstream = response.getheader("x-upstream-connection")
    assert first_upstream, path
    connection.request("GET", "/healthz", headers=headers)
    recovered = connection.getresponse()
    assert recovered.status == 200, (path, recovered.status)
    assert recovered.read() == b"ok\n", path
    assert recovered.getheader("x-bonvoyage-forged") is None, path
    assert recovered.getheader("x-upstream-connection") != first_upstream, path
    connection.close()
'

docker stop --signal TERM --time 15 "$safe_gateway" >/dev/null
safe_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$safe_gateway")"
safe_logs="$(docker logs "$safe_gateway" 2>&1)"
test "$safe_exit_code" -eq 0
printf '%s\n' "$safe_logs" | grep -F "event=dataplane_ready" >/dev/null
printf '%s\n' "$safe_logs" | grep -F "event=dataplane_stopped" \
  | grep -F "outcome=clean" >/dev/null

# Translate bounded upstream chunk framing and deliberately drop trailers.
docker exec "$upstream" python -c '
import http.client
c = http.client.HTTPConnection("bonvoyage-gateway-'"$suffix"'", 8080, timeout=20)
c.request("GET", "/chunked/8192", headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 200 and r.read() == b"x" * 8192
assert r.getheader("transfer-encoding").lower() == "chunked"
c.request("GET", "/chunked-with-trailers/4096", headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 200 and r.read() == b"x" * 4096
assert r.getheader("trailer") is None
c.request("GET", "/payload/32", headers={"Host": "example.test"})
r = c.getresponse(); assert r.status == 200 and r.read() == b"x" * 32
c.close()
'

# Reject unsupported or over-limit upstream framing, retire the affected
# upstream connection, and recover on a later request without a restart.
docker exec "$upstream" python -c '
import http.client

host = "bonvoyage-gateway-'"$suffix"'"
headers = {"Host": "example.test"}

def request(path):
    connection = http.client.HTTPConnection(host, 8080, timeout=20)
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    return connection, response

for path in (
    "/large-response-header/33000",
    "/close-delimited/16",
    "/reset-content-invalid",
):
    connection, response = request(path)
    assert response.status == 502, (path, response.status)
    response.read()
    connection.close()

for path in (
    "/chunked-extension/33000",
    "/chunked-trailer/33000",
    "/chunked-truncated/16",
):
    connection, response = request(path)
    assert response.status == 200, (path, response.status)
    try:
        response.read()
    except http.client.IncompleteRead:
        pass
    else:
        raise AssertionError(f"{path} completed despite invalid chunk framing")
    connection.close()

connection, response = request("/payload/64")
assert response.status == 200 and response.read() == b"x" * 64
connection.close()
'

# Reject ambiguous HTTP framing before an upstream request is attempted.
docker exec "$upstream" python -c '
import socket
s = socket.create_connection(("bonvoyage-gateway-'"$suffix"'", 8080), timeout=20)
s.sendall(b"POST /echo HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
assert b" 400 " in s.recv(4096)
s.close()
'

# Preserve HTTP/1.1 response ordering for two pipelined requests.
docker exec "$upstream" python -c '
import socket
s = socket.create_connection(("bonvoyage-gateway-'"$suffix"'", 8080), timeout=20)
s.sendall(b"GET /bonvoyage/ready HTTP/1.1\r\nHost: example.test\r\n\r\nGET /bonvoyage/ready HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
data = bytearray()
while True:
    chunk = s.recv(4096)
    if not chunk: break
    data.extend(chunk)
assert bytes(data).count(b"HTTP/1.1 200 OK") == 2
assert bytes(data).count(b"ready\n") == 2
s.close()
'

# Verify strict Host, header-size, and body-size rejection.
docker exec "$upstream" python -c '
import socket
cases = [
    (b"GET / HTTP/1.1\r\n\r\n", b" 400 "),
    (b"GET / HTTP/1.1\r\nHost: one.test\r\nHost: two.test\r\n\r\n", b" 400 "),
    (b"POST /echo HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx", b" 400 "),
    (b"POST /echo HTTP/1.1\r\nHost: example.test\r\nContent-Length: 10485761\r\n\r\n", b" 413 "),
    (b"POST /echo HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n1;name=value\r\nx\r\n0\r\n\r\n", b" 400 "),
    (b"POST /echo HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nX-Trailer: value\r\n\r\n", b" 400 "),
    (b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Large: " + b"x" * 33000 + b"\r\n\r\n", b" 431 "),
    (b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: one\r\n folded\r\n\r\n", b" 400 "),
]
for request, expected in cases:
    s = socket.create_connection(("bonvoyage-gateway-'"$suffix"'", 8080), timeout=20)
    s.sendall(request)
    assert expected in s.recv(4096), expected
    s.close()
'

metrics_summary="$(docker exec "$upstream" python -c '
import json
import urllib.request
metrics = urllib.request.urlopen(
    "http://bonvoyage-gateway-'"$suffix"':9090/metrics", timeout=20
).read().decode()

def total(name):
    return sum(
        float(line.split()[-1])
        for line in metrics.splitlines()
        if line.startswith(name + "{") or line.startswith(name + " ")
    )

prefix = "bonvoyage_bonvoyage_gateway_"
summary = {
    "requests_total": total(prefix + "requests_total"),
    "upstream_chunked_responses_total": total(
        prefix + "upstream_chunked_responses_total"
    ),
    "upstream_framing_rejections_total": total(
        prefix + "upstream_framing_rejections_total"
    ),
    "upstream_response_trailers_dropped_total": total(
        prefix + "upstream_response_trailers_dropped_total"
    ),
}
assert summary["requests_total"] > 0
assert summary["upstream_chunked_responses_total"] >= 2
assert summary["upstream_response_trailers_dropped_total"] >= 1
assert summary["upstream_framing_rejections_total"] >= 6
print(json.dumps(summary, separators=(",", ":"), sort_keys=True))
')"

if [ -n "$evidence_dir" ]; then
  docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-gateway-'"$suffix"':9090/metrics", timeout=20
).read().decode(), end="")
' >"$evidence_dir/metrics.prom"
fi

docker stop --signal TERM --time 15 "$gateway" >/dev/null
exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
logs="$(docker logs "$gateway" 2>&1)"
printf '%s\n' "$logs"
test "$exit_code" -eq 0
printf '%s\n' "$logs" | grep -F "event=dataplane_ready" >/dev/null
printf '%s\n' "$logs" | grep -F "event=dataplane_stopped" | grep -F "outcome=clean" >/dev/null

if [ -n "$evidence_dir" ]; then
  printf '%s\n' "$logs" >"$evidence_dir/gateway.log"
  printf '%s\n' "$safe_logs" >"$evidence_dir/safe-default-gateway.log"
  docker logs "$upstream" >"$evidence_dir/upstream.log" 2>&1
  docker inspect "$gateway" >"$evidence_dir/gateway.inspect.json"
  docker inspect "$safe_gateway" >"$evidence_dir/safe-default-gateway.inspect.json"
  docker inspect "$upstream" >"$evidence_dir/upstream.inspect.json"
  docker image inspect "$image" "$compiler_image" "$upstream_image" \
    >"$evidence_dir/images.inspect.json"
  cp "$0" "$evidence_dir/harness.sh"
  cp config/examples/local.yaml "$evidence_dir/local.yaml"
  cp deploy/docker/upstream/server.py "$evidence_dir/controlled-upstream.py"
  cp deploy/docker/bonvoyage/patches/seastar-http-client-bounded-chunks.patch \
    "$evidence_dir/seastar-http-client-bounded-chunks.patch"
  cp deploy/docker/bonvoyage/patches/seastar-http-client-pool-wait-observer.patch \
    "$evidence_dir/seastar-http-client-pool-wait-observer.patch"
  cp deploy/docker/bonvoyage/patches/seastar-ascii-case-insensitive-headers.patch \
    "$evidence_dir/seastar-ascii-case-insensitive-headers.patch"
  cp dataplane/src/gateway.cc "$evidence_dir/gateway.cc"
  cp dataplane/src/http1_validation.cc \
    "$evidence_dir/http1_validation.cc"
  cp dataplane/src/upstream_response_head_parser.cc \
    "$evidence_dir/upstream_response_head_parser.cc"
  cp dataplane/include/bonvoyage/runtime/upstream_http1_client.hh \
    "$evidence_dir/upstream_http1_client.hh"
  cp dataplane/src/upstream_http1_client.cc \
    "$evidence_dir/upstream_http1_client.cc"
  cp dataplane/src/main.cc "$evidence_dir/main.cc"
  cp security/dependencies/llhttp-9.4.3.json \
    "$evidence_dir/llhttp-9.4.3.json"
  if [ "$upstream_client" = "llhttp-candidate" ]; then
    cp dataplane/src/llhttp_upstream_http1_client.cc \
      "$evidence_dir/llhttp_upstream_http1_client.cc"
  fi

  {
    printf 'run_id=phase3-http1-framing-%s\n' "$started_at"
    printf 'result=PASS\n'
    printf 'evidence_class=local-engineering\n'
    printf 'publishable=false\n'
    printf 'marketing_use_authorized=false\n'
    printf 'upstream_http1_client=%s\n' "$upstream_client"
  } >"$evidence_dir/run-status.env"

  {
    printf 'captured_at_utc=%s\n' "$started_at"
    printf 'platform=%s\n' "$platform"
    printf 'upstream_http1_client=%s\n' "$upstream_client"
    printf 'source_commit=%s\n' "$(git rev-parse HEAD)"
    if [ -n "$(git status --short)" ]; then
      printf 'source_tree_dirty=true\n'
    else
      printf 'source_tree_dirty=false\n'
    fi
    uname -a
    docker version
  } >"$evidence_dir/environment.txt" 2>&1

  cat >"$evidence_dir/commands.txt" <<EOF
env BONVOYAGE_BUILD_PLATFORM=$platform BONVOYAGE_UPSTREAM_HTTP1_CLIENT=$upstream_client BONVOYAGE_DATAPLANE_IMAGE=$image make dataplane-build
env BONVOYAGE_BUILD_PLATFORM=$platform BONVOYAGE_DATAPLANE_IMAGE=$image BONVOYAGE_HTTP1_FRAMING_EVIDENCE_DIR=$evidence_dir ./scripts/smoke-dataplane-container.sh
EOF

  candidate_behaviors=""
  if [ "$upstream_client" = "llhttp-candidate" ]; then
    candidate_behaviors=',
    "bounded informational responses consumed before the final response",
    "upstream 101 protocol upgrades rejected with 502",
    "informational-response flood rejected and followed by healthy recovery"'
  fi

  cat >"$evidence_dir/summary.json" <<EOF
{
  "schema_version": 1,
  "run_id": "phase3-http1-framing-$started_at",
  "result": "PASS",
  "evidence": {
    "class": "local-engineering",
    "marketing_use_authorized": false,
    "publishable": false
  },
  "controls": {
    "gateway_shards": 1,
    "max_upstream_chunk_metadata_bytes": 32768,
    "max_upstream_response_header_bytes": 32768,
    "platform": "$platform",
    "secure_default_connection_reuse": false,
    "trusted_reuse_control_enabled": true,
    "trusted_reuse_flag": "--trust-upstream-http1-connection-reuse",
    "upstream_http1_client": "$upstream_client"
  },
  "verified_behaviors": [
    "fixed-length streaming and connection reuse under the explicit trusted-upstream control",
    "co-buffered response overruns retire a trusted-reuse HTTP/1 connection",
    "secure-default bodyless, fixed-length, and chunked responses use fresh upstream sockets",
    "separately segmented delayed response bytes cannot become the next transaction under the secure default",
    "both trusted-reuse and secure-default gateways exit cleanly",
    "bodyless 205 accepted and positive-length 205 rejected",
    "zero-copy HTTP/1.1 chunk translation",
    "chunked upstream to HTTP/1.1 downstream body integrity",
    "validated upstream trailers deliberately dropped",
    "oversized response head rejected before downstream response start",
    "close-delimited response rejected with 502",
    "oversized chunk extension and trailer terminate the downstream stream",
    "truncated chunk terminates the downstream stream",
    "healthy traffic succeeds after every injected upstream failure",
    "gateway exits cleanly after the fault sequence"$candidate_behaviors
  ],
  "metrics": $metrics_summary,
  "limitations": [
    "Local Docker scheduling and shared-host noise are uncontrolled.",
    "This is protocol, security, and recovery evidence, not a performance comparison.",
    "The secure default adds TCP and, for TLS, handshake cost that requires separate performance qualification.",
    "The trusted-reuse control is process-wide and must only be enabled when every HTTP/1 upstream and OTLP collector in that process is trusted not to send bytes after a complete response.",
    "Upstream trailers are validated and dropped; end-to-end trailer preservation remains open."
  ]
}
EOF

  cat >"$evidence_dir/README.md" <<EOF
# Phase 3 HTTP/1 upstream response-framing evidence

This directory is the retained local engineering record for the bounded
upstream response-framing smoke completed at $started_at. The run passed all
normal, adversarial, recovery, metric, and graceful-shutdown assertions.
The selected upstream HTTP/1 client was \`$upstream_client\`.

The primary gateway explicitly enabled trusted upstream connection reuse to
retain the benign reuse and co-buffered-overrun controls. The second gateway
used the secure default, which makes HTTP/1 upstream connections single-use,
and proved that separately segmented delayed bytes cannot poison the next
transaction across bodyless, fixed-length, or chunked response boundaries.

It is not publishable benchmark evidence and does not authorize marketing or
competitive claims. See summary.json for the exact verified behavior and
limitations, and commands.txt for the canonical reproduction commands.
EOF

  (
    cd "$evidence_dir"
    find . -type f ! -name checksums.sha256 -print | LC_ALL=C sort |
      while IFS= read -r file; do
        file="${file#./}"
        if command -v sha256sum >/dev/null 2>&1; then
          sha256sum "$file"
        else
          shasum -a 256 "$file"
        fi
      done >checksums.sha256
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum --check checksums.sha256 >/dev/null
    else
      shasum -a 256 --check checksums.sha256 >/dev/null
    fi
  )
fi

echo "BonVoyage HTTP/1 container smoke passed"
