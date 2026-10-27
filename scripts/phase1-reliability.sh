#!/bin/sh
set -eu

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
soak_seconds="${BONVOYAGE_SOAK_SECONDS:-60}"
suffix="$$"
network="bonvoyage-reliability-$suffix"
volume="bonvoyage-reliability-snapshot-$suffix"
gateway="bonvoyage-reliability-gateway-$suffix"
upstream="bonvoyage-reliability-upstream-$suffix"

cleanup() {
  status="$?"
  if [ "$status" -ne 0 ] && docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >&2 || true
    docker logs "$upstream" >&2 || true
  fi
  docker rm --force "$gateway" "$upstream" >/dev/null 2>&1 || true
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
  --volume "$PWD/tests/fixtures/phase1-reliability.yaml:/etc/bonvoyage/config.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" "$compiler_image" \
  -input /etc/bonvoyage/config.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >/dev/null
docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream "$upstream_image" >/dev/null

attempt=0
until docker exec "$upstream" python -c \
  'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8081/healthz", timeout=2).status == 200' \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  test "$attempt" -lt 30 || exit 1
  sleep 1
done

docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --volume "$volume:/etc/bonvoyage:ro" "$image" \
  --snapshot /etc/bonvoyage/snapshot.pb \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null

attempt=0
until docker exec "$upstream" python -c \
  'import urllib.request; assert urllib.request.urlopen("http://bonvoyage-reliability-gateway-'"$suffix"':9901/health/ready", timeout=2).status == 200' \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    docker logs "$gateway"
    exit 1
  fi
  sleep 1
done

# One active upstream request and one waiter are admitted; excess work is rejected.
docker exec "$upstream" python -c '
import concurrent.futures
import http.client

host = "bonvoyage-reliability-gateway-'"$suffix"'"
def request():
    connection = http.client.HTTPConnection(host, 8080, timeout=15)
    connection.request("GET", "/slow/500", headers={"Host": "example.test"})
    response = connection.getresponse()
    status = response.status
    response.read()
    connection.close()
    return status

with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
    statuses = list(executor.map(lambda _: request(), range(8)))
assert statuses.count(200) == 2, statuses
assert statuses.count(503) == 6, statuses

connection = http.client.HTTPConnection(host, 8080, timeout=15)
connection.request("GET", "/payload/16", headers={"Host": "example.test"})
response = connection.getresponse()
assert response.status == 200 and len(response.read()) == 16
connection.close()
'

# Idle downstream sockets are capped per shard, rejected, and then reclaimed.
docker exec "$upstream" python -c '
import re
import socket
import time
import urllib.request

host = "bonvoyage-reliability-gateway-'"$suffix"'"
sockets = [socket.create_connection((host, 8080), timeout=10) for _ in range(12)]
time.sleep(1)
metrics = urllib.request.urlopen("http://%s:9090/metrics" % host, timeout=10).read().decode()
rejected = re.search(r"downstream_connection_rejections_total[^\n]* (\d+)", metrics)
active = re.search(r"active_connections[^\n]* (\d+)", metrics)
assert rejected and int(rejected.group(1)) >= 4, metrics
assert active and int(active.group(1)) <= 8, metrics
for connection in sockets:
    connection.close()
time.sleep(4)
'

rss_before="$(docker stats --no-stream --format '{{.MemUsage}}' "$gateway" | cut -d/ -f1 | tr -d ' ')"
docker exec "$upstream" python -c '
import http.client
import time

host = "bonvoyage-reliability-gateway-'"$suffix"'"
deadline = time.monotonic() + float("'"$soak_seconds"'")
requests = 0
connection = http.client.HTTPConnection(host, 8080, timeout=15)
while time.monotonic() < deadline:
    connection.request("GET", "/payload/256", headers={"Host": "example.test"})
    response = connection.getresponse()
    assert response.status == 200 and len(response.read()) == 256
    requests += 1
connection.close()
print("soak_requests=%d" % requests)
'
rss_after="$(docker stats --no-stream --format '{{.MemUsage}}' "$gateway" | cut -d/ -f1 | tr -d ' ')"

docker stop --signal TERM --time 10 "$gateway" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$gateway")" -eq 0
printf 'rss_before=%s\nrss_after=%s\n' "$rss_before" "$rss_after"
echo "BonVoyage Phase 1 overload, connection-bound, recovery, and soak checks passed"
