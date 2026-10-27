#!/bin/sh
set -eu
umask 077
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
output="${BONVOYAGE_ACCEPT_RECOVERY_EVIDENCE_DIR:-$repo_root/build/evidence/accept-recovery-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
case "$output" in /*) ;; *) output="$repo_root/$output" ;; esac
mkdir -p "${output%/*}"
suffix="$$"
network="bonvoyage-accept-test-$suffix"
volume="bonvoyage-accept-test-$suffix"
gateway="bonvoyage-accept-gateway-$suffix"
upstream="bonvoyage-accept-upstream-$suffix"
mkdir "$output"
git rev-parse HEAD >"$output/source-commit.txt"
git status --short >"$output/source-state.txt"
docker image inspect "$image" >"$output/runtime-image.inspect.json"
cleanup() {
  status=$?
  docker logs "$gateway" >"$output/gateway.log" 2>&1 || true
  docker inspect "$gateway" >"$output/gateway.inspect.json" 2>/dev/null || true
  docker rm -f "$gateway" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  printf '%s\n' "$status" >"$output/exit-code"
}
trap cleanup EXIT
docker network create --internal "$network" >/dev/null
docker volume create "$volume" >/dev/null
docker run --rm --platform "$platform" --network none -v "$PWD/config/examples/local.yaml:/input.yaml:ro" -v "$volume:/var/lib/bonvoyage" "$compiler_image" -input /input.yaml -output /var/lib/bonvoyage/snapshot.pb >"$output/compiler.log"
docker run -d --platform "$platform" --name "$upstream" --network "$network" --network-alias upstream "$upstream_image" >/dev/null
docker run -d --platform "$platform" --name "$gateway" --network "$network" --network-alias gateway --dns-search . --ulimit nofile=128:128 -v "$volume:/snapshot:ro" "$image" --snapshot /snapshot/snapshot.pb --admin-address 0.0.0.0 --metrics-address 0.0.0.0 --smp 1 --memory 256M --runtime-log-transport stderr-pipe --overprovisioned >/dev/null
docker inspect "$gateway" --format '{{.State.StartedAt}}' >"$output/started-before.txt"
docker exec "$upstream" python -c '
import http.client, json, socket, time
def request():
    c=http.client.HTTPConnection("gateway",8080,timeout=1)
    try:
        c.request("GET","/bonvoyage/ready")
        r=c.getresponse()
        assert r.status==200 and r.read()==b"ready\n"
    finally:
        c.close()
for attempt in range(30):
    try:
        request()
        break
    except (OSError, http.client.HTTPException):
        if attempt==29: raise
        time.sleep(0.1)
sockets=[]
for _ in range(256):
    try: sockets.append(socket.create_connection(("gateway",8080),timeout=0.1))
    except OSError: break
assert len(sockets)>=128, len(sockets)
time.sleep(1)
for connection in sockets: connection.close()
for attempt in range(10):
    try:
        request()
        break
    except (OSError,http.client.HTTPException):
        if attempt==9: raise
        time.sleep(0.1)
for _ in range(10): request()
print(json.dumps({"opened_connections":len(sockets),"recovery_requests":11,"result":"PASS"}))
' >"$output/client.json" 2>"$output/client.stderr"
docker inspect "$gateway" --format '{{.State.StartedAt}}' >"$output/started-after.txt"
cmp "$output/started-before.txt" "$output/started-after.txt"
test "$(docker inspect "$gateway" --format '{{.RestartCount}}')" = 0
docker logs "$gateway" >"$output/gateway.log" 2>&1
grep -q 'listener accept resource exhaustion' "$output/gateway.log"
grep -q 'listener accept recovered' "$output/gateway.log"
docker stop --timeout 10 "$gateway" >/dev/null
test "$(docker inspect "$gateway" --format '{{.State.ExitCode}}')" = 0
