#!/bin/sh
# Native Linux-container regression for blocked HTTP/1 downstream response writes.
set -eu
umask 077

script_dir="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
repo_root="$(CDPATH='' cd "$script_dir/.." && pwd)"
cd "$repo_root"
# shellcheck source=scripts/test-fixture-secrets.sh
. "$script_dir/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-}"
iterations="${BONVOYAGE_HTTP1_SLOW_READER_ITERATIONS:-3}"
rss_growth_bound_kib="${BONVOYAGE_HTTP1_SLOW_READER_RSS_GROWTH_KIB:-16384}"
evidence="${BONVOYAGE_HTTP1_SLOW_READER_EVIDENCE_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-http1-slow-reader.XXXXXX")}"
mkdir -p "$evidence"
evidence="$(CDPATH='' cd "$evidence" && pwd)"
[ ! -e "$evidence/environment.txt" ] || {
  echo "evidence directory already used: $evidence" >&2
  exit 2
}

suffix="$$"
network="bonvoyage-h1-slow-reader-$suffix"
snapshot_volume="bonvoyage-h1-slow-reader-snapshot-$suffix"
secret_volume="${snapshot_volume}-secrets"
gateway="bonvoyage-h1-slow-reader-gateway-$suffix"
upstream="bonvoyage-h1-slow-reader-upstream-$suffix"
client="bonvoyage-h1-slow-reader-client-$suffix"
secrets_dir=""
failed=0
network_created=false
snapshot_created=false
secrets_staged=false
upstream_started=false
gateway_started=false

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

fail() {
  printf '%s\n' "$*" >>"$evidence/failure.txt"
  printf 'FAIL: %s\n' "$*" >&2
  failed=1
}

write_checksums() {
  (
    cd "$evidence" || exit 1
    # The temporary manifest is explicitly excluded and then atomically renamed.
    # shellcheck disable=SC2094
    find . -type f ! -name checksums.sha256 ! -name checksums.sha256.tmp -print \
      | LC_ALL=C sort \
      | while IFS= read -r file; do hash_file "$file" || exit 1; done \
      >checksums.sha256.tmp || exit 1
    mv checksums.sha256.tmp checksums.sha256 || exit 1
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum --check checksums.sha256 >/dev/null
    else
      shasum -a 256 --check checksums.sha256 >/dev/null
    fi
  )
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  if [ "$gateway_started" = true ]; then
    docker logs "$gateway" >"$evidence/gateway.log" 2>&1
    docker inspect "$gateway" >"$evidence/gateway-final.inspect.json" 2>&1
  fi
  if [ "$upstream_started" = true ]; then
    docker logs "$upstream" >"$evidence/upstream.log" 2>&1
  fi
  docker rm --force "$client" "$gateway" "$upstream" >/dev/null 2>&1
  if [ "$network_created" = true ]; then
    docker network rm "$network" >/dev/null 2>&1
  fi
  if [ "$snapshot_created" = true ]; then
    docker volume rm "$snapshot_volume" >/dev/null 2>&1
  fi
  if [ "$secrets_staged" = true ]; then
    bv_remove_fixture_secrets "$secret_volume" "$secrets_dir" >/dev/null 2>&1 || {
      echo "private fixture volume cleanup failed: $secret_volume" >&2
      [ "$status" -ne 0 ] || status=1
    }
  fi
  if [ -n "$secrets_dir" ] && ! rm -rf "$secrets_dir"; then
    fail "could not remove ephemeral secrets: $secrets_dir"
    status=1
  fi
  [ "$status" -eq 0 ] || failed=1
  if [ "$status" -ne 0 ] && [ ! -f "$evidence/failure.txt" ]; then
    printf 'gate exited with status %s; see retained evidence\n' "$status" \
      >"$evidence/failure.txt"
  fi
  printf 'failed=%s\nexit_code=%s\n' "$failed" "$status" \
    >"$evidence/run-status.env"
  if ! write_checksums; then
    fail "evidence checksum generation or verification failed"
    status=1
    printf 'failed=1\nexit_code=1\n' >"$evidence/run-status.env"
    write_checksums || rm -f "$evidence/checksums.sha256" \
      "$evidence/checksums.sha256.tmp"
  fi
  printf 'HTTP/1 slow-reader evidence: %s\n' "$evidence"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for tool in docker openssl git python3; do
  command -v "$tool" >/dev/null 2>&1 || {
    fail "$tool is required"
    exit 1
  }
done
case "$iterations:$rss_growth_bound_kib" in
  *[!0-9:]*|0:*|*:0|:|*:) fail "iterations and RSS growth bound must be positive integers"; exit 2 ;;
esac

printf 'HTTP/1 slow-reader evidence: %s\n' "$evidence"
image_id="$(docker image inspect --format '{{.Id}}' "$image")"
compiler_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")"
platform="${platform:-$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image_id")}" 
compiler_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$compiler_id")"
source_status="$(git status --porcelain)"
source_dirty=false
[ -z "$source_status" ] || source_dirty=true
{
  printf 'git_commit=%s\nplatform=%s\n' "$(git rev-parse HEAD)" "$platform"
  printf 'source_dirty=%s\n' "$source_dirty"
  printf 'dataplane_ref=%s\ndataplane_id=%s\ncompiler_id=%s\n' \
    "$image" "$image_id" "$compiler_id"
  printf 'request_timeout_ms=400\nrelease_bound_ms=2000\n'
  printf 'iterations_per_protocol=%s\nrss_growth_bound_kib=%s\n' \
    "$iterations" "$rss_growth_bound_kib"
  printf 'response_bytes=33554432\nsource_image_binding=unverified\n'
  printf 'git_status_begin\n%s\ngit_status_end\n' "$source_status"
} >"$evidence/environment.txt"

mkdir -p "$evidence/source"
cp scripts/phase5-http1-slow-reader.sh \
  scripts/phase5-http1-slow-reader-client.py \
  scripts/test-fixture-secrets.sh \
  tests/fixtures/phase5-http1-slow-reader.yaml \
  deploy/docker/upstream/server.py \
  "$evidence/source/"
for source in \
  scripts/phase5-http1-slow-reader.sh \
  scripts/phase5-http1-slow-reader-client.py \
  scripts/test-fixture-secrets.sh \
  tests/fixtures/phase5-http1-slow-reader.yaml \
  deploy/docker/upstream/server.py \
  dataplane/src/gateway.cc; do
  hash_file "$source"
done >"$evidence/source-checksums.sha256"

secrets_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-http1-slow-reader-secrets.XXXXXX")"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj /CN=api.example.test -addext subjectAltName=DNS:api.example.test \
  -keyout "$secrets_dir/server-key.pem" \
  -out "$secrets_dir/server-chain.pem" >"$evidence/certificate.log" 2>&1
chmod 0600 "$secrets_dir/server-key.pem"
chmod 0644 "$secrets_dir/server-chain.pem"

docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream \
  >"$evidence/upstream-build.log" 2>&1
upstream_id="$(docker image inspect --format '{{.Id}}' "$upstream_image")"
printf 'upstream_id=%s\n' "$upstream_id" >>"$evidence/environment.txt"
docker image inspect "$image_id" "$compiler_id" "$upstream_id" \
  >"$evidence/images.inspect.json"

docker network create "$network" >/dev/null
network_created=true
docker volume create "$snapshot_volume" >/dev/null
snapshot_created=true
bv_stage_fixture_secrets "$secret_volume" "$secrets_dir" "$upstream_image" \
  "$platform" server-chain.pem server-key.pem
secrets_staged=true
docker run --rm --platform "$compiler_platform" --network none \
  --volume "$repo_root/tests/fixtures/phase5-http1-slow-reader.yaml:/fixture.yaml:ro" \
  --volume "$snapshot_volume:/var/lib/bonvoyage" \
  "$compiler_id" -input /fixture.yaml \
  -output /var/lib/bonvoyage/snapshot.pb >"$evidence/compiler.log" 2>&1

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream "$upstream_id" >/dev/null
upstream_started=true
docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias gateway \
  --volume "$snapshot_volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  --env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
  --env UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$image_id" --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 384M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null
gateway_started=true

attempt=0
until docker run --rm --platform "$platform" --network "$network" \
  --entrypoint python "$upstream_id" -c \
  'import urllib.request; urllib.request.urlopen("http://gateway:9901/health/ready", timeout=2).read()' \
  >"$evidence/readiness.log" 2>&1; do
  docker inspect --format '{{.State.Running}}' "$gateway" | grep -Fxq true || {
    fail "gateway exited during readiness"
    exit 1
  }
  attempt=$((attempt + 1))
  [ "$attempt" -lt 30 ] || {
    fail "gateway readiness exceeded 30 attempts"
    exit 1
  }
  sleep 1
done

# Establish the persistent upstream connection before resource baselining.
docker run --rm --platform "$platform" --network "$network" \
  --entrypoint python "$upstream_id" -c \
  'import http.client; c=http.client.HTTPConnection("gateway",8080,timeout=2); c.request("GET","/healthz",headers={"Host":"api.example.test"}); r=c.getresponse(); assert r.status == 200 and r.read() == b"ok\n"; c.close()' \
  >"$evidence/warmup.log" 2>&1

capture_resources() {
  docker run --rm --platform "$platform" --pid "container:$gateway" \
    --entrypoint python "$upstream_id" -c \
    'import os; fields={};
for line in open("/proc/1/status", encoding="ascii"):
 key, _, value=line.partition(":")
 if key in ("VmRSS","VmHWM","Threads"): fields[key]=value.strip()
print("fd_count=" + str(len(os.listdir("/proc/1/fd"))))
for key in ("VmRSS","VmHWM","Threads"): print(key.lower()+"="+fields.get(key,"missing"))'
}

docker inspect --format '{{.State.Pid}} {{.RestartCount}} {{.State.StartedAt}} {{.State.Running}}' \
  "$gateway" >"$evidence/process-before.txt"
capture_resources >"$evidence/resources-before.txt"

for protocol in plain tls; do
  case "$protocol" in
    plain) address=gateway:8080 ;;
    tls) address=gateway:8443 ;;
  esac
  mkdir -p "$evidence/$protocol"
  iteration=1
  while [ "$iteration" -le "$iterations" ]; do
    docker run --rm --name "$client" --platform "$platform" \
      --network "$network" --user "$(id -u):$(id -g)" \
      --volume "$repo_root/scripts/phase5-http1-slow-reader-client.py:/client.py:ro" \
      --volume "$secrets_dir/server-chain.pem:/secrets/ca.pem:ro" \
      --entrypoint python "$upstream_id" /client.py \
      --protocol "$protocol" --address "$address" --ca /secrets/ca.pem \
      >"$evidence/$protocol/client-$iteration.json" \
      2>"$evidence/$protocol/client-$iteration.stderr" \
      || fail "$protocol slow-reader assertions failed in iteration $iteration"
    iteration=$((iteration + 1))
  done
done

docker inspect --format '{{.State.Pid}} {{.RestartCount}} {{.State.StartedAt}} {{.State.Running}}' \
  "$gateway" >"$evidence/process-after.txt"
capture_resources >"$evidence/resources-after.txt"
cmp -s "$evidence/process-before.txt" "$evidence/process-after.txt" \
  || fail "gateway PID, restart count, start time, or running state changed"

before_fds="$(sed -n 's/^fd_count=//p' "$evidence/resources-before.txt")"
after_fds="$(sed -n 's/^fd_count=//p' "$evidence/resources-after.txt")"
case "$before_fds:$after_fds" in
  *[!0-9:]*|:|*:) fail "could not parse gateway descriptor counts" ;;
  *) [ "$after_fds" -le "$before_fds" ] \
       || fail "gateway descriptors grew from $before_fds to $after_fds" ;;
esac
before_rss="$(sed -n 's/^vmrss=\([0-9][0-9]*\) kB$/\1/p' "$evidence/resources-before.txt")"
after_rss="$(sed -n 's/^vmrss=\([0-9][0-9]*\) kB$/\1/p' "$evidence/resources-after.txt")"
case "$before_rss:$after_rss" in
  *[!0-9:]*|:|*:) fail "could not parse gateway RSS values" ;;
  *) [ "$after_rss" -le $((before_rss + rss_growth_bound_kib)) ] \
       || fail "gateway RSS grew from $before_rss to $after_rss KiB" ;;
esac

docker stop --timeout 10 "$gateway" >"$evidence/shutdown.txt" 2>&1 \
  || fail "gateway stop failed"
shutdown="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
printf 'exit_code=%s\n' "$shutdown" >>"$evidence/shutdown.txt"
[ "$shutdown" = 0 ] || fail "gateway shutdown exit code $shutdown, expected 0"
docker logs "$gateway" >"$evidence/gateway.log" 2>&1
scan_status=0
LC_ALL=C grep -Ein \
  'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:|heap-use-after-free|stack-use-after|double-free|SEGV|Assertion.*failed|Aborting on shard|Exceptional future ignored' \
  "$evidence/gateway.log" >"$evidence/sanitizer-scan.txt" || scan_status=$?
case "$scan_status" in
  0) fail "gateway log contains sanitizer/assertion/unhandled-future evidence" ;;
  1) ;;
  *) fail "gateway log scan failed" ;;
esac

[ "$failed" -eq 0 ] || exit 1
printf 'HTTP/1 plaintext and TLS slow-reader release passed; process unchanged; shutdown=0\n'
