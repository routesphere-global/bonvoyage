#!/bin/sh
set -eu

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

umask 077

gateway_image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
helper_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="${BONVOYAGE_PERF05_TLS_BOUNDARY_EVIDENCE_DIR:-${TMPDIR:-/tmp}/bonvoyage-perf05-tls-boundary-$stamp}"
suffix="$$"
network="bonvoyage-perf05-tls-boundary-$suffix"
snapshot_volume="bonvoyage-perf05-tls-boundary-snapshot-$suffix"
secret_volume="bonvoyage-perf05-tls-boundary-secrets-$suffix"
gateway="bonvoyage-perf05-tls-boundary-gateway-$suffix"
upstream="bonvoyage-perf05-tls-boundary-upstream-$suffix"
client="bonvoyage-perf05-tls-boundary-client-$suffix"
fixture="$PWD/tests/fixtures/perf05-tls-boundary/fixture.py"
rss_growth_bound_kib=16384
fd_growth_bound=4
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-perf05-tls-boundary.XXXXXX")"
failed=0
evidence_created=0
secrets_staged=0

fail() {
  printf 'PERF-05 TLS boundary preflight: %s\n' "$*" >&2
  failed=1
}

capture_resources() {
  docker run --rm --platform "$platform" --pid "container:$gateway" \
    --network none --read-only --security-opt no-new-privileges:true \
    --cap-drop ALL --user 65532:65532 --entrypoint python "$helper_id" -c \
    'import os
fields = {}
for line in open("/proc/1/status", encoding="ascii"):
    key, _, value = line.partition(":")
    if key in ("VmRSS", "VmHWM", "Threads"):
        fields[key] = value.strip()
print("fd_count=" + str(len(os.listdir("/proc/1/fd"))))
for key in ("VmRSS", "VmHWM", "Threads"):
    print(key.lower() + "=" + fields.get(key, "missing"))'
}

write_checksums() {
  (
    cd "$evidence"
    # Both output names are excluded, so the pipeline cannot consume its output.
    # shellcheck disable=SC2094
    find . -type f ! -name checksums.sha256 ! -name checksums.sha256.tmp -print |
      LC_ALL=C sort |
      while IFS= read -r file; do shasum -a 256 "$file"; done \
        >checksums.sha256.tmp
    mv checksums.sha256.tmp checksums.sha256
    shasum -a 256 -c checksums.sha256 >/dev/null
  )
}

cleanup() {
  status="$?"
  trap - EXIT INT TERM
  if [ "$evidence_created" -eq 1 ] && docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >"$evidence/gateway-cleanup.log" 2>&1 || true
  fi
  if [ "$evidence_created" -eq 1 ] && docker inspect "$upstream" >/dev/null 2>&1; then
    docker logs "$upstream" >"$evidence/upstream-cleanup.log" 2>&1 || true
  fi
  docker rm --force "$client" "$gateway" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$snapshot_volume" >/dev/null 2>&1 || true
  if [ "$secrets_staged" -eq 1 ]; then
    if ! bv_remove_fixture_secrets "$secret_volume" "$work_dir" >/dev/null 2>&1; then
      fail "private fixture volume cleanup failed: $secret_volume"
    fi
  else
    docker volume rm "$secret_volume" >/dev/null 2>&1 || true
  fi
  if ! rm -rf "$work_dir"; then
    fail "could not remove ephemeral TLS workspace"
  fi
  [ "$status" -eq 0 ] || failed=1
  if [ "$evidence_created" -ne 1 ]; then
    [ "$failed" -eq 0 ] && exit "$status"
    exit 1
  fi
  if [ "$failed" -eq 0 ]; then
    printf 'preflight-pass\n' >"$evidence/decision.txt"
  else
    printf 'investigate\n' >"$evidence/decision.txt"
  fi
  printf 'failed=%s\nexit_code=%s\n' "$failed" "$status" >"$evidence/run-status.env"
  if ! write_checksums; then
    fail "evidence checksum generation or verification failed"
    printf 'failed=1\nexit_code=1\n' >"$evidence/run-status.env"
    status=1
  fi
  printf 'PERF-05 TLS boundary evidence: %s\n' "$evidence"
  if [ "$failed" -ne 0 ]; then
    exit 1
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for tool in docker openssl git shasum; do
  command -v "$tool" >/dev/null 2>&1 || {
    fail "$tool is required"
    exit 1
  }
done

if [ -e "$evidence" ]; then
  fail "evidence directory already exists: $evidence"
  exit 1
fi
mkdir -p "$evidence/source"
evidence_created=1

git status --porcelain=v1 --untracked-files=all >"$evidence/source-status-before.txt"
source_dirty=false
if [ -s "$evidence/source-status-before.txt" ]; then
  source_dirty=true
fi
source_commit="$(git rev-parse HEAD)"

gateway_id="$(docker image inspect --format '{{.Id}}' "$gateway_image")"
compiler_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")"
helper_id="$(docker image inspect --format '{{.Id}}' "$helper_image")"
for item in "$gateway_id" "$compiler_id" "$helper_id"; do
  observed_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$item")"
  if [ "$observed_platform" != "$platform" ]; then
    fail "image $item is $observed_platform, expected $platform"
    exit 1
  fi
done

{
  printf 'schema_version=1\nprofile=P5-T01\n'
  printf 'source_commit=%s\nsource_dirty=%s\n' "$source_commit" "$source_dirty"
  printf 'platform=%s\npublication_authorized=false\n' "$platform"
  printf 'gateway_image=%s\ngateway_id=%s\n' "$gateway_image" "$gateway_id"
  printf 'compiler_image=%s\ncompiler_id=%s\n' "$compiler_image" "$compiler_id"
  printf 'helper_image=%s\nhelper_id=%s\n' "$helper_image" "$helper_id"
  printf 'evidence_class=local-docker-development-preflight\n'
} >"$evidence/environment.env"

for source in \
  Makefile \
  deploy/docker/upstream/server.py \
  scripts/phase5-tls-boundary-preflight.sh \
  scripts/test-fixture-secrets.sh \
  tests/fixtures/perf05-tls-boundary/fixture.py \
  tests/fixtures/perf05-tls-boundary/test_fixture.py \
  benchmarks/workloads/protocol-streaming/phase5-protocol-streaming.json; do
  shasum -a 256 "$source"
done >"$evidence/source-checksums.sha256"
cp scripts/phase5-tls-boundary-preflight.sh \
  tests/fixtures/perf05-tls-boundary/fixture.py \
  tests/fixtures/perf05-tls-boundary/test_fixture.py "$evidence/source/"

docker image inspect "$gateway_id" "$compiler_id" "$helper_id" \
  >"$evidence/images.inspect.json"

docker run --rm --platform "$platform" --network none --read-only \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --volume "$fixture:/fixture.py:ro" --entrypoint python "$helper_id" \
  /fixture.py render-config >"$work_dir/config.json"
cp "$work_dir/config.json" "$evidence/generated-config.json"
(
  cd "$evidence"
  shasum -a 256 generated-config.json >generated-config.sha256
  shasum -a 256 -c generated-config.sha256 >/dev/null
)

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj '/CN=BonVoyage PERF-05 Test CA' \
  -keyout "$work_dir/ca-key.pem" -out "$work_dir/ca.pem" \
  >"$evidence/ca-generation.log" 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=api.example.test' \
  -keyout "$work_dir/server-key.pem" -out "$work_dir/server.csr" \
  >"$evidence/server-csr.log" 2>&1
printf '%s\n' \
  'subjectAltName=DNS:api.example.test' \
  'extendedKeyUsage=serverAuth' \
  'keyUsage=digitalSignature,keyEncipherment' >"$work_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$work_dir/server.csr" \
  -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca-key.pem" -CAcreateserial \
  -extfile "$work_dir/server-ext.cnf" -out "$work_dir/server-chain.pem" \
  >"$evidence/server-certificate.log" 2>&1
chmod 600 "$work_dir"/*-key.pem
openssl x509 -in "$work_dir/ca.pem" -noout -fingerprint -sha256 \
  >"$evidence/ca-fingerprint.txt"
openssl x509 -in "$work_dir/server-chain.pem" -noout -fingerprint -sha256 \
  >"$evidence/server-fingerprint.txt"

docker network create "$network" >/dev/null
docker volume create "$snapshot_volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$work_dir" \
  "$helper_image" "$platform" ca.pem server-chain.pem server-key.pem
secrets_staged=1

docker run --rm --platform "$platform" --network none \
  --volume "$work_dir/config.json:/fixture.json:ro" \
  --volume "$snapshot_volume:/var/lib/bonvoyage" \
  "$compiler_id" -input /fixture.json -output /var/lib/bonvoyage/snapshot.pb \
  >"$evidence/compiler.log" 2>&1

docker run --detach --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream \
  "$helper_id" >"$evidence/upstream-container.txt"

upstream_ready=0
attempt=0
while [ "$attempt" -lt 30 ]; do
  if docker run --rm --platform "$platform" --network "$network" --read-only \
      --security-opt no-new-privileges:true --cap-drop ALL \
      --volume "$fixture:/fixture.py:ro" --entrypoint python "$helper_id" \
      /fixture.py ready --url http://upstream:8081/healthz >/dev/null 2>&1; then
    upstream_ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$upstream_ready" -ne 1 ]; then
  fail "controlled upstream did not become ready"
  exit 1
fi

docker run --detach --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias gateway --network-alias api.example.test \
  --volume "$snapshot_volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  "$gateway_id" --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 512M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug \
  >"$evidence/gateway-container.txt"

gateway_ready=0
attempt=0
while [ "$attempt" -lt 30 ]; do
  bv_gateway_running "$gateway" || exit 1
  if docker run --rm --platform "$platform" --network "$network" --read-only \
      --security-opt no-new-privileges:true --cap-drop ALL \
      --volume "$fixture:/fixture.py:ro" --entrypoint python "$helper_id" \
      /fixture.py ready --url "http://$gateway:9901/health/ready" >/dev/null 2>&1; then
    gateway_ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$gateway_ready" -ne 1 ]; then
  fail "gateway did not become ready"
  exit 1
fi

docker inspect "$gateway" >"$evidence/gateway-before.inspect.json"
before="$(docker inspect --format \
  '{{.State.Pid}} {{.RestartCount}} {{.State.StartedAt}} {{.State.Running}}' "$gateway")"
printf '%s\n' "$before" >"$evidence/process-before.txt"
capture_resources >"$evidence/resources-before.txt"

set +e
docker run --rm --name "$client" --platform "$platform" --network "$network" \
  --read-only --security-opt no-new-privileges:true --cap-drop ALL \
  --user 65532:65532 \
  --volume "$fixture:/fixture.py:ro" --volume "$secret_volume:/secrets:ro" \
  --entrypoint python "$helper_id" /fixture.py client \
  >"$evidence/client.json" 2>"$evidence/client.stderr"
client_status="$?"
set -e
printf 'exit_code=%s\n' "$client_status" >"$evidence/client-status.env"
if [ "$client_status" -ne 0 ]; then
  fail "controlled TLS boundary assertions failed"
fi

if ! docker run --rm --platform "$platform" --network "$network" --read-only \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --volume "$fixture:/fixture.py:ro" --entrypoint python "$helper_id" \
    /fixture.py metrics --url http://gateway:9090/metrics \
    >"$evidence/final-metrics.txt" 2>&1; then
  fail "final gateway metrics were not drained"
fi
capture_resources >"$evidence/resources-after.txt"

before_fds="$(sed -n 's/^fd_count=//p' "$evidence/resources-before.txt")"
after_fds="$(sed -n 's/^fd_count=//p' "$evidence/resources-after.txt")"
case "$before_fds:$after_fds" in
  *[!0-9:]*|:|*:) fail "could not parse gateway descriptor counts" ;;
  *)
    if [ "$after_fds" -gt $((before_fds + fd_growth_bound)) ]; then
      fail "gateway descriptors grew from $before_fds to $after_fds"
    fi
    ;;
esac
before_rss="$(sed -n 's/^vmrss=\([0-9][0-9]*\) kB$/\1/p' "$evidence/resources-before.txt")"
after_rss="$(sed -n 's/^vmrss=\([0-9][0-9]*\) kB$/\1/p' "$evidence/resources-after.txt")"
case "$before_rss:$after_rss" in
  *[!0-9:]*|:|*:) fail "could not parse gateway RSS values" ;;
  *)
    if [ "$after_rss" -gt $((before_rss + rss_growth_bound_kib)) ]; then
      fail "gateway RSS grew from $before_rss to $after_rss KiB"
    fi
    ;;
esac

after="$(docker inspect --format \
  '{{.State.Pid}} {{.RestartCount}} {{.State.StartedAt}} {{.State.Running}}' "$gateway")"
printf '%s\n' "$after" >"$evidence/process-after.txt"
if [ "$before" != "$after" ]; then
  fail "gateway PID, restart count, start time, or running state changed"
fi
docker inspect "$gateway" >"$evidence/gateway-after.inspect.json"

docker stop --timeout 10 "$gateway" >"$evidence/shutdown.txt" 2>&1 || fail "gateway stop failed"
exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
printf 'exit_code=%s\n' "$exit_code" >>"$evidence/shutdown.txt"
if [ "$exit_code" != 0 ]; then
  fail "gateway shutdown exit code was $exit_code"
fi
docker logs "$gateway" >"$evidence/gateway.log" 2>&1
docker logs "$upstream" >"$evidence/upstream.log" 2>&1

for size in 15360 16384 17408 65536; do
  hits="$(grep -c "GET /payload/$size HTTP/1.1.* 200 " "$evidence/upstream.log" || true)"
  if [ "$hits" -ne 1 ]; then
    fail "expected one controlled upstream payload/$size request, observed $hits"
  fi
done
if grep -q '/perf05/fixed/' "$evidence/upstream.log"; then
  fail "a fixed response reached the controlled upstream"
fi

scan_status=0
LC_ALL=C grep -Ein \
  'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:|heap-use-after-free|stack-use-after|double-free|SEGV|Assertion.*failed|Aborting on shard|Exceptional future ignored' \
  "$evidence/gateway.log" >"$evidence/runtime-diagnostic-scan.txt" || scan_status="$?"
case "$scan_status" in
  0) fail "gateway log contains fatal runtime diagnostics" ;;
  1) ;;
  *) fail "gateway log scan failed" ;;
esac

git status --porcelain=v1 --untracked-files=all >"$evidence/source-status-after.txt"
if ! cmp -s "$evidence/source-status-before.txt" "$evidence/source-status-after.txt"; then
  fail "source state changed during the preflight"
fi

find "$evidence" -type f -print | LC_ALL=C sort >"$evidence/file-inventory.txt"
if find "$evidence" -type f \( -name '*key*' -o -name '*.pem' \) -print |
    grep . >"$evidence/forbidden-secret-files.txt"; then
  fail "evidence contains a private-key or PEM-shaped file"
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi
printf 'PERF-05 TLS boundary local preflight passed; source_dirty=%s\n' "$source_dirty"
