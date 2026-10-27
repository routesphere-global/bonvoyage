#!/bin/sh
# Isolated live regression. Builds only the pinned Go fixture, never the gateway.
# Usage: scripts/phase3-http2-deadline.sh [flow-control|transport|cookie|all]
set -eu
umask 077
script_dir="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
repo_root="$(CDPATH='' cd "$script_dir/.." && pwd)"
cd "$repo_root"
# shellcheck source=scripts/test-fixture-secrets.sh
. "$script_dir/test-fixture-secrets.sh"
mode="${1:-flow-control}"
case "$mode" in flow-control|transport|cookie|all) ;; *) echo "usage: $0 [flow-control|transport|cookie|all]" >&2; exit 2 ;; esac
image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
client_image="${BONVOYAGE_HTTP2_DEADLINE_CLIENT_IMAGE:-bonvoyage-http2-deadline-client:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-}"
evidence="${BONVOYAGE_HTTP2_DEADLINE_EVIDENCE_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-http2-deadline.XXXXXX")}"
mkdir -p "$evidence"
evidence="$(CDPATH='' cd "$evidence" && pwd)"
[ ! -e "$evidence/environment.txt" ] || { echo "evidence directory already used: $evidence" >&2; exit 2; }
suffix="$$"
network="bonvoyage-h2-deadline-$suffix"
volume="bonvoyage-h2-deadline-snapshot-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-h2-deadline-gateway-$suffix"
upstream="bonvoyage-h2-deadline-upstream-$suffix"
client="bonvoyage-h2-deadline-client-$suffix"
failed=0
secrets_dir=""

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}
fail() { printf '%s\n' "$*" >>"$evidence/failure.txt"; printf 'FAIL: %s\n' "$*" >&2; failed=1; }
write_checksums() {
  (
    cd "$evidence" || exit 1
    # The output manifest and its temporary file are explicitly excluded.
    # shellcheck disable=SC2094
    find . -type f ! -name checksums.sha256 ! -name checksums.sha256.tmp -print | LC_ALL=C sort | while IFS= read -r file; do
      hash_file "$file" || exit 1
    done >checksums.sha256.tmp || exit 1
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
  docker logs "$gateway" >"$evidence/gateway.log" 2>&1
  docker inspect "$gateway" >"$evidence/gateway-final.inspect.json" 2>&1
  docker logs "$upstream" >"$evidence/upstream.log" 2>&1
  docker rm --force "$client" "$gateway" "$upstream" >/dev/null 2>&1
  docker network rm "$network" >/dev/null 2>&1
  docker volume rm "$volume" >/dev/null 2>&1
  bv_remove_fixture_secrets "$secret_volume" "$secrets_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  # Keys never enter the evidence tree and are removed before hashing, on both
  # success and failure. Do not publish a manifest if secret cleanup fails.
  if [ -n "$secrets_dir" ] && ! rm -rf "$secrets_dir"; then
    fail "could not remove ephemeral secrets: $secrets_dir"
    printf 'failed=1\nexit_code=1\n' >"$evidence/run-status.env"
    exit 1
  fi
  [ "$status" -eq 0 ] || failed=1
  if [ "$status" -ne 0 ] && [ ! -f "$evidence/failure.txt" ]; then
    printf 'harness exited with status %s; see retained stage logs\n' "$status" >"$evidence/failure.txt"
  fi
  printf 'failed=%s\nexit_code=%s\n' "$failed" "$status" >"$evidence/run-status.env"
  if ! write_checksums; then
    fail "evidence checksum generation or verification failed"
    status=1
    printf 'failed=1\nexit_code=1\n' >"$evidence/run-status.env"
    write_checksums || rm -f "$evidence/checksums.sha256" "$evidence/checksums.sha256.tmp"
  fi
  printf 'HTTP/2 deadline evidence: %s\n' "$evidence"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for tool in docker openssl git; do command -v "$tool" >/dev/null 2>&1 || { fail "$tool is required"; exit 1; }; done
printf 'HTTP/2 deadline evidence: %s\n' "$evidence"
# Freeze mutable input tags before any build or concurrent parent image retag.
image_id="$(docker image inspect --format '{{.Id}}' "$image")"
compiler_id="$(docker image inspect --format '{{.Id}}' "$compiler_image")"
platform="${platform:-$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image_id")}"
compiler_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$compiler_id")"
source_status="$(git status --porcelain)"
source_dirty=false
[ -z "$source_status" ] || source_dirty=true
{
  printf 'git_commit=%s\nmode=%s\nplatform=%s\n' "$(git rev-parse HEAD)" "$mode" "$platform"
  printf 'source_dirty=%s\nworkspace_hash_manifest=source-checksums.sha256\n' "$source_dirty"
  printf 'workspace_hashes_are_image_provenance=false\nsource_image_binding=unverified\n'
  printf 'provenance_note=git_commit and source hashes describe the observed workspace, not proven build inputs of dataplane_id; concurrent workspace edits may occur\n'
  printf 'dataplane_ref=%s\ndataplane_id=%s\ncompiler_id=%s\n' "$image" "$image_id" "$compiler_id"
  printf 'client_build_skipped=%s\ngit_status_begin\n%s\ngit_status_end\n' "${BONVOYAGE_HTTP2_DEADLINE_SKIP_BUILD:-0}" "$source_status"
} >"$evidence/environment.txt"
mkdir -p "$evidence/source"
secrets_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-http2-deadline-secrets.XXXXXX")"
cp scripts/phase3-http2-deadline.sh scripts/test-fixture-secrets.sh tests/fixtures/http2-deadline/*.go tests/fixtures/http2-deadline/Dockerfile tests/fixtures/http2-deadline/Dockerfile.dockerignore "$evidence/source/"
for source in scripts/phase3-http2-deadline.sh scripts/test-fixture-secrets.sh deploy/docker/upstream/Dockerfile tests/fixtures/http2-deadline/*.go tests/fixtures/http2-deadline/Dockerfile tests/fixtures/http2-deadline/Dockerfile.dockerignore control-plane/go.mod control-plane/go.sum api/gen/go.mod api/gen/go.sum dataplane/src/gateway.cc; do
  hash_file "$source"
done >"$evidence/source-checksums.sha256"

if [ "${BONVOYAGE_HTTP2_DEADLINE_SKIP_BUILD:-0}" != 1 ]; then
  docker buildx build --platform "$platform" --load --tag "$client_image" --file tests/fixtures/http2-deadline/Dockerfile . >"$evidence/client-build.log" 2>&1
fi
client_id="$(docker image inspect --format '{{.Id}}' "$client_image")"
printf 'client_id=%s\n' "$client_id" >>"$evidence/environment.txt"
docker image inspect "$image_id" "$compiler_id" "$client_id" >"$evidence/images.inspect.json"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj /CN=api.example.test -addext subjectAltName=DNS:api.example.test \
  -keyout "$secrets_dir/server-key.pem" -out "$secrets_dir/server-chain.pem" >"$evidence/certificate.log" 2>&1
docker run --rm --platform "$platform" --network none "$client_id" -mode generate >"$evidence/fixture.yaml"
# This generated configuration contains references, never secret material.
chmod 644 "$evidence/fixture.yaml"
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  --file deploy/docker/upstream/Dockerfile deploy/docker/upstream >"$evidence/fixture-helper-build.log" 2>&1
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
bv_stage_fixture_secrets "$secret_volume" "$secrets_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem
docker run --rm --platform "$compiler_platform" --network none \
  --volume "$evidence/fixture.yaml:/fixture.yaml:ro" --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_id" -input /fixture.yaml -output /var/lib/bonvoyage/snapshot.pb >"$evidence/compiler.log" 2>&1
docker run --detach --platform "$platform" --name "$upstream" --network "$network" --network-alias upstream "$client_id" -mode upstream >/dev/null
docker run --detach --platform "$platform" --name "$gateway" --network "$network" \
  --network-alias gateway --network-alias api.example.test \
  --volume "$volume:/snapshot:ro" --volume "$secret_volume:/etc/bonvoyage/secrets:ro" \
  --env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 --env UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$image_id" --snapshot /snapshot/snapshot.pb --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 --smp 1 --memory 320M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug >/dev/null
attempt=0
bv_gateway_running "$gateway" || { fail "gateway exited before readiness"; exit 1; }
until docker run --rm --platform "$platform" --network "$network" "$client_id" -mode ready >"$evidence/readiness.log" 2>&1; do
  bv_gateway_running "$gateway" || { fail "gateway exited during readiness"; exit 1; }
  attempt=$((attempt+1))
  [ "$attempt" -lt 30 ] || { fail "gateway readiness exceeded 30 attempts"; exit 1; }
  sleep 1
done
bv_gateway_running "$gateway" || { fail "gateway exited after readiness"; exit 1; }
docker inspect "$gateway" >"$evidence/gateway-before.inspect.json"
before="$(docker inspect --format '{{.State.Pid}} {{.RestartCount}} {{.State.StartedAt}} {{.State.Running}}' "$gateway")"
printf '%s\n' "$before" >"$evidence/process-before.txt"
modes="$mode"
[ "$mode" != all ] || modes="flow-control transport"
for current in $modes; do
  mkdir -p "$evidence/$current"
  # Client cases have independent <=6s connection deadlines. Keep its container
  # identity for cleanup on interruption; JSON survives both red and green runs.
  # Bind-mounted evidence must stay readable by the non-root checksum executor.
  docker run --rm --name "$client" --platform "$platform" --network "$network" \
    --user "$(id -u):$(id -g)" \
    --volume "$secrets_dir:/secrets:ro" --volume "$evidence/$current:/evidence" \
    "$client_id" -mode "$current" >"$evidence/$current/client.json" 2>"$evidence/$current/client.stderr" \
    || fail "$current client assertions failed"
done
docker run --rm --platform "$platform" --network "$network" --user "$(id -u):$(id -g)" \
  --volume "$evidence:/evidence" "$client_id" -mode metrics \
  >"$evidence/metrics-capture.log" 2>&1 || fail "final metrics capture failed"
after="$(docker inspect --format '{{.State.Pid}} {{.RestartCount}} {{.State.StartedAt}} {{.State.Running}}' "$gateway")"
printf '%s\n' "$after" >"$evidence/process-after.txt"
[ "$before" = "$after" ] || fail "PID, restart count, start time, or running state changed"
docker inspect "$gateway" >"$evidence/gateway-after.inspect.json"
docker stop --time 10 "$gateway" >"$evidence/shutdown.txt" 2>&1 || fail "gateway stop failed"
shutdown="$(docker inspect --format '{{.State.ExitCode}}' "$gateway")"
printf 'exit_code=%s\n' "$shutdown" >>"$evidence/shutdown.txt"
[ "$shutdown" = 0 ] || fail "gateway shutdown exit code $shutdown, expected 0"
docker logs "$gateway" >"$evidence/gateway.log" 2>&1
scan_status=0
LC_ALL=C grep -Ein 'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:|heap-use-after-free|stack-use-after|double-free|SEGV|Assertion.*failed|Aborting on shard|Exceptional future ignored' "$evidence/gateway.log" >"$evidence/sanitizer-scan.txt" || scan_status=$?
case "$scan_status" in
  0) fail "gateway log contains sanitizer/assertion/unhandled-future evidence" ;;
  1) ;;
  *) fail "gateway log scan failed" ;;
esac
[ "$failed" -eq 0 ] || exit 1
printf 'HTTP/2 deadline %s passed; shutdown=0; process unchanged\n' "$mode"
