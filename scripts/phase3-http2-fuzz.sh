#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

jobs="${BONVOYAGE_BUILD_JOBS:-2}"
seconds="${BONVOYAGE_HTTP2_FUZZ_SECONDS:-30}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${BONVOYAGE_HTTP2_FUZZ_EVIDENCE_DIR:-$repo_root/build/evidence/phase3-http2-fuzz/$timestamp}"

# Capture provenance before creating an in-repository evidence directory. Otherwise
# the harness records its own output as an untracked source change.
source_status="$(git status --porcelain=v1 --untracked-files=all)"
source_dirty=false
[ -z "$source_status" ] || source_dirty=true

case "$jobs" in
  ''|*[!0-9]*)
    echo "BONVOYAGE_BUILD_JOBS must be a positive integer" >&2
    exit 2
    ;;
esac
case "$seconds" in
  ''|*[!0-9]*)
    echo "BONVOYAGE_HTTP2_FUZZ_SECONDS must be an integer" >&2
    exit 2
    ;;
esac
if [ "$jobs" -lt 1 ] || [ "$seconds" -lt 1 ] || [ "$seconds" -gt 600 ]; then
  echo "build jobs must be positive and fuzz seconds must be 1..600" >&2
  exit 2
fi

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() {
    sha256sum "$1" | awk '{print $1}'
  }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() {
    shasum -a 256 "$1" | awk '{print $1}'
  }
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi

if [ -e "$evidence_dir" ] || [ -L "$evidence_dir" ]; then
  echo "fuzz evidence directory already exists: $evidence_dir" >&2
  exit 2
fi
mkdir -p "$evidence_dir"
# Docker bind mounts require an absolute host path, including RC-derived paths.
evidence_dir="$(CDPATH='' cd -- "$evidence_dir" && pwd -P)"

{
  printf '%s\n' \
    deploy/docker/bonvoyage/Dockerfile \
    deploy/docker/bonvoyage/patches/nghttp2-rfc9113-stream-errors.patch \
    security/dependencies/nghttp2-1.70.0.json \
    security/dependencies/llhttp-9.4.3.json
} | LC_ALL=C sort -u > "$evidence_dir/dependency-source-files.txt"

while IFS= read -r source_file; do
  test -f "$source_file"
  printf '%s  %s\n' "$(hash_file "$source_file")" "$source_file"
done < "$evidence_dir/dependency-source-files.txt" \
  > "$evidence_dir/dependency-source-SHA256SUMS"

dependency_key="$(hash_file "$evidence_dir/dependency-source-SHA256SUMS")"
short_dependency_key="$(printf '%s' "$dependency_key" | cut -c1-16)"

{
  cat "$evidence_dir/dependency-source-files.txt"
  find dataplane/include dataplane/fuzz -type f -print
  printf '%s\n' \
    dataplane/src/http2_session.cc \
    dataplane/src/http2_client_session.cc \
    dataplane/src/upstream_response_head_parser.cc \
    scripts/phase3-http2-fuzz.sh
} | LC_ALL=C sort -u > "$evidence_dir/source-files.txt"

while IFS= read -r source_file; do
  test -f "$source_file"
  printf '%s  %s\n' "$(hash_file "$source_file")" "$source_file"
done < "$evidence_dir/source-files.txt" > "$evidence_dir/source-SHA256SUMS"

source_key="$(hash_file "$evidence_dir/source-SHA256SUMS")"
short_key="$(printf '%s' "$source_key" | cut -c1-16)"
base_image="routesphere-global/bonvoyage-protocol-fuzz-base:$short_dependency_key"
fuzz_image="routesphere-global/bonvoyage-http2-fuzz:$short_key"

engine_arch="$(docker info --format '{{.Architecture}}')"
case "$engine_arch" in
  amd64|x86_64)
    platform=linux/amd64
    ;;
  arm64|aarch64)
    platform=linux/arm64
    ;;
  *)
    echo "unsupported Docker engine architecture: $engine_arch" >&2
    exit 1
    ;;
esac

{
  printf 'git_commit=%s\n' "$(git rev-parse HEAD)"
  printf 'dependency_manifest_sha256=%s\n' "$dependency_key"
  printf 'source_manifest_sha256=%s\n' "$source_key"
  printf 'platform=%s\n' "$platform"
  printf 'base_image=%s\n' "$base_image"
  printf 'fuzz_image=%s\n' "$fuzz_image"
  printf 'fuzz_seconds=%s\n' "$seconds"
  printf 'source_dirty=%s\n' "$source_dirty"
} > "$evidence_dir/run-manifest.txt"
printf '%s' "$source_status" > "$evidence_dir/git-status.txt"

if ! docker image inspect "$base_image" >/dev/null 2>&1; then
  if ! docker buildx build \
      --platform "$platform" \
      --target protocol-fuzz-dependencies \
      --build-arg "BUILD_JOBS=$jobs" \
      --build-arg BONVOYAGE_ENABLE_SANITIZERS=ON \
      --file deploy/docker/bonvoyage/Dockerfile \
      --tag "$base_image" \
      --load \
      . > "$evidence_dir/base-image-build.log" 2>&1; then
    tail -n 100 "$evidence_dir/base-image-build.log" >&2
    echo "HTTP/2 fuzz base image build failed" >&2
    exit 1
  fi
else
  printf 'reused immutable source-keyed image %s\n' "$base_image" \
    > "$evidence_dir/base-image-build.log"
fi

if ! docker buildx build \
    --platform "$platform" \
    --build-arg "BONVOYAGE_FUZZ_BASE=$base_image" \
    --build-arg "BONVOYAGE_BUILD_JOBS=$jobs" \
    --file dataplane/fuzz/Dockerfile \
    --tag "$fuzz_image" \
    --load \
    . > "$evidence_dir/fuzz-image-build.log" 2>&1; then
  tail -n 100 "$evidence_dir/fuzz-image-build.log" >&2
  echo "HTTP/2 fuzz image build failed" >&2
  exit 1
fi

docker image inspect "$base_image" > "$evidence_dir/base-image-inspect.json"
docker image inspect "$fuzz_image" > "$evidence_dir/fuzz-image-inspect.json"

set +e
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --cpus 2 \
  --memory 3g \
  --ulimit core=0 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=128m \
  --user "$(id -u):$(id -g)" \
  --env "BONVOYAGE_HTTP2_FUZZ_SECONDS=$seconds" \
  --env BONVOYAGE_FUZZ_EVIDENCE_DIR=/evidence \
  --volume "$evidence_dir:/evidence" \
  "$fuzz_image"
run_status=$?
set -e

checksum_lines="$(
  cd "$evidence_dir"
  find . -type f ! -name SHA256SUMS -print \
    | LC_ALL=C sort \
    | while IFS= read -r file; do
        printf '%s  %s\n' "$(hash_file "$file")" "$file"
      done
)"
printf '%s\n' "$checksum_lines" > "$evidence_dir/SHA256SUMS"

printf 'HTTP/2 fuzz evidence: %s\n' "$evidence_dir"
if [ "$run_status" -ne 0 ]; then
  echo "HTTP/2 sanitizer fuzz qualification failed" >&2
  exit "$run_status"
fi

echo "HTTP/2 sanitizer fuzz qualification passed"
