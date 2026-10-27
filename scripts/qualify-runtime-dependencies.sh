#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
syft_image="anchore/syft:v1.44.0@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6"
grype_image="anchore/grype:v0.116.1@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${BONVOYAGE_SECURITY_EVIDENCE_DIR:-$repo_root/benchmarks/results/local-archives/runtime-security-$timestamp}"
if [ -n "${BONVOYAGE_GRYPE_CACHE_MIB:-}" ]; then
  echo "BONVOYAGE_GRYPE_CACHE_MIB is obsolete; unset it: the shared database now uses retained disk with an 8 GiB free-space preflight" >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || {
  echo "docker is required for runtime dependency qualification" >&2
  exit 1
}
command -v node >/dev/null 2>&1 || {
  echo "node is required to normalize and gate scanner output" >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required to verify runtime package ownership" >&2
  exit 1
}

# Scanners keep no capabilities and write as the caller. Only Syft receives
# the existing Docker socket group needed to read the selected image.
scanner_uid="$(id -u)"
scanner_gid="$(id -g)"
case "$(uname -s)" in
  Darwin)
    # Docker Desktop projects the socket into Linux containers as root:root,
    # regardless of the group reported for the macOS-side symlink target.
    docker_socket_gid=0
    ;;
  *)
    docker_socket_gid="$(stat -L -c '%g' /var/run/docker.sock 2>/dev/null ||
      stat -L -f '%g' /var/run/docker.sock)"
    ;;
esac
case "$docker_socket_gid" in
  ''|*[!0-9]*) echo "cannot determine Docker socket group" >&2; exit 2 ;;
esac

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
docker image inspect "$image" >/dev/null 2>&1 || {
  echo "runtime image is missing: $image" >&2
  exit 1
}

image_id="$(docker image inspect "$image" --format '{{.Id}}')"
image_platform="$(docker image inspect "$image_id" --format '{{.Os}}/{{.Architecture}}')"
upstream_http1_client="$(docker image inspect "$image_id" --format \
  '{{index .Config.Labels "io.routesphere.bonvoyage.upstream-http1-client"}}')"
runtime_source_revision="$(docker image inspect "$image_id" --format \
  '{{index .Config.Labels "org.opencontainers.image.revision"}}')"
runtime_source_dirty="$(docker image inspect "$image_id" --format \
  '{{index .Config.Labels "io.routesphere.bonvoyage.source-dirty"}}')"
case "$upstream_http1_client" in
  seastar-reference|llhttp-candidate) ;;
  *)
    echo "runtime image has an unsupported upstream HTTP/1 client label: $upstream_http1_client" >&2
    exit 2
    ;;
esac
source_commit="$(git rev-parse HEAD)"
source_status="$(git status --porcelain=v1 --untracked-files=all)"
source_dirty=true
if [ -z "$source_status" ]; then
  source_dirty=false
fi
expected_id="${BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID:-}"
if [ -n "$expected_id" ]; then
  if [ "$expected_id" != "$image_id" ] || [ "$image_platform" != linux/amd64 ] || \
     [ "$source_dirty" != false ]; then
    echo "locked runtime scan requires the expected AMD64 image and clean source, including untracked files" >&2
    exit 2
  fi
  if [ "$runtime_source_revision" != "$source_commit" ] || \
     [ "$runtime_source_dirty" != false ]; then
    echo "locked runtime scan requires revision and dirty-state labels for the current clean source" >&2
    exit 2
  fi
fi

# Never overwrite an earlier scan, including an incomplete or failed attempt.
mkdir -p "$(dirname -- "$evidence_dir")"
if ! mkdir "$evidence_dir"; then
  echo "runtime security evidence directory must be new: $evidence_dir" >&2
  exit 2
fi
evidence_dir="$(CDPATH='' cd -- "$evidence_dir" && pwd)"
cat > "$evidence_dir/environment.txt" <<EOF
captured_at_utc=$timestamp
source_commit=$source_commit
source_dirty=$source_dirty
runtime_image=$image
runtime_image_id=$image_id
runtime_scan_target=docker:$image_id
runtime_platform=$image_platform
runtime_source_revision=$runtime_source_revision
runtime_source_dirty=$runtime_source_dirty
upstream_http1_client=$upstream_http1_client
syft_image=$syft_image
grype_image=$grype_image
database_storage=dual-format/database (retained disk, not transient tmpfs)
EOF

cat > "$evidence_dir/source-files.txt" <<'EOF'
.dockerignore
deploy/docker/bonvoyage/Dockerfile
scripts/build-dataplane-container.sh
scripts/augment-runtime-sbom.mjs
scripts/augment-runtime-spdx.mjs
scripts/build-runtime-package-index.py
scripts/verify-runtime-package-overlap.py
scripts/verify-runtime-image-binding.py
scripts/scan-runtime-sbom-pair.py
scripts/verify-runtime-scan-parity.mjs
scripts/qualify-runtime-dependencies.sh
scripts/inspect-runtime-glibc-reachability.py
scripts/bind-runtime-glibc-reachability.py
scripts/summarize-vulnerability-scan.mjs
security/dependencies/nghttp2-1.70.0.json
security/dependencies/libjwt-3.6.1.json
security/dependencies/llhttp-9.4.3.json
security/dependencies/seastar-25.05.0.json
security/dependencies/abseil-20250512.1.json
security/dependencies/c-ares-1.34.8.json
security/dependencies/re2-2025-11-05.json
security/dependencies/opentelemetry-proto-1.11.0.json
third_party/opentelemetry-proto/LICENSE
third_party/opentelemetry-proto/opentelemetry/proto/collector/trace/v1/trace_service.proto
third_party/opentelemetry-proto/opentelemetry/proto/common/v1/common.proto
third_party/opentelemetry-proto/opentelemetry/proto/resource/v1/resource.proto
third_party/opentelemetry-proto/opentelemetry/proto/trace/v1/trace.proto
EOF
find deploy/docker/bonvoyage/patches -type f -name '*.patch' -print \
  | LC_ALL=C sort >> "$evidence_dir/source-files.txt"
while IFS= read -r source_file; do
  test -f "$source_file"
  printf '%s  %s\n' "$(hash_file "$source_file")" "$source_file"
done < "$evidence_dir/source-files.txt" \
  > "$evidence_dir/source-checksums.sha256"

# Independent Docker-save bytes anchor the scanner's lossy source identities.
# A legacy non-OCI save layout fails closed instead of guessing a root digest.
docker image save --output "$evidence_dir/runtime.oci.tar" "$image_id"

docker run --rm \
  --network none \
  --user "$scanner_uid:$scanner_gid" \
  --group-add "$docker_socket_gid" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env SYFT_CHECK_FOR_APP_UPDATE=false \
  --tmpfs "/tmp:rw,noexec,nosuid,size=512m,mode=0700,uid=$scanner_uid,gid=$scanner_gid" \
  --tmpfs "/.cache:rw,noexec,nosuid,size=32m,mode=0700,uid=$scanner_uid,gid=$scanner_gid" \
  --volume /var/run/docker.sock:/var/run/docker.sock:ro \
  --volume "$evidence_dir:/out" \
  "$syft_image" "docker:$image_id" \
  --platform "$image_platform" \
  -o syft-json=/out/runtime.raw.syft.json \
  -o cyclonedx-json@1.6=/out/runtime.raw.cdx.json \
  -o spdx-json@2.3=/out/runtime.raw.spdx.json

# Augmentation never overwrites the original generator evidence.
cp "$evidence_dir/runtime.raw.cdx.json" "$evidence_dir/runtime.cdx.json"
cp "$evidence_dir/runtime.raw.spdx.json" "$evidence_dir/runtime.syft.spdx.json"
(
  cd "$evidence_dir"
  for raw in runtime.raw.syft.json runtime.raw.cdx.json runtime.raw.spdx.json; do
    printf '%s  %s\n' "$(hash_file "$raw")" "$raw"
  done
) > "$evidence_dir/raw-checksums.sha256"

# Keep an unpruned diagnostic so partial overlap cannot silently hide an ELF
# aggregate. The verifier checks the effective setting, not just this request.
docker run --rm \
  --network none \
  --user "$scanner_uid:$scanner_gid" \
  --group-add "$docker_socket_gid" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env SYFT_CHECK_FOR_APP_UPDATE=false \
  --env SYFT_PACKAGE_EXCLUDE_BINARY_OVERLAP_BY_OWNERSHIP=false \
  --tmpfs "/tmp:rw,noexec,nosuid,size=512m,mode=0700,uid=$scanner_uid,gid=$scanner_gid" \
  --tmpfs "/.cache:rw,noexec,nosuid,size=32m,mode=0700,uid=$scanner_uid,gid=$scanner_gid" \
  --volume /var/run/docker.sock:/var/run/docker.sock:ro \
  --volume "$evidence_dir:/out" \
  "$syft_image" "docker:$image_id" --platform "$image_platform" \
  -o syft-json=/out/runtime.diagnostic.syft.json
printf '%s  %s\n' "$(hash_file "$evidence_dir/runtime.diagnostic.syft.json")" \
  runtime.diagnostic.syft.json >> "$evidence_dir/raw-checksums.sha256"

dependency_record_dir="$evidence_dir/.runtime-dependency-records"
mkdir -p "$dependency_record_dir"
# Read the declarations carried by this immutable image. A newer checkout must
# not add a corrected dependency to an older image's SBOM.
record_container="$(docker create --network none "$image_id")"
trap 'docker rm "$record_container" >/dev/null 2>&1 || true' EXIT
if [ -n "$expected_id" ]; then
  docker image inspect "$image_id" > "$evidence_dir/runtime-image-inspect.json"
  docker container inspect "$record_container" > "$evidence_dir/runtime-container-inspect.json"
  docker export --output "$evidence_dir/runtime-rootfs.tar" "$record_container"
  docker cp "$record_container:/usr/local/bin/bonvoyage-dataplane" \
    "$evidence_dir/runtime-gateway.bin"
fi
docker cp "$record_container:/usr/share/bonvoyage/dependencies/." "$dependency_record_dir/"
docker cp "$record_container:/usr/share/bonvoyage/runtime-package-ownership.json" \
  "$evidence_dir/runtime-package-ownership.json"
if [ -n "$expected_id" ]; then
  python3 -B scripts/inspect-runtime-glibc-reachability.py \
    --rootfs "$evidence_dir/runtime-rootfs.tar" \
    --image-inspect "$evidence_dir/runtime-image-inspect.json" \
    --container-inspect "$evidence_dir/runtime-container-inspect.json" \
    --expected-image-id "$image_id" --source-commit "$source_commit" \
    --expected-gateway-sha256 "$(hash_file "$evidence_dir/runtime-gateway.bin")" \
    --output "$evidence_dir/runtime-glibc-reachability.json"
fi
docker rm "$record_container" >/dev/null
trap - EXIT
python3 -B scripts/verify-runtime-package-overlap.py \
  --diagnostic "$evidence_dir/runtime.diagnostic.syft.json" \
  --standard "$evidence_dir/runtime.raw.syft.json" \
  --ownership "$evidence_dir/runtime-package-ownership.json" \
  --output "$evidence_dir/package-overlap-verification.json"
for record_file in "$dependency_record_dir"/*.json; do
  record_name="$(basename -- "$record_file")"
  source_record="security/dependencies/$record_name"
  if [ ! -f "$source_record" ] || [ -L "$record_file" ] || \
     [ "$(hash_file "$record_file")" != "$(hash_file "$source_record")" ]; then
    echo "image dependency record differs from the captured source: $record_name" >&2
    exit 1
  fi
done

node scripts/augment-runtime-sbom.mjs \
  "$evidence_dir/runtime.cdx.json" "$dependency_record_dir" "$upstream_http1_client"
node scripts/augment-runtime-spdx.mjs \
  "$evidence_dir/runtime.syft.spdx.json" "$dependency_record_dir" "$upstream_http1_client"
rm -r "$dependency_record_dir"

node - "$evidence_dir/runtime.cdx.json" \
  "$evidence_dir/runtime.syft.spdx.json" \
  "$upstream_http1_client" <<'NODE'
const fs = require("node:fs");
const sbom = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const names = new Set((sbom.components ?? []).map((component) => component.name));
const requiredNames = [
  "abseil",
  "c-ares",
  "libjwt",
  "llhttp",
  "nghttp2",
  "opentelemetry-proto",
  "re2",
  "seastar",
];
for (const required of requiredNames) {
  if (!names.has(required) || sbom.components.filter((c) => c.name === required).length !== 1) {
    throw new Error(`runtime SBOM is missing required static dependency: ${required}`);
  }
}
const operatingSystem = (sbom.components ?? []).find(
  (component) => component.type === "operating-system" && component.name === "ubuntu",
);
if (operatingSystem?.version !== "24.04") {
  throw new Error(
    `runtime SBOM distro identity is not Ubuntu 24.04: ${operatingSystem?.version ?? "missing"}`,
  );
}
const spdx = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const spdxNames = new Set((spdx.packages ?? []).map((entry) => entry.name));
for (const required of requiredNames) {
  if (!spdxNames.has(required) || spdx.packages.filter((p) => p.name === required).length !== 1) {
    throw new Error(`runtime SPDX SBOM is missing static dependency: ${required}`);
  }
}
const cpe = "cpe:2.3:a:c-ares_project:c-ares:1.34.8:*:*:*:*:*:*:*";
const cares = sbom.components.find((c) => c.name === "c-ares");
const spdxCares = spdx.packages.find((p) => p.name === "c-ares");
if (cares.version !== "1.34.8" || cares.cpe !== cpe || spdxCares.versionInfo !== "1.34.8" ||
    !spdxCares.externalRefs.some((r) => r.referenceCategory === "SECURITY" &&
      r.referenceType === "cpe23Type" && r.referenceLocator === cpe)) {
  throw new Error("cross-format c-ares version/CPE identity mismatch");
}
NODE

python3 -B scripts/verify-runtime-image-binding.py \
  --archive "$evidence_dir/runtime.oci.tar" --expected-image-id "$image_id" \
  --platform "$image_platform" --syft "$evidence_dir/runtime.raw.syft.json" \
  --cyclonedx "$evidence_dir/runtime.cdx.json" --spdx "$evidence_dir/runtime.syft.spdx.json" \
  --output "$evidence_dir/image-binding-verification.json"

# Rebind from bytes again, decode both formats, hydrate one retained DB, then
# scan offline. A vulnerability failure must still retain complete evidence.
scan_status=0
python3 -B scripts/scan-runtime-sbom-pair.py \
  --evidence-dir "$evidence_dir" --output "$evidence_dir/dual-format" \
  --expected-image-id "$image_id" --platform "$image_platform" || scan_status=$?
if [ "$scan_status" -gt 1 ]; then
  echo "invalid dual-format qualification; inspect $evidence_dir/dual-format" >&2
  exit "$scan_status"
fi
# Preserve the CDX filenames consumed by artifact locking. The additional pair
# receipt is required here before the legacy per-format summary can be emitted.
cp "$evidence_dir/dual-format/scan-cdx.stdout" "$evidence_dir/vulnerabilities.grype.json"
summary_status=0
node scripts/summarize-vulnerability-scan.mjs \
  "$evidence_dir/vulnerabilities.grype.json" "$evidence_dir/vulnerability-summary.json" \
  "docker:$image_id" || summary_status=$?
if [ "$summary_status" -ne "$scan_status" ]; then
  echo "pair and compatibility-summary status disagree" >&2
  exit 2
fi

if [ -n "$expected_id" ]; then
  python3 -B scripts/bind-runtime-glibc-reachability.py \
    --evidence-dir "$evidence_dir" --repo-root "$repo_root" \
    --output "$evidence_dir/runtime-glibc-binding.json"
fi

# Bind the completed scan to the same source and immutable image as its start.
if [ "$(git rev-parse HEAD)" != "$source_commit" ] || \
   [ "$(git status --porcelain=v1 --untracked-files=all)" != "$source_status" ] || \
   [ "$(docker image inspect "$image_id" --format '{{.Id}}')" != "$image_id" ]; then
  echo "source or runtime identity changed during dependency qualification" >&2
  exit 1
fi
while read -r expected_hash source_file; do
  if [ "$(hash_file "$source_file")" != "$expected_hash" ]; then
    echo "runtime dependency source changed during qualification: $source_file" >&2
    exit 1
  fi
done < "$evidence_dir/source-checksums.sha256"

(
  cd "$evidence_dir"
  set -- environment.txt source-files.txt source-checksums.sha256 \
    runtime.cdx.json runtime.syft.spdx.json \
    runtime.raw.syft.json runtime.raw.cdx.json runtime.raw.spdx.json raw-checksums.sha256 \
    runtime.diagnostic.syft.json runtime-package-ownership.json package-overlap-verification.json \
    runtime.oci.tar image-binding-verification.json \
    dual-format/result.json dual-format/evidence-checksums.json \
    vulnerabilities.grype.json vulnerability-summary.json
  if [ -n "$expected_id" ]; then
    set -- "$@" runtime-image-inspect.json runtime-container-inspect.json \
      runtime-rootfs.tar runtime-gateway.bin runtime-glibc-reachability.json \
      runtime-glibc-binding.json
  fi
  for evidence_file do
    printf '%s  %s\n' "$(hash_file "$evidence_file")" "$evidence_file"
  done > evidence-checksums.sha256
)

if [ "$scan_status" -eq 1 ]; then
  printf '%s\n' "runtime dependency vulnerability gate blocked; evidence retained: $evidence_dir" >&2
else
  printf '%s\n' "runtime dependency scan parity and High-severity gate passed (coverage remains unqualified): $evidence_dir"
fi
exit "$scan_status"
