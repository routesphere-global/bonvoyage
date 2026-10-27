#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
reference_image="${BONVOYAGE_AB_BASELINE_IMAGE:-bonvoyage-dataplane:seastar-reference}"
candidate_image="${BONVOYAGE_AB_CANDIDATE_IMAGE:-bonvoyage-dataplane:llhttp-candidate}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-benchmark-upstream:phase2}"
result_root="${BONVOYAGE_AB_RESULT_ROOT:-$repo/benchmarks/results/optimization}"

cd "$repo"

BONVOYAGE_BUILD_PLATFORM="$platform" \
BONVOYAGE_UPSTREAM_HTTP1_CLIENT=seastar-reference \
BONVOYAGE_DATAPLANE_IMAGE="$reference_image" \
  ./scripts/build-dataplane-container.sh
BONVOYAGE_BUILD_PLATFORM="$platform" \
BONVOYAGE_UPSTREAM_HTTP1_CLIENT=llhttp-candidate \
BONVOYAGE_DATAPLANE_IMAGE="$candidate_image" \
  ./scripts/build-dataplane-container.sh

docker buildx build --platform "$platform" --load --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile .
docker buildx build --platform "$platform" --load --tag "$upstream_image" \
  benchmarks/products/upstream

reference_label="$(docker image inspect "$reference_image" --format \
  '{{index .Config.Labels "io.routesphere.bonvoyage.upstream-http1-client"}}')"
candidate_label="$(docker image inspect "$candidate_image" --format \
  '{{index .Config.Labels "io.routesphere.bonvoyage.upstream-http1-client"}}')"
test "$reference_label" = "seastar-reference"
test "$candidate_label" = "llhttp-candidate"

export BONVOYAGE_REPO="$repo"
export BONVOYAGE_BUILD_PLATFORM="$platform"
export BONVOYAGE_AB_BASELINE_IMAGE="$reference_image"
export BONVOYAGE_AB_CANDIDATE_IMAGE="$candidate_image"
export BONVOYAGE_COMPILER_IMAGE="$compiler_image"
export BONVOYAGE_UPSTREAM_IMAGE="$upstream_image"
export BONVOYAGE_AB_EXPERIMENT_ID=upstream-http1-client-local-ab
export BONVOYAGE_AB_REPORT_TITLE="Upstream HTTP/1 client local A/B"
export BONVOYAGE_AB_EVIDENCE_CLASS=local-virtualized-balanced-upstream-client-ab
export BONVOYAGE_AB_PUBLICATION_REASON="Local virtualized scheduling; client-selection evidence only"
export BONVOYAGE_AB_RESULT_ROOT="$result_root"

exec "$script_dir/run-copy-transfer-local-ab.sh"
