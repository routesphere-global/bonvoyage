#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

remote_ref="${BONVOYAGE_DEDICATED_REMOTE_REF:-origin/main}"
commit="$(git rev-parse HEAD)"
short_commit="$(printf '%s' "$commit" | cut -c1-12)"
output="${BONVOYAGE_DEDICATED_IMAGE_ENV:-benchmarks/results/local-archives/dedicated-rc-$short_commit/images.env}"

if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
  echo "dedicated RC image preparation requires a clean tree" >&2
  exit 2
fi
if ! git merge-base --is-ancestor "$commit" "$remote_ref"; then
  echo "dedicated RC image preparation requires HEAD on $remote_ref" >&2
  exit 2
fi

case "$output" in
  benchmarks/results/local-archives/*) ;;
  *)
    echo "BONVOYAGE_DEDICATED_IMAGE_ENV must be below benchmarks/results/local-archives" >&2
    exit 2
    ;;
esac
if [ -e "$output" ]; then
  echo "dedicated RC image environment already exists: $output" >&2
  exit 2
fi

dataplane_image="bonvoyage-dataplane:rc-$short_commit"
compiler_image="bonvoyage-snapshot-compiler:rc-$short_commit"
upstream_image="bonvoyage-controlled-upstream:rc-$short_commit"
phase3_upstream_image="bonvoyage-phase3-upstream:rc-$short_commit"
upstream_http1_client="${BONVOYAGE_UPSTREAM_HTTP1_CLIENT:-seastar-reference}"
prometheus_image="prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
syft_image="anchore/syft:v1.44.0@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6"
grype_image="anchore/grype:v0.116.1@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db"

BONVOYAGE_BUILD_PLATFORM=linux/amd64 \
BONVOYAGE_BUILD_JOBS=2 \
BONVOYAGE_DATAPLANE_IMAGE="$dataplane_image" \
BONVOYAGE_UPSTREAM_HTTP1_CLIENT="$upstream_http1_client" \
  ./scripts/build-dataplane-container.sh

docker buildx build \
  --platform linux/amd64 \
  --load \
  --tag "$compiler_image" \
  --file deploy/docker/control-plane/Dockerfile \
  .
docker buildx build \
  --platform linux/amd64 \
  --load \
  --tag "$upstream_image" \
  --file benchmarks/products/upstream/Dockerfile \
  benchmarks/products/upstream
docker buildx build \
  --platform linux/amd64 \
  --load \
  --tag "$phase3_upstream_image" \
  deploy/docker/upstream

# The JavaScript template expressions are intentionally quoted from the shell.
# shellcheck disable=SC2016
node -e '
const lock = require("./benchmarks/products/lock.json");
for (const product of lock.products) {
  process.stdout.write(`${product.repository}@${product.manifests.linux_amd64}\n`);
}
process.stdout.write(`${lock.load_generator.repository}@${lock.load_generator.manifests.linux_amd64}\n`);
' | while IFS= read -r image; do
  docker pull --platform linux/amd64 "$image"
done
for image in "$prometheus_image" "$syft_image" "$grype_image"; do
  docker pull --platform linux/amd64 "$image"
done

for image in "$dataplane_image" "$compiler_image" "$upstream_image" \
  "$phase3_upstream_image"; do
  platform="$(docker image inspect "$image" --format '{{.Os}}/{{.Architecture}}')"
  if [ "$platform" != "linux/amd64" ]; then
    echo "prepared image is not linux/amd64: $image ($platform)" >&2
    exit 1
  fi
done

if [ "$(git rev-parse HEAD)" != "$commit" ] || \
  [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
  echo "source changed during dedicated RC image preparation" >&2
  exit 1
fi

mkdir -p "${output%/*}"
cat >"$output" <<EOF
BONVOYAGE_DEDICATED_SOURCE_COMMIT=$commit
BONVOYAGE_UPSTREAM_HTTP1_CLIENT=$upstream_http1_client
BONVOYAGE_DEDICATED_BONVOYAGE_IMAGE=$dataplane_image
BONVOYAGE_DEDICATED_COMPILER_IMAGE=$compiler_image
BONVOYAGE_DEDICATED_UPSTREAM_IMAGE=$upstream_image
BONVOYAGE_DEDICATED_PHASE3_UPSTREAM_IMAGE=$phase3_upstream_image
BONVOYAGE_DEDICATED_PROMETHEUS_IMAGE=$prometheus_image
BONVOYAGE_DEDICATED_SYFT_IMAGE=$syft_image
BONVOYAGE_DEDICATED_GRYPE_IMAGE=$grype_image
EOF

printf '%s\n' "prepared exact Linux AMD64 RC images: $output"
