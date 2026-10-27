#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
jobs="${BONVOYAGE_BUILD_JOBS:-2}"
upstream_http1_client="${BONVOYAGE_UPSTREAM_HTTP1_CLIENT:-seastar-reference}"
source_commit="$(git -C "$repo_root" rev-parse HEAD)"
source_dirty=true
if [ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]; then
  source_dirty=false
fi

case "$source_commit" in
  *[!0-9a-f]*|'')
    echo "a full lowercase Git source commit is required" >&2
    exit 2
    ;;
esac
if [ "${#source_commit}" -ne 40 ]; then
  echo "a full 40-character Git source commit is required" >&2
  exit 2
fi

case "$upstream_http1_client" in
  seastar-reference|llhttp-candidate) ;;
  *)
    echo "unsupported upstream HTTP/1 client: $upstream_http1_client" >&2
    exit 2
    ;;
esac

cd "$repo_root"
exec docker buildx build \
  --platform "$platform" \
  --load \
  --build-arg "BUILD_JOBS=$jobs" \
  --build-arg "BONVOYAGE_UPSTREAM_HTTP1_CLIENT=$upstream_http1_client" \
  --label "org.opencontainers.image.revision=$source_commit" \
  --label "io.routesphere.bonvoyage.source-dirty=$source_dirty" \
  --target runtime \
  --tag "$image" \
  --file deploy/docker/bonvoyage/Dockerfile \
  .
