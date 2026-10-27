#!/bin/sh
set -eu

image="${BONVOYAGE_DATAPLANE_IMAGE:-}"
expected_id="${BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID:-}"

if [ -z "$image" ] || [ -z "$expected_id" ]; then
  echo "BONVOYAGE_DATAPLANE_IMAGE and BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID are required" >&2
  exit 2
fi

actual_id="$(docker image inspect "$image" --format '{{.Id}}')"
actual_platform="$(docker image inspect "$image" --format '{{.Os}}/{{.Architecture}}')"

if [ "$actual_id" != "$expected_id" ]; then
  echo "locked dataplane image mismatch: expected $expected_id, got $actual_id" >&2
  exit 1
fi
if [ "$actual_platform" != "linux/amd64" ]; then
  echo "locked dataplane platform mismatch: expected linux/amd64, got $actual_platform" >&2
  exit 1
fi

printf '%s\n' "locked dataplane image accepted: $image ($actual_id)"
