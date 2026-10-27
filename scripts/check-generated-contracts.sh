#!/bin/sh
set -eu

before="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-generated.XXXXXX")"
cleanup() {
  rm -rf "$before"
}
trap cleanup EXIT INT TERM

cp -R api/gen "$before/gen"
buf generate --config api/buf.yaml --template api/buf.gen.yaml

if ! diff -ru "$before/gen" api/gen; then
  echo "Generated Go contracts are stale. Run 'make api-generate'." >&2
  exit 1
fi
