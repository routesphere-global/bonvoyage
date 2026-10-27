#!/bin/sh
set -eu

compose_file="benchmarks/docker-compose.yml"
payload_file="$(mktemp)"

cleanup() {
  rm -f "$payload_file"
  docker compose -f "$compose_file" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker compose -f "$compose_file" up --build --detach upstream

attempt=0
until curl --fail --silent --show-error \
  http://127.0.0.1:8081/healthz >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    docker compose -f "$compose_file" logs upstream
    echo "benchmark upstream did not become healthy" >&2
    exit 1
  fi
  sleep 1
done

for expected_size in 256 8192 15360 16384 17408 32768 65536 1048576; do
  curl --fail --silent --show-error \
    "http://127.0.0.1:8081/payload/$expected_size" >"$payload_file"
  actual_size="$(wc -c <"$payload_file" | tr -d ' ')"
  test "$actual_size" = "$expected_size"
  test -z "$(tr -d x <"$payload_file")"
done

actual_sha256="$(shasum -a 256 "$payload_file" | awk '{print $1}')"
test "$actual_sha256" = \
  "8f990ba0b577b51cf009ea049368c16bbda1b21e1b93be07a824758bb253c39b"

echo "benchmark upstream smoke passed"
