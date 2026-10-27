#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}
NODE_ID=${BONVOYAGE_DISCOVERY_NODE_ID:-node-a}
CONTROL_PORT=${BONVOYAGE_DISCOVERY_PORT:-$((20000 + ($$ % 20000)))}
EVIDENCE_DIR=${BONVOYAGE_DISCOVERY_EVIDENCE_DIR:-}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-phase4-discovery.XXXXXX")
CONTAINER_NAME="bonvoyage-phase4-discovery-$$"
CONTROL_PID=

dump_dataplane_diagnostics() {
  if docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    docker inspect "${CONTAINER_NAME}" \
      --format 'dataplane state={{json .State}}' >&2 || true
    docker logs "${CONTAINER_NAME}" >&2 || true
  fi
}

cleanup() {
  if [[ -n "${CONTROL_PID}" ]] && kill -0 "${CONTROL_PID}" 2>/dev/null; then
    kill -TERM "${CONTROL_PID}" 2>/dev/null || true
    wait "${CONTROL_PID}" 2>/dev/null || true
  fi
  docker rm --force "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

fail() {
  printf 'phase4 discovery integration: %s\n' "$*" >&2
  dump_dataplane_diagnostics
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

wait_for_log() {
  local log_file=$1
  local pattern=$2
  local attempts=${3:-200}
  for ((attempt = 0; attempt < attempts; ++attempt)); do
    if grep -Fq "${pattern}" "${log_file}" 2>/dev/null; then
      return 0
    fi
    if [[ -n "${CONTROL_PID}" ]] && ! kill -0 "${CONTROL_PID}" 2>/dev/null; then
      cat "${log_file}" >&2 || true
      fail "control-plane process stopped before becoming ready"
    fi
    sleep 0.1
  done
  cat "${log_file}" >&2 || true
  fail "timed out waiting for: ${pattern}"
}

wait_for_http() {
  local url=$1
  local output=$2
  local pattern=$3
  for ((attempt = 0; attempt < 300; ++attempt)); do
    if docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1 &&
       [[ "$(docker inspect "${CONTAINER_NAME}" --format '{{.State.Running}}')" != true ]]; then
      fail "dataplane stopped while waiting for ${url}"
    fi
    if curl --fail --silent --show-error "${url}" >"${output}.tmp" 2>/dev/null &&
       grep -Fq "${pattern}" "${output}.tmp"; then
      mv "${output}.tmp" "${output}"
      return 0
    fi
    sleep 0.1
  done
  fail "timed out waiting for ${url} to contain ${pattern}"
}

start_control_plane() {
  local sequence=$1
  local log_file=$2
  : >"${log_file}"
  "${WORK_DIR}/bonvoyage-control-plane" serve-discovery \
    -repository-root "${WORK_DIR}/repository" \
    -rollout-sequence "${sequence}" \
    -start-rollout \
    -listen-address "0.0.0.0:${CONTROL_PORT}" \
    -tls-server-cert "${WORK_DIR}/tls/server.pem" \
    -tls-server-key "${WORK_DIR}/tls/server-key.pem" \
    -tls-client-ca "${WORK_DIR}/tls/ca.pem" \
    -spiffe-trust-domain routesphere.test \
    -spiffe-node-path-prefix /bonvoyage/nodes/ \
    >"${log_file}" 2>&1 &
  CONTROL_PID=$!
  wait_for_log "${log_file}" "discovery listener ready:"
}

stop_control_plane() {
  [[ -n "${CONTROL_PID}" ]] || return 0
  kill -TERM "${CONTROL_PID}"
  for ((attempt = 0; attempt < 150; ++attempt)); do
    if ! kill -0 "${CONTROL_PID}" 2>/dev/null; then
      wait "${CONTROL_PID}"
      CONTROL_PID=
      return 0
    fi
    sleep 0.1
  done
  fail "control-plane process did not stop within its bounded drain deadline"
}

verify_rollout() {
  local sequence=$1
  local phase=$2
  local node_phase=$3
  local minimum_events=$4
  local output=$5
  shift 5
  "${WORK_DIR}/discoveryfixture" verify \
    -repository "${WORK_DIR}/repository" \
    -sequence "${sequence}" \
    -phase "${phase}" \
    -node-id "${NODE_ID}" \
    -node-phase "${node_phase}" \
    -minimum-events "${minimum_events}" \
    "$@" >"${output}"
}

for command in docker go curl git; do
  require_command "${command}"
done
docker image inspect "${IMAGE}" >/dev/null 2>&1 ||
  fail "dataplane image is unavailable: ${IMAGE}"

if [[ -z "${EVIDENCE_DIR}" ]]; then
  EVIDENCE_DIR="${WORK_DIR}/evidence"
fi
mkdir -p "${EVIDENCE_DIR}"

(
  cd "${ROOT_DIR}/control-plane"
  go build -trimpath -o "${WORK_DIR}/bonvoyage-control-plane" ./cmd/bonvoyage-control-plane
  go build -trimpath -o "${WORK_DIR}/discoveryfixture" ./tests/discoveryfixture
)

"${WORK_DIR}/discoveryfixture" prepare \
  -repository "${WORK_DIR}/repository" \
  -bootstrap-config "${ROOT_DIR}/control-plane/tests/testdata/phase4-live-bootstrap.yaml" \
  -candidate-config "${ROOT_DIR}/control-plane/tests/testdata/phase4-live-candidate.yaml" \
  -restart-config "${ROOT_DIR}/control-plane/tests/testdata/phase4-listener-restart-required.yaml" \
  -bootstrap-output "${WORK_DIR}/bootstrap.pb" \
  -tls-directory "${WORK_DIR}/tls" \
  -node-id "${NODE_ID}" >"${WORK_DIR}/fixture.env"

while IFS='=' read -r key value; do
  case "${key}" in
    VALID_SEQUENCE) VALID_SEQUENCE=${value} ;;
    INVALID_SEQUENCE) INVALID_SEQUENCE=${value} ;;
    BOOTSTRAP_SNAPSHOT_ID) BOOTSTRAP_SNAPSHOT_ID=${value} ;;
    VALID_SNAPSHOT_ID) VALID_SNAPSHOT_ID=${value} ;;
    INVALID_SNAPSHOT_ID) INVALID_SNAPSHOT_ID=${value} ;;
  esac
done <"${WORK_DIR}/fixture.env"
: "${VALID_SEQUENCE:?missing valid sequence}"
: "${INVALID_SEQUENCE:?missing invalid sequence}"
: "${BOOTSTRAP_SNAPSHOT_ID:?missing bootstrap snapshot ID}"
: "${VALID_SNAPSHOT_ID:?missing valid snapshot ID}"
: "${INVALID_SNAPSHOT_ID:?missing invalid snapshot ID}"

docker run --detach \
  --name "${CONTAINER_NAME}" \
  --add-host host.docker.internal:host-gateway \
  --publish 127.0.0.1::8080 \
  --publish 127.0.0.1::9901 \
  --volume "${WORK_DIR}/bootstrap.pb:/etc/bonvoyage/snapshot.pb:ro" \
  --volume "${WORK_DIR}/tls/ca.pem:/etc/bonvoyage/discovery/ca.pem:ro" \
  --volume "${WORK_DIR}/tls/node.pem:/etc/bonvoyage/discovery/node.pem:ro" \
  --volume "${WORK_DIR}/tls/node-key.pem:/etc/bonvoyage/discovery/node-key.pem:ro" \
  "${IMAGE}" \
  --snapshot /etc/bonvoyage/snapshot.pb \
  --admin-address 0.0.0.0 \
  --admin-port 9901 \
  --metrics-port 0 \
  --runtime-log-transport stderr-pipe \
  --discovery-address host.docker.internal \
  --discovery-port "${CONTROL_PORT}" \
  --discovery-authority "discovery.test:${CONTROL_PORT}" \
  --discovery-server-name discovery.test \
  --discovery-trust-bundle /etc/bonvoyage/discovery/ca.pem \
  --discovery-client-certificate /etc/bonvoyage/discovery/node.pem \
  --discovery-client-private-key /etc/bonvoyage/discovery/node-key.pem \
  --discovery-node-id "${NODE_ID}" \
  --discovery-heartbeat-interval-ms 250 \
  --discovery-reconnect-initial-backoff-ms 50 \
  --discovery-reconnect-max-backoff-ms 500 \
  --smp 2 \
  --memory 512M \
  --overprovisioned >/dev/null

GATEWAY_PORT=$(docker port "${CONTAINER_NAME}" 8080/tcp | sed -n '1s/.*://p')
ADMIN_PORT=$(docker port "${CONTAINER_NAME}" 9901/tcp | sed -n '1s/.*://p')
[[ -n "${GATEWAY_PORT}" && -n "${ADMIN_PORT}" ]] ||
  fail "Docker did not publish the gateway and admin ports"

wait_for_http "http://127.0.0.1:${ADMIN_PORT}/config/active" \
  "${WORK_DIR}/bootstrap-state.json" "${BOOTSTRAP_SNAPSHOT_ID}"
wait_for_http "http://127.0.0.1:${GATEWAY_PORT}/bonvoyage/ready" \
  "${WORK_DIR}/bootstrap-response.txt" "ready"

start_control_plane "${VALID_SEQUENCE}" "${WORK_DIR}/control-valid-first.log"
wait_for_http "http://127.0.0.1:${ADMIN_PORT}/config/active" \
  "${WORK_DIR}/activated-state.json" "${VALID_SNAPSHOT_ID}"
wait_for_http "http://127.0.0.1:${GATEWAY_PORT}/bonvoyage/ready" \
  "${WORK_DIR}/activated-response.txt" "activated"
sleep 0.5
stop_control_plane
verify_rollout "${VALID_SEQUENCE}" ACTIVE ACTIVE 4 \
  "${WORK_DIR}/valid-first.verify"
FIRST_EVENT_COUNT=$(sed -n 's/^EVENT_COUNT=//p' "${WORK_DIR}/valid-first.verify")

start_control_plane "${VALID_SEQUENCE}" "${WORK_DIR}/control-valid-reconnect.log"
sleep 1
stop_control_plane
verify_rollout "${VALID_SEQUENCE}" ACTIVE ACTIVE "$((FIRST_EVENT_COUNT + 1))" \
  "${WORK_DIR}/valid-reconnect.verify"

start_control_plane "${INVALID_SEQUENCE}" "${WORK_DIR}/control-invalid.log"
sleep 1
wait_for_http "http://127.0.0.1:${ADMIN_PORT}/config/active" \
  "${WORK_DIR}/post-nack-state.json" "${VALID_SNAPSHOT_ID}"
wait_for_http "http://127.0.0.1:${GATEWAY_PORT}/bonvoyage/ready" \
  "${WORK_DIR}/post-nack-response.txt" "activated"

docker logs "${CONTAINER_NAME}" >"${WORK_DIR}/dataplane.log" 2>&1
docker stop --time 10 "${CONTAINER_NAME}" >/dev/null
stop_control_plane
verify_rollout "${INVALID_SEQUENCE}" CANCELLED FAILED 3 \
  "${WORK_DIR}/invalid.verify" \
  -require-issue snapshot.listener_restart_required

docker inspect "${IMAGE}" --format '{{.Id}}' >"${WORK_DIR}/image-id.txt"
git -C "${ROOT_DIR}" rev-parse HEAD >"${WORK_DIR}/source-commit.txt"
if [[ -n "$(git -C "${ROOT_DIR}" status --porcelain)" ]]; then
  printf 'true\n' >"${WORK_DIR}/source-dirty.txt"
else
  printf 'false\n' >"${WORK_DIR}/source-dirty.txt"
fi

cp "${WORK_DIR}/fixture.env" "${EVIDENCE_DIR}/"
cp "${WORK_DIR}"/*.verify "${EVIDENCE_DIR}/"
cp "${WORK_DIR}"/*-state.json "${EVIDENCE_DIR}/"
cp "${WORK_DIR}"/*-response.txt "${EVIDENCE_DIR}/"
cp "${WORK_DIR}"/*.log "${EVIDENCE_DIR}/"
cp "${WORK_DIR}/image-id.txt" "${WORK_DIR}/source-commit.txt" \
  "${WORK_DIR}/source-dirty.txt" "${EVIDENCE_DIR}/"

cat >"${EVIDENCE_DIR}/summary.txt" <<EOF
checkpoint=Phase 4 Checkpoint 7 shipped discovery transport
transport=TLS 1.3 mutual TLS over HTTP/2 gRPC
node_id=${NODE_ID}
bootstrap_snapshot=${BOOTSTRAP_SNAPSHOT_ID}
activated_snapshot=${VALID_SNAPSHOT_ID}
rejected_snapshot=${INVALID_SNAPSHOT_ID}
standalone_bootstrap_response=ready
activated_response=activated
post_nack_response=activated
valid_rollout_phase=ACTIVE
invalid_rollout_phase=CANCELLED
reconnect_verified=true
listener_restart_nack_verified=true
EOF

CHECKSUM_FILE="${WORK_DIR}/SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "${EVIDENCE_DIR}"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 |
      sort -z | xargs -0 sha256sum >"${CHECKSUM_FILE}"
  )
else
  (
    cd "${EVIDENCE_DIR}"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -print |
      LC_ALL=C sort | xargs shasum -a 256 >"${CHECKSUM_FILE}"
  )
fi
mv "${CHECKSUM_FILE}" "${EVIDENCE_DIR}/SHA256SUMS"

printf 'Phase 4 discovery integration passed. Evidence: %s\n' "${EVIDENCE_DIR}"
