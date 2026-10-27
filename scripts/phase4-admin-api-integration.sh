#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}
NODE_ID=${BONVOYAGE_ADMIN_NODE_ID:-node-a}
CONTROL_PORT=${BONVOYAGE_ADMIN_DISCOVERY_PORT:-$((24000 + ($$ % 12000)))}
ADMIN_PORT=${BONVOYAGE_ADMIN_API_PORT:-$((CONTROL_PORT + 1))}
EVIDENCE_DIR=${BONVOYAGE_ADMIN_EVIDENCE_DIR:-}
TEMP_ROOT=${TMPDIR:-/tmp}
TEMP_ROOT=${TEMP_ROOT%/}
WORK_DIR=$(mktemp -d "${TEMP_ROOT}/bonvoyage-phase4-admin.XXXXXX")
FAILURE_EVIDENCE_DIR="${TEMP_ROOT}/bonvoyage-phase4-admin-failure-$$"
CONTAINER_NAME="bonvoyage-phase4-admin-$$"
CONTROL_PID=
AUTH_GENERATION=0
CURRENT_CONTROL_LOG=

fail() {
  printf 'phase4 Admin API integration: %s\n' "$*" >&2
  mkdir -p "${FAILURE_EVIDENCE_DIR}" 2>/dev/null || true
  if docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    docker inspect "${CONTAINER_NAME}" --format 'dataplane state={{json .State}}' >&2 || true
    docker logs "${CONTAINER_NAME}" >&2 || true
    docker inspect "${CONTAINER_NAME}" --format '{{json .State}}' \
      >"${FAILURE_EVIDENCE_DIR}/dataplane-state.json" 2>/dev/null || true
    docker logs "${CONTAINER_NAME}" \
      >"${FAILURE_EVIDENCE_DIR}/dataplane.log" 2>&1 || true
  fi
  if [[ -n "${CURRENT_CONTROL_LOG}" && -f "${CURRENT_CONTROL_LOG}" ]]; then
    tail -n 100 "${CURRENT_CONTROL_LOG}" >&2 || true
  fi
  for log_file in "${WORK_DIR}"/control-*.log; do
    [[ -f "${log_file}" ]] || continue
    cp "${log_file}" "${FAILURE_EVIDENCE_DIR}/" 2>/dev/null || true
  done
  for response_file in "${WORK_DIR}"/*-response.json* "${WORK_DIR}"/*-status.json* \
    "${WORK_DIR}"/*-problem.json*; do
    [[ -f "${response_file}" ]] || continue
    cp "${response_file}" "${FAILURE_EVIDENCE_DIR}/" 2>/dev/null || true
  done
  [[ ! -f "${WORK_DIR}/admin-authorizations.json" ]] || \
    cp "${WORK_DIR}/admin-authorizations.json" "${FAILURE_EVIDENCE_DIR}/" 2>/dev/null || true
  [[ ! -f "${WORK_DIR}/admin-tls/node.pem" ]] || \
    cp "${WORK_DIR}/admin-tls/node.pem" "${FAILURE_EVIDENCE_DIR}/admin-client-certificate.pem" \
      2>/dev/null || true
  printf 'failure diagnostics: %s\n' "${FAILURE_EVIDENCE_DIR}" >&2
  exit 1
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

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

wait_for_log() {
  local log_file=$1
  local pattern=$2
  for ((attempt = 0; attempt < 300; ++attempt)); do
    if grep -Fq "${pattern}" "${log_file}" 2>/dev/null; then
      return 0
    fi
    if [[ -n "${CONTROL_PID}" ]] && ! kill -0 "${CONTROL_PID}" 2>/dev/null; then
      cat "${log_file}" >&2 || true
      fail "control-plane process stopped while waiting for ${pattern}"
    fi
    sleep 0.1
  done
  fail "timed out waiting for ${pattern}"
}

json_value() {
  node -e '
    const fs = require("fs");
    let value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    for (const component of process.argv[2].split(".")) value = value[component];
    if (value === undefined || value === null) process.exit(2);
    process.stdout.write(String(value));
  ' "$1" "$2"
}

admin_call() {
  local method=$1
  local path=$2
  local input=$3
  local output=$4
  shift 4
  local arguments=(
    --silent --show-error
    --cert "${WORK_DIR}/admin-tls/node.pem"
    --key "${WORK_DIR}/admin-tls/node-key.pem"
    --cacert "${WORK_DIR}/admin-tls/ca.pem"
    --resolve "admin.test:${ADMIN_PORT}:127.0.0.1"
    --request "${method}"
    --output "${output}.tmp"
    --write-out '%{http_code}'
  )
  if [[ -n "${input}" ]]; then
    arguments+=(--header 'Content-Type: application/json' --data-binary "@${input}")
  fi
  arguments+=("$@" "https://admin.test:${ADMIN_PORT}${path}")
  local status
  status=$(curl "${arguments[@]}")
  mv "${output}.tmp" "${output}"
  printf '%s\n' "${status}"
}

wait_for_admin_status() {
  local sequence=$1
  local phase=$2
  local snapshot_id=$3
  local output=$4
  local status
  for ((attempt = 0; attempt < 400; ++attempt)); do
    status=$(admin_call GET /api/v1/rollouts/current '' "${output}.tmp" 2>/dev/null || true)
    if [[ "${status}" == 200 ]] &&
       [[ "$(json_value "${output}.tmp" sequence 2>/dev/null || true)" == "${sequence}" ]] &&
       [[ "$(json_value "${output}.tmp" phase 2>/dev/null || true)" == "${phase}" ]] &&
       [[ "$(json_value "${output}.tmp" artifact.snapshot_id 2>/dev/null || true)" == "${snapshot_id}" ]]; then
      mv "${output}.tmp" "${output}"
      return 0
    fi
    if [[ "${status}" == 401 || "${status}" == 403 ]]; then
      fail "Admin status request was rejected with HTTP ${status}"
    fi
    sleep 0.1
  done
  fail "timed out waiting for rollout ${sequence} phase ${phase} snapshot ${snapshot_id}"
}

wait_for_gateway_body() {
  local port=$1
  local expected=$2
  local output=$3
  for ((attempt = 0; attempt < 300; ++attempt)); do
    if curl --fail --silent --show-error "http://127.0.0.1:${port}/bonvoyage/ready" >"${output}.tmp" 2>/dev/null &&
       grep -Fxq "${expected}" "${output}.tmp"; then
      mv "${output}.tmp" "${output}"
      return 0
    fi
    sleep 0.1
  done
  fail "timed out waiting for gateway response ${expected}"
}

write_authorizations() {
  local fingerprint=$1
  local role=$2
  AUTH_GENERATION=$((AUTH_GENERATION + 1))
  node -e '
    const fs = require("fs");
    const now = new Date();
    const document = {
      version: 1,
      generation: Number(process.argv[2]),
      updated_at: now.toISOString(),
      valid_until: new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
      principals: [{
        spiffe_id: "spiffe://admin.routesphere.test/bonvoyage/operators/operator-a",
        certificate_sha256: "sha256:" + process.argv[3],
        role: process.argv[4],
        source_channel: "gitops",
      }],
    };
    fs.writeFileSync(process.argv[1], JSON.stringify(document, null, 2));
  ' "${WORK_DIR}/admin-authorizations.next" "${AUTH_GENERATION}" "${fingerprint}" "${role}"
  chmod 600 "${WORK_DIR}/admin-authorizations.next"
  mv -f "${WORK_DIR}/admin-authorizations.next" "${WORK_DIR}/admin-authorizations.json"
}

start_control_plane() {
  local bootstrap_sequence=$1
  local log_file=$2
  : >"${log_file}"
  CURRENT_CONTROL_LOG=${log_file}
  "${WORK_DIR}/bonvoyage-control-plane" serve-discovery \
    -repository-root "${WORK_DIR}/repository" \
    -rollout-sequence "${bootstrap_sequence}" \
    -listen-address "0.0.0.0:${CONTROL_PORT}" \
    -tls-server-cert "${WORK_DIR}/node-tls/server.pem" \
    -tls-server-key "${WORK_DIR}/node-tls/server-key.pem" \
    -tls-client-ca "${WORK_DIR}/node-tls/ca.pem" \
    -spiffe-trust-domain routesphere.test \
    -spiffe-node-path-prefix /bonvoyage/nodes/ \
    -admin-listen-address "127.0.0.1:${ADMIN_PORT}" \
    -admin-tls-server-cert "${WORK_DIR}/admin-tls/server.pem" \
    -admin-tls-server-key "${WORK_DIR}/admin-tls/server-key.pem" \
    -admin-tls-client-ca "${WORK_DIR}/admin-tls/ca.pem" \
    -admin-tls-server-name admin.test \
    -admin-authorizations "${WORK_DIR}/admin-authorizations.json" \
    -admin-spiffe-trust-domain admin.routesphere.test \
    -admin-spiffe-operator-path-prefix /bonvoyage/operators/ \
    -admin-spiffe-service-account-path-prefix /bonvoyage/service-accounts/ \
    -admin-max-concurrent 32 >"${log_file}" 2>&1 &
  CONTROL_PID=$!
  wait_for_log "${log_file}" 'Admin API listener ready:'
  wait_for_log "${log_file}" 'discovery listener ready:'
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

make_preview_request() {
  node -e '
    const fs = require("fs");
    fs.writeFileSync(process.argv[3], JSON.stringify({
      document: fs.readFileSync(process.argv[1], "utf8"),
      baseline_rollout_sequence: Number(process.argv[2]),
      target_node_ids: ["node-a"],
    }));
  ' "$1" "$2" "$3"
}

make_apply_request() {
  node -e '
    const fs = require("fs");
    fs.writeFileSync(process.argv[6], JSON.stringify({
      document: fs.readFileSync(process.argv[1], "utf8"),
      source_revision: "git:phase4-checkpoint-9",
      reason: process.argv[5],
      target_node_ids: ["node-a"],
      expected_selected_rollout_sequence: Number(process.argv[2]),
      expected_active_artifact_sha256: process.argv[3],
      preview_fingerprint_sha256: process.argv[4],
    }));
  ' "$1" "$2" "$3" "$4" "$5" "$6"
}

make_rollback_request() {
  node -e '
    const fs = require("fs");
    fs.writeFileSync(process.argv[5], JSON.stringify({
      reason: "restore exact retained baseline",
      target_node_ids: ["node-a"],
      expected_selected_rollout_sequence: Number(process.argv[1]),
      expected_active_artifact_sha256: process.argv[2],
      rollback_target_sequence: Number(process.argv[3]),
      preview_fingerprint_sha256: process.argv[4],
    }));
  ' "$1" "$2" "$3" "$4" "$5"
}

for command in docker go curl git node openssl; do
  require_command "${command}"
done
docker image inspect "${IMAGE}" >/dev/null 2>&1 ||
  fail "dataplane image is unavailable: ${IMAGE}"
if [[ "${CONTROL_PORT}" == "${ADMIN_PORT}" ]]; then
  fail "discovery and Admin ports must differ"
fi
if [[ -z "${EVIDENCE_DIR}" ]]; then
  EVIDENCE_DIR="${WORK_DIR}/evidence"
fi
mkdir -p "${EVIDENCE_DIR}" "${WORK_DIR}/node-tls" "${WORK_DIR}/admin-tls"

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
  -tls-directory "${WORK_DIR}/node-tls" \
  -node-id "${NODE_ID}" >"${WORK_DIR}/fixture.env"
"${WORK_DIR}/discoveryfixture" generate-tls \
  -tls-directory "${WORK_DIR}/admin-tls" \
  -node-id operator-a \
  -server-name admin.test \
  -spiffe-trust-domain admin.routesphere.test \
  -spiffe-path-prefix /bonvoyage/operators/

while IFS='=' read -r key value; do
  case "${key}" in
    VALID_SEQUENCE) BASELINE_SEQUENCE=${value} ;;
    INVALID_SEQUENCE) RESERVED_SEQUENCE=${value} ;;
    BOOTSTRAP_SNAPSHOT_ID) BOOTSTRAP_SNAPSHOT_ID=${value} ;;
    VALID_SNAPSHOT_ID) BASELINE_SNAPSHOT_ID=${value} ;;
  esac
done <"${WORK_DIR}/fixture.env"
: "${BASELINE_SEQUENCE:?missing baseline sequence}"
: "${RESERVED_SEQUENCE:?missing reserved sequence}"
: "${BOOTSTRAP_SNAPSHOT_ID:?missing bootstrap snapshot ID}"
: "${BASELINE_SNAPSHOT_ID:?missing baseline snapshot ID}"

ADMIN_FINGERPRINT=$(openssl x509 -in "${WORK_DIR}/admin-tls/node.pem" -outform DER |
  openssl dgst -sha256 -r | awk '{print $1}')
[[ "${ADMIN_FINGERPRINT}" =~ ^[0-9a-f]{64}$ ]] || fail "could not derive Admin certificate fingerprint"
write_authorizations "${ADMIN_FINGERPRINT}" operator

docker run --detach \
  --name "${CONTAINER_NAME}" \
  --add-host host.docker.internal:host-gateway \
  --publish 127.0.0.1::8080 \
  --publish 127.0.0.1::9901 \
  --volume "${WORK_DIR}/bootstrap.pb:/etc/bonvoyage/snapshot.pb:ro" \
  --volume "${WORK_DIR}/node-tls/ca.pem:/etc/bonvoyage/discovery/ca.pem:ro" \
  --volume "${WORK_DIR}/node-tls/node.pem:/etc/bonvoyage/discovery/node.pem:ro" \
  --volume "${WORK_DIR}/node-tls/node-key.pem:/etc/bonvoyage/discovery/node-key.pem:ro" \
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
[[ -n "${GATEWAY_PORT}" ]] || fail "Docker did not publish the gateway port"
DATAPLANE_PID=$(docker inspect "${CONTAINER_NAME}" --format '{{.State.Pid}}')
INITIAL_RESTARTS=$(docker inspect "${CONTAINER_NAME}" --format '{{.RestartCount}}')
wait_for_gateway_body "${GATEWAY_PORT}" ready "${WORK_DIR}/bootstrap-response.txt"
start_control_plane "${BASELINE_SEQUENCE}" "${WORK_DIR}/control-initial.log"
wait_for_gateway_body "${GATEWAY_PORT}" activated "${WORK_DIR}/baseline-response.txt"
wait_for_admin_status "${BASELINE_SEQUENCE}" ACTIVE "${BASELINE_SNAPSHOT_ID}" \
  "${WORK_DIR}/baseline-status.json"
BASELINE_DIGEST=$(json_value "${WORK_DIR}/baseline-status.json" artifact.artifact_sha256)

node -e '
  const fs = require("fs");
  fs.writeFileSync(process.argv[2], JSON.stringify({document: fs.readFileSync(process.argv[1], "utf8")}));
' "${ROOT_DIR}/control-plane/tests/testdata/phase4-admin-api-candidate.yaml" \
  "${WORK_DIR}/validate-request.json"
[[ "$(admin_call POST /api/v1/configurations/validate "${WORK_DIR}/validate-request.json" "${WORK_DIR}/validate-response.json")" == 200 ]] ||
  fail "configuration validation did not return 200"

make_preview_request \
  "${ROOT_DIR}/control-plane/tests/testdata/phase4-admin-api-candidate.yaml" \
  "${BASELINE_SEQUENCE}" "${WORK_DIR}/preview-request.json"
[[ "$(admin_call POST /api/v1/configurations/preview "${WORK_DIR}/preview-request.json" "${WORK_DIR}/preview-response.json")" == 200 ]] ||
  fail "configuration preview did not return 200"
PREVIEW_FINGERPRINT=$(json_value "${WORK_DIR}/preview-response.json" plan_fingerprint_sha256)
[[ "$(json_value "${WORK_DIR}/preview-response.json" no_change)" == false ]] || fail "preview reported no change"

make_apply_request \
  "${ROOT_DIR}/control-plane/tests/testdata/phase4-admin-api-candidate.yaml" \
  "${BASELINE_SEQUENCE}" "${BASELINE_DIGEST}" "${PREVIEW_FINGERPRINT}" \
  'activate Admin API candidate' "${WORK_DIR}/apply-request.json"
APPLY_KEY=checkpoint9-apply-idempotency-0001
apply_pids=()
for attempt in 1 2 3 4 5 6 7 8; do
  (
    admin_call POST /api/v1/rollouts "${WORK_DIR}/apply-request.json" \
      "${WORK_DIR}/apply-response-${attempt}.json" \
      --header "Idempotency-Key: ${APPLY_KEY}" >"${WORK_DIR}/apply-status-${attempt}.txt"
  ) &
  apply_pids+=("$!")
done
for pid in "${apply_pids[@]}"; do
  wait "${pid}" || fail "concurrent idempotent apply request failed"
done
APPLIED_SEQUENCE=
for attempt in 1 2 3 4 5 6 7 8; do
  [[ "$(cat "${WORK_DIR}/apply-status-${attempt}.txt")" == 202 ]] ||
    fail "concurrent apply ${attempt} did not return 202"
  sequence=$(json_value "${WORK_DIR}/apply-response-${attempt}.json" status.sequence)
  if [[ -z "${APPLIED_SEQUENCE}" ]]; then
    APPLIED_SEQUENCE=${sequence}
  elif [[ "${sequence}" != "${APPLIED_SEQUENCE}" ]]; then
    fail "idempotent apply allocated multiple rollout sequences"
  fi
done
[[ "${APPLIED_SEQUENCE}" == "$((RESERVED_SEQUENCE + 1))" ]] ||
  fail "unexpected apply sequence ${APPLIED_SEQUENCE}"
APPLIED_DIGEST=$(json_value "${WORK_DIR}/apply-response-1.json" status.artifact.artifact_sha256)
wait_for_admin_status "${APPLIED_SEQUENCE}" ACTIVE phase4-admin-api-candidate \
  "${WORK_DIR}/applied-status.json"
wait_for_gateway_body "${GATEWAY_PORT}" admin-api-candidate "${WORK_DIR}/applied-response.txt"

make_apply_request \
  "${ROOT_DIR}/control-plane/tests/testdata/phase4-admin-api-candidate.yaml" \
  "${BASELINE_SEQUENCE}" "${BASELINE_DIGEST}" "${PREVIEW_FINGERPRINT}" \
  'changed replay must fail' "${WORK_DIR}/changed-replay-request.json"
[[ "$(admin_call POST /api/v1/rollouts "${WORK_DIR}/changed-replay-request.json" \
  "${WORK_DIR}/changed-replay-problem.json" --header "Idempotency-Key: ${APPLY_KEY}")" == 409 ]] ||
  fail "changed idempotency replay was not rejected"
[[ "$(admin_call POST /api/v1/rollouts "${WORK_DIR}/apply-request.json" \
  "${WORK_DIR}/stale-write-problem.json" --header 'Idempotency-Key: checkpoint9-stale-writer-0001')" == 409 ]] ||
  fail "stale selected-rollout precondition was not rejected"
[[ "$(admin_call GET "/api/v1/rollouts/${APPLIED_SEQUENCE}/diagnostics" '' \
  "${WORK_DIR}/applied-diagnostics.json")" == 200 ]] || fail "diagnostics did not return 200"

node -e '
  const fs = require("fs");
  fs.writeFileSync(process.argv[4], JSON.stringify({
    current_rollout_sequence: Number(process.argv[1]),
    target_rollout_sequence: Number(process.argv[2]),
    target_node_ids: ["node-a"],
  }));
' "${APPLIED_SEQUENCE}" "${BASELINE_SEQUENCE}" ignored "${WORK_DIR}/rollback-preview-request.json"
[[ "$(admin_call POST /api/v1/rollbacks/preview "${WORK_DIR}/rollback-preview-request.json" \
  "${WORK_DIR}/rollback-preview-response.json")" == 200 ]] || fail "rollback preview did not return 200"
ROLLBACK_FINGERPRINT=$(json_value "${WORK_DIR}/rollback-preview-response.json" plan_fingerprint_sha256)
make_rollback_request "${APPLIED_SEQUENCE}" "${APPLIED_DIGEST}" "${BASELINE_SEQUENCE}" \
  "${ROLLBACK_FINGERPRINT}" "${WORK_DIR}/rollback-request.json"
[[ "$(admin_call POST /api/v1/rollbacks "${WORK_DIR}/rollback-request.json" \
  "${WORK_DIR}/rollback-response.json" --header 'Idempotency-Key: checkpoint9-rollback-idempotency-01')" == 202 ]] ||
  fail "rollback did not return 202"
ROLLBACK_SEQUENCE=$(json_value "${WORK_DIR}/rollback-response.json" status.sequence)
[[ "$(json_value "${WORK_DIR}/rollback-response.json" status.artifact.artifact_sha256)" == "${BASELINE_DIGEST}" ]] ||
  fail "rollback did not select the exact retained baseline artifact"
wait_for_admin_status "${ROLLBACK_SEQUENCE}" ACTIVE "${BASELINE_SNAPSHOT_ID}" \
  "${WORK_DIR}/rollback-status.json"
wait_for_gateway_body "${GATEWAY_PORT}" activated "${WORK_DIR}/rollback-response.txt"

write_authorizations "$(printf '0%.0s' {1..64})" operator
[[ "$(admin_call GET /api/v1/rollouts/current '' "${WORK_DIR}/fingerprint-problem.json")" == 401 ]] ||
  fail "wrong positive-authorization fingerprint was accepted"
write_authorizations "${ADMIN_FINGERPRINT}" viewer
[[ "$(admin_call POST /api/v1/rollbacks "${WORK_DIR}/rollback-request.json" \
  "${WORK_DIR}/viewer-problem.json" --header 'Idempotency-Key: checkpoint9-viewer-denial-0001')" == 403 ]] ||
  fail "viewer principal could mutate rollout state"
write_authorizations "${ADMIN_FINGERPRINT}" operator
[[ "$(admin_call GET /api/v1/rollouts/current '' "${WORK_DIR}/origin-problem.json" \
  --header 'Origin: https://browser.example')" == 403 ]] || fail "browser-origin request was accepted"
printf '{"document":"one","document":"two"}' >"${WORK_DIR}/duplicate-request.json"
[[ "$(admin_call POST /api/v1/configurations/validate "${WORK_DIR}/duplicate-request.json" \
  "${WORK_DIR}/duplicate-problem.json")" == 400 ]] || fail "duplicate JSON keys were accepted"

if curl --silent --show-error --cacert "${WORK_DIR}/admin-tls/ca.pem" \
  --resolve "admin.test:${ADMIN_PORT}:127.0.0.1" \
  "https://admin.test:${ADMIN_PORT}/api/v1/rollouts/current" \
  >"${WORK_DIR}/missing-client-cert.log" 2>&1; then
  fail "Admin listener accepted a request without a client certificate"
fi
if curl --silent --show-error \
  --cert "${WORK_DIR}/node-tls/node.pem" --key "${WORK_DIR}/node-tls/node-key.pem" \
  --cacert "${WORK_DIR}/admin-tls/ca.pem" --resolve "admin.test:${ADMIN_PORT}:127.0.0.1" \
  "https://admin.test:${ADMIN_PORT}/api/v1/rollouts/current" \
  >"${WORK_DIR}/node-certificate-rejection.log" 2>&1; then
  fail "Admin listener accepted a node-plane client certificate"
fi
if curl --silent --show-error --tls-max 1.2 \
  --cert "${WORK_DIR}/admin-tls/node.pem" --key "${WORK_DIR}/admin-tls/node-key.pem" \
  --cacert "${WORK_DIR}/admin-tls/ca.pem" --resolve "admin.test:${ADMIN_PORT}:127.0.0.1" \
  "https://admin.test:${ADMIN_PORT}/api/v1/rollouts/current" \
  >"${WORK_DIR}/tls12-rejection.log" 2>&1; then
  fail "Admin listener accepted TLS 1.2"
fi

stop_control_plane
start_control_plane "${BASELINE_SEQUENCE}" "${WORK_DIR}/control-restart.log"
wait_for_log "${WORK_DIR}/control-restart.log" "rollout_sequence=${ROLLBACK_SEQUENCE}"
wait_for_admin_status "${ROLLBACK_SEQUENCE}" ACTIVE "${BASELINE_SNAPSHOT_ID}" \
  "${WORK_DIR}/restart-status.json"
wait_for_gateway_body "${GATEWAY_PORT}" activated "${WORK_DIR}/restart-response.txt"
[[ "$(docker inspect "${CONTAINER_NAME}" --format '{{.State.Pid}}')" == "${DATAPLANE_PID}" ]] ||
  fail "dataplane process identity changed"
[[ "$(docker inspect "${CONTAINER_NAME}" --format '{{.RestartCount}}')" == "${INITIAL_RESTARTS}" ]] ||
  fail "dataplane container restarted"

docker logs "${CONTAINER_NAME}" >"${WORK_DIR}/dataplane.log" 2>&1
docker inspect "${CONTAINER_NAME}" --format '{{json .State}}' >"${WORK_DIR}/dataplane-state.json"
stop_control_plane
"${WORK_DIR}/discoveryfixture" verify -repository "${WORK_DIR}/repository" \
  -sequence "${BASELINE_SEQUENCE}" -phase ACTIVE -node-id "${NODE_ID}" -node-phase ACTIVE \
  -minimum-events 4 >"${WORK_DIR}/baseline.verify"
"${WORK_DIR}/discoveryfixture" verify -repository "${WORK_DIR}/repository" \
  -sequence "${APPLIED_SEQUENCE}" -phase ACTIVE -node-id "${NODE_ID}" -node-phase ACTIVE \
  -minimum-events 4 >"${WORK_DIR}/applied.verify"
"${WORK_DIR}/discoveryfixture" verify -repository "${WORK_DIR}/repository" \
  -sequence "${ROLLBACK_SEQUENCE}" -phase ACTIVE -node-id "${NODE_ID}" -node-phase ACTIVE \
  -minimum-events 4 >"${WORK_DIR}/rollback.verify"
docker stop --time 10 "${CONTAINER_NAME}" >/dev/null

docker inspect "${IMAGE}" --format '{{.Id}}' >"${WORK_DIR}/image-id.txt"
git -C "${ROOT_DIR}" rev-parse HEAD >"${WORK_DIR}/source-commit.txt"
git -C "${ROOT_DIR}" status --porcelain >"${WORK_DIR}/source-status.txt"
if [[ -s "${WORK_DIR}/source-status.txt" ]]; then
  printf 'true\n' >"${WORK_DIR}/source-dirty.txt"
else
  printf 'false\n' >"${WORK_DIR}/source-dirty.txt"
fi

cp "${WORK_DIR}/fixture.env" "${EVIDENCE_DIR}/"
cp "${WORK_DIR}"/*-response.json "${WORK_DIR}"/*-status.json \
  "${WORK_DIR}"/*-diagnostics.json "${WORK_DIR}"/*-problem.json \
  "${WORK_DIR}"/*.verify "${WORK_DIR}"/control-*.log "${WORK_DIR}/dataplane.log" \
  "${WORK_DIR}/dataplane-state.json" "${WORK_DIR}/image-id.txt" \
  "${WORK_DIR}/source-commit.txt" "${WORK_DIR}/source-status.txt" \
  "${WORK_DIR}/source-dirty.txt" "${EVIDENCE_DIR}/"
cp "${WORK_DIR}"/*-rejection.log "${WORK_DIR}/missing-client-cert.log" "${EVIDENCE_DIR}/"

if grep -R -Fq -- 'PRIVATE KEY-----' "${EVIDENCE_DIR}"; then
  fail "retained evidence contains private-key material"
fi
if grep -R -Fq -- "${WORK_DIR}" "${EVIDENCE_DIR}"/*problem.json; then
  fail "sanitized problem response exposed an internal path"
fi

{
  echo 'checkpoint=Phase 4 Checkpoint 9 standalone Admin API and GitOps surface'
  echo 'transport=separate TLS 1.3 mutual-TLS HTTP/1.1 Admin listener'
  echo 'authorization=fresh fingerprint-pinned SPIFFE positive authorization'
  echo 'api_operations=validate,preview,apply,status,diagnostics,rollback'
  echo "baseline_sequence=${BASELINE_SEQUENCE}"
  echo "apply_sequence=${APPLIED_SEQUENCE}"
  echo "rollback_sequence=${ROLLBACK_SEQUENCE}"
  echo 'concurrent_idempotent_apply_attempts=8'
  echo 'changed_replay_rejected=true'
  echo 'stale_writer_rejected=true'
  echo 'exact_retained_artifact_rollback=true'
  echo 'persisted_selection_restart=true'
  echo 'missing_client_certificate_rejected=true'
  echo 'node_plane_certificate_rejected=true'
  echo 'tls12_rejected=true'
  echo 'wrong_fingerprint_rejected=true'
  echo 'viewer_mutation_rejected=true'
  echo 'browser_origin_rejected=true'
  echo 'duplicate_json_key_rejected=true'
  echo "dataplane_pid=${DATAPLANE_PID}"
  echo "container_restarts=${INITIAL_RESTARTS}"
} >"${EVIDENCE_DIR}/summary.txt"

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

printf 'Phase 4 Admin API integration passed. Evidence: %s\n' "${EVIDENCE_DIR}"
