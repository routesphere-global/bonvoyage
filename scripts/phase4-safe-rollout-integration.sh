#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}
CONTROL_PORT=${BONVOYAGE_SAFE_ROLLOUT_DISCOVERY_PORT:-$((25000 + ($$ % 10000)))}
ADMIN_PORT=${BONVOYAGE_SAFE_ROLLOUT_ADMIN_PORT:-$((CONTROL_PORT + 1))}
EVIDENCE_DIR=${BONVOYAGE_SAFE_ROLLOUT_EVIDENCE_DIR:-}
TEMP_ROOT=${TMPDIR:-/tmp}
TEMP_ROOT=${TEMP_ROOT%/}
WORK_DIR=$(mktemp -d "${TEMP_ROOT}/bonvoyage-phase4-safe-rollout.XXXXXX")
FAILURE_EVIDENCE_DIR="${TEMP_ROOT}/bonvoyage-phase4-safe-rollout-failure-$$"
NODE_IDS=(node-a node-b node-c)
CERT_PREFIXES=(node node-b node-c)
CONTAINER_NAMES=(
  "bonvoyage-phase4-safe-node-a-$$"
  "bonvoyage-phase4-safe-node-b-$$"
  "bonvoyage-phase4-safe-node-c-$$"
)
GATEWAY_PORTS=()
DATAPLANE_PIDS=()
INITIAL_RESTARTS=()
CONTROL_PID=
CURRENT_CONTROL_LOG=
AUTH_GENERATION=0

fail() {
  printf 'phase4 safe rollout integration: %s\n' "$*" >&2
  mkdir -p "${FAILURE_EVIDENCE_DIR}" 2>/dev/null || true
  for container in "${CONTAINER_NAMES[@]}"; do
    docker unpause "${container}" >/dev/null 2>&1 || true
    if docker inspect "${container}" >/dev/null 2>&1; then
      docker inspect "${container}" --format 'dataplane state={{json .State}}' >&2 || true
      docker logs "${container}" >&2 || true
      docker inspect "${container}" --format '{{json .State}}' \
        >"${FAILURE_EVIDENCE_DIR}/${container}-state.json" 2>/dev/null || true
      docker logs "${container}" \
        >"${FAILURE_EVIDENCE_DIR}/${container}.log" 2>&1 || true
    fi
  done
  if [[ -n "${CURRENT_CONTROL_LOG}" && -f "${CURRENT_CONTROL_LOG}" ]]; then
    tail -n 150 "${CURRENT_CONTROL_LOG}" >&2 || true
  fi
  for file in "${WORK_DIR}"/*.json "${WORK_DIR}"/*.log "${WORK_DIR}"/*.txt; do
    [[ -f "${file}" ]] || continue
    cp "${file}" "${FAILURE_EVIDENCE_DIR}/" 2>/dev/null || true
  done
  printf 'failure diagnostics: %s\n' "${FAILURE_EVIDENCE_DIR}" >&2
  exit 1
}

cleanup() {
  for container in "${CONTAINER_NAMES[@]}"; do
    docker unpause "${container}" >/dev/null 2>&1 || true
  done
  if [[ -n "${CONTROL_PID}" ]] && kill -0 "${CONTROL_PID}" 2>/dev/null; then
    kill -TERM "${CONTROL_PID}" 2>/dev/null || true
    wait "${CONTROL_PID}" 2>/dev/null || true
  fi
  for container in "${CONTAINER_NAMES[@]}"; do
    docker rm --force "${container}" >/dev/null 2>&1 || true
  done
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

wait_for_log() {
  local log_file=$1
  local pattern=$2
  for ((attempt = 0; attempt < 400; ++attempt)); do
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
  for ((attempt = 0; attempt < 600; ++attempt)); do
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

wait_for_automatic_rollback() {
  local failed_sequence=$1
  local target_sequence=$2
  local output=$3
  local status sequence kind target
  for ((attempt = 0; attempt < 600; ++attempt)); do
    status=$(admin_call GET /api/v1/rollouts/current '' "${output}.tmp" 2>/dev/null || true)
    sequence=$(json_value "${output}.tmp" sequence 2>/dev/null || true)
    kind=$(json_value "${output}.tmp" kind 2>/dev/null || true)
    target=$(json_value "${output}.tmp" rollback_target_sequence 2>/dev/null || true)
    if [[ "${status}" == 200 && "${sequence}" -gt "${failed_sequence}" &&
          "${kind}" == ROLLBACK && "${target}" == "${target_sequence}" ]]; then
      mv "${output}.tmp" "${output}"
      return 0
    fi
    sleep 0.1
  done
  fail "timed out waiting for automatic rollback of rollout ${failed_sequence}"
}

wait_for_node_phases() {
  local sequence=$1
  local fleet_phase=$2
  local expected_node_phase=$3
  local expected_count=$4
  local output=$5
  local status
  for ((attempt = 0; attempt < 600; ++attempt)); do
    status=$(admin_call GET "/api/v1/rollouts/${sequence}" '' "${output}.tmp" 2>/dev/null || true)
    if [[ "${status}" == 200 ]] && node -e '
      const fs = require("fs");
      const status = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const phase = process.argv[2];
      const nodePhase = process.argv[3];
      const count = Number(process.argv[4]);
      if (status.phase !== phase || status.nodes.length !== count ||
          !status.nodes.every((node) => node.phase === nodePhase)) process.exit(1);
    ' "${output}.tmp" "${fleet_phase}" "${expected_node_phase}" "${expected_count}"; then
      mv "${output}.tmp" "${output}"
      return 0
    fi
    sleep 0.1
  done
  fail "timed out waiting for rollout ${sequence} node phase ${expected_node_phase}"
}

wait_for_gateway_body() {
  local port=$1
  local expected=$2
  local output=$3
  for ((attempt = 0; attempt < 400; ++attempt)); do
    if curl --fail --silent --show-error "http://127.0.0.1:${port}/bonvoyage/ready" \
      >"${output}.tmp" 2>/dev/null && grep -Fxq "${expected}" "${output}.tmp"; then
      mv "${output}.tmp" "${output}"
      return 0
    fi
    sleep 0.1
  done
  fail "timed out waiting for gateway response ${expected} on port ${port}"
}

wait_for_all_gateway_bodies() {
  local expected=$1
  local prefix=$2
  local index
  for index in "${!NODE_IDS[@]}"; do
    wait_for_gateway_body "${GATEWAY_PORTS[${index}]}" "${expected}" \
      "${WORK_DIR}/${prefix}-${NODE_IDS[${index}]}.txt"
  done
}

write_authorizations() {
  local fingerprint=$1
  AUTH_GENERATION=$((AUTH_GENERATION + 1))
  node -e '
    const fs = require("fs");
    const now = new Date();
    fs.writeFileSync(process.argv[1], JSON.stringify({
      version: 1,
      generation: Number(process.argv[2]),
      updated_at: now.toISOString(),
      valid_until: new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
      principals: [{
        spiffe_id: "spiffe://admin.routesphere.test/bonvoyage/operators/operator-a",
        certificate_sha256: "sha256:" + process.argv[3],
        role: "operator",
        source_channel: "gitops",
      }],
    }, null, 2));
  ' "${WORK_DIR}/admin-authorizations.next" "${AUTH_GENERATION}" "${fingerprint}"
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
    -admin-max-concurrent 32 \
    -rollout-policy-interval 100ms >"${log_file}" 2>&1 &
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

write_preview_request() {
  local document=$1
  local baseline_sequence=$2
  local targets=$3
  local output=$4
  node -e '
    const fs = require("fs");
    fs.writeFileSync(process.argv[4], JSON.stringify({
      document: fs.readFileSync(process.argv[1], "utf8"),
      baseline_rollout_sequence: Number(process.argv[2]),
      target_node_ids: process.argv[3].split(","),
      policy: {
        strategy: "CANARY",
        canary_node_ids: ["node-a"],
        minimum_healthy_canary_percent: 100,
        canary_observation_seconds: 5,
        prepare_timeout_seconds: 15,
        activation_timeout_seconds: 15,
        heartbeat_stale_after_seconds: 1,
        automatic_rollback: true,
      },
    }));
  ' "${document}" "${baseline_sequence}" "${targets}" "${output}"
}

write_apply_request() {
  local document=$1
  local selected_sequence=$2
  local selected_digest=$3
  local preview_fingerprint=$4
  local targets=$5
  local reason=$6
  local output=$7
  node -e '
    const fs = require("fs");
    fs.writeFileSync(process.argv[7], JSON.stringify({
      document: fs.readFileSync(process.argv[1], "utf8"),
      source_revision: "git:phase4-checkpoint-10",
      reason: process.argv[6],
      target_node_ids: process.argv[5].split(","),
      expected_selected_rollout_sequence: Number(process.argv[2]),
      expected_active_artifact_sha256: process.argv[3],
      preview_fingerprint_sha256: process.argv[4],
      policy: {
        strategy: "CANARY",
        canary_node_ids: ["node-a"],
        minimum_healthy_canary_percent: 100,
        canary_observation_seconds: 5,
        prepare_timeout_seconds: 15,
        activation_timeout_seconds: 15,
        heartbeat_stale_after_seconds: 1,
        automatic_rollback: true,
      },
    }));
  ' "${document}" "${selected_sequence}" "${selected_digest}" "${preview_fingerprint}" \
    "${targets}" "${reason}" "${output}"
}

prepare_rollout_request() {
  local label=$1
  local document=$2
  local baseline_sequence=$3
  local baseline_digest=$4
  local targets=$5
  local reason=$6
  write_preview_request "${document}" "${baseline_sequence}" "${targets}" \
    "${WORK_DIR}/${label}-preview-request.json"
  [[ "$(admin_call POST /api/v1/configurations/preview \
    "${WORK_DIR}/${label}-preview-request.json" "${WORK_DIR}/${label}-preview-response.json")" == 200 ]] ||
    fail "${label} preview did not return 200"
  local fingerprint
  fingerprint=$(json_value "${WORK_DIR}/${label}-preview-response.json" plan_fingerprint_sha256)
  write_apply_request "${document}" "${baseline_sequence}" "${baseline_digest}" "${fingerprint}" \
    "${targets}" "${reason}" "${WORK_DIR}/${label}-apply-request.json"
}

for command in docker go curl git node openssl; do
  require_command "${command}"
done
docker image inspect "${IMAGE}" >/dev/null 2>&1 || fail "dataplane image is unavailable: ${IMAGE}"
if [[ "${CONTROL_PORT}" == "${ADMIN_PORT}" ]]; then
  fail "discovery and Admin ports must differ"
fi
if [[ -z "${EVIDENCE_DIR}" ]]; then
  EVIDENCE_DIR="${TEMP_ROOT}/bonvoyage-phase4-safe-rollout-evidence-$$"
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
  -node-id node-a \
  -node-ids node-a,node-b,node-c >"${WORK_DIR}/fixture.env"
for node_id in node-b node-c; do
  "${WORK_DIR}/discoveryfixture" issue-client \
    -tls-directory "${WORK_DIR}/node-tls" \
    -node-id "${node_id}" \
    -output-prefix "${node_id}"
done
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
    VALID_SNAPSHOT_ID) BASELINE_SNAPSHOT_ID=${value} ;;
  esac
done <"${WORK_DIR}/fixture.env"
: "${BASELINE_SEQUENCE:?missing baseline sequence}"
: "${RESERVED_SEQUENCE:?missing reserved sequence}"
: "${BASELINE_SNAPSHOT_ID:?missing baseline snapshot ID}"

ADMIN_FINGERPRINT=$(openssl x509 -in "${WORK_DIR}/admin-tls/node.pem" -outform DER |
  openssl dgst -sha256 -r | awk '{print $1}')
[[ "${ADMIN_FINGERPRINT}" =~ ^[0-9a-f]{64}$ ]] || fail "could not derive Admin certificate fingerprint"
write_authorizations "${ADMIN_FINGERPRINT}"

for index in "${!NODE_IDS[@]}"; do
  node_id=${NODE_IDS[${index}]}
  certificate_prefix=${CERT_PREFIXES[${index}]}
  container=${CONTAINER_NAMES[${index}]}
  docker run --detach \
    --name "${container}" \
    --add-host host.docker.internal:host-gateway \
    --publish 127.0.0.1::8080 \
    --publish 127.0.0.1::9901 \
    --volume "${WORK_DIR}/bootstrap.pb:/etc/bonvoyage/snapshot.pb:ro" \
    --volume "${WORK_DIR}/node-tls/ca.pem:/etc/bonvoyage/discovery/ca.pem:ro" \
    --volume "${WORK_DIR}/node-tls/${certificate_prefix}.pem:/etc/bonvoyage/discovery/node.pem:ro" \
    --volume "${WORK_DIR}/node-tls/${certificate_prefix}-key.pem:/etc/bonvoyage/discovery/node-key.pem:ro" \
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
    --discovery-node-id "${node_id}" \
    --discovery-heartbeat-interval-ms 250 \
    --discovery-reconnect-initial-backoff-ms 50 \
    --discovery-reconnect-max-backoff-ms 500 \
    --smp 2 \
    --memory 512M \
    --overprovisioned >/dev/null
  port=$(docker port "${container}" 8080/tcp | sed -n '1s/.*://p')
  [[ -n "${port}" ]] || fail "Docker did not publish the gateway port for ${node_id}"
  GATEWAY_PORTS+=("${port}")
  DATAPLANE_PIDS+=("$(docker inspect "${container}" --format '{{.State.Pid}}')")
  INITIAL_RESTARTS+=("$(docker inspect "${container}" --format '{{.RestartCount}}')")
done

wait_for_all_gateway_bodies ready bootstrap
start_control_plane "${BASELINE_SEQUENCE}" "${WORK_DIR}/control-initial.log"
wait_for_all_gateway_bodies activated baseline
wait_for_admin_status "${BASELINE_SEQUENCE}" ACTIVE "${BASELINE_SNAPSHOT_ID}" \
  "${WORK_DIR}/baseline-status.json"
wait_for_node_phases "${BASELINE_SEQUENCE}" ACTIVE ACTIVE 3 "${WORK_DIR}/baseline-nodes.json"
BASELINE_DIGEST=$(json_value "${WORK_DIR}/baseline-status.json" artifact.artifact_sha256)

# Healthy canary: only node-a may activate before the observation window closes.
prepare_rollout_request healthy \
  "${ROOT_DIR}/control-plane/tests/testdata/phase4-admin-api-candidate.yaml" \
  "${BASELINE_SEQUENCE}" "${BASELINE_DIGEST}" node-a,node-b,node-c \
  'prove health-gated canary promotion'
[[ "$(admin_call POST /api/v1/rollouts "${WORK_DIR}/healthy-apply-request.json" \
  "${WORK_DIR}/healthy-apply-response.json" \
  --header 'Idempotency-Key: checkpoint10-healthy-canary-0001')" == 202 ]] ||
  fail "healthy canary apply did not return 202"
HEALTHY_SEQUENCE=$(json_value "${WORK_DIR}/healthy-apply-response.json" status.sequence)
HEALTHY_SNAPSHOT_ID=$(json_value "${WORK_DIR}/healthy-apply-response.json" status.artifact.snapshot_id)
HEALTHY_DIGEST=$(json_value "${WORK_DIR}/healthy-apply-response.json" status.artifact.artifact_sha256)
[[ "${HEALTHY_SEQUENCE}" == "$((RESERVED_SEQUENCE + 1))" ]] ||
  fail "unexpected healthy rollout sequence ${HEALTHY_SEQUENCE}"
wait_for_admin_status "${HEALTHY_SEQUENCE}" OBSERVING "${HEALTHY_SNAPSHOT_ID}" \
  "${WORK_DIR}/healthy-observing-status.json"
wait_for_gateway_body "${GATEWAY_PORTS[0]}" admin-api-candidate \
  "${WORK_DIR}/healthy-observing-node-a.txt"
wait_for_gateway_body "${GATEWAY_PORTS[1]}" activated \
  "${WORK_DIR}/healthy-observing-node-b.txt"
wait_for_gateway_body "${GATEWAY_PORTS[2]}" activated \
  "${WORK_DIR}/healthy-observing-node-c.txt"
wait_for_admin_status "${HEALTHY_SEQUENCE}" ACTIVE "${HEALTHY_SNAPSHOT_ID}" \
  "${WORK_DIR}/healthy-active-status.json"
wait_for_node_phases "${HEALTHY_SEQUENCE}" ACTIVE ACTIVE 3 "${WORK_DIR}/healthy-active-nodes.json"
wait_for_all_gateway_bodies admin-api-candidate healthy-active
[[ "$(admin_call GET "/api/v1/rollouts/${HEALTHY_SEQUENCE}/diagnostics" '' \
  "${WORK_DIR}/healthy-diagnostics.json")" == 200 ]] || fail "healthy diagnostics did not return 200"

# Failed canary: make the active canary stale and require an exact mixed-fleet rollback.
prepare_rollout_request failure \
  "${ROOT_DIR}/control-plane/tests/testdata/phase4-live-candidate.yaml" \
  "${HEALTHY_SEQUENCE}" "${HEALTHY_DIGEST}" node-a,node-b,node-c \
  'prove stale-canary automatic exact rollback'
[[ "$(admin_call POST /api/v1/rollouts "${WORK_DIR}/failure-apply-request.json" \
  "${WORK_DIR}/failure-apply-response.json" \
  --header 'Idempotency-Key: checkpoint10-failed-canary-0001')" == 202 ]] ||
  fail "failure canary apply did not return 202"
FAILED_SEQUENCE=$(json_value "${WORK_DIR}/failure-apply-response.json" status.sequence)
FAILED_SNAPSHOT_ID=$(json_value "${WORK_DIR}/failure-apply-response.json" status.artifact.snapshot_id)
wait_for_admin_status "${FAILED_SEQUENCE}" OBSERVING "${FAILED_SNAPSHOT_ID}" \
  "${WORK_DIR}/failure-observing-status.json"
wait_for_gateway_body "${GATEWAY_PORTS[0]}" activated "${WORK_DIR}/failure-observing-node-a.txt"
wait_for_gateway_body "${GATEWAY_PORTS[1]}" admin-api-candidate \
  "${WORK_DIR}/failure-observing-node-b.txt"
wait_for_gateway_body "${GATEWAY_PORTS[2]}" admin-api-candidate \
  "${WORK_DIR}/failure-observing-node-c.txt"
docker pause "${CONTAINER_NAMES[0]}" >/dev/null
wait_for_admin_status "${FAILED_SEQUENCE}" REQUIRES_ROLLBACK "${FAILED_SNAPSHOT_ID}" \
  "${WORK_DIR}/failure-requires-rollback-status.json"
docker unpause "${CONTAINER_NAMES[0]}" >/dev/null
wait_for_automatic_rollback "${FAILED_SEQUENCE}" "${HEALTHY_SEQUENCE}" \
  "${WORK_DIR}/automatic-rollback-selected-status.json"
ROLLBACK_SEQUENCE=$(json_value "${WORK_DIR}/automatic-rollback-selected-status.json" sequence)
wait_for_admin_status "${ROLLBACK_SEQUENCE}" ACTIVE "${HEALTHY_SNAPSHOT_ID}" \
  "${WORK_DIR}/automatic-rollback-active-status.json"
wait_for_node_phases "${ROLLBACK_SEQUENCE}" ACTIVE ACTIVE 3 \
  "${WORK_DIR}/automatic-rollback-active-nodes.json"
wait_for_all_gateway_bodies admin-api-candidate automatic-rollback
[[ "$(admin_call GET "/api/v1/rollouts/${FAILED_SEQUENCE}" '' \
  "${WORK_DIR}/failed-final-status.json")" == 200 ]] || fail "failed rollout status did not return 200"
[[ "$(json_value "${WORK_DIR}/failed-final-status.json" phase)" == REQUIRES_ROLLBACK ]] ||
  fail "failed canary did not retain REQUIRES_ROLLBACK"
[[ "$(admin_call GET "/api/v1/rollouts/${FAILED_SEQUENCE}/diagnostics" '' \
  "${WORK_DIR}/failure-diagnostics.json")" == 200 ]] || fail "failure diagnostics did not return 200"
[[ "$(admin_call GET "/api/v1/rollouts/${ROLLBACK_SEQUENCE}/diagnostics" '' \
  "${WORK_DIR}/automatic-rollback-diagnostics.json")" == 200 ]] ||
  fail "automatic rollback diagnostics did not return 200"

# Restart replay must retain the selected exact rollback and reconcile every node.
stop_control_plane
start_control_plane "${BASELINE_SEQUENCE}" "${WORK_DIR}/control-restart.log"
wait_for_log "${WORK_DIR}/control-restart.log" "rollout_sequence=${ROLLBACK_SEQUENCE}"
wait_for_admin_status "${ROLLBACK_SEQUENCE}" ACTIVE "${HEALTHY_SNAPSHOT_ID}" \
  "${WORK_DIR}/restart-status.json"
wait_for_all_gateway_bodies admin-api-candidate restart

# Cancellation is last: an absent fourth target deterministically holds PREPARE.
prepare_rollout_request cancellation \
  "${ROOT_DIR}/control-plane/tests/testdata/phase4-live-candidate.yaml" \
  "${ROLLBACK_SEQUENCE}" "${HEALTHY_DIGEST}" node-a,node-b,node-c,node-missing \
  'prove explicit pre-activation cancellation'
[[ "$(admin_call POST /api/v1/rollouts "${WORK_DIR}/cancellation-apply-request.json" \
  "${WORK_DIR}/cancellation-apply-response.json" \
  --header 'Idempotency-Key: checkpoint10-cancellation-apply-0001')" == 202 ]] ||
  fail "cancellation setup apply did not return 202"
CANCEL_SEQUENCE=$(json_value "${WORK_DIR}/cancellation-apply-response.json" status.sequence)
CANCEL_SNAPSHOT_ID=$(json_value "${WORK_DIR}/cancellation-apply-response.json" status.artifact.snapshot_id)
wait_for_admin_status "${CANCEL_SEQUENCE}" PREPARING "${CANCEL_SNAPSHOT_ID}" \
  "${WORK_DIR}/cancellation-preparing-status.json"
printf '{"reason":"operator cancelled before activation"}' >"${WORK_DIR}/cancel-request.json"
[[ "$(admin_call POST "/api/v1/rollouts/${CANCEL_SEQUENCE}/cancel" \
  "${WORK_DIR}/cancel-request.json" "${WORK_DIR}/cancel-response.json" \
  --header 'Idempotency-Key: checkpoint10-cancel-0001')" == 202 ]] ||
  fail "rollout cancellation did not return 202"
[[ "$(admin_call POST "/api/v1/rollouts/${CANCEL_SEQUENCE}/cancel" \
  "${WORK_DIR}/cancel-request.json" "${WORK_DIR}/cancel-replay-response.json" \
  --header 'Idempotency-Key: checkpoint10-cancel-0001')" == 202 ]] ||
  fail "idempotent cancellation replay did not return 202"
wait_for_admin_status "${CANCEL_SEQUENCE}" CANCELLED "${CANCEL_SNAPSHOT_ID}" \
  "${WORK_DIR}/cancelled-fleet-status.json"
node -e '
  const fs = require("fs");
  const status = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const byNode = new Map(status.nodes.map((node) => [node.node_id, node.phase]));
  for (const node of ["node-a", "node-b", "node-c"])
    if (byNode.get(node) !== "CANCELLED") process.exit(1);
  if (byNode.get("node-missing") !== "CANCEL_PENDING") process.exit(1);
' "${WORK_DIR}/cancelled-fleet-status.json" || fail "cancelled rollout node states are incorrect"
wait_for_all_gateway_bodies admin-api-candidate cancelled
[[ "$(admin_call GET "/api/v1/rollouts/${CANCEL_SEQUENCE}/diagnostics" '' \
  "${WORK_DIR}/cancellation-diagnostics.json")" == 200 ]] ||
  fail "cancellation diagnostics did not return 200"

for index in "${!NODE_IDS[@]}"; do
  container=${CONTAINER_NAMES[${index}]}
  [[ "$(docker inspect "${container}" --format '{{.State.Pid}}')" == "${DATAPLANE_PIDS[${index}]}" ]] ||
    fail "${NODE_IDS[${index}]} process identity changed"
  [[ "$(docker inspect "${container}" --format '{{.RestartCount}}')" == "${INITIAL_RESTARTS[${index}]}" ]] ||
    fail "${NODE_IDS[${index}]} container restarted"
  docker logs "${container}" >"${WORK_DIR}/${NODE_IDS[${index}]}-dataplane.log" 2>&1
  docker inspect "${container}" --format '{{json .State}}' \
    >"${WORK_DIR}/${NODE_IDS[${index}]}-dataplane-state.json"
done

stop_control_plane
for node_id in "${NODE_IDS[@]}"; do
  "${WORK_DIR}/discoveryfixture" verify -repository "${WORK_DIR}/repository" \
    -sequence "${HEALTHY_SEQUENCE}" -phase ACTIVE -node-id "${node_id}" -node-phase ACTIVE \
    -minimum-events 8 >"${WORK_DIR}/healthy-${node_id}.verify"
  "${WORK_DIR}/discoveryfixture" verify -repository "${WORK_DIR}/repository" \
    -sequence "${FAILED_SEQUENCE}" -phase REQUIRES_ROLLBACK -node-id "${node_id}" \
    -node-phase "$([[ "${node_id}" == node-a ]] && printf ACTIVE || printf PRIOR_ACTIVE)" \
    -minimum-events 6 >"${WORK_DIR}/failed-${node_id}.verify"
  "${WORK_DIR}/discoveryfixture" verify -repository "${WORK_DIR}/repository" \
    -sequence "${ROLLBACK_SEQUENCE}" -phase ACTIVE -node-id "${node_id}" -node-phase ACTIVE \
    -minimum-events 4 >"${WORK_DIR}/rollback-${node_id}.verify"
  "${WORK_DIR}/discoveryfixture" verify -repository "${WORK_DIR}/repository" \
    -sequence "${CANCEL_SEQUENCE}" -phase CANCELLED -node-id "${node_id}" -node-phase CANCELLED \
    -minimum-events 4 >"${WORK_DIR}/cancelled-${node_id}.verify"
done
"${WORK_DIR}/discoveryfixture" verify -repository "${WORK_DIR}/repository" \
  -sequence "${CANCEL_SEQUENCE}" -phase CANCELLED -node-id node-missing -node-phase CANCEL_PENDING \
  -minimum-events 4 >"${WORK_DIR}/cancelled-node-missing.verify"

for container in "${CONTAINER_NAMES[@]}"; do
  docker stop --time 10 "${container}" >/dev/null
done
docker inspect "${IMAGE}" --format '{{.Id}}' >"${WORK_DIR}/image-id.txt"
git -C "${ROOT_DIR}" rev-parse HEAD >"${WORK_DIR}/source-commit.txt"
git -C "${ROOT_DIR}" status --porcelain >"${WORK_DIR}/source-status.txt"
if [[ -s "${WORK_DIR}/source-status.txt" ]]; then
  printf 'true\n' >"${WORK_DIR}/source-dirty.txt"
else
  printf 'false\n' >"${WORK_DIR}/source-dirty.txt"
fi

for file in "${WORK_DIR}"/*.json "${WORK_DIR}"/*.log "${WORK_DIR}"/*.txt \
  "${WORK_DIR}"/*.verify "${WORK_DIR}/fixture.env"; do
  [[ -f "${file}" ]] || continue
  cp "${file}" "${EVIDENCE_DIR}/"
done
if grep -R -Fq -- 'PRIVATE KEY-----' "${EVIDENCE_DIR}"; then
  fail "retained evidence contains private-key material"
fi
if grep -R -Fq -- "${WORK_DIR}" "${EVIDENCE_DIR}"/*.json; then
  fail "retained API evidence exposed an internal path"
fi

{
  echo 'checkpoint=Phase 4 Checkpoint 10 deterministic safe rollout policy'
  echo 'topology=three independently authenticated live dataplane nodes'
  echo 'policy=single canary,100 percent healthy threshold,5 second observation,1 second freshness'
  echo "baseline_sequence=${BASELINE_SEQUENCE}"
  echo "healthy_sequence=${HEALTHY_SEQUENCE}"
  echo "failed_sequence=${FAILED_SEQUENCE}"
  echo "automatic_rollback_sequence=${ROLLBACK_SEQUENCE}"
  echo "cancelled_sequence=${CANCEL_SEQUENCE}"
  echo 'canary_isolation_before_promotion=true'
  echo 'health_gated_promotion=true'
  echo 'stale_canary_detected=true'
  echo 'automatic_exact_mixed_fleet_rollback=true'
  echo 'selected_rollout_replay_after_restart=true'
  echo 'pre_activation_cancellation=true'
  echo 'missing_target_cancel_pending=true'
  echo 'real_targets_cancelled=true'
  echo 'dataplane_process_identity_stable=true'
  echo 'dataplane_container_restarts=0'
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

printf 'Phase 4 safe rollout integration passed. Evidence: %s\n' "${EVIDENCE_DIR}"
