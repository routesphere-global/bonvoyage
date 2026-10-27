#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}
CONTROL_PORT=${BONVOYAGE_OPERATIONS_DISCOVERY_PORT:-$((26000 + ($$ % 9000)))}
ADMIN_PORT=${BONVOYAGE_OPERATIONS_ADMIN_PORT:-$((CONTROL_PORT + 1))}
EVIDENCE_DIR=${BONVOYAGE_OPERATIONS_EVIDENCE_DIR:-}
TEMP_ROOT=${TMPDIR:-/tmp}
TEMP_ROOT=${TEMP_ROOT%/}
WORK_DIR=$(mktemp -d "${TEMP_ROOT}/bonvoyage-phase4-operations.XXXXXX")
FAILURE_EVIDENCE_DIR="${TEMP_ROOT}/bonvoyage-phase4-operations-failure-$$"
NODE_IDS=(node-a node-b node-c)
CERT_PREFIXES=(node node-b node-c)
CONTAINER_NAMES=(
  "bonvoyage-phase4-operations-node-a-$$"
  "bonvoyage-phase4-operations-node-b-$$"
  "bonvoyage-phase4-operations-node-c-$$"
)
GATEWAY_PORTS=()
DATAPLANE_PIDS=()
INITIAL_RESTARTS=()
CONTROL_PID=
CURRENT_CONTROL_LOG=
AUTH_GENERATION=0

fail() {
  printf 'phase4 operational recovery integration: %s\n' "$*" >&2
  mkdir -p "${FAILURE_EVIDENCE_DIR}" 2>/dev/null || true
  for container in "${CONTAINER_NAMES[@]}"; do
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
  for file in "${WORK_DIR}"/*.json "${WORK_DIR}"/*.log "${WORK_DIR}"/*.txt \
    "${WORK_DIR}"/*.prom; do
    [[ -f "${file}" ]] || continue
    cp "${file}" "${FAILURE_EVIDENCE_DIR}/" 2>/dev/null || true
  done
  printf 'failure diagnostics: %s\n' "${FAILURE_EVIDENCE_DIR}" >&2
  exit 1
}

cleanup() {
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
  local output=$3
  local status
  status=$(curl --silent --show-error \
    --cert "${WORK_DIR}/admin-tls/node.pem" \
    --key "${WORK_DIR}/admin-tls/node-key.pem" \
    --cacert "${WORK_DIR}/admin-tls/ca.pem" \
    --resolve "admin.test:${ADMIN_PORT}:127.0.0.1" \
    --request "${method}" \
    --output "${output}.tmp" \
    --write-out '%{http_code}' \
    "https://admin.test:${ADMIN_PORT}${path}")
  mv "${output}.tmp" "${output}"
  printf '%s\n' "${status}"
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

wait_for_reconciled_status() {
  local output=$1
  local status
  for ((attempt = 0; attempt < 600; ++attempt)); do
    status=$(admin_call GET /api/v1/rollouts/current "${output}.tmp" 2>/dev/null || true)
    if [[ "${status}" == 200 ]] && node -e '
      const fs = require("fs");
      const status = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      if (status.phase !== "ACTIVE" || status.nodes.length !== 3 ||
          status.connections.length !== 3 ||
          !status.nodes.every((node) => node.phase === "ACTIVE" && node.connected) ||
          !status.connections.every((connection) => connection.reconciled)) process.exit(1);
    ' "${output}.tmp"; then
      mv "${output}.tmp" "${output}"
      return 0
    fi
    sleep 0.1
  done
  fail "timed out waiting for three reconciled active nodes"
}

wait_for_metrics() {
  local output=$1
  local status
  for ((attempt = 0; attempt < 400; ++attempt)); do
    status=$(admin_call GET /metrics "${output}.tmp" 2>/dev/null || true)
    if [[ "${status}" == 200 ]] &&
      grep -Fxq 'bonvoyage_control_plane_ready 1' "${output}.tmp" &&
      grep -Fxq 'bonvoyage_control_plane_runtime_authority_match 1' "${output}.tmp" &&
      grep -Fxq 'bonvoyage_control_plane_connected_nodes 3' "${output}.tmp" &&
      grep -Fxq 'bonvoyage_control_plane_reconciled_nodes 3' "${output}.tmp" &&
      grep -Fxq 'bonvoyage_control_plane_unreconciled_nodes 0' "${output}.tmp" &&
      grep -Fxq 'bonvoyage_control_plane_rollout_phase{phase="ACTIVE"} 1' "${output}.tmp"; then
      mv "${output}.tmp" "${output}"
      return 0
    fi
    sleep 0.1
  done
  fail "timed out waiting for converged control-plane metrics"
}

metric_value() {
  local file=$1
  local metric=$2
  awk -v metric="${metric}" '$1 == metric { print $2; exit }' "${file}"
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
        role: "viewer",
        source_channel: "api",
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

run_outage_load() {
  local port=$1
  local output=$2
  local successful=0
  local body
  for ((request = 0; request < 200; ++request)); do
    body=$(curl --fail --silent --show-error --connect-timeout 1 --max-time 2 \
      "http://127.0.0.1:${port}/bonvoyage/ready") || return 1
    [[ "${body}" == activated ]] || return 1
    successful=$((successful + 1))
  done
  printf '%d\n' "${successful}" >"${output}"
}

for command in docker go curl git node openssl awk; do
  require_command "${command}"
done
docker image inspect "${IMAGE}" >/dev/null 2>&1 || fail "dataplane image is unavailable: ${IMAGE}"
[[ "${CONTROL_PORT}" != "${ADMIN_PORT}" ]] || fail "discovery and Admin ports must differ"
if [[ -z "${EVIDENCE_DIR}" ]]; then
  EVIDENCE_DIR="${TEMP_ROOT}/bonvoyage-phase4-operations-evidence-$$"
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
    VALID_SNAPSHOT_ID) BASELINE_SNAPSHOT_ID=${value} ;;
  esac
done <"${WORK_DIR}/fixture.env"
: "${BASELINE_SEQUENCE:?missing baseline sequence}"
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
wait_for_all_gateway_bodies activated active
wait_for_reconciled_status "${WORK_DIR}/pre-outage-status.json"
wait_for_metrics "${WORK_DIR}/pre-outage-metrics.prom"
[[ "$(admin_call GET "/api/v1/rollouts/${BASELINE_SEQUENCE}/audit?limit=2" \
  "${WORK_DIR}/pre-audit-page-1.json")" == 200 ]] || fail "first audit page did not return 200"
NEXT_INDEX=$(json_value "${WORK_DIR}/pre-audit-page-1.json" journal.next_after_index)
[[ "$(admin_call GET "/api/v1/rollouts/${BASELINE_SEQUENCE}/audit?after_index=${NEXT_INDEX}&limit=250" \
  "${WORK_DIR}/pre-audit-page-2.json")" == 200 ]] || fail "second audit page did not return 200"
[[ "$(admin_call GET "/api/v1/rollouts/${BASELINE_SEQUENCE}/audit?limit=250" \
  "${WORK_DIR}/pre-audit-full.json")" == 200 ]] || fail "complete bounded audit page did not return 200"
node -e '
  const fs = require("fs");
  const first = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const second = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const full = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
  if (first.manifest_sha256 !== second.manifest_sha256 ||
      first.manifest_sha256 !== full.manifest_sha256 ||
      first.journal.events.length !== 2 ||
      first.journal.next_after_index !== first.journal.last_index ||
      first.journal.events.length + second.journal.events.length !== full.journal.total_events ||
      full.journal.events.length !== full.journal.total_events ||
      !full.journal.events.every((event) => /^[0-9a-f]{64}$/.test(event.event_sha256))) process.exit(1);
' "${WORK_DIR}/pre-audit-page-1.json" "${WORK_DIR}/pre-audit-page-2.json" \
  "${WORK_DIR}/pre-audit-full.json" || fail "audit pagination or manifest binding is invalid"

stop_control_plane
if curl --silent --show-error --connect-timeout 1 --max-time 1 \
  --cert "${WORK_DIR}/admin-tls/node.pem" \
  --key "${WORK_DIR}/admin-tls/node-key.pem" \
  --cacert "${WORK_DIR}/admin-tls/ca.pem" \
  --resolve "admin.test:${ADMIN_PORT}:127.0.0.1" \
  "https://admin.test:${ADMIN_PORT}/metrics" >"${WORK_DIR}/outage-admin-unreachable.log" 2>&1; then
  fail "Admin endpoint remained reachable after the control plane stopped"
fi

OUTAGE_LOAD_PIDS=()
for index in "${!NODE_IDS[@]}"; do
  run_outage_load "${GATEWAY_PORTS[${index}]}" \
    "${WORK_DIR}/outage-${NODE_IDS[${index}]}-successes.txt" &
  OUTAGE_LOAD_PIDS+=("$!")
done
for pid in "${OUTAGE_LOAD_PIDS[@]}"; do
  wait "${pid}" || fail "dataplane traffic failed while the control plane was absent"
done
for node_id in "${NODE_IDS[@]}"; do
  [[ "$(<"${WORK_DIR}/outage-${node_id}-successes.txt")" == 200 ]] ||
    fail "${node_id} did not serve all outage requests"
done

sleep 1.2
start_control_plane "${BASELINE_SEQUENCE}" "${WORK_DIR}/control-restart.log"
wait_for_reconciled_status "${WORK_DIR}/post-restart-status.json"
wait_for_metrics "${WORK_DIR}/post-restart-metrics.prom"
wait_for_all_gateway_bodies activated recovered
[[ "$(admin_call GET "/api/v1/rollouts/${BASELINE_SEQUENCE}/audit?limit=250" \
  "${WORK_DIR}/post-restart-audit.json")" == 200 ]] || fail "post-restart audit did not return 200"

node -e '
  const fs = require("fs");
  const before = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const after = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  if (after.manifest_sha256 === before.manifest_sha256 ||
      after.journal.total_events <= before.journal.total_events ||
      after.rollout.actor !== before.rollout.actor ||
      after.rollout.artifact_sha256 !== before.rollout.artifact_sha256 ||
      after.rollout.target_node_ids.join(",") !== before.rollout.target_node_ids.join(",")) process.exit(1);
  for (let index = 0; index < before.journal.events.length; ++index) {
    const left = before.journal.events[index];
    const right = after.journal.events[index];
    if (!right || left.index !== right.index || left.event_sha256 !== right.event_sha256) process.exit(1);
  }
' "${WORK_DIR}/pre-audit-full.json" "${WORK_DIR}/post-restart-audit.json" ||
  fail "restart changed retained audit lineage or failed to append reconciliation"

PRE_START=$(metric_value "${WORK_DIR}/pre-outage-metrics.prom" \
  bonvoyage_control_plane_process_start_time_seconds)
POST_START=$(metric_value "${WORK_DIR}/post-restart-metrics.prom" \
  bonvoyage_control_plane_process_start_time_seconds)
[[ -n "${PRE_START}" && -n "${POST_START}" && "${POST_START}" -gt "${PRE_START}" ]] ||
  fail "process restart was not visible in operational metrics"
RECONNECTS=$(metric_value "${WORK_DIR}/post-restart-metrics.prom" \
  'bonvoyage_control_plane_journal_event_kind{kind="RECONNECT"}')
[[ -n "${RECONNECTS}" && "${RECONNECTS}" -ge 6 ]] ||
  fail "post-restart metrics did not retain reconnect evidence"
if grep -Eq 'actor=|artifact=|digest=|node=|node_id=|request_id=|rollout_id=|sequence=|tenant=|user=' \
  "${WORK_DIR}/post-restart-metrics.prom"; then
  fail "control-plane metrics contain a forbidden high-cardinality label"
fi
for identity in "${NODE_IDS[@]}"; do
  grep -Fq "${identity}" "${WORK_DIR}/post-restart-metrics.prom" &&
    fail "control-plane metrics exposed node identity ${identity}"
done

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
    -sequence "${BASELINE_SEQUENCE}" -phase ACTIVE -node-id "${node_id}" -node-phase ACTIVE \
    -minimum-events 5 >"${WORK_DIR}/${node_id}.verify"
done
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
  "${WORK_DIR}"/*.prom "${WORK_DIR}"/*.verify "${WORK_DIR}/fixture.env"; do
  [[ -f "${file}" ]] || continue
  cp "${file}" "${EVIDENCE_DIR}/"
done
if grep -R -Fq -- 'PRIVATE KEY-----' "${EVIDENCE_DIR}"; then
  fail "retained evidence contains private-key material"
fi
if grep -R -Fq -- "${WORK_DIR}" "${EVIDENCE_DIR}"/*.json; then
  fail "retained API evidence exposed an internal path"
fi

PRE_EVENTS=$(json_value "${WORK_DIR}/pre-audit-full.json" journal.total_events)
POST_EVENTS=$(json_value "${WORK_DIR}/post-restart-audit.json" journal.total_events)
PRE_MANIFEST=$(json_value "${WORK_DIR}/pre-audit-full.json" manifest_sha256)
POST_MANIFEST=$(json_value "${WORK_DIR}/post-restart-audit.json" manifest_sha256)
{
  echo 'checkpoint=Phase 4 Checkpoint 11 operational telemetry audit and recovery'
  echo 'topology=three independently authenticated live dataplane nodes'
  echo 'admin_identity_role=viewer'
  echo "rollout_sequence=${BASELINE_SEQUENCE}"
  echo 'outage_requests_per_node=200'
  echo 'outage_successful_requests=600'
  echo 'dataplane_continued_without_control_plane=true'
  echo 'dataplane_process_identity_stable=true'
  echo 'dataplane_container_restarts=0'
  echo 'runtime_authority_match_after_restart=true'
  echo 'all_nodes_reconciled_after_restart=true'
  echo 'metrics_fixed_cardinality=true'
  echo "pre_restart_journal_events=${PRE_EVENTS}"
  echo "post_restart_journal_events=${POST_EVENTS}"
  echo "pre_restart_audit_manifest_sha256=${PRE_MANIFEST}"
  echo "post_restart_audit_manifest_sha256=${POST_MANIFEST}"
  echo 'retained_audit_prefix_unchanged=true'
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

printf 'Phase 4 operational recovery integration passed. Evidence: %s\n' "${EVIDENCE_DIR}"
