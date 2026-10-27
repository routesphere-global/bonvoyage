#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}
NODE_ID=${BONVOYAGE_IDENTITY_NODE_ID:-node-a}
CONTROL_PORT=${BONVOYAGE_IDENTITY_DISCOVERY_PORT:-$((22000 + ($$ % 15000)))}
ENROLLMENT_PORT=${BONVOYAGE_IDENTITY_ENROLLMENT_PORT:-$((CONTROL_PORT + 1))}
EVIDENCE_DIR=${BONVOYAGE_IDENTITY_EVIDENCE_DIR:-}
TMP_BASE=${TMPDIR:-/tmp}
WORK_DIR=$(mktemp -d "${TMP_BASE%/}/bonvoyage-phase4-identity.XXXXXX")
CONTAINER_NAME="bonvoyage-phase4-identity-$$"
CONTROL_PID=

fail() {
  printf 'phase4 identity lifecycle: %s\n' "$*" >&2
  if docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    docker inspect "${CONTAINER_NAME}" --format 'dataplane state={{json .State}}' >&2 || true
    docker logs "${CONTAINER_NAME}" >&2 || true
  fi
  if [[ -f "${WORK_DIR}/control.log" ]]; then
    tail -n 100 "${WORK_DIR}/control.log" >&2 || true
  fi
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
  local attempts=${3:-300}
  for ((attempt = 0; attempt < attempts; ++attempt)); do
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

wait_for_pattern_count_greater() {
  local source=$1
  local pattern=$2
  local baseline=$3
  local attempts=${4:-300}
  local count
  for ((attempt = 0; attempt < attempts; ++attempt)); do
    if [[ "${source}" == container ]]; then
      docker logs "${CONTAINER_NAME}" >"${WORK_DIR}/dataplane-current.log" 2>&1 || true
      count=$(grep -Fc "${pattern}" "${WORK_DIR}/dataplane-current.log" || true)
    else
      count=$(grep -Fc "${pattern}" "${source}" 2>/dev/null || true)
    fi
    if ((count > baseline)); then
      printf '%s\n' "${count}"
      return 0
    fi
    sleep 0.1
  done
  fail "timed out waiting for a new ${pattern} record"
}

pattern_count() {
  local source=$1
  local pattern=$2
  if [[ "${source}" == container ]]; then
    docker logs "${CONTAINER_NAME}" >"${WORK_DIR}/dataplane-current.log" 2>&1 || true
    grep -Fc "${pattern}" "${WORK_DIR}/dataplane-current.log" || true
  else
    grep -Fc "${pattern}" "${source}" 2>/dev/null || true
  fi
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

atomic_replace() {
  local source=$1
  local destination=$2
  local mode=$3
  local temporary="${destination}.checkpoint8.$$"
  install -m "${mode}" "${source}" "${temporary}"
  mv -f "${temporary}" "${destination}"
}

bump_credential_generation() {
  local root=$1
  local marker="${root}/current-generation.json"
  local temporary="${marker}.checkpoint8.$$"
  cp "${marker}" "${temporary}"
  printf '\n' >>"${temporary}"
  chmod 600 "${temporary}"
  mv -f "${temporary}" "${marker}"
}

credential_hashes() {
  local root=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${root}/ca.pem" "${root}/node.pem" "${root}/node-key.pem"
  else
    shasum -a 256 "${root}/ca.pem" "${root}/node.pem" "${root}/node-key.pem"
  fi
}

verify_rollout() {
  local output=$1
  local minimum_events=$2
  "${WORK_DIR}/discoveryfixture" verify \
    -repository "${WORK_DIR}/repository" \
    -sequence "${VALID_SEQUENCE}" \
    -phase ACTIVE \
    -node-id "${NODE_ID}" \
    -node-phase ACTIVE \
    -minimum-events "${minimum_events}" >"${output}"
}

for command in docker go curl git install; do
  require_command "${command}"
done
docker image inspect "${IMAGE}" >/dev/null 2>&1 || fail "dataplane image is unavailable: ${IMAGE}"

if [[ -z "${EVIDENCE_DIR}" ]]; then
  EVIDENCE_DIR="${WORK_DIR}/evidence"
fi
mkdir -p "${EVIDENCE_DIR}"
mkdir -p "${WORK_DIR}/tls-old" "${WORK_DIR}/tls-new" "${WORK_DIR}/control-tls"

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
  -tls-directory "${WORK_DIR}/tls-old" \
  -node-id "${NODE_ID}" >"${WORK_DIR}/fixture.env"
"${WORK_DIR}/discoveryfixture" generate-tls \
  -tls-directory "${WORK_DIR}/tls-new" \
  -node-id "${NODE_ID}"

while IFS='=' read -r key value; do
  case "${key}" in
    VALID_SEQUENCE) VALID_SEQUENCE=${value} ;;
    BOOTSTRAP_SNAPSHOT_ID) BOOTSTRAP_SNAPSHOT_ID=${value} ;;
    VALID_SNAPSHOT_ID) VALID_SNAPSHOT_ID=${value} ;;
  esac
done <"${WORK_DIR}/fixture.env"
: "${VALID_SEQUENCE:?missing valid sequence}"
: "${BOOTSTRAP_SNAPSHOT_ID:?missing bootstrap snapshot ID}"
: "${VALID_SNAPSHOT_ID:?missing valid snapshot ID}"

atomic_replace "${WORK_DIR}/tls-old/server.pem" "${WORK_DIR}/control-tls/server.pem" 600
atomic_replace "${WORK_DIR}/tls-old/server-key.pem" "${WORK_DIR}/control-tls/server-key.pem" 600
atomic_replace "${WORK_DIR}/tls-old/issuer.pem" "${WORK_DIR}/control-tls/issuer.pem" 600
atomic_replace "${WORK_DIR}/tls-old/issuer-key.pem" "${WORK_DIR}/control-tls/issuer-key.pem" 600
atomic_replace "${WORK_DIR}/tls-old/ca.pem" "${WORK_DIR}/control-tls/trust-bundle.pem" 600

"${WORK_DIR}/bonvoyage-control-plane" initialize-revocations \
  -revocation-file "${WORK_DIR}/control-tls/revocations.json" \
  -valid-for 24h >"${WORK_DIR}/revocation-initialize.txt"
"${WORK_DIR}/bonvoyage-control-plane" issue-enrollment-token \
  -identity-repository-root "${WORK_DIR}/identity-repository" \
  -node-id "${NODE_ID}" \
  -audience phase4-checkpoint-8 \
  -ttl 10m \
  -token-output "${WORK_DIR}/enrollment.token" >"${WORK_DIR}/token-issue.txt"

"${WORK_DIR}/bonvoyage-control-plane" serve-discovery \
  -repository-root "${WORK_DIR}/repository" \
  -rollout-sequence "${VALID_SEQUENCE}" \
  -start-rollout \
  -listen-address "0.0.0.0:${CONTROL_PORT}" \
  -tls-server-cert "${WORK_DIR}/control-tls/server.pem" \
  -tls-server-key "${WORK_DIR}/control-tls/server-key.pem" \
  -tls-client-ca "${WORK_DIR}/control-tls/trust-bundle.pem" \
  -spiffe-trust-domain routesphere.test \
  -spiffe-node-path-prefix /bonvoyage/nodes/ \
  -enrollment-listen-address "0.0.0.0:${ENROLLMENT_PORT}" \
  -identity-repository-root "${WORK_DIR}/identity-repository" \
  -identity-audience phase4-checkpoint-8 \
  -identity-issuer-cert "${WORK_DIR}/control-tls/issuer.pem" \
  -identity-issuer-key "${WORK_DIR}/control-tls/issuer-key.pem" \
  -tls-revocations "${WORK_DIR}/control-tls/revocations.json" \
  -tls-server-name discovery.test \
  -tls-reload-interval 100ms \
  -tls-minimum-validity 1m \
  -identity-clock-skew 1m \
  -identity-observation-max-age 5m >"${WORK_DIR}/control.log" 2>&1 &
CONTROL_PID=$!
wait_for_log "${WORK_DIR}/control.log" "node enrollment listener ready:"
wait_for_log "${WORK_DIR}/control.log" "discovery listener ready:"

"${WORK_DIR}/bonvoyage-control-plane" enroll-node \
  -endpoint "127.0.0.1:${ENROLLMENT_PORT}" \
  -server-name discovery.test \
  -server-trust "${WORK_DIR}/tls-old/ca.pem" \
  -credential-root "${WORK_DIR}/node-credentials" \
  -node-id "${NODE_ID}" \
  -spiffe-trust-domain routesphere.test \
  -spiffe-node-path-prefix /bonvoyage/nodes/ \
  -token-file "${WORK_DIR}/enrollment.token" >"${WORK_DIR}/enroll.txt"
if "${WORK_DIR}/bonvoyage-control-plane" enroll-node \
  -endpoint "127.0.0.1:${ENROLLMENT_PORT}" \
  -server-name discovery.test \
  -server-trust "${WORK_DIR}/tls-old/ca.pem" \
  -credential-root "${WORK_DIR}/replay-credentials" \
  -node-id "${NODE_ID}" \
  -spiffe-trust-domain routesphere.test \
  -spiffe-node-path-prefix /bonvoyage/nodes/ \
  -token-file "${WORK_DIR}/enrollment.token" \
  >"${WORK_DIR}/token-replay.log" 2>&1; then
  fail "consumed enrollment token was accepted for a second credential root"
fi

docker run --detach \
  --name "${CONTAINER_NAME}" \
  --add-host host.docker.internal:host-gateway \
  --publish 127.0.0.1::8080 \
  --publish 127.0.0.1::9901 \
  --volume "${WORK_DIR}/bootstrap.pb:/etc/bonvoyage/snapshot.pb:ro" \
  --volume "${WORK_DIR}/node-credentials:/etc/bonvoyage/discovery:ro" \
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
  --discovery-credential-generation-file /etc/bonvoyage/discovery/current-generation.json \
  --discovery-node-id "${NODE_ID}" \
  --discovery-heartbeat-interval-ms 250 \
  --discovery-reconnect-initial-backoff-ms 50 \
  --discovery-reconnect-max-backoff-ms 500 \
  --smp 2 \
  --memory 512M \
  --overprovisioned >/dev/null

GATEWAY_PORT=$(docker port "${CONTAINER_NAME}" 8080/tcp | sed -n '1s/.*://p')
ADMIN_PORT=$(docker port "${CONTAINER_NAME}" 9901/tcp | sed -n '1s/.*://p')
[[ -n "${GATEWAY_PORT}" && -n "${ADMIN_PORT}" ]] || fail "Docker did not publish runtime ports"
wait_for_http "http://127.0.0.1:${ADMIN_PORT}/config/active" \
  "${WORK_DIR}/activated-state.json" "${VALID_SNAPSHOT_ID}"
wait_for_http "http://127.0.0.1:${GATEWAY_PORT}/bonvoyage/ready" \
  "${WORK_DIR}/activated-response.txt" activated

DATAPLANE_PID=$(docker inspect "${CONTAINER_NAME}" --format '{{.State.Pid}}')
INITIAL_RESTARTS=$(docker inspect "${CONTAINER_NAME}" --format '{{.RestartCount}}')
credential_hashes "${WORK_DIR}/node-credentials" >"${WORK_DIR}/before-failed-renewal.sha256"
if "${WORK_DIR}/bonvoyage-control-plane" renew-node \
  -endpoint 127.0.0.1:1 \
  -server-name discovery.test \
  -credential-root "${WORK_DIR}/node-credentials" \
  -timeout 1s >"${WORK_DIR}/failed-renewal.log" 2>&1; then
  fail "unavailable renewal endpoint unexpectedly succeeded"
fi
credential_hashes "${WORK_DIR}/node-credentials" >"${WORK_DIR}/after-failed-renewal.sha256"
cmp -s "${WORK_DIR}/before-failed-renewal.sha256" "${WORK_DIR}/after-failed-renewal.sha256" ||
  fail "failed renewal changed the current credential generation"
wait_for_http "http://127.0.0.1:${GATEWAY_PORT}/bonvoyage/ready" \
  "${WORK_DIR}/post-failed-renewal-response.txt" activated

RELOADS=$(pattern_count container "controlled reconnect requested")
"${WORK_DIR}/bonvoyage-control-plane" renew-node \
  -endpoint "127.0.0.1:${CONTROL_PORT}" \
  -server-name discovery.test \
  -credential-root "${WORK_DIR}/node-credentials" >"${WORK_DIR}/renew-1.txt"
NEW_RELOADS=$(wait_for_pattern_count_greater container "controlled reconnect requested" "${RELOADS}")
sleep 1.2
FINAL_RELOADS=$(pattern_count container "controlled reconnect requested")
[[ "${NEW_RELOADS}" == "$((RELOADS + 1))" && "${FINAL_RELOADS}" == "${NEW_RELOADS}" ]] ||
  fail "one credential publication did not produce exactly one controlled reconnect"

mkdir -p "${WORK_DIR}/credential-backup"
cp "${WORK_DIR}/node-credentials/ca.pem" "${WORK_DIR}/credential-backup/ca.pem"
cp "${WORK_DIR}/node-credentials/node.pem" "${WORK_DIR}/credential-backup/node.pem"
cp "${WORK_DIR}/node-credentials/node-key.pem" "${WORK_DIR}/credential-backup/node-key.pem"
echo 'not a certificate' >"${WORK_DIR}/malformed-node.pem"
RELOADS=$(pattern_count container "controlled reconnect requested")
FAILURES=$(pattern_count container "credential reload rejected")
atomic_replace "${WORK_DIR}/malformed-node.pem" "${WORK_DIR}/node-credentials/node.pem" 644
bump_credential_generation "${WORK_DIR}/node-credentials"
wait_for_pattern_count_greater container "credential reload rejected" "${FAILURES}" >/dev/null
sleep 0.2
[[ "$(pattern_count container "controlled reconnect requested")" == "${RELOADS}" ]] ||
  fail "malformed credential caused a reconnect"
wait_for_http "http://127.0.0.1:${GATEWAY_PORT}/bonvoyage/ready" \
  "${WORK_DIR}/malformed-response.txt" activated
atomic_replace "${WORK_DIR}/credential-backup/node.pem" "${WORK_DIR}/node-credentials/node.pem" 644
bump_credential_generation "${WORK_DIR}/node-credentials"
wait_for_pattern_count_greater container "controlled reconnect requested" "${RELOADS}" >/dev/null

RELOADS=$(pattern_count container "controlled reconnect requested")
FAILURES=$(pattern_count container "credential reload rejected")
atomic_replace "${WORK_DIR}/tls-old/node-key.pem" "${WORK_DIR}/node-credentials/node-key.pem" 600
bump_credential_generation "${WORK_DIR}/node-credentials"
wait_for_pattern_count_greater container "credential reload rejected" "${FAILURES}" >/dev/null
sleep 0.2
[[ "$(pattern_count container "controlled reconnect requested")" == "${RELOADS}" ]] ||
  fail "mismatched private key caused a reconnect"
wait_for_http "http://127.0.0.1:${GATEWAY_PORT}/bonvoyage/ready" \
  "${WORK_DIR}/mismatched-response.txt" activated
atomic_replace "${WORK_DIR}/credential-backup/node-key.pem" "${WORK_DIR}/node-credentials/node-key.pem" 600
bump_credential_generation "${WORK_DIR}/node-credentials"
wait_for_pattern_count_greater container "controlled reconnect requested" "${RELOADS}" >/dev/null

RELOADS=$(pattern_count container "controlled reconnect requested")
FAILURES=$(pattern_count container "credential reload rejected")
mv "${WORK_DIR}/node-credentials/ca.pem" "${WORK_DIR}/credential-backup/missing-ca.pem"
bump_credential_generation "${WORK_DIR}/node-credentials"
wait_for_pattern_count_greater container "credential reload rejected" "${FAILURES}" >/dev/null
[[ "$(pattern_count container "controlled reconnect requested")" == "${RELOADS}" ]] ||
  fail "missing trust material caused a reconnect"
wait_for_http "http://127.0.0.1:${GATEWAY_PORT}/bonvoyage/ready" \
  "${WORK_DIR}/missing-response.txt" activated
atomic_replace "${WORK_DIR}/credential-backup/missing-ca.pem" "${WORK_DIR}/node-credentials/ca.pem" 644
bump_credential_generation "${WORK_DIR}/node-credentials"
wait_for_pattern_count_greater container "controlled reconnect requested" "${RELOADS}" >/dev/null

TLS_GENERATIONS=$(pattern_count "${WORK_DIR}/control.log" "identity TLS generation active:")
cat "${WORK_DIR}/tls-old/ca.pem" "${WORK_DIR}/tls-new/ca.pem" >"${WORK_DIR}/overlap-ca.pem"
atomic_replace "${WORK_DIR}/overlap-ca.pem" "${WORK_DIR}/control-tls/trust-bundle.pem" 600
wait_for_pattern_count_greater "${WORK_DIR}/control.log" "identity TLS generation active:" "${TLS_GENERATIONS}" >/dev/null
RELOADS=$(pattern_count container "controlled reconnect requested")
"${WORK_DIR}/bonvoyage-control-plane" renew-node \
  -endpoint "127.0.0.1:${CONTROL_PORT}" \
  -server-name discovery.test \
  -credential-root "${WORK_DIR}/node-credentials" >"${WORK_DIR}/renew-overlap.txt"
wait_for_pattern_count_greater container "controlled reconnect requested" "${RELOADS}" >/dev/null
cp -a "${WORK_DIR}/node-credentials" "${WORK_DIR}/old-credential-root"

TLS_GENERATIONS=$(pattern_count "${WORK_DIR}/control.log" "identity TLS generation active:")
atomic_replace "${WORK_DIR}/tls-new/server.pem" "${WORK_DIR}/control-tls/server.pem" 600
atomic_replace "${WORK_DIR}/tls-new/server-key.pem" "${WORK_DIR}/control-tls/server-key.pem" 600
atomic_replace "${WORK_DIR}/tls-new/issuer.pem" "${WORK_DIR}/control-tls/issuer.pem" 600
atomic_replace "${WORK_DIR}/tls-new/issuer-key.pem" "${WORK_DIR}/control-tls/issuer-key.pem" 600
wait_for_pattern_count_greater "${WORK_DIR}/control.log" "identity TLS generation active:" "${TLS_GENERATIONS}" >/dev/null
RELOADS=$(pattern_count container "controlled reconnect requested")
"${WORK_DIR}/bonvoyage-control-plane" renew-node \
  -endpoint "127.0.0.1:${CONTROL_PORT}" \
  -server-name discovery.test \
  -credential-root "${WORK_DIR}/node-credentials" >"${WORK_DIR}/renew-new-issuer.txt"
wait_for_pattern_count_greater container "controlled reconnect requested" "${RELOADS}" >/dev/null

TLS_GENERATIONS=$(pattern_count "${WORK_DIR}/control.log" "identity TLS generation active:")
atomic_replace "${WORK_DIR}/tls-new/ca.pem" "${WORK_DIR}/control-tls/trust-bundle.pem" 600
wait_for_pattern_count_greater "${WORK_DIR}/control.log" "identity TLS generation active:" "${TLS_GENERATIONS}" >/dev/null
RELOADS=$(pattern_count container "controlled reconnect requested")
"${WORK_DIR}/bonvoyage-control-plane" renew-node \
  -endpoint "127.0.0.1:${CONTROL_PORT}" \
  -server-name discovery.test \
  -credential-root "${WORK_DIR}/node-credentials" >"${WORK_DIR}/renew-retired-root.txt"
wait_for_pattern_count_greater container "controlled reconnect requested" "${RELOADS}" >/dev/null
credential_hashes "${WORK_DIR}/old-credential-root" >"${WORK_DIR}/old-before-rejection.sha256"
if "${WORK_DIR}/bonvoyage-control-plane" renew-node \
  -endpoint "127.0.0.1:${CONTROL_PORT}" \
  -server-name discovery.test \
  -credential-root "${WORK_DIR}/old-credential-root" \
  -timeout 3s >"${WORK_DIR}/old-root-rejection.log" 2>&1; then
  fail "credential under the retired trust root was accepted"
fi
credential_hashes "${WORK_DIR}/old-credential-root" >"${WORK_DIR}/old-after-rejection.sha256"
cmp -s "${WORK_DIR}/old-before-rejection.sha256" "${WORK_DIR}/old-after-rejection.sha256" ||
  fail "rejected old-root renewal changed its last valid generation"

"${WORK_DIR}/bonvoyage-control-plane" revoke-node \
  -revocation-file "${WORK_DIR}/control-tls/revocations.json" \
  -node-id "${NODE_ID}" \
  -reason "checkpoint-8 active revocation" \
  -valid-for 24h >"${WORK_DIR}/revoke.txt"
wait_for_log "${WORK_DIR}/control.log" "revocation_generation=2"
sleep 1.5
credential_hashes "${WORK_DIR}/node-credentials" >"${WORK_DIR}/revoked-before-renewal.sha256"
if "${WORK_DIR}/bonvoyage-control-plane" renew-node \
  -endpoint "127.0.0.1:${CONTROL_PORT}" \
  -server-name discovery.test \
  -credential-root "${WORK_DIR}/node-credentials" \
  -timeout 3s >"${WORK_DIR}/revoked-renewal.log" 2>&1; then
  fail "revoked node renewed a credential"
fi
credential_hashes "${WORK_DIR}/node-credentials" >"${WORK_DIR}/revoked-after-renewal.sha256"
cmp -s "${WORK_DIR}/revoked-before-renewal.sha256" "${WORK_DIR}/revoked-after-renewal.sha256" ||
  fail "revoked renewal changed the last valid generation"
wait_for_http "http://127.0.0.1:${GATEWAY_PORT}/bonvoyage/ready" \
  "${WORK_DIR}/post-revocation-response.txt" activated

[[ "$(docker inspect "${CONTAINER_NAME}" --format '{{.State.Pid}}')" == "${DATAPLANE_PID}" ]] ||
  fail "dataplane process identity changed"
[[ "$(docker inspect "${CONTAINER_NAME}" --format '{{.RestartCount}}')" == "${INITIAL_RESTARTS}" ]] ||
  fail "dataplane container restarted"
FINAL_RELOADS=$(pattern_count container "controlled reconnect requested")
if [[ ! "${FINAL_RELOADS}" =~ ^[0-9]+$ ]] || ((FINAL_RELOADS <= 0)); then
  fail "no controlled credential reconnect was observed"
fi
docker logs "${CONTAINER_NAME}" >"${WORK_DIR}/dataplane.log" 2>&1
docker inspect "${CONTAINER_NAME}" --format '{{json .State}}' >"${WORK_DIR}/dataplane-state.json"
docker stop --time 10 "${CONTAINER_NAME}" >/dev/null
kill -TERM "${CONTROL_PID}"
wait "${CONTROL_PID}"
CONTROL_PID=
verify_rollout "${WORK_DIR}/final.verify" "$((4 + FINAL_RELOADS))"

docker inspect "${IMAGE}" --format '{{.Id}}' >"${WORK_DIR}/image-id.txt"
git -C "${ROOT_DIR}" rev-parse HEAD >"${WORK_DIR}/source-commit.txt"
git -C "${ROOT_DIR}" status --porcelain >"${WORK_DIR}/source-status.txt"
if [[ -s "${WORK_DIR}/source-status.txt" ]]; then
  echo true >"${WORK_DIR}/source-dirty.txt"
else
  echo false >"${WORK_DIR}/source-dirty.txt"
fi

cp "${WORK_DIR}/fixture.env" "${EVIDENCE_DIR}/"
cp "${WORK_DIR}"/*.txt "${EVIDENCE_DIR}/" 2>/dev/null || true
cp "${WORK_DIR}"/*.log "${EVIDENCE_DIR}/" 2>/dev/null || true
cp "${WORK_DIR}"/*.json "${EVIDENCE_DIR}/" 2>/dev/null || true
cp "${WORK_DIR}"/*.verify "${EVIDENCE_DIR}/" 2>/dev/null || true
cp "${WORK_DIR}"/*.sha256 "${EVIDENCE_DIR}/" 2>/dev/null || true
cp "${WORK_DIR}/image-id.txt" "${WORK_DIR}/source-commit.txt" \
  "${WORK_DIR}/source-dirty.txt" "${WORK_DIR}/source-status.txt" "${EVIDENCE_DIR}/"

TOKEN_VALUE=$(tr -d '\n' <"${WORK_DIR}/enrollment.token")
if grep -R -Fq -- "${TOKEN_VALUE}" "${EVIDENCE_DIR}"; then
  fail "retained evidence contains the enrollment token"
fi
if grep -R -Fq -- 'PRIVATE KEY-----' "${EVIDENCE_DIR}"; then
  fail "retained evidence contains private-key material"
fi

{
  echo 'checkpoint=Phase 4 Checkpoint 8 node identity and certificate lifecycle'
  echo 'transport=TLS 1.3 enrollment plus mutual TLS renewal and discovery'
  echo "node_id=${NODE_ID}"
  echo 'bootstrap=enrollment token was single-use and node key stayed local'
  echo 'failed_renewal=last valid generation retained and traffic remained active'
  echo 'valid_rotation=one complete generation produced one controlled reconnect'
  echo 'malformed_rotation=active stream and traffic retained without reconnect'
  echo 'mismatched_key=active stream and traffic retained without reconnect'
  echo 'missing_material=active stream and traffic retained without reconnect'
  echo 'trust_rotation=overlap, new issuer, old-root retirement, and old-client rejection passed'
  echo 'revocation=active stream denied renewal while last-known-good traffic remained active'
  echo "dataplane_pid=${DATAPLANE_PID}"
  echo "container_restarts=${INITIAL_RESTARTS}"
  echo "controlled_reconnects=${FINAL_RELOADS}"
  echo 'final_response=activated'
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

printf 'Phase 4 identity lifecycle integration passed. Evidence: %s\n' "${EVIDENCE_DIR}"
