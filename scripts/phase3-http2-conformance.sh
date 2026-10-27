#!/bin/sh
set -eu

umask 077

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/test-fixture-secrets.sh
. "$PWD/scripts/test-fixture-secrets.sh"

image="${BONVOYAGE_DATAPLANE_IMAGE:-bonvoyage-dataplane:dev}"
compiler_image="${BONVOYAGE_COMPILER_IMAGE:-bonvoyage-snapshot-compiler:dev}"
upstream_image="${BONVOYAGE_UPSTREAM_IMAGE:-bonvoyage-upstream:dev}"
oha_image="${BONVOYAGE_OHA_IMAGE:-ghcr.io/hatoo/oha@sha256:57c2247792c1466c88ecc83ddb9253aa0b58dcb852b1d7f2026a0acf7744c965}"
h2spec_image="${BONVOYAGE_H2SPEC_IMAGE:-summerwind/h2spec@sha256:5f4a65c30cae8569558ced048b4bfe0dcf01a221e36767ae504ccd8348a7aeb0}"
platform="${BONVOYAGE_BUILD_PLATFORM:-linux/amd64}"
h2spec_platform="${BONVOYAGE_H2SPEC_PLATFORM:-linux/amd64}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
suffix="$$"
network="bonvoyage-http2-conformance-$suffix"
volume="bonvoyage-http2-conformance-$suffix"
secret_volume="${volume}-secrets"
gateway="bonvoyage-http2-conformance-gateway-$suffix"
upstream="bonvoyage-http2-conformance-upstream-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-http2-conformance.XXXXXX")"
secrets_dir="$work_dir/secrets"
client_dir="$work_dir/client"
h2spec_output_dir="$work_dir/h2spec-output"
h2spec_allowlist="$repo_root/tests/compatibility/h2spec-rfc9113-variance-allowlist.json"
evidence_root="${BONVOYAGE_HTTP2_CONFORMANCE_EVIDENCE_ROOT:-$repo_root/benchmarks/results/verification}"
evidence_dir="${BONVOYAGE_HTTP2_CONFORMANCE_EVIDENCE_DIR:-$evidence_root/http2-conformance-$timestamp}"
stage="initialization"
h2spec_status="not-run"
h2spec_summary_status="not-run"
h2spec_allowed_variances="not-run"
h2spec_unexpected_failures="not-run"
h2spec_missing_variances="not-run"
h2spec_resolved_variances="not-run"
h2spec_unexercised_variances="not-run"
raw_status="not-run"
oha_fixed_status="not-run"
oha_response_status="not-run"
oha_request_status="not-run"
oha_summary_status="not-run"
evidence_ready=0

case "$evidence_dir" in
  /*) ;;
  *) evidence_dir="$repo_root/$evidence_dir" ;;
esac

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "$1 is required for downstream HTTP/2 conformance qualification" >&2
    exit 1
  }
}

classify_h2spec_junit() {
  python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import json
import pathlib
import sys
import xml.etree.ElementTree as ET

junit_path = pathlib.Path(sys.argv[1])
allowlist_path = pathlib.Path(sys.argv[2])
classification_path = pathlib.Path(sys.argv[3])
summary_path = pathlib.Path(sys.argv[4])
process_status = int(sys.argv[5])

counts = {
    "tests": 0,
    "passed": 0,
    "skipped": 0,
    "junit_failures": 0,
    "junit_errors": 0,
    "observed_nonpassing_outcomes": 0,
    "allowed_variances": 0,
    "unexpected_failures": 0,
    "expected_variances_not_observed": 0,
    "resolved_variances": 0,
    "unexercised_variances": 0,
}
classification = {
    "schema_version": 1,
    "classification": "supplemental_legacy_h2spec_with_reviewed_rfc9113_variances",
    "specifications": ["RFC 7540", "RFC 7541 HPACK"],
    "not_authoritative_for": "RFC 9113",
    "process_exit_status": process_status,
    "junit": {
        "artifact": junit_path.name,
        "present": junit_path.is_file(),
    },
    "allowlist": {
        "source": "tests/compatibility/h2spec-rfc9113-variance-allowlist.json",
    },
    "counts": counts,
    "observed_nonpassing": [],
    "expected_variances_not_observed": [],
}
gate_reasons = []


def clean_text(node):
    return "\n".join(
        line.strip()
        for line in "".join(node.itertext()).splitlines()
        if line.strip()
    )


try:
    manifest = json.loads(allowlist_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("allowlist schema_version must be 1")
    if manifest.get("match_fields") != ["package", "classname", "outcome"]:
        raise ValueError(
            "allowlist match_fields must be package, classname, and outcome"
        )
    tool = manifest.get("tool", {})
    if tool.get("name") != "h2spec" or tool.get("version") != "2.6.0":
        raise ValueError("allowlist must target h2spec v2.6.0 exactly")
    review = manifest.get("review", {})
    if review.get("status") != "approved":
        raise ValueError("allowlist review status must be approved")

    variances = manifest.get("variances")
    if not isinstance(variances, list) or not variances:
        raise ValueError("allowlist variances must be a non-empty list")
    if manifest.get("expected_variance_count") != 5 or len(variances) != 5:
        raise ValueError("allowlist must contain exactly five reviewed variances")

    allow_by_key = {}
    variance_ids = set()
    for variance in variances:
        required = (
            "id",
            "package",
            "classname",
            "outcome",
            "rfc9113",
            "rationale",
            "review_status",
        )
        missing = [field for field in required if not variance.get(field)]
        if missing:
            raise ValueError(
                "allowlist variance is missing fields: " + ", ".join(missing)
            )
        if variance["review_status"] != "approved":
            raise ValueError(
                f"allowlist variance {variance['id']} is not approved"
            )
        if variance["outcome"] not in ("error", "failure"):
            raise ValueError(
                f"allowlist variance {variance['id']} has an invalid outcome"
            )
        rfc9113 = variance["rfc9113"]
        if not isinstance(rfc9113, dict) or not rfc9113.get("sections") or \
                not str(rfc9113.get("url", "")).startswith(
                    "https://www.rfc-editor.org/rfc/rfc9113.html#section-"
                ):
            raise ValueError(
                f"allowlist variance {variance['id']} lacks an RFC 9113 basis"
            )
        if variance["id"] in variance_ids:
            raise ValueError(f"duplicate allowlist id: {variance['id']}")
        variance_ids.add(variance["id"])
        key = (
            variance["package"],
            variance["classname"],
            variance["outcome"],
        )
        if key in allow_by_key:
            raise ValueError(
                "duplicate allowlist match key: " + " | ".join(key)
            )
        allow_by_key[key] = variance

    classification["allowlist"].update({
        "id": manifest.get("id"),
        "review": review,
        "entries": len(allow_by_key),
        "match_fields": manifest["match_fields"],
        "policy": manifest.get("policy", {}),
    })

    if not junit_path.is_file():
        raise ValueError("h2spec JUnit artifact is missing")
    raw_xml = junit_path.read_bytes()
    sanitized_xml = bytes(
        value if value in (0x09, 0x0A, 0x0D) or value >= 0x20 else 0x3F
        for value in raw_xml
    )
    root = ET.fromstring(sanitized_xml)
    cases = list(root.iter("testcase"))
    if not cases:
        raise ValueError("h2spec JUnit artifact contains no testcases")

    counts["tests"] = len(cases)
    case_states = {}
    observed_keys = set()
    for case in cases:
        package = case.get("package", "")
        classname = case.get("classname", "")
        identity = (package, classname)
        if not package or not classname:
            gate_reasons.append("junit_testcase_missing_exact_identity")

        outcomes = []
        for outcome in ("failure", "error"):
            node = case.find(outcome)
            if node is not None:
                outcomes.append((outcome, node))
                counts[f"junit_{outcome}s"] += 1

        if outcomes:
            case_state = "nonpassing"
        elif case.find("skipped") is not None:
            case_state = "skipped"
            counts["skipped"] += 1
        else:
            case_state = "passed"
            counts["passed"] += 1
        case_states.setdefault(identity, []).append(case_state)

        for outcome, node in outcomes:
            key = (package, classname, outcome)
            observed_keys.add(key)
            variance = allow_by_key.get(key)
            item = {
                "package": package,
                "classname": classname,
                "outcome": outcome,
                "diagnostic": clean_text(node),
            }
            if variance is None:
                item["classification"] = "unexpected_legacy_failure"
                counts["unexpected_failures"] += 1
            else:
                item.update({
                    "classification": "allowed_rfc9113_variance",
                    "variance_id": variance["id"],
                    "rfc9113": variance["rfc9113"],
                    "rationale": variance["rationale"],
                })
                counts["allowed_variances"] += 1
            classification["observed_nonpassing"].append(item)

    counts["observed_nonpassing_outcomes"] = len(
        classification["observed_nonpassing"]
    )
    for key, variance in allow_by_key.items():
        if key in observed_keys:
            continue
        identity = key[:2]
        states = case_states.get(identity, [])
        if "passed" in states:
            observed_state = "passed"
            disposition = "resolved_or_stricter_behavior"
            counts["resolved_variances"] += 1
        elif "skipped" in states:
            observed_state = "skipped"
            disposition = "unexercised_allowlist_entry"
            counts["unexercised_variances"] += 1
        elif states:
            observed_state = "different_nonpassing_outcome"
            disposition = "outcome_did_not_match_allowlist"
        else:
            observed_state = "absent"
            disposition = "unexercised_allowlist_entry"
            counts["unexercised_variances"] += 1
        counts["expected_variances_not_observed"] += 1
        classification["expected_variances_not_observed"].append({
            "variance_id": variance["id"],
            "package": variance["package"],
            "classname": variance["classname"],
            "expected_outcome": variance["outcome"],
            "observed_state": observed_state,
            "disposition": disposition,
        })

    if counts["unexpected_failures"]:
        gate_reasons.append("unexpected_h2spec_failures")
    if counts["unexercised_variances"]:
        gate_reasons.append("allowlisted_h2spec_tests_not_exercised")
    if process_status == 0 and counts["observed_nonpassing_outcomes"]:
        gate_reasons.append("h2spec_exit_status_inconsistent_with_junit")
    if process_status == 1 and not counts["observed_nonpassing_outcomes"]:
        gate_reasons.append("unexplained_nonzero_h2spec_exit_status")
    if process_status not in (0, 1):
        gate_reasons.append("h2spec_runtime_or_invocation_failure")
except (OSError, ValueError, json.JSONDecodeError, ET.ParseError) as error:
    gate_reasons.append("classification_input_invalid")
    classification["classification_error"] = str(error)

gate_reasons = list(dict.fromkeys(gate_reasons))
result = "PASS" if not gate_reasons else "FAIL"
classification["gate"] = {
    "result": result,
    "reasons": gate_reasons,
    "missing_expected_variances_are_nonfatal_only_when_present_and_passing": True,
}
summary = {
    "schema_version": 1,
    "classification": classification["classification"],
    "result": result,
    "process_exit_status": process_status,
    "junit_present": classification["junit"]["present"],
    "tests": counts["tests"],
    "passed": counts["passed"],
    "skipped": counts["skipped"],
    "junit_failures": counts["junit_failures"],
    "junit_errors": counts["junit_errors"],
    "allowed_variances": counts["allowed_variances"],
    "unexpected_failures": counts["unexpected_failures"],
    "expected_variances_not_observed": counts[
        "expected_variances_not_observed"
    ],
    "resolved_variances": counts["resolved_variances"],
    "unexercised_variances": counts["unexercised_variances"],
    "gate_reasons": gate_reasons,
    "classification_artifact": classification_path.name,
    "allowlist_artifact": "h2spec-rfc9113-variance-allowlist.json",
}
classification_path.write_text(
    json.dumps(classification, indent=2) + "\n", encoding="utf-8"
)
summary_path.write_text(
    json.dumps(summary, indent=2) + "\n", encoding="utf-8"
)
print(
    counts["allowed_variances"],
    counts["unexpected_failures"],
    counts["expected_variances_not_observed"],
    counts["resolved_variances"],
    counts["unexercised_variances"],
)
sys.exit(0 if result == "PASS" else 1)
PY
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

write_checksum_manifest() {
  manifest="$evidence_dir/checksums.sha256"
  (
    cd "$evidence_dir" || exit 1
    find . -type f ! -name checksums.sha256 -print | LC_ALL=C sort |
      while IFS= read -r artifact; do
        hash_file "$artifact"
      done
  ) >"$manifest"
}

container_exists() {
  docker inspect "$1" >/dev/null 2>&1
}

cleanup() {
  status="$?"
  trap - EXIT INT TERM
  set +e

  if [ "$evidence_ready" -ne 1 ]; then
    rm -rf "$work_dir"
    exit "$status"
  fi

  if container_exists "$gateway"; then
    docker logs "$gateway" >"$evidence_dir/gateway.log" 2>&1
    docker inspect "$gateway" >"$evidence_dir/gateway-inspect.json" 2>&1
  fi
  if container_exists "$upstream"; then
    docker logs "$upstream" >"$evidence_dir/upstream.log" 2>&1
    docker inspect "$upstream" >"$evidence_dir/upstream-inspect.json" 2>&1
  fi
  docker network inspect "$network" >"$evidence_dir/network-inspect.json" \
    2>/dev/null
  docker volume inspect "$volume" >"$evidence_dir/volume-inspect.json" \
    2>/dev/null

  if [ ! -f "$evidence_dir/overall-summary.txt" ]; then
    cat >"$evidence_dir/overall-summary.txt" <<EOF
result=FAIL
failed_stage=$stage
exit_status=$status
h2spec_status=$h2spec_status
h2spec_summary_status=$h2spec_summary_status
h2spec_allowed_variances=$h2spec_allowed_variances
h2spec_unexpected_failures=$h2spec_unexpected_failures
h2spec_missing_variances=$h2spec_missing_variances
h2spec_resolved_variances=$h2spec_resolved_variances
h2spec_unexercised_variances=$h2spec_unexercised_variances
h2spec_classification_artifact=h2spec-classification.json
h2spec_variance_allowlist_artifact=h2spec-rfc9113-variance-allowlist.json
rfc9113_raw_status=$raw_status
oha_fixed_status=$oha_fixed_status
oha_response_status=$oha_response_status
oha_request_status=$oha_request_status
oha_summary_status=$oha_summary_status
scope=downstream HTTP/2 qualification only
h2spec_scope=supplemental legacy RFC 7540 and RFC 7541 HPACK signal; not RFC 9113 proof
EOF
  fi

  docker rm --force "$gateway" "$upstream" >/dev/null 2>&1
  docker network rm "$network" >/dev/null 2>&1
  docker volume rm "$volume" >/dev/null 2>&1
  bv_remove_fixture_secrets "$secret_volume" "$secrets_dir" >/dev/null 2>&1 || {
    echo "private fixture volume cleanup failed: $secret_volume" >&2
    [ "$status" -ne 0 ] || status=1
  }
  rm -rf "$work_dir"
  write_checksum_manifest || true

  if [ "$status" -ne 0 ]; then
    echo "Downstream HTTP/2 conformance qualification failed at: $stage" >&2
    if [ -f "$evidence_dir/h2spec.full.txt" ]; then
      echo "Last h2spec output lines:" >&2
      tail -40 "$evidence_dir/h2spec.full.txt" >&2
    fi
  fi
  echo "Retained HTTP/2 conformance evidence: $evidence_dir"
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "${1:-}" = "--classify-h2spec-junit" ]; then
  if [ "$#" -ne 5 ]; then
    echo "usage: $0 --classify-h2spec-junit JUNIT CLASSIFICATION SUMMARY PROCESS_STATUS" >&2
    exit 2
  fi
  require_command python3
  classify_h2spec_junit "$2" "$h2spec_allowlist" "$3" "$4" "$5"
  exit "$?"
fi

for command_name in date docker find git id openssl python3 tail; do
  require_command "$command_name"
done
if ! command -v sha256sum >/dev/null 2>&1; then
  require_command shasum
fi

if [ -e "$evidence_dir" ]; then
  echo "Evidence directory already exists: $evidence_dir" >&2
  exit 1
fi
mkdir -p "$evidence_dir" "$secrets_dir" "$client_dir" \
  "$h2spec_output_dir"
evidence_ready=1

stage="recording environment"
{
  printf 'started_at_utc=%s\n' "$timestamp"
  printf 'repository=%s\n' "$repo_root"
  printf 'git_commit=%s\n' "$(git rev-parse HEAD)"
  printf 'git_status_begin\n'
  git status --short --branch
  printf 'git_status_end\n'
  printf 'platform=%s\n' "$platform"
  printf 'h2spec_platform=%s\n' "$h2spec_platform"
  printf 'dataplane_image=%s\n' "$image"
  printf 'compiler_image=%s\n' "$compiler_image"
  printf 'upstream_image=%s\n' "$upstream_image"
  printf 'oha_image=%s\n' "$oha_image"
  printf 'h2spec_image=%s\n' "$h2spec_image"
  printf 'h2spec_variance_allowlist=%s\n' \
    'tests/compatibility/h2spec-rfc9113-variance-allowlist.json'
  printf 'network_internal=true\n'
  printf 'published_host_ports=none\n'
  printf 'h2spec_classification=supplemental legacy RFC 7540/RFC 7541 HPACK tool\n'
  printf 'rfc9113_authority=targeted raw negative tests in this qualification\n'
  printf 'h2spec_certificate_mode=ephemeral test certificate verification disabled because h2spec has no custom CA option\n'
  printf 'oha_certificate_mode=ephemeral CA and hostname verified; insecure mode is not used\n'
  printf 'raw_certificate_mode=ephemeral CA and hostname verified; insecure mode is not used\n'
  printf 'docker_version=%s\n' "$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
  uname -a
} >"$evidence_dir/run-metadata.txt"

cp "$h2spec_allowlist" \
  "$evidence_dir/h2spec-rfc9113-variance-allowlist.json"
{
  hash_file "$script_dir/phase3-http2-conformance.sh"
  hash_file "$script_dir/test-fixture-secrets.sh"
  hash_file "$h2spec_allowlist"
  hash_file "$repo_root/tests/fixtures/phase3-http2-conformance.yaml"
} >"$evidence_dir/source-checksums.sha256"

stage="checking immutable client images"
if ! docker image inspect "$h2spec_image" >/dev/null 2>&1; then
  docker pull --platform "$h2spec_platform" "$h2spec_image"
fi
if ! docker image inspect "$oha_image" >/dev/null 2>&1; then
  docker pull --platform "$platform" "$oha_image"
fi
docker image inspect "$image" >/dev/null 2>&1 || {
  echo "Dataplane image is missing: $image" >&2
  echo "Build the current BonVoyage dataplane image before qualification." >&2
  exit 1
}

{
  for inspected_image in "$image" "$h2spec_image" "$oha_image"; do
    printf 'reference=%s\n' "$inspected_image"
    docker image inspect --format \
      'id={{.Id}} architecture={{.Architecture}} os={{.Os}} repo_digests={{json .RepoDigests}}' \
      "$inspected_image"
  done
} >"$evidence_dir/client-image-identities.txt"

docker run --rm --pull never --platform "$h2spec_platform" --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 32 --memory 64m "$h2spec_image" --version \
  >"$evidence_dir/h2spec-version.txt" 2>&1
docker run --rm --pull never --platform "$platform" --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 32 --memory 64m "$oha_image" --version \
  >"$evidence_dir/oha-version.txt" 2>&1

stage="creating ephemeral TLS identity"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=BonVoyage HTTP2 Conformance Test CA" \
  -keyout "$secrets_dir/ca-key.pem" -out "$secrets_dir/ca.pem" \
  >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=api.example.test" \
  -keyout "$secrets_dir/server-key.pem" -out "$secrets_dir/server.csr" \
  >/dev/null 2>&1
printf '%s\n' \
  "subjectAltName=DNS:api.example.test" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=digitalSignature,keyEncipherment" \
  >"$secrets_dir/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$secrets_dir/server.csr" \
  -CA "$secrets_dir/ca.pem" -CAkey "$secrets_dir/ca-key.pem" \
  -CAcreateserial -extfile "$secrets_dir/server-ext.cnf" \
  -out "$secrets_dir/server-chain.pem" >/dev/null 2>&1
chmod 600 "$secrets_dir"/*-key.pem
cp "$secrets_dir/ca.pem" "$client_dir/ca.pem"
dd if=/dev/zero bs=32768 count=1 2>/dev/null | tr '\000' x \
  >"$client_dir/request-body.bin"
{
  openssl x509 -in "$secrets_dir/server-chain.pem" -noout -subject -issuer \
    -dates -fingerprint -sha256
  printf 'private_keys_retained=false\n'
} >"$evidence_dir/tls-certificate.txt"

stage="building fixture support images"
{
  docker buildx build --platform "$platform" --load --tag "$compiler_image" \
    --file deploy/docker/control-plane/Dockerfile .
  docker buildx build --platform "$platform" --load --tag "$upstream_image" \
    --file deploy/docker/upstream/Dockerfile deploy/docker/upstream
} >"$evidence_dir/setup-build.log" 2>&1

stage="starting isolated fixture"
docker network create --internal \
  --label routesphere.bonvoyage.test=http2-conformance "$network" \
  >"$evidence_dir/network-create.txt"
docker volume create \
  --label routesphere.bonvoyage.test=http2-conformance "$volume" \
  >"$evidence_dir/volume-create.txt"

bv_stage_fixture_secrets "$secret_volume" "$secrets_dir" "$upstream_image" "$platform" \
  server-chain.pem server-key.pem

docker run --rm --pull never --platform "$platform" --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --volume "$repo_root/tests/fixtures/phase3-http2-conformance.yaml:/etc/bonvoyage/http2.yaml:ro" \
  --volume "$volume:/var/lib/bonvoyage" \
  "$compiler_image" -input /etc/bonvoyage/http2.yaml \
  -output /var/lib/bonvoyage/snapshot.pb \
  >"$evidence_dir/snapshot-compiler.txt" 2>&1

docker run --detach --pull never --platform "$platform" --name "$upstream" \
  --network "$network" --network-alias upstream --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 256m \
  "$upstream_image" >"$evidence_dir/upstream-start.txt"
docker run --detach --pull never --platform "$platform" --name "$gateway" \
  --network "$network" --network-alias api.example.test --dns-search . --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --cap-add SYS_NICE \
  --security-opt no-new-privileges --pids-limit 256 --memory 512m \
  --volume "$volume:/snapshot:ro" \
  --volume "$secret_volume:/etc/bonvoyage/secrets:ro" "$image" \
  --snapshot /snapshot/snapshot.pb \
  --secrets-directory /etc/bonvoyage/secrets \
  --admin-address 0.0.0.0 --metrics-address 0.0.0.0 \
  --smp 1 --memory 256M --overprovisioned \
  --logger-log-level bonvoyage-gateway=debug \
  >"$evidence_dir/gateway-start.txt"

bv_wait_gateway_ready "$gateway" "$upstream" "http://$gateway:9901/health/ready"

docker exec "$upstream" python -c '
import urllib.request
print(urllib.request.urlopen(
    "http://bonvoyage-http2-conformance-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$evidence_dir/metrics-before.prom"

stage="running supplemental legacy h2spec"
cat >"$evidence_dir/h2spec-scope.txt" <<EOF
classification=supplemental legacy conformance signal
tool=summerwind/h2spec v2.6.0
image=$h2spec_image
covered_specifications=RFC 7540 HTTP/2 and RFC 7541 HPACK
authoritative_current_specification=RFC 9113
limitation=h2spec v2.6.0 predates RFC 9113 and cannot establish RFC 9113 conformance
variance_policy=only exact package, classname, and outcome matches in the retained reviewed RFC 9113 allowlist are accepted
unexpected_failure_policy=fail
resolved_variance_policy=report without failure when an allowlisted testcase is present and passes
unexercised_variance_policy=fail when an allowlisted testcase is absent or skipped
tls=TLS and ALPN h2 remain required
certificate_verification=h2spec -k is used only because the legacy client has no custom CA option and the certificate is ephemeral; oha and raw clients verify the CA and hostname
sections=http2 hpack
strict_mode=true
target=https://api.example.test:8443/slow/250
EOF

printf '%s\n' \
  'SUPPLEMENTAL/LEGACY ONLY: h2spec v2.6.0 covers RFC 7540 and RFC 7541 HPACK, not RFC 9113.' \
  'Only exact failures in the retained, reviewed RFC 9113 variance allowlist may pass this supplemental gate.' \
  'The -k exception applies only to verification of this run-specific test certificate; TLS and ALPN h2 remain mandatory.' \
  >"$evidence_dir/h2spec.full.txt"
set +e
docker run --rm --pull never --platform "$h2spec_platform" \
  --network "$network" --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 \
  --memory 128m --user "$(id -u):$(id -g)" \
  --volume "$h2spec_output_dir:/output:rw" "$h2spec_image" \
  -S -t -k -h api.example.test -p 8443 -P /slow/250 -o 5 \
  -j /output/h2spec.junit.xml http2 hpack \
  >>"$evidence_dir/h2spec.full.txt" 2>&1
h2spec_status="$?"
set -e
if [ -f "$h2spec_output_dir/h2spec.junit.xml" ]; then
  cp "$h2spec_output_dir/h2spec.junit.xml" "$evidence_dir/h2spec.junit.xml"
fi
printf '%s\n' "$h2spec_status" >"$evidence_dir/h2spec-exit-status.txt"

set +e
h2spec_classification_counts="$(
  classify_h2spec_junit "$evidence_dir/h2spec.junit.xml" \
    "$h2spec_allowlist" "$evidence_dir/h2spec-classification.json" \
    "$evidence_dir/h2spec-summary.json" "$h2spec_status"
)"
h2spec_summary_status="$?"
set -e
classification_extra=""
IFS=' ' read -r \
  h2spec_allowed_variances \
  h2spec_unexpected_failures \
  h2spec_missing_variances \
  h2spec_resolved_variances \
  h2spec_unexercised_variances \
  classification_extra <<EOF
$h2spec_classification_counts
EOF
if [ -n "$classification_extra" ] || \
   [ -z "$h2spec_unexercised_variances" ]; then
  h2spec_summary_status=1
fi

stage="running targeted RFC 9113 malformed-frame tests"
# Capability-dropped root cannot read caller-private bind mounts on native Linux.
printf '%s\n' \
  'Targeted RFC 9113 raw-frame negative tests use CA-verified TLS, hostname verification, and exact ALPN h2.' \
  >"$evidence_dir/rfc9113-raw.stderr.txt"
set +e
docker run --rm --pull never --platform "$platform" --network "$network" \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 128m \
  --user "$(id -u):$(id -g)" \
  --volume "$client_dir:/tls:ro" --entrypoint python "$upstream_image" -c '
import json
import socket
import ssl
import struct
import sys
import time

HOST = "api.example.test"
PORT = 8443
CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
PROTOCOL_ERROR = 0x1
FRAME_SIZE_ERROR = 0x6

def frame(frame_type, flags, stream_id, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes((frame_type, flags)) +
            (stream_id & 0x7fffffff).to_bytes(4, "big") + payload)

tests = [
    ("data_on_stream_zero", frame(0x0, 0x0, 0), PROTOCOL_ERROR),
    ("headers_on_stream_zero", frame(0x1, 0x5, 0, b"\x82"), PROTOCOL_ERROR),
    ("rst_stream_on_stream_zero",
     frame(0x3, 0x0, 0, struct.pack("!I", 0)), PROTOCOL_ERROR),
    ("settings_on_stream_one", frame(0x4, 0x0, 1), PROTOCOL_ERROR),
    ("settings_ack_with_payload",
     frame(0x4, 0x1, 0, struct.pack("!HI", 0x1, 4096)), FRAME_SIZE_ERROR),
    ("settings_wrong_length", frame(0x4, 0x0, 0, b"\x00"), FRAME_SIZE_ERROR),
    ("ping_on_stream_one", frame(0x6, 0x0, 1, b"12345678"), PROTOCOL_ERROR),
    ("ping_wrong_length", frame(0x6, 0x0, 0, b"1234567"), FRAME_SIZE_ERROR),
    ("window_update_zero_connection",
     frame(0x8, 0x0, 0, struct.pack("!I", 0)), PROTOCOL_ERROR),
]

def parse_frames(buffer):
    parsed = []
    offset = 0
    while len(buffer) - offset >= 9:
        length = int.from_bytes(buffer[offset:offset + 3], "big")
        if len(buffer) - offset < 9 + length:
            break
        frame_type = buffer[offset + 3]
        flags = buffer[offset + 4]
        stream_id = int.from_bytes(buffer[offset + 5:offset + 9], "big") & 0x7fffffff
        payload = buffer[offset + 9:offset + 9 + length]
        item = {"type": frame_type, "flags": flags,
                "stream_id": stream_id, "length": length}
        if frame_type == 0x7 and length >= 8:
            item["last_stream_id"] = int.from_bytes(payload[:4], "big") & 0x7fffffff
            item["error_code"] = int.from_bytes(payload[4:8], "big")
            item["debug_data_hex"] = payload[8:72].hex()
        parsed.append(item)
        offset += 9 + length
    return parsed, buffer[offset:]

def run_case(name, malformed, expected_error):
    context = ssl.create_default_context(cafile="/tls/ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["h2"])
    observed = []
    remainder = b""
    closed = False
    tls_version = None
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as plain:
            with context.wrap_socket(plain, server_hostname=HOST) as secure:
                tls_version = secure.version()
                if secure.selected_alpn_protocol() != "h2":
                    raise RuntimeError("server did not negotiate ALPN h2")
                secure.settimeout(0.25)
                secure.sendall(CLIENT_PREFACE + frame(0x4, 0x0, 0) + malformed)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    try:
                        chunk = secure.recv(65535)
                    except socket.timeout:
                        continue
                    except (ConnectionError, OSError, ssl.SSLError):
                        closed = True
                        break
                    if not chunk:
                        closed = True
                        break
                    parsed, remainder = parse_frames(remainder + chunk)
                    observed.extend(parsed)
                    if any(item.get("error_code") == expected_error
                           for item in observed if item["type"] == 0x7):
                        break
    except Exception as error:
        return {"name": name, "expected_goaway_error": expected_error,
                "result": "FAIL", "error": repr(error),
                "tls_version": tls_version, "frames": observed}

    goaway_errors = [item["error_code"] for item in observed
                     if item["type"] == 0x7 and "error_code" in item]
    passed = expected_error in goaway_errors
    return {"name": name, "expected_goaway_error": expected_error,
            "observed_goaway_errors": goaway_errors,
            "transport_closed": closed, "tls_version": tls_version,
            "alpn": "h2", "frames": observed,
            "result": "PASS" if passed else "FAIL"}

results = [run_case(*case) for case in tests]
summary = {
    "classification": "targeted RFC 9113 malformed-frame negative tests",
    "transport": "CA-verified TLS with hostname verification and ALPN h2",
    "total": len(results),
    "passed": sum(item["result"] == "PASS" for item in results),
    "failed": sum(item["result"] != "PASS" for item in results),
    "results": results,
}
summary["result"] = "PASS" if summary["failed"] == 0 else "FAIL"
print(json.dumps(summary, indent=2))
sys.exit(0 if summary["result"] == "PASS" else 1)
' >"$evidence_dir/rfc9113-raw-results.json" \
  2>>"$evidence_dir/rfc9113-raw.stderr.txt"
raw_status="$?"
set -e
printf '%s\n' "$raw_status" >"$evidence_dir/rfc9113-raw-exit-status.txt"

stage="running independent oha HTTP/2 interoperability"
set +e
docker run --rm --pull never --platform "$platform" --network "$network" \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 256m \
  --user "$(id -u):$(id -g)" \
  --volume "$client_dir:/tls:ro" "$oha_image" \
  -n 64 -c 2 -p 16 --no-tui --no-color --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/bonvoyage/ready \
  >"$evidence_dir/oha-fixed-response.json" 2>"$evidence_dir/oha-fixed-response.stderr.txt"
oha_fixed_status="$?"

docker run --rm --pull never --platform "$platform" --network "$network" \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 256m \
  --user "$(id -u):$(id -g)" \
  --volume "$client_dir:/tls:ro" "$oha_image" \
  -n 16 -c 1 -p 4 --no-tui --no-color --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/payload/131072 \
  >"$evidence_dir/oha-flow-controlled-response.json" \
  2>"$evidence_dir/oha-flow-controlled-response.stderr.txt"
oha_response_status="$?"

docker run --rm --pull never --platform "$platform" --network "$network" \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 256m \
  --user "$(id -u):$(id -g)" \
  --volume "$client_dir:/tls:ro" "$oha_image" \
  -n 16 -c 2 -p 2 -m POST -D /tls/request-body.bin \
  -T application/octet-stream --no-tui --no-color --output-format json \
  --http-version 2 --disable-compression --cacert /tls/ca.pem \
  https://api.example.test:8443/echo \
  >"$evidence_dir/oha-flow-controlled-request.json" \
  2>"$evidence_dir/oha-flow-controlled-request.stderr.txt"
oha_request_status="$?"
set -e

printf 'fixed_response=%s\nflow_controlled_response=%s\nflow_controlled_request=%s\n' \
  "$oha_fixed_status" "$oha_response_status" "$oha_request_status" \
  >"$evidence_dir/oha-exit-statuses.txt"

set +e
python3 - "$evidence_dir" "$oha_fixed_status" "$oha_response_status" \
  "$oha_request_status" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
definitions = [
    ("fixed_response", "oha-fixed-response.json", 64, int(sys.argv[2])),
    ("flow_controlled_response", "oha-flow-controlled-response.json", 16,
     int(sys.argv[3])),
    ("flow_controlled_request", "oha-flow-controlled-request.json", 16,
     int(sys.argv[4])),
]
results = []
for name, filename, expected, process_status in definitions:
    path = root / filename
    item = {"name": name, "artifact": filename,
            "expected_requests": expected,
            "process_exit_status": process_status}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        status_codes = payload.get("statusCodeDistribution", {})
        errors = payload.get("errorDistribution", {})
        summary = payload["summary"]
        item.update({
            "successful_requests": status_codes.get("200", 0),
            "success_rate": summary["successRate"],
            "requests_per_second": summary["requestsPerSec"],
            "p99_seconds": payload.get("latencyPercentiles", {}).get("p99"),
            "errors": errors,
        })
        passed = (process_status == 0 and summary["successRate"] == 1 and
                  status_codes.get("200") == expected and not errors)
    except Exception as error:
        item["parse_error"] = repr(error)
        passed = False
    item["result"] = "PASS" if passed else "FAIL"
    results.append(item)

report = {
    "classification": "independent oha HTTP/2 interoperability",
    "transport": "CA-verified TLS with hostname verification and forced HTTP/2",
    "insecure_mode": False,
    "total": len(results),
    "passed": sum(item["result"] == "PASS" for item in results),
    "failed": sum(item["result"] != "PASS" for item in results),
    "results": results,
}
report["result"] = "PASS" if report["failed"] == 0 else "FAIL"
(root / "oha-summary.json").write_text(
    json.dumps(report, indent=2) + "\n", encoding="utf-8")
sys.exit(0 if report["result"] == "PASS" else 1)
PY
oha_summary_status="$?"
set -e

stage="verifying post-test recovery"
docker exec "$upstream" python -c '
import urllib.request
ready = urllib.request.urlopen(
    "http://bonvoyage-http2-conformance-gateway-'"$suffix"':9901/health/ready",
    timeout=10,
)
assert ready.status == 200
print(urllib.request.urlopen(
    "http://bonvoyage-http2-conformance-gateway-'"$suffix"':9090/metrics",
    timeout=10,
).read().decode(), end="")
' >"$evidence_dir/metrics-after.prom"

overall_result="PASS"
if [ "$h2spec_summary_status" -ne 0 ] || [ "$raw_status" -ne 0 ] || \
   [ "$oha_fixed_status" -ne 0 ] || \
   [ "$oha_response_status" -ne 0 ] || [ "$oha_request_status" -ne 0 ] || \
   [ "$oha_summary_status" -ne 0 ]; then
  overall_result="FAIL"
fi

cat >"$evidence_dir/overall-summary.txt" <<EOF
result=$overall_result
completed_at_utc=$(date -u +%Y%m%dT%H%M%SZ)
scope=downstream HTTP/2 qualification only
network_isolation=private internal Docker network with no published host ports
h2spec_result=$(if [ "$h2spec_summary_status" -eq 0 ]; then printf PASS; else printf FAIL; fi)
h2spec_process_exit_status=$h2spec_status
h2spec_scope=supplemental legacy RFC 7540 and RFC 7541 HPACK signal; not RFC 9113 proof
h2spec_variance_policy=only exact package, classname, and outcome matches in the reviewed RFC 9113 allowlist are accepted
h2spec_allowed_variances=$h2spec_allowed_variances
h2spec_unexpected_failures=$h2spec_unexpected_failures
h2spec_missing_variances=$h2spec_missing_variances
h2spec_resolved_variances=$h2spec_resolved_variances
h2spec_unexercised_variances=$h2spec_unexercised_variances
h2spec_classification_artifact=h2spec-classification.json
h2spec_summary_artifact=h2spec-summary.json
h2spec_variance_allowlist_artifact=h2spec-rfc9113-variance-allowlist.json
h2spec_certificate_exception=verification disabled only for the ephemeral test certificate because h2spec has no custom CA option
rfc9113_raw_result=$(if [ "$raw_status" -eq 0 ]; then printf PASS; else printf FAIL; fi)
rfc9113_raw_transport=CA-verified TLS, hostname verification, exact ALPN h2
oha_interoperability_result=$(if [ "$oha_summary_status" -eq 0 ]; then printf PASS; else printf FAIL; fi)
oha_transport=CA-verified TLS, hostname verification, forced HTTP/2, no insecure mode
private_keys_retained=false
EOF

stage="completed"
if [ "$overall_result" != "PASS" ]; then
  exit 1
fi

echo "BonVoyage downstream HTTP/2 conformance qualification passed"
