#!/bin/sh
set -eu

umask 077

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
catalog="$repo/benchmarks/workloads/policy-cost/phase5-policy-cost.json"
validator="$repo/benchmarks/scripts/phase5-policy-semantic.mjs"
renderer="$repo/benchmarks/scripts/phase5-policy-nginx.mjs"

loadgen_host="${BONVOYAGE_POLICY_LOADGEN_HOST:-load-generator.example.test}"
gateway_host="${BONVOYAGE_POLICY_GATEWAY_HOST:-gateway-target.example.test}"
upstream_a_host="${BONVOYAGE_POLICY_UPSTREAM_A_HOST:-upstream-a.example.test}"
upstream_b_host="${BONVOYAGE_POLICY_UPSTREAM_B_HOST:-upstream-b.example.test}"
gateway_ip="${BONVOYAGE_POLICY_GATEWAY_IP:-192.0.2.20}"
upstream_a_ip="${BONVOYAGE_POLICY_UPSTREAM_A_IP:-192.0.2.30}"
upstream_b_ip="${BONVOYAGE_POLICY_UPSTREAM_B_IP:-192.0.2.31}"
upstream_a_original="${BONVOYAGE_POLICY_UPSTREAM_A_CONTAINER:-bonvoyage-perf01-upstream}"
upstream_b_original="${BONVOYAGE_POLICY_UPSTREAM_B_CONTAINER:-bonvoyage-perf01-upstream-b}"
gateway_service="bonvoyage.service"
gateway_binary_sha256="bcd3122bfcaf5787ca431c6f534185c7cf48494ddd52bfa8724559ccc23a9bf0"
nginx_image="docker.io/library/nginx@sha256:9e4b33ead4c69e9845e53a1f175d0aa70a6cea62425b5d08957ba7eee5dc9b1d"
upstream_image="bonvoyage-upstream:perf01"
run_id="policy-semantic-$(date -u +%Y%m%dT%H%M%SZ)-$$"
remote_dir="/var/tmp/bonvoyage-$run_id"
evidence="${BONVOYAGE_POLICY_EVIDENCE_DIR:-}"
private="$(mktemp -d "${TMPDIR:-/tmp}/bonvoyage-policy-semantic.XXXXXX")"
restored=0
runtime_touched=0

fail() { echo "phase5-policy-semantic-preflight: $*" >&2; exit 1; }

safe_host() {
  case "$1" in
    ''|*[!A-Za-z0-9._-]*) fail "unsafe SSH host alias: $1" ;;
  esac
}

safe_container() {
  case "$1" in
    ''|*[!A-Za-z0-9_.-]*) fail "unsafe container name: $1" ;;
  esac
}

safe_ipv4() (
  value="$1"
  printf '%s\n' "$value" | awk -F. '
    NF != 4 { exit 1 }
    { for (part = 1; part <= 4; part++) {
        if ($part !~ /^[0-9]+$/ || $part > 255) exit 1
      }
    }
  ' || fail "invalid IPv4 address: $value"
)

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

remote() ( host="$1"; shift; ssh -o BatchMode=yes "$host" "$@"; )

restore_remote() (
  restore_status=0
  for profile in c00 c01 c02 c03 c04 c05; do
    remote "$gateway_host" "sudo systemctl stop bonvoyage-phase5-policy-$profile.service >/dev/null 2>&1 || true" || restore_status=1
  done
  remote "$gateway_host" "sudo docker rm --force bonvoyage-phase5-policy-nginx >/dev/null 2>&1 || true" || restore_status=1
  remote "$upstream_a_host" "sudo docker rm --force bonvoyage-phase5-policy-upstream-a >/dev/null 2>&1 || true" || restore_status=1
  remote "$upstream_a_host" "sudo docker start '$upstream_a_original' >/dev/null" || restore_status=1
  remote "$upstream_a_host" "sudo rm -rf '$remote_dir'" || restore_status=1
  remote "$upstream_b_host" "sudo docker rm --force bonvoyage-phase5-policy-upstream-b >/dev/null 2>&1 || true" || restore_status=1
  remote "$upstream_b_host" "sudo docker start '$upstream_b_original' >/dev/null" || restore_status=1
  remote "$upstream_b_host" "sudo rm -rf '$remote_dir'" || restore_status=1
  remote "$gateway_host" "sudo rm -rf '$remote_dir'" || restore_status=1
  remote "$gateway_host" "sudo systemctl start '$gateway_service'" || restore_status=1
  remote "$loadgen_host" "sudo rm -rf '$remote_dir'" || restore_status=1
  return "$restore_status"
)

cleanup() {
  status="$?"
  trap - EXIT INT TERM
  set +e
  if [ "$runtime_touched" -eq 1 ] && [ "$restored" -ne 1 ]; then
    restore_remote || status=1
  fi
  rm -rf "$private"
  if [ "$status" -ne 0 ] && [ -d "$evidence" ]; then
    echo "semantic preflight failed; safe partial evidence retained at $evidence" >&2
  elif [ "$status" -ne 0 ]; then
    echo 'semantic preflight failed before evidence-directory creation' >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for host in "$loadgen_host" "$gateway_host" "$upstream_a_host" "$upstream_b_host"; do safe_host "$host"; done
safe_container "$upstream_a_original"
safe_container "$upstream_b_original"
[ "$loadgen_host" != "$gateway_host" ] &&
  [ "$loadgen_host" != "$upstream_a_host" ] &&
  [ "$loadgen_host" != "$upstream_b_host" ] &&
  [ "$gateway_host" != "$upstream_a_host" ] &&
  [ "$gateway_host" != "$upstream_b_host" ] &&
  [ "$upstream_a_host" != "$upstream_b_host" ] || fail 'all four role hosts must be distinct'
for address in "$gateway_ip" "$upstream_a_ip" "$upstream_b_ip"; do safe_ipv4 "$address"; done
[ "$gateway_ip" != "$upstream_a_ip" ] && [ "$gateway_ip" != "$upstream_b_ip" ] &&
  [ "$upstream_a_ip" != "$upstream_b_ip" ] || fail 'gateway and upstream addresses must be distinct'
for tool in git go jq node openssl scp ssh; do command -v "$tool" >/dev/null 2>&1 || fail "$tool required"; done
[ -n "$evidence" ] || fail 'BONVOYAGE_POLICY_EVIDENCE_DIR is required'
case "$evidence" in "$repo"/*) ;; *) fail 'evidence directory must be inside the repository' ;; esac
[ ! -e "$evidence" ] || fail "evidence path already exists: $evidence"
[ -z "$(git -C "$repo" status --porcelain)" ] || fail 'source tree must be clean'
source_commit="$(git -C "$repo" rev-parse HEAD)"
[ "$source_commit" = "$(git -C "$repo" rev-parse origin/main)" ] ||
  fail 'source commit must match origin/main'
evidence_relative="${evidence#"$repo/"}"
mkdir -p "$evidence/raw" "$evidence/results" "$evidence/compile" "$private/snapshots" "$private/nginx" "$private/secrets"

for host in "$loadgen_host" "$gateway_host" "$upstream_a_host" "$upstream_b_host"; do
  remote "$host" 'hostname; hostname -I; uname -a; uptime; df -h /' >"$evidence/$host.txt"
done
grep -qw "$gateway_ip" "$evidence/$gateway_host.txt" || fail 'gateway private address changed'
grep -qw "$upstream_a_ip" "$evidence/$upstream_a_host.txt" || fail 'upstream-a private address changed'
grep -qw "$upstream_b_ip" "$evidence/$upstream_b_host.txt" || fail 'upstream-b private address changed'
remote "$gateway_host" "sha256sum /usr/bin/bonvoyage-dataplane; systemctl is-active '$gateway_service'; systemctl show '$gateway_service' -p MainPID -p NRestarts --no-pager; getent hosts upstream-a upstream-b" >"$evidence/gateway-before.txt"
grep -Fq "$gateway_binary_sha256  /usr/bin/bonvoyage-dataplane" "$evidence/gateway-before.txt" || fail 'gateway binary identity changed'
grep -Fq "$upstream_a_ip" "$evidence/gateway-before.txt" || fail 'upstream-a resolution changed'
grep -Fq "$upstream_b_ip" "$evidence/gateway-before.txt" || fail 'upstream-b resolution changed'
grep -Fxq active "$evidence/gateway-before.txt" || fail 'gateway package service must be active before preflight'
remote "$upstream_a_host" "sudo docker inspect '$upstream_a_original' --format '{{.State.Running}} {{.Config.Image}}'" >"$evidence/upstream-a-before.txt"
remote "$upstream_b_host" "sudo docker inspect '$upstream_b_original' --format '{{.State.Running}} {{.Config.Image}}'" >"$evidence/upstream-b-before.txt"
grep -Fq 'true ' "$evidence/upstream-a-before.txt" || fail 'upstream-a baseline container is not running'
grep -Fq 'true ' "$evidence/upstream-b-before.txt" || fail 'upstream-b baseline container is not running'

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj '/CN=BonVoyage Phase 5 Policy CA' \
  -keyout "$private/secrets/ca-key.pem" -out "$private/secrets/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=api.example.test' \
  -keyout "$private/secrets/server-key.pem" -out "$private/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:api.example.test' 'extendedKeyUsage=serverAuth' \
  'keyUsage=digitalSignature,keyEncipherment' >"$private/server-ext.cnf"
openssl x509 -req -days 1 -sha256 -in "$private/server.csr" \
  -CA "$private/secrets/ca.pem" -CAkey "$private/secrets/ca-key.pem" \
  -CAcreateserial -extfile "$private/server-ext.cnf" \
  -out "$private/secrets/server-chain.pem" >/dev/null 2>&1
api_key="$(openssl rand -hex 24)"
printf '%s\n' "$api_key" >"$private/secrets/phase5-policy-api-keys.txt"
chmod 600 "$private/secrets"/*-key.pem "$private/secrets/phase5-policy-api-keys.txt"

for profile in c00 c01 c02 c03 c04 c05; do
  (cd "$repo/control-plane" && go run ./cmd/bonvoyage-control-plane \
    -input "../tests/fixtures/phase5-policy-$profile.yaml" \
    -output "$private/snapshots/$profile.pb") >"$evidence/compile/$profile.log"
done
for profile in P5-C00 P5-C01 P5-C02; do
  node "$renderer" --catalog "$catalog" --profile "$profile" --workers 8 \
    --upstream-a "$upstream_a_ip" --upstream-b "$upstream_b_ip" \
    >"$private/nginx/$profile.conf"
done

for host in "$loadgen_host" "$gateway_host" "$upstream_a_host" "$upstream_b_host"; do
  remote "$host" "install -d -m 700 '$remote_dir'"
done
scp -q "$repo/benchmarks/products/upstream/nginx.conf" "$upstream_a_host:$remote_dir/nginx.conf"
scp -q "$repo/benchmarks/products/upstream/nginx.conf" "$upstream_b_host:$remote_dir/nginx.conf"
runtime_touched=1
remote "$upstream_a_host" "sudo docker stop '$upstream_a_original' >/dev/null && sudo docker run --detach --name bonvoyage-phase5-policy-upstream-a --network host --volume '$remote_dir/nginx.conf:/etc/nginx/nginx.conf:ro' '$upstream_image' >/dev/null"
remote "$upstream_b_host" "sudo docker stop '$upstream_b_original' >/dev/null && sudo docker run --detach --name bonvoyage-phase5-policy-upstream-b --network host --volume '$remote_dir/nginx.conf:/etc/nginx/nginx.conf:ro' '$upstream_image' >/dev/null"
remote "$upstream_a_host" 'for attempt in 1 2 3 4 5 6 7 8 9 10; do curl -fsS http://127.0.0.1:8081/healthz >/dev/null && exit 0; sleep 1; done; exit 1'
remote "$upstream_b_host" 'for attempt in 1 2 3 4 5 6 7 8 9 10; do curl -fsS http://127.0.0.1:8081/healthz >/dev/null && exit 0; sleep 1; done; exit 1'
remote "$upstream_a_host" "sudo docker exec bonvoyage-phase5-policy-upstream-a sha256sum /etc/nginx/nginx.conf /srv/payload/256 /srv/payload/8192; sudo docker image inspect '$upstream_image' --format '{{.Id}} {{json .RepoDigests}}'" >"$evidence/upstream-a-runtime.txt"
remote "$upstream_b_host" "sudo docker exec bonvoyage-phase5-policy-upstream-b sha256sum /etc/nginx/nginx.conf /srv/payload/256 /srv/payload/8192; sudo docker image inspect '$upstream_image' --format '{{.Id}} {{json .RepoDigests}}'" >"$evidence/upstream-b-runtime.txt"

remote "$gateway_host" "install -d -m 700 '$remote_dir/snapshots' '$remote_dir/secrets' '$remote_dir/nginx' && sudo systemctl stop '$gateway_service'"
scp -q "$private/snapshots/"*.pb "$gateway_host:$remote_dir/snapshots/"
scp -q "$private/secrets/ca.pem" "$private/secrets/server-chain.pem" \
  "$private/secrets/server-key.pem" "$private/secrets/phase5-policy-api-keys.txt" \
  "$gateway_host:$remote_dir/secrets/"
scp -q "$private/nginx/"*.conf "$gateway_host:$remote_dir/nginx/"
remote "$gateway_host" "sudo chmod 711 '$remote_dir' && sudo chmod 700 '$remote_dir/snapshots' '$remote_dir/secrets' && sudo chmod 600 '$remote_dir/secrets/ca.pem' '$remote_dir/secrets/server-chain.pem' '$remote_dir/secrets/server-key.pem' '$remote_dir/secrets/phase5-policy-api-keys.txt' '$remote_dir/snapshots/c00.pb' '$remote_dir/snapshots/c01.pb' '$remote_dir/snapshots/c02.pb' '$remote_dir/snapshots/c03.pb' '$remote_dir/snapshots/c04.pb' '$remote_dir/snapshots/c05.pb' && sudo chown -R bonvoyage:bonvoyage '$remote_dir/snapshots' '$remote_dir/secrets'"
scp -q "$private/secrets/ca.pem" "$loadgen_host:$remote_dir/ca.pem"

start_gateway() (
  profile="$1"
  remote "$gateway_host" "sudo systemd-run --quiet --collect --unit 'bonvoyage-phase5-policy-$profile' --property User=bonvoyage --property Group=bonvoyage --property LimitNOFILE=1048576 --property NoNewPrivileges=true /usr/bin/bonvoyage-dataplane --snapshot '$remote_dir/snapshots/$profile.pb' --secrets-directory '$remote_dir/secrets' --admin-address 127.0.0.1 --metrics-address 127.0.0.1 --runtime-log-transport unix --runtime-log-socket /dev/log --log-to-syslog 1 --log-to-stdout 0 --smp 1 --memory 512M --overprovisioned"
  if ! remote "$gateway_host" 'for attempt in 1 2 3 4 5 6 7 8 9 10; do curl -fsS http://127.0.0.1:9901/health/ready >/dev/null && exit 0; sleep 1; done; exit 1'; then
    remote "$gateway_host" "sudo journalctl -u 'bonvoyage-phase5-policy-$profile.service' --no-pager -n 100" >"$evidence/$profile-startup-failure.log" 2>&1 || true
    fail "$profile gateway did not become ready"
  fi
)

stop_gateway() (
  profile="$1"
  remote "$gateway_host" "sudo systemctl stop 'bonvoyage-phase5-policy-$profile.service'"
)

write_request() (
  profile="$1"; request_case="$2"; request_path="$3"; shift 3
  request_file="$private/request.conf"
  {
    printf '%s\n' 'silent' 'show-error' 'http1.1'
    printf 'cacert = "%s/ca.pem"\n' "$remote_dir"
    printf 'resolve = "api.example.test:8443:%s"\n' "$gateway_ip"
    printf 'url = "https://api.example.test:8443%s"\n' "$request_path"
    for header in "$@"; do printf 'header = "%s"\n' "$header"; done
  } >"$request_file"
  chmod 600 "$request_file"
  remote_request="$remote_dir/$profile-$request_case.request"
  scp -q "$request_file" "$loadgen_host:$remote_request"
  remote "$loadgen_host" "chmod 600 '$remote_request'; curl --config '$remote_request' --dump-header '$remote_dir/$profile-$request_case.headers' --output '$remote_dir/$profile-$request_case.body' --write-out '%{http_code}\\n' >'$remote_dir/$profile-$request_case.status'; rm -f '$remote_request'"
)

retain_probe() (
  product="$1"; profile="$2"; request_case="$3"
  stem="$product-$profile-$request_case"
  scp -q "$loadgen_host:$remote_dir/$profile-$request_case.status" "$evidence/raw/$stem.status"
  scp -q "$loadgen_host:$remote_dir/$profile-$request_case.headers" "$evidence/raw/$stem.headers"
  scp -q "$loadgen_host:$remote_dir/$profile-$request_case.body" "$evidence/raw/$stem.body"
  remote "$loadgen_host" "rm -f '$remote_dir/$profile-$request_case.status' '$remote_dir/$profile-$request_case.headers' '$remote_dir/$profile-$request_case.body'"
  node "$validator" --catalog "$catalog" --profile "$profile" --product "$product" \
    --case "$request_case" --status "$evidence/raw/$stem.status" \
    --headers "$evidence/raw/$stem.headers" --body "$evidence/raw/$stem.body" \
    >"$evidence/results/$stem.json"
)

run_probe() (
  product="$1"; profile="$2"; request_case="$3"; request_path="$4"; shift 4
  write_request "$profile" "$request_case" "$request_path" "$@"
  retain_probe "$product" "$profile" "$request_case"
)

for profile in c00 c01 c02; do
  upper="$(printf '%s' "$profile" | tr '[:lower:]' '[:upper:]')"
  start_gateway "$profile"
  case "$profile" in
    c00) run_probe bonvoyage "P5-$upper" allow /policy/payload/8192 ;;
    c01) run_probe bonvoyage "P5-$upper" allow /policy/payload/256 \
      'x-policy-set: client-set' 'x-policy-append: client-append' 'x-policy-remove: client-remove' ;;
    c02) run_probe bonvoyage "P5-$upper" allow /policy/payload/8192 \
      'x-policy-set: client-set' 'x-policy-append: client-append' 'x-policy-remove: client-remove' ;;
  esac
  stop_gateway "$profile"
done

start_gateway c03
run_probe bonvoyage P5-C03 allow /policy/payload/8192 "x-api-key: $api_key"
run_probe bonvoyage P5-C03 invalid-credential /policy/payload/8192 'x-api-key: invalid-phase5-key'
run_probe bonvoyage P5-C03 missing-credential /policy/payload/8192
stop_gateway c03

for profile in c04 c05; do
  rm -rf "$private/jwt"
  "$repo/scripts/generate-jwt-smoke-material.py" "$private/jwt"
  cp "$private/jwt/phase3-jwks.json" "$private/secrets/phase5-policy-jwks.json"
  scp -q "$private/secrets/phase5-policy-jwks.json" "$gateway_host:$remote_dir/phase5-policy-jwks.json"
  remote "$gateway_host" "sudo install -o bonvoyage -g bonvoyage -m 600 '$remote_dir/phase5-policy-jwks.json' '$remote_dir/secrets/phase5-policy-jwks.json' && rm -f '$remote_dir/phase5-policy-jwks.json'"
  valid_token="$(jq -r .valid "$private/jwt/jwt-tokens.json")"
  bad_token="$(jq -r .bad_signature "$private/jwt/jwt-tokens.json")"
  scope_token="$(jq -r .wrong_scope "$private/jwt/jwt-tokens.json")"
  start_gateway "$profile"
  if [ "$profile" = c04 ]; then payload=256; else payload=8192; fi
  upper="$(printf '%s' "$profile" | tr '[:lower:]' '[:upper:]')"
  run_probe bonvoyage "P5-$upper" allow "/policy/payload/$payload" "Authorization: Bearer $valid_token"
  run_probe bonvoyage "P5-$upper" invalid-credential "/policy/payload/$payload" "Authorization: Bearer $bad_token"
  run_probe bonvoyage "P5-$upper" insufficient-scope "/policy/payload/$payload" "Authorization: Bearer $scope_token"
  stop_gateway "$profile"
  unset valid_token bad_token scope_token
done

for profile in P5-C00 P5-C01 P5-C02; do
  remote "$gateway_host" "sudo docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m --volume '$remote_dir/nginx/$profile.conf:/etc/nginx/nginx.conf:ro' --volume '$remote_dir/secrets:/tls:ro' '$nginx_image' nginx -t" >"$evidence/$profile-nginx-t.log" 2>&1
  remote "$gateway_host" "sudo docker run --detach --name bonvoyage-phase5-policy-nginx --network host --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m --volume '$remote_dir/nginx/$profile.conf:/etc/nginx/nginx.conf:ro' --volume '$remote_dir/secrets:/tls:ro' '$nginx_image' nginx -g 'daemon off;' -c /etc/nginx/nginx.conf >/dev/null"
  remote "$gateway_host" 'for attempt in 1 2 3 4 5 6 7 8 9 10; do curl -fsS http://127.0.0.1:9901/health/ready >/dev/null && exit 0; sleep 1; done; exit 1'
  case "$profile" in
    P5-C00) run_probe nginx "$profile" allow /policy/payload/8192 ;;
    P5-C01) run_probe nginx "$profile" allow /policy/payload/256 \
      'x-policy-set: client-set' 'x-policy-append: client-append' 'x-policy-remove: client-remove' ;;
    P5-C02) run_probe nginx "$profile" allow /policy/payload/8192 \
      'x-policy-set: client-set' 'x-policy-append: client-append' 'x-policy-remove: client-remove' ;;
  esac
  remote "$gateway_host" 'sudo docker rm --force bonvoyage-phase5-policy-nginx >/dev/null'
done

[ "$(find "$evidence/results" -type f -name '*.json' | wc -l | tr -d ' ')" -eq 15 ] || fail 'semantic result count changed'
[ "$source_commit" = "$(git -C "$repo" rev-parse HEAD)" ] || fail 'source commit changed during preflight'
git -C "$repo" diff --quiet || fail 'tracked source changed during preflight'
git -C "$repo" diff --cached --quiet || fail 'staged source changed during preflight'
unexpected_untracked="$(git -C "$repo" ls-files --others --exclude-standard | awk -v prefix="$evidence_relative/" 'index($0, prefix) != 1')"
[ -z "$unexpected_untracked" ] || fail 'untracked source changed during preflight'

restore_remote || fail 'remote restoration failed'
remote "$gateway_host" "test ! -e '$remote_dir' && test -z \"\$(sudo docker ps -a --filter name=^/bonvoyage-phase5-policy-nginx\$ --format '{{.Names}}')\" && test -z \"\$(systemctl list-units --all 'bonvoyage-phase5-policy-*' --no-legend --plain)\" && systemctl is-active '$gateway_service' && systemctl show '$gateway_service' -p NRestarts --no-pager" >"$evidence/gateway-after.txt"
grep -Fxq active "$evidence/gateway-after.txt" || fail 'gateway package service was not restored'
remote "$upstream_a_host" "test ! -e '$remote_dir' && for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do [ \"\$(sudo docker inspect '$upstream_a_original' --format '{{.State.Health.Status}}' 2>/dev/null)\" = healthy ] && curl -fsS http://127.0.0.1:8081/healthz >/dev/null && break; sleep 1; done && [ \"\$(sudo docker inspect '$upstream_a_original' --format '{{.State.Health.Status}}' 2>/dev/null)\" = healthy ] && curl -fsS http://127.0.0.1:8081/healthz >/dev/null && sudo docker inspect '$upstream_a_original' --format '{{.State.Running}} {{.State.Health.Status}} {{.Config.Image}}'" >"$evidence/upstream-a-after.txt"
remote "$upstream_b_host" "test ! -e '$remote_dir' && for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do [ \"\$(sudo docker inspect '$upstream_b_original' --format '{{.State.Health.Status}}' 2>/dev/null)\" = healthy ] && curl -fsS http://127.0.0.1:8081/healthz >/dev/null && break; sleep 1; done && [ \"\$(sudo docker inspect '$upstream_b_original' --format '{{.State.Health.Status}}' 2>/dev/null)\" = healthy ] && curl -fsS http://127.0.0.1:8081/healthz >/dev/null && sudo docker inspect '$upstream_b_original' --format '{{.State.Running}} {{.State.Health.Status}} {{.Config.Image}}'" >"$evidence/upstream-b-after.txt"
grep -Fq 'true healthy ' "$evidence/upstream-a-after.txt" || fail 'upstream-a baseline container was not restored healthy'
grep -Fq 'true healthy ' "$evidence/upstream-b-after.txt" || fail 'upstream-b baseline container was not restored healthy'
remote "$loadgen_host" "test ! -e '$remote_dir'"
restored=1

jq -n --arg commit "$source_commit" --arg binary "$gateway_binary_sha256" \
  --arg nginx "$nginx_image" --arg run_id "$run_id" \
  '{schema_version:1,evidence_class:"shared-vm-semantic-preflight",source_commit:$commit,source_dirty:false,run_id:$run_id,bonvoyage_binary_sha256:$binary,nginx_image:$nginx,bonvoyage_probe_count:12,nginx_probe_count:3,semantic_result:"pass",performance_claim_authorized:false}' \
  >"$evidence/summary.json"
{
  printf '%s  %s\n' "$(sha256_file "$repo/benchmarks/workloads/policy-cost/phase5-policy-cost.json")" 'benchmarks/workloads/policy-cost/phase5-policy-cost.json'
  printf '%s  %s\n' "$(sha256_file "$repo/benchmarks/scripts/phase5-policy-semantic.mjs")" 'benchmarks/scripts/phase5-policy-semantic.mjs'
  printf '%s  %s\n' "$(sha256_file "$repo/benchmarks/scripts/phase5-policy-semantic-preflight.sh")" 'benchmarks/scripts/phase5-policy-semantic-preflight.sh'
  printf '%s  %s\n' "$(sha256_file "$repo/benchmarks/scripts/phase5-policy-nginx.mjs")" 'benchmarks/scripts/phase5-policy-nginx.mjs'
  printf '%s  %s\n' "$(sha256_file "$repo/benchmarks/products/upstream/nginx.conf")" 'benchmarks/products/upstream/nginx.conf'
  for profile in c00 c01 c02 c03 c04 c05; do
    printf '%s  %s\n' "$(sha256_file "$repo/tests/fixtures/phase5-policy-$profile.yaml")" "tests/fixtures/phase5-policy-$profile.yaml"
  done
} >"$evidence/source-checksums.sha256"
(cd "$evidence" && find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | while IFS= read -r file; do printf '%s  %s\n' "$(sha256_file "$file")" "$file"; done) >"$evidence/SHA256SUMS"

rm -rf "$private"
trap - EXIT INT TERM
echo "Phase 5 policy semantic preflight passed: $evidence"
