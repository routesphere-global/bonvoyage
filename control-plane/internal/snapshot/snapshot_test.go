package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"google.golang.org/protobuf/proto"
)

func TestOSSNativeFixtureMatchesContractAndArtifact(t *testing.T) {
	type artifactRecord struct {
		Path       string `json:"path"`
		SnapshotID string `json:"snapshot_id"`
		Generation uint64 `json:"generation"`
		Bytes      int    `json:"bytes"`
		SHA256     string `json:"sha256"`
	}
	type fixtureRecord struct {
		Path     string         `json:"path"`
		Bytes    int            `json:"bytes"`
		SHA256   string         `json:"sha256"`
		Snapshot artifactRecord `json:"snapshot"`
	}
	var contract struct {
		Fixture fixtureRecord `json:"fixture"`
	}
	contractRaw, err := os.ReadFile("../../../packaging/release/debian/oss-native-fresh-install-contract.json")
	if err != nil {
		t.Fatalf("read native contract: %v", err)
	}
	if err := json.Unmarshal(contractRaw, &contract); err != nil {
		t.Fatalf("decode native contract: %v", err)
	}
	fixturePath := "../../../" + contract.Fixture.Path
	fixtureRaw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read native fixture: %v", err)
	}
	fixtureDigest := fmt.Sprintf("%x", sha256.Sum256(fixtureRaw))
	if len(fixtureRaw) != contract.Fixture.Bytes || fixtureDigest != contract.Fixture.SHA256 {
		t.Fatalf("native fixture binding mismatch: bytes=%d sha256=%s", len(fixtureRaw), fixtureDigest)
	}
	compiled, err := Compile(bytes.NewReader(fixtureRaw))
	if err != nil {
		t.Fatalf("compile native fixture: %v", err)
	}
	compiledRaw, err := MarshalDeterministic(compiled)
	if err != nil {
		t.Fatalf("marshal native fixture: %v", err)
	}
	artifactRaw, err := os.ReadFile("../../../" + contract.Fixture.Snapshot.Path)
	if err != nil {
		t.Fatalf("read native fixture artifact: %v", err)
	}
	artifactDigest := fmt.Sprintf("%x", sha256.Sum256(artifactRaw))
	if !bytes.Equal(compiledRaw, artifactRaw) ||
		len(artifactRaw) != contract.Fixture.Snapshot.Bytes ||
		artifactDigest != contract.Fixture.Snapshot.SHA256 ||
		compiled.GetSnapshotId() != contract.Fixture.Snapshot.SnapshotID ||
		compiled.GetGeneration() != contract.Fixture.Snapshot.Generation {
		t.Fatalf("native fixture artifact does not match contract: bytes=%d sha256=%s snapshot=%s generation=%d",
			len(artifactRaw), artifactDigest, compiled.GetSnapshotId(), compiled.GetGeneration())
	}
}

const validConfig = `server:
  node_id: node-1
  admin_addr: 127.0.0.1:9901
  metrics_addr: 127.0.0.1:9090
snapshot:
  schema_version: 1
  snapshot_id: test-snapshot
  generation: 7
  minimum_dataplane_version: 0.1.0
listeners:
  - name: http
    address: 0.0.0.0
    port: 8080
    protocol: http1
    virtual_hosts: [default]
virtual_hosts:
  - name: default
    domains: ["*"]
    routes:
      - name: api
        match:
          path_prefix: /api
        cluster: backend
clusters:
  - name: backend
    load_balancing_policy: round_robin
    connect_timeout_ms: 1000
    max_connections_per_shard: 128
    max_pending_requests_per_shard: 256
    endpoints:
      - name: backend-1
        address: upstream
        port: 8081
        weight: 1
runtime_limits:
  max_downstream_connections_per_shard: 16384
  max_request_header_bytes: 32768
  max_request_body_bytes: 10485760
  max_upstream_response_header_bytes: 32768
  max_upstream_chunk_metadata_bytes: 32768
  request_timeout_ms: 15000
  downstream_idle_timeout_ms: 60000
`

func TestCompileExampleGoldenDeterministic(t *testing.T) {
	compiled, err := CompileFile("../../../config/examples/local.yaml")
	if err != nil {
		t.Fatalf("CompileFile() error = %v", err)
	}
	first, err := MarshalDeterministic(compiled)
	if err != nil {
		t.Fatalf("MarshalDeterministic() error = %v", err)
	}
	second, err := MarshalDeterministic(compiled)
	if err != nil {
		t.Fatalf("MarshalDeterministic() second error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("deterministic marshaling produced different bytes")
	}

	const wantSHA256 = "0df685415364762d826d71e722864ba2b7ed1f53508999c8be080897c0b1774b"
	gotSHA256 := fmt.Sprintf("%x", sha256.Sum256(first))
	if gotSHA256 != wantSHA256 {
		t.Fatalf("snapshot SHA-256 = %s, want %s", gotSHA256, wantSHA256)
	}

	var decoded bonvoyagev1.Snapshot
	if err := proto.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	if decoded.GetSchemaVersion() != 1 || decoded.GetSnapshotId() != "local-bootstrap" || decoded.GetGeneration() != 1 {
		t.Fatalf("unexpected snapshot identity: %+v", &decoded)
	}
	if got := decoded.GetListeners()[0].GetProtocol(); got != bonvoyagev1.Protocol_PROTOCOL_HTTP1 {
		t.Fatalf("listener protocol = %v, want HTTP1", got)
	}
	fixed := decoded.GetVirtualHosts()[0].GetRoutes()[0].GetFixedResponse()
	if fixed.GetStatusCode() != 200 || fixed.GetBody() != "ready\n" || fixed.GetContentType() != "text/plain" {
		t.Fatalf("unexpected fixed response: %+v", fixed)
	}
}

func TestCompilePhase5PolicyFixtures(t *testing.T) {
	for index := 0; index <= 5; index++ {
		id := fmt.Sprintf("phase5-policy-c%02d", index)
		t.Run(id, func(t *testing.T) {
			compiled, err := CompileFile(fmt.Sprintf("../../../tests/fixtures/%s.yaml", id))
			if err != nil {
				t.Fatalf("CompileFile() error = %v", err)
			}
			if compiled.GetSnapshotId() != id || len(compiled.GetListeners()) != 1 ||
				len(compiled.GetVirtualHosts()) != 1 ||
				len(compiled.GetVirtualHosts()[0].GetRoutes()) != 1 ||
				len(compiled.GetClusters()) != 1 {
				t.Fatalf("unexpected isolated policy snapshot: %+v", compiled)
			}
			artifact, err := MarshalDeterministic(compiled)
			if err != nil {
				t.Fatalf("MarshalDeterministic() error = %v", err)
			}
			if len(artifact) == 0 {
				t.Fatal("compiled policy snapshot is empty")
			}
		})
	}
}

func TestCompileAppliesSafeDefaults(t *testing.T) {
	input := validConfig
	for _, line := range []string{
		"    connect_timeout_ms: 1000\n",
		"    max_connections_per_shard: 128\n",
		"    max_pending_requests_per_shard: 256\n",
		"runtime_limits:\n",
		"  max_request_header_bytes: 32768\n",
		"  max_request_body_bytes: 10485760\n",
		"  max_upstream_response_header_bytes: 32768\n",
		"  max_upstream_chunk_metadata_bytes: 32768\n",
		"  request_timeout_ms: 15000\n",
		"  downstream_idle_timeout_ms: 60000\n",
		"  max_downstream_connections_per_shard: 16384\n",
	} {
		input = strings.Replace(input, line, "", 1)
	}

	compiled := compileForTest(t, input)
	cluster := compiled.GetClusters()[0]
	if cluster.GetConnectTimeoutMs() != defaultConnectTimeoutMS ||
		cluster.GetProtocol() != bonvoyagev1.Protocol_PROTOCOL_HTTP1 ||
		cluster.GetMaxConnectionsPerShard() != defaultMaxConnectionsPerShard ||
		cluster.GetMaxPendingRequestsPerShard() != defaultMaxPendingPerShard ||
		cluster.GetMaxHttp2StreamsPerConnection() != 0 ||
		cluster.GetMaxConcurrentRequestsPerEndpoint() !=
			defaultMaxConnectionsPerShard+defaultMaxPendingPerShard {
		t.Fatalf("cluster defaults were not applied: %+v", cluster)
	}
	limits := compiled.GetRuntimeLimits()
	if limits.GetMaxRequestHeaderBytes() != defaultMaxHeaderBytes ||
		limits.GetMaxRequestBodyBytes() != defaultMaxBodyBytes ||
		limits.GetMaxUpstreamResponseHeaderBytes() != defaultMaxUpstreamHeaderBytes ||
		limits.GetMaxUpstreamChunkMetadataBytes() != defaultMaxUpstreamChunkBytes ||
		limits.GetRequestTimeoutMs() != defaultRequestTimeoutMS ||
		limits.GetDownstreamIdleTimeoutMs() != defaultIdleTimeoutMS ||
		limits.GetMaxDownstreamConnectionsPerShard() != defaultMaxDownstreamPerShard {
		t.Fatalf("runtime defaults were not applied: %+v", limits)
	}
}

func TestCompileRouteAdmissionPolicy(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		"        cluster: backend\n        max_concurrent_requests_per_shard: 37\n        local_rate_limit:\n          capacity: 120\n          refill_tokens_per_second: 30\n",
		1,
	)
	compiled := compileForTest(t, input)
	route := compiled.GetVirtualHosts()[0].GetRoutes()[0]
	if route.GetMaxConcurrentRequestsPerShard() != 37 {
		t.Fatalf("route concurrency = %d, want 37", route.GetMaxConcurrentRequestsPerShard())
	}
	limit := route.GetLocalRateLimit()
	if limit.GetCapacity() != 120 || limit.GetRefillTokensPerSecond() != 30 {
		t.Fatalf("unexpected local rate limit: %+v", limit)
	}
}

func TestCompileWebSocketPolicy(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		"        cluster: backend\n        max_concurrent_requests_per_shard: 17\n        websocket:\n          idle_timeout_ms: 45000\n",
		1,
	)
	route := compileForTest(t, input).GetVirtualHosts()[0].GetRoutes()[0]
	if route.GetWebsocket().GetIdleTimeoutMs() != 45_000 ||
		route.GetMaxConcurrentRequestsPerShard() != 17 {
		t.Fatalf("unexpected compiled WebSocket policy: %+v", route)
	}

	defaultInput := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		"        cluster: backend\n        max_concurrent_requests_per_shard: 17\n        websocket: {}\n",
		1,
	)
	if got := compileForTest(t, defaultInput).GetVirtualHosts()[0].GetRoutes()[0].GetWebsocket().GetIdleTimeoutMs(); got != defaultWebSocketIdleTimeoutMS {
		t.Fatalf("default WebSocket idle timeout = %d, want %d", got, defaultWebSocketIdleTimeoutMS)
	}
}

func TestCompileRejectsInvalidWebSocketPolicy(t *testing.T) {
	withWebSocket := func(policy string) string {
		return strings.Replace(
			validConfig,
			"        cluster: backend\n",
			"        cluster: backend\n        max_concurrent_requests_per_shard: 17\n"+policy,
			1,
		)
	}
	base := withWebSocket("        websocket: {}\n")
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "missing route concurrency",
			config: strings.Replace(
				base, "        max_concurrent_requests_per_shard: 17\n", "", 1),
			wantErr: "is required for a bounded WebSocket route",
		},
		{
			name: "local response action",
			config: strings.Replace(
				base, "        cluster: backend\n", "        fixed_response:\n          status_code: 204\n", 1),
			wantErr: "supported only on reverse-proxy routes",
		},
		{
			name: "route excludes GET",
			config: strings.Replace(
				base, "          path_prefix: /api\n", "          path_prefix: /api\n          methods: [POST]\n", 1),
			wantErr: "a WebSocket route must permit GET",
		},
		{
			name:    "idle timeout below bound",
			config:  withWebSocket("        websocket:\n          idle_timeout_ms: 999\n"),
			wantErr: "must be between 1000 and 3600000",
		},
		{
			name:    "idle timeout above bound",
			config:  withWebSocket("        websocket:\n          idle_timeout_ms: 3600001\n"),
			wantErr: "must be between 1000 and 3600000",
		},
		{
			name: "HTTP2 upstream",
			config: strings.Replace(
				base,
				"    load_balancing_policy:",
				"    protocol: http2\n    upstream_tls:\n      server_name: upstream.example.test\n      trust_bundle_secret: upstream-ca.pem\n    load_balancing_policy:",
				1,
			),
			wantErr: "cluster \"backend\" must use protocol http1",
		},
		{
			name: "HTTP2 listener",
			config: strings.Replace(
				base,
				"    protocol: http1\n",
				"    protocol: http2\n    downstream_tls:\n      certificate_chain_secret: server-chain.pem\n      private_key_secret: server-key.pem\n",
				1,
			),
			wantErr: "contains a WebSocket route and requires http1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(test.config))
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

func TestCompileWeightedClusters(t *testing.T) {
	const canaryCluster = `  - name: canary
    load_balancing_policy: round_robin
    endpoints:
      - name: canary-1
        address: canary-upstream
        port: 8082
        weight: 1
`
	input := strings.Replace(validConfig, "runtime_limits:\n", canaryCluster+"runtime_limits:\n", 1)
	input = strings.Replace(
		input,
		"        cluster: backend\n",
		`        weighted_clusters:
          - {cluster: backend, weight: 9}
          - {cluster: canary, weight: 1}
        header_transformations:
          request:
            - {operation: set, name: x-release, value: canary}
        rewrite:
          path_prefix: /internal
`,
		1,
	)

	route := compileForTest(t, input).GetVirtualHosts()[0].GetRoutes()[0]
	targets := route.GetWeightedClusters()
	if route.GetClusterName() != "" || len(targets) != 2 ||
		targets[0].GetClusterName() != "backend" || targets[0].GetWeight() != 9 ||
		targets[1].GetClusterName() != "canary" || targets[1].GetWeight() != 1 {
		t.Fatalf("unexpected weighted route action: %+v", route)
	}
	if route.GetHeaderTransformations() == nil || route.GetRewrite() == nil {
		t.Fatalf("weighted proxy route lost compatible policies: %+v", route)
	}
}

func TestCompileRejectsInvalidWeightedClusters(t *testing.T) {
	const canaryCluster = `  - name: canary
    load_balancing_policy: round_robin
    endpoints:
      - name: canary-1
        address: canary-upstream
        port: 8082
        weight: 1
`
	base := strings.Replace(validConfig, "runtime_limits:\n", canaryCluster+"runtime_limits:\n", 1)
	withAction := func(action string) string {
		return strings.Replace(base, "        cluster: backend\n", action, 1)
	}
	var tooMany strings.Builder
	tooMany.WriteString("        weighted_clusters:\n")
	for index := 0; index < 17; index++ {
		fmt.Fprintf(&tooMany, "          - {cluster: backend, weight: 1} # %d\n", index)
	}

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "one target",
			input:   withAction("        weighted_clusters:\n          - {cluster: backend, weight: 1}\n"),
			wantErr: "weighted_clusters: must contain between 2 and 16 entries",
		},
		{
			name:    "too many targets",
			input:   withAction(tooMany.String()),
			wantErr: "weighted_clusters: must contain between 2 and 16 entries",
		},
		{
			name:    "unknown cluster",
			input:   withAction("        weighted_clusters:\n          - {cluster: backend, weight: 1}\n          - {cluster: missing, weight: 1}\n"),
			wantErr: `references unknown cluster "missing"`,
		},
		{
			name:    "duplicate cluster",
			input:   withAction("        weighted_clusters:\n          - {cluster: backend, weight: 1}\n          - {cluster: backend, weight: 1}\n"),
			wantErr: `duplicate cluster "backend"`,
		},
		{
			name:    "zero weight",
			input:   withAction("        weighted_clusters:\n          - {cluster: backend, weight: 0}\n          - {cluster: canary, weight: 1}\n"),
			wantErr: "weight: must be between 1 and 4096",
		},
		{
			name:    "weight total overflow",
			input:   withAction("        weighted_clusters:\n          - {cluster: backend, weight: 4096}\n          - {cluster: canary, weight: 1}\n"),
			wantErr: "total weight must not exceed 4096",
		},
		{
			name: "single and weighted actions",
			input: strings.Replace(
				base,
				"        cluster: backend\n",
				"        cluster: backend\n        weighted_clusters:\n          - {cluster: backend, weight: 1}\n          - {cluster: canary, weight: 1}\n",
				1,
			),
			wantErr: "exactly one of cluster, weighted_clusters, fixed_response, or redirect is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(test.input))
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Compile() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestCompileAPIKeyAuthPolicy(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		"        cluster: backend\n        api_key_auth:\n          header_name: X-Tenant-Key\n          credentials_secret: tenant-api-keys.txt\n",
		1,
	)
	compiled := compileForTest(t, input)
	policy := compiled.GetVirtualHosts()[0].GetRoutes()[0].GetApiKeyAuth()
	if policy.GetHeaderName() != "x-tenant-key" || policy.GetCredentialsSecret() != "tenant-api-keys.txt" {
		t.Fatalf("unexpected API-key policy: %+v", policy)
	}

	defaultInput := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		"        cluster: backend\n        api_key_auth:\n          credentials_secret: tenant-api-keys.txt\n",
		1,
	)
	defaultPolicy := compileForTest(t, defaultInput).GetVirtualHosts()[0].GetRoutes()[0].GetApiKeyAuth()
	if defaultPolicy.GetHeaderName() != defaultAPIKeyHeader {
		t.Fatalf("default API-key header = %q, want %q", defaultPolicy.GetHeaderName(), defaultAPIKeyHeader)
	}
}

func TestCompileJWTAuthPolicy(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		`        cluster: backend
        jwt_auth:
          jwks_secret: payments-jwks.json
          issuer: https://identity.example.test/tenant
          audience: payments-api
          required_type: JWT
          algorithms: [PS256, RS256, ES256]
          clock_skew_seconds: 45
          max_token_lifetime_seconds: 3600
          required_scopes: [payments.read, payments.write]
          required_claims:
            - {name: tenant_id, exact: acme}
            - {name: customer_tier, exact: premium customer}
          verification_rate_limit:
            capacity: 64
            refill_tokens_per_second: 16
`,
		1,
	)
	policy := compileForTest(t, input).GetVirtualHosts()[0].GetRoutes()[0].GetJwtAuth()
	if policy.GetJwksSecret() != "payments-jwks.json" ||
		policy.GetIssuer() != "https://identity.example.test/tenant" ||
		policy.GetAudience() != "payments-api" ||
		policy.GetRequiredType() != "JWT" ||
		policy.GetClockSkewSeconds() != 45 ||
		policy.GetMaxTokenLifetimeSeconds() != 3600 {
		t.Fatalf("unexpected JWT policy: %+v", policy)
	}
	wantAlgorithms := []bonvoyagev1.JwtAlgorithm{
		bonvoyagev1.JwtAlgorithm_JWT_ALGORITHM_PS256,
		bonvoyagev1.JwtAlgorithm_JWT_ALGORITHM_RS256,
		bonvoyagev1.JwtAlgorithm_JWT_ALGORITHM_ES256,
	}
	if got := policy.GetAlgorithms(); len(got) != len(wantAlgorithms) {
		t.Fatalf("JWT algorithms = %v, want %v", got, wantAlgorithms)
	} else {
		for index := range wantAlgorithms {
			if got[index] != wantAlgorithms[index] {
				t.Fatalf("JWT algorithms = %v, want configured order %v", got, wantAlgorithms)
			}
		}
	}
	if got := policy.GetRequiredScopes(); len(got) != 2 || got[0] != "payments.read" || got[1] != "payments.write" {
		t.Fatalf("unexpected JWT scopes: %v", got)
	}
	if got := policy.GetRequiredClaims(); len(got) != 2 ||
		got[0].GetName() != "tenant_id" || got[0].GetExact() != "acme" ||
		got[1].GetName() != "customer_tier" || got[1].GetExact() != "premium customer" {
		t.Fatalf("unexpected JWT claims: %+v", got)
	}
	if got := policy.GetVerificationRateLimit(); got.GetCapacity() != 64 || got.GetRefillTokensPerSecond() != 16 {
		t.Fatalf("unexpected JWT verification rate limit: %+v", got)
	}

	defaultInput := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		`        cluster: backend
        jwt_auth:
          jwks_secret: default-jwks.json
          issuer: https://identity.example.test
          audience: default-api
          required_type: JWT
          algorithms: [RS256]
          max_token_lifetime_seconds: 900
          verification_rate_limit:
            capacity: 1
            refill_tokens_per_second: 1
`,
		1,
	)
	defaultPolicy := compileForTest(t, defaultInput).GetVirtualHosts()[0].GetRoutes()[0].GetJwtAuth()
	if defaultPolicy.GetClockSkewSeconds() != 0 || len(defaultPolicy.GetRequiredScopes()) != 0 || len(defaultPolicy.GetRequiredClaims()) != 0 {
		t.Fatalf("JWT optional fields did not retain safe zero defaults: %+v", defaultPolicy)
	}
	if got := defaultPolicy.GetVerificationRateLimit(); got.GetCapacity() != 1 || got.GetRefillTokensPerSecond() != 1 {
		t.Fatalf("unexpected required JWT verification rate limit: %+v", got)
	}
}

func TestCompileRejectsInvalidJWTAuthPolicy(t *testing.T) {
	const validPolicy = `        jwt_auth:
          jwks_secret: identity-jwks.json
          issuer: https://identity.example.test/tenant
          audience: payments-api
          required_type: JWT
          algorithms: [RS256, PS256]
          clock_skew_seconds: 30
          max_token_lifetime_seconds: 3600
          verification_rate_limit:
            capacity: 20
            refill_tokens_per_second: 5
`
	withPolicy := func(policy string) string {
		return strings.Replace(validConfig, "        cluster: backend\n", "        cluster: backend\n"+policy, 1)
	}
	tests := []struct {
		name    string
		policy  string
		wantErr string
	}{
		{
			name:    "unsafe JWKS path",
			policy:  strings.Replace(validPolicy, "identity-jwks.json", "../identity-jwks.json", 1),
			wantErr: "jwt_auth.jwks_secret: must be a safe secret filename",
		},
		{
			name:    "non-HTTPS issuer",
			policy:  strings.Replace(validPolicy, "https://identity.example.test/tenant", "http://identity.example.test/tenant", 1),
			wantErr: "jwt_auth.issuer: must be an HTTPS URI-like value",
		},
		{
			name:    "issuer userinfo",
			policy:  strings.Replace(validPolicy, "https://identity.example.test/tenant", "https://user@identity.example.test/tenant", 1),
			wantErr: "jwt_auth.issuer: must be an HTTPS URI-like value",
		},
		{
			name:    "issuer surrounding whitespace",
			policy:  strings.Replace(validPolicy, "https://identity.example.test/tenant", "' https://identity.example.test/tenant'", 1),
			wantErr: "jwt_auth.issuer: must not contain surrounding whitespace",
		},
		{
			name:    "issuer too long",
			policy:  strings.Replace(validPolicy, "https://identity.example.test/tenant", "https://"+strings.Repeat("a", maxJWTIssuerBytes), 1),
			wantErr: "jwt_auth.issuer: must contain between 1 and 1024 bytes of visible text",
		},
		{
			name:    "audience surrounding whitespace",
			policy:  strings.Replace(validPolicy, "payments-api", "'payments-api '", 1),
			wantErr: "jwt_auth.audience: must not contain surrounding whitespace",
		},
		{
			name:    "audience too long",
			policy:  strings.Replace(validPolicy, "payments-api", strings.Repeat("a", maxJWTAudienceBytes+1), 1),
			wantErr: "jwt_auth.audience: must contain between 1 and 256 bytes of visible text",
		},
		{
			name:    "invalid required type",
			policy:  strings.Replace(validPolicy, "required_type: JWT", "required_type: 'JWT token'", 1),
			wantErr: "jwt_auth.required_type: must be an HTTP token",
		},
		{
			name:    "empty algorithms",
			policy:  strings.Replace(validPolicy, "algorithms: [RS256, PS256]", "algorithms: []", 1),
			wantErr: "jwt_auth.algorithms: must contain between 1 and 3 unique algorithms",
		},
		{
			name:    "duplicate algorithms",
			policy:  strings.Replace(validPolicy, "algorithms: [RS256, PS256]", "algorithms: [RS256, RS256]", 1),
			wantErr: `jwt_auth.algorithms[1]: duplicate algorithm "RS256"`,
		},
		{
			name:    "unsupported algorithm",
			policy:  strings.Replace(validPolicy, "algorithms: [RS256, PS256]", "algorithms: [HS256]", 1),
			wantErr: "jwt_auth.algorithms[0]: unsupported; use RS256, PS256, or ES256",
		},
		{
			name:    "too many algorithms",
			policy:  strings.Replace(validPolicy, "algorithms: [RS256, PS256]", "algorithms: [RS256, PS256, ES256, RS256]", 1),
			wantErr: "jwt_auth.algorithms: must contain between 1 and 3 unique algorithms",
		},
		{
			name:    "excessive clock skew",
			policy:  strings.Replace(validPolicy, "clock_skew_seconds: 30", "clock_skew_seconds: 301", 1),
			wantErr: "jwt_auth.clock_skew_seconds: must not exceed 300",
		},
		{
			name:    "missing maximum token lifetime",
			policy:  strings.Replace(validPolicy, "          max_token_lifetime_seconds: 3600\n", "", 1),
			wantErr: "jwt_auth.max_token_lifetime_seconds: is required",
		},
		{
			name:    "zero maximum token lifetime",
			policy:  strings.Replace(validPolicy, "max_token_lifetime_seconds: 3600", "max_token_lifetime_seconds: 0", 1),
			wantErr: "jwt_auth.max_token_lifetime_seconds: must be between 1 and 86400",
		},
		{
			name:    "excessive maximum token lifetime",
			policy:  strings.Replace(validPolicy, "max_token_lifetime_seconds: 3600", "max_token_lifetime_seconds: 86401", 1),
			wantErr: "jwt_auth.max_token_lifetime_seconds: must be between 1 and 86400",
		},
		{
			name: "missing verification rate limit",
			policy: strings.Replace(validPolicy, `          verification_rate_limit:
            capacity: 20
            refill_tokens_per_second: 5
`, "", 1),
			wantErr: "jwt_auth.verification_rate_limit: capacity and refill_tokens_per_second are required",
		},
		{
			name:    "missing verification capacity",
			policy:  strings.Replace(validPolicy, "            capacity: 20\n", "", 1),
			wantErr: "jwt_auth.verification_rate_limit: capacity and refill_tokens_per_second are required",
		},
		{
			name:    "missing verification refill",
			policy:  strings.Replace(validPolicy, "            refill_tokens_per_second: 5\n", "", 1),
			wantErr: "jwt_auth.verification_rate_limit: capacity and refill_tokens_per_second are required",
		},
		{
			name:    "zero verification capacity",
			policy:  strings.Replace(validPolicy, "capacity: 20", "capacity: 0", 1),
			wantErr: "jwt_auth.verification_rate_limit.capacity: must be between 1 and 1000000",
		},
		{
			name:    "excessive verification capacity",
			policy:  strings.Replace(validPolicy, "capacity: 20", "capacity: 1000001", 1),
			wantErr: "jwt_auth.verification_rate_limit.capacity: must be between 1 and 1000000",
		},
		{
			name:    "zero verification refill",
			policy:  strings.Replace(validPolicy, "refill_tokens_per_second: 5", "refill_tokens_per_second: 0", 1),
			wantErr: "jwt_auth.verification_rate_limit.refill_tokens_per_second: must be between 1 and 1000000",
		},
		{
			name:    "excessive verification refill",
			policy:  strings.Replace(validPolicy, "refill_tokens_per_second: 5", "refill_tokens_per_second: 1000001", 1),
			wantErr: "jwt_auth.verification_rate_limit.refill_tokens_per_second: must be between 1 and 1000000",
		},
		{
			name:    "duplicate scopes",
			policy:  validPolicy + "          required_scopes: [payments.read, payments.read]\n",
			wantErr: `jwt_auth.required_scopes[1]: duplicate scope "payments.read"`,
		},
		{
			name:    "scope contains whitespace",
			policy:  validPolicy + "          required_scopes: ['payments read']\n",
			wantErr: "jwt_auth.required_scopes[0]: must contain between 1 and 128 visible ASCII bytes without whitespace",
		},
		{
			name:    "non-ASCII scope",
			policy:  validPolicy + "          required_scopes: [\"payments.r\\u00e9\"]\n",
			wantErr: "jwt_auth.required_scopes[0]: must contain between 1 and 128 visible ASCII bytes without whitespace",
		},
		{
			name:    "too many scopes",
			policy:  validPolicy + "          required_scopes:\n" + strings.Repeat("            - scope\n", maxJWTPolicyEntries+1),
			wantErr: "jwt_auth.required_scopes: must not contain more than 16 entries",
		},
		{
			name:    "duplicate claim names",
			policy:  validPolicy + "          required_claims: [{name: tenant_id, exact: acme}, {name: tenant_id, exact: other}]\n",
			wantErr: `jwt_auth.required_claims[1].name: duplicate claim name "tenant_id"`,
		},
		{
			name:    "invalid claim name",
			policy:  validPolicy + "          required_claims: [{name: 'tenant id', exact: acme}]\n",
			wantErr: "jwt_auth.required_claims[0].name: must be an HTTP token",
		},
		{
			name:    "claim exact surrounding whitespace",
			policy:  validPolicy + "          required_claims: [{name: tenant_id, exact: ' acme'}]\n",
			wantErr: "jwt_auth.required_claims[0].exact: must not contain surrounding whitespace",
		},
		{
			name:    "non-ASCII claim exact value",
			policy:  validPolicy + "          required_claims: [{name: tenant_id, exact: \"acm\\u00e9\"}]\n",
			wantErr: "jwt_auth.required_claims[0].exact: must contain between 1 and 256 bytes of visible ASCII text",
		},
		{
			name:    "too many claims",
			policy:  validPolicy + "          required_claims:\n" + strings.Repeat("            - {name: tenant_id, exact: acme}\n", maxJWTPolicyEntries+1),
			wantErr: "jwt_auth.required_claims: must not contain more than 16 entries",
		},
		{
			name:    "API-key and JWT conflict",
			policy:  validPolicy + "        api_key_auth:\n          credentials_secret: api-keys.txt\n",
			wantErr: "api_key_auth and jwt_auth cannot be configured together",
		},
	}
	for _, claim := range []string{"iss", "aud", "exp", "nbf", "iat", "scope", "sub"} {
		tests = append(tests, struct {
			name    string
			policy  string
			wantErr string
		}{
			name:    "reserved claim " + claim,
			policy:  validPolicy + fmt.Sprintf("          required_claims: [{name: %s, exact: value}]\n", claim),
			wantErr: fmt.Sprintf(`jwt_auth.required_claims[0].name: claim %q is owned by the base JWT policy`, claim),
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(withPolicy(test.policy)))
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

func TestCompileSourceIPPolicy(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		`        cluster: backend
        source_ip_policy:
          allow_cidrs:
            - ' 198.51.100.0/24 '
            - 2001:0db8:0000::/32
          deny_cidrs:
            - 198.51.100.128/25
            - 2001:db8:1:dead::/64
`,
		1,
	)
	policy := compileForTest(t, input).GetVirtualHosts()[0].GetRoutes()[0].GetSourceIpPolicy()
	wantAllow := []string{"198.51.100.0/24", "2001:db8::/32"}
	wantDeny := []string{"198.51.100.128/25", "2001:db8:1:dead::/64"}
	if got := policy.GetAllowCidrs(); !slices.Equal(got, wantAllow) {
		t.Fatalf("source IP allow CIDRs = %v, want %v", got, wantAllow)
	}
	if got := policy.GetDenyCidrs(); !slices.Equal(got, wantDeny) {
		t.Fatalf("source IP deny CIDRs = %v, want %v", got, wantDeny)
	}
}

func TestCompileRejectsInvalidSourceIPPolicy(t *testing.T) {
	withPolicy := func(policy string) string {
		return strings.Replace(validConfig, "        cluster: backend\n", "        cluster: backend\n"+policy, 1)
	}
	var oversized strings.Builder
	oversized.WriteString("        source_ip_policy:\n          allow_cidrs:\n")
	for index := 0; index < maxSourceIPCIDRs+1; index++ {
		fmt.Fprintf(&oversized, "            - 203.0.113.%d/32\n", index)
	}
	tests := []struct {
		name    string
		policy  string
		wantErr string
	}{
		{
			name:    "empty policy",
			policy:  "        source_ip_policy: {}\n",
			wantErr: "source_ip_policy: must contain between 1 and 64 total CIDRs",
		},
		{
			name:    "configured empty allow list",
			policy:  "        source_ip_policy:\n          allow_cidrs: []\n",
			wantErr: "source_ip_policy.allow_cidrs: must not be empty when configured",
		},
		{
			name:    "host bits",
			policy:  "        source_ip_policy:\n          allow_cidrs: [198.51.100.1/24]\n",
			wantErr: "source_ip_policy.allow_cidrs[0]: must be a canonical numeric IPv4 or IPv6 CIDR",
		},
		{
			name:    "hostname",
			policy:  "        source_ip_policy:\n          allow_cidrs: [client.example/24]\n",
			wantErr: "source_ip_policy.allow_cidrs[0]: must be a canonical numeric IPv4 or IPv6 CIDR",
		},
		{
			name:    "IPv4-mapped IPv6",
			policy:  "        source_ip_policy:\n          allow_cidrs: ['::ffff:198.51.100.0/120']\n",
			wantErr: "source_ip_policy.allow_cidrs[0]: must be a canonical numeric IPv4 or IPv6 CIDR",
		},
		{
			name:    "semantic duplicate",
			policy:  "        source_ip_policy:\n          allow_cidrs: [2001:db8::/32, 2001:0db8:0000::/32]\n",
			wantErr: `source_ip_policy.allow_cidrs[1]: duplicate source IP CIDR "2001:db8::/32"`,
		},
		{
			name:    "same network in both lists",
			policy:  "        source_ip_policy:\n          allow_cidrs: [198.51.100.0/24]\n          deny_cidrs: [198.51.100.0/24]\n",
			wantErr: `source_ip_policy: CIDR "198.51.100.0/24" cannot appear in both allow_cidrs and deny_cidrs`,
		},
		{
			name:    "combined list bound",
			policy:  oversized.String(),
			wantErr: "source_ip_policy: must contain between 1 and 64 total CIDRs",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(withPolicy(test.policy)))
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

func TestCompileCORSPolicy(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		`        cluster: backend
        cors:
          allowed_origins:
            - HTTPS://ADMIN.EXAMPLE.COM:443/
            - https://[2001:0db8::1]:8443
          allowed_methods: [POST, GET]
          allowed_headers: [X-Request-Id, Authorization, Content-Type]
          exposed_headers: [X-Trace-Id, X-Request-Id]
          allow_credentials: true
`,
		1,
	)
	policy := compileForTest(t, input).GetVirtualHosts()[0].GetRoutes()[0].GetCors()
	if policy == nil {
		t.Fatal("compiled CORS policy is nil")
	}
	if got, want := policy.GetAllowedOrigins(), []string{"https://[2001:db8::1]:8443", "https://admin.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("allowed origins = %v, want %v", got, want)
	}
	if got, want := policy.GetAllowedMethods(), []string{"GET", "POST"}; !slices.Equal(got, want) {
		t.Fatalf("allowed methods = %v, want %v", got, want)
	}
	if got, want := policy.GetAllowedHeaders(), []string{"authorization", "content-type", "x-request-id"}; !slices.Equal(got, want) {
		t.Fatalf("allowed headers = %v, want %v", got, want)
	}
	if got, want := policy.GetExposedHeaders(), []string{"x-request-id", "x-trace-id"}; !slices.Equal(got, want) {
		t.Fatalf("exposed headers = %v, want %v", got, want)
	}
	if !policy.GetAllowCredentials() || policy.GetAllowAnyOrigin() {
		t.Fatalf("unexpected CORS flags: %+v", policy)
	}
	if policy.GetMaxAgeSeconds() != defaultCORSMaxAgeSeconds {
		t.Fatalf("max age = %d, want %d", policy.GetMaxAgeSeconds(), defaultCORSMaxAgeSeconds)
	}
}

func TestCompileRejectsInvalidCORSPolicy(t *testing.T) {
	withPolicy := func(policy string) string {
		return strings.Replace(validConfig, "        cluster: backend\n", "        cluster: backend\n"+policy, 1)
	}
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:    "empty policy",
			config:  withPolicy("        cors: {}\n"),
			wantErr: "cors.allowed_origins: at least one exact origin is required",
		},
		{
			name: "credential wildcard",
			config: withPolicy(`        cors:
          allow_any_origin: true
          allowed_methods: [GET]
          allow_credentials: true
`),
			wantErr: "cors: allow_credentials cannot be combined with allow_any_origin",
		},
		{
			name: "wildcard and exact origins",
			config: withPolicy(`        cors:
          allow_any_origin: true
          allowed_origins: [https://app.example.com]
          allowed_methods: [GET]
`),
			wantErr: "cors: allow_any_origin and allowed_origins cannot be configured together",
		},
		{
			name: "origin path",
			config: withPolicy(`        cors:
          allowed_origins: [https://app.example.com/path]
          allowed_methods: [GET]
`),
			wantErr: "cors.allowed_origins[0]: must not contain a path",
		},
		{
			name: "normalized duplicate origin",
			config: withPolicy(`        cors:
          allowed_origins: [https://APP.example.com:443/, https://app.example.com]
          allowed_methods: [GET]
`),
			wantErr: `cors.allowed_origins[1]: duplicate normalized origin "https://app.example.com"`,
		},
		{
			name: "lowercase method",
			config: withPolicy(`        cors:
          allowed_origins: [https://app.example.com]
          allowed_methods: [get]
`),
			wantErr: "cors.allowed_methods[0]: must be an uppercase HTTP method token",
		},
		{
			name: "method outside route matcher",
			config: strings.Replace(withPolicy(`        cors:
          allowed_origins: [https://app.example.com]
          allowed_methods: [POST]
`), "          path_prefix: /api\n", "          path_prefix: /api\n          methods: [GET]\n", 1),
			wantErr: `cors.allowed_methods[0]: method "POST" is not accepted by the route matcher`,
		},
		{
			name: "route header predicate ambiguity",
			config: strings.Replace(withPolicy(`        cors:
          allowed_origins: [https://app.example.com]
          allowed_methods: [GET]
`), "          path_prefix: /api\n", "          path_prefix: /api\n          headers: [{name: X-Tenant, present: true}]\n", 1),
			wantErr: "cors: routes with CORS cannot use ordinary header match predicates",
		},
		{
			name: "wildcard request header",
			config: withPolicy(`        cors:
          allowed_origins: [https://app.example.com]
          allowed_methods: [GET]
          allowed_headers: ['*']
`),
			wantErr: "cors.allowed_headers[0]: must be an explicit HTTP field-name",
		},
		{
			name: "protocol request header",
			config: withPolicy(`        cors:
          allowed_origins: [https://app.example.com]
          allowed_methods: [GET]
          allowed_headers: [Origin]
`),
			wantErr: `cors.allowed_headers[0]: "origin" is controlled by the HTTP or CORS protocol`,
		},
		{
			name: "cookie exposure",
			config: withPolicy(`        cors:
          allowed_origins: [https://app.example.com]
          allowed_methods: [GET]
          exposed_headers: [Set-Cookie]
`),
			wantErr: `cors.exposed_headers[0]: "set-cookie" cannot be exposed to browser code`,
		},
		{
			name: "max age bound",
			config: withPolicy(`        cors:
          allowed_origins: [https://app.example.com]
          allowed_methods: [GET]
          max_age_seconds: 86401
`),
			wantErr: "cors.max_age_seconds: must not exceed 86400",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(test.config))
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

func TestCompileRequestContentPolicy(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		`        cluster: backend
        request_content:
          max_body_bytes: 4096
          allowed_content_types:
            - application/problem+json
            - application/json
`,
		1,
	)
	policy := compileForTest(t, input).GetVirtualHosts()[0].GetRoutes()[0].GetRequestContent()
	if policy == nil {
		t.Fatal("compiled request-content policy is nil")
	}
	if policy.GetMaxBodyBytes() != 4096 {
		t.Fatalf("max body bytes = %d, want 4096", policy.GetMaxBodyBytes())
	}
	if got, want := policy.GetAllowedContentTypes(), []string{"application/json", "application/problem+json"}; !slices.Equal(got, want) {
		t.Fatalf("allowed content types = %v, want %v", got, want)
	}

	contentTypeOnly := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		"        cluster: backend\n        request_content:\n          allowed_content_types: [application/json]\n",
		1,
	)
	if got := compileForTest(t, contentTypeOnly).GetVirtualHosts()[0].GetRoutes()[0].GetRequestContent().GetMaxBodyBytes(); got != 0 {
		t.Fatalf("content-type-only policy max body bytes = %d, want inherited zero", got)
	}
}

func TestCompileRejectsInvalidRequestContentPolicy(t *testing.T) {
	withPolicy := func(policy string) string {
		return strings.Replace(validConfig, "        cluster: backend\n", "        cluster: backend\n"+policy, 1)
	}
	tooManyTypes := "        request_content:\n          allowed_content_types:\n"
	for index := 0; index < maxRequestContentTypes+1; index++ {
		tooManyTypes += fmt.Sprintf("            - application/x-type-%d\n", index)
	}
	contentTypePredicate := strings.Replace(
		withPolicy("        request_content:\n          allowed_content_types: [application/json]\n"),
		"          path_prefix: /api\n",
		"          path_prefix: /api\n          headers:\n            - name: Content-Type\n              exact: application/json\n",
		1,
	)
	contentTypeAPIKey := withPolicy(
		"        api_key_auth:\n          header_name: Content-Type\n          credentials_secret: request-content-keys.txt\n" +
			"        request_content:\n          allowed_content_types: [application/json]\n",
	)
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:    "empty policy",
			config:  withPolicy("        request_content: {}\n"),
			wantErr: "request_content: at least one of max_body_bytes or allowed_content_types is required",
		},
		{
			name:    "zero body limit",
			config:  withPolicy("        request_content:\n          max_body_bytes: 0\n"),
			wantErr: "request_content.max_body_bytes: must be between 1",
		},
		{
			name:    "above global body limit",
			config:  withPolicy("        request_content:\n          max_body_bytes: 10485761\n"),
			wantErr: "request_content.max_body_bytes: must be between 1 and runtime_limits.max_request_body_bytes (10485760)",
		},
		{
			name:    "uppercase media type",
			config:  withPolicy("        request_content:\n          allowed_content_types: [Application/JSON]\n"),
			wantErr: "request_content.allowed_content_types[0]: must be a canonical lowercase media type",
		},
		{
			name:    "wildcard media type",
			config:  withPolicy("        request_content:\n          allowed_content_types: [application/*]\n"),
			wantErr: "request_content.allowed_content_types[0]: must be an exact base media type",
		},
		{
			name:    "parameterized media type",
			config:  withPolicy("        request_content:\n          allowed_content_types: ['application/json; charset=utf-8']\n"),
			wantErr: "request_content.allowed_content_types[0]: must be an exact base media type",
		},
		{
			name:    "duplicate media type",
			config:  withPolicy("        request_content:\n          allowed_content_types: [application/json, application/json]\n"),
			wantErr: `request_content.allowed_content_types[1]: duplicate media type "application/json"`,
		},
		{
			name:    "too many media types",
			config:  withPolicy(tooManyTypes),
			wantErr: "request_content.allowed_content_types: must not contain more than 16 media types",
		},
		{
			name:    "Content-Type route predicate conflict",
			config:  contentTypePredicate,
			wantErr: "request_content: must not duplicate a Content-Type route predicate",
		},
		{
			name:    "Content-Type API-key conflict",
			config:  contentTypeAPIKey,
			wantErr: "request_content: Content-Type cannot carry an API key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(test.config))
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

func TestCompileHeaderTransformations(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		`        cluster: backend
        header_transformations:
          request:
            - operation: set
              name: x-route-tier
              value: gold
            - operation: append
              name: x-tags
              value: gateway
            - operation: remove
              name: x-remove-me
          response:
            - operation: set
              name: x-security-policy
              value: strict
            - operation: append
              name: cache-control
              value: private
            - operation: remove
              name: set-cookie
`,
		1,
	)
	policy := compileForTest(t, input).GetVirtualHosts()[0].GetRoutes()[0].GetHeaderTransformations()
	if policy == nil || len(policy.GetRequest()) != 3 || len(policy.GetResponse()) != 3 {
		t.Fatalf("unexpected header transformation policy: %+v", policy)
	}
	if policy.GetRequest()[0].GetName() != "x-remove-me" ||
		policy.GetRequest()[1].GetName() != "x-route-tier" ||
		policy.GetRequest()[2].GetName() != "x-tags" {
		t.Fatalf("request mutations were not sorted deterministically: %+v", policy.GetRequest())
	}
	if policy.GetResponse()[0].GetName() != "cache-control" ||
		policy.GetResponse()[0].GetOperation() != bonvoyagev1.HeaderMutationOperation_HEADER_MUTATION_OPERATION_APPEND ||
		policy.GetResponse()[2].GetOperation() != bonvoyagev1.HeaderMutationOperation_HEADER_MUTATION_OPERATION_SET {
		t.Fatalf("response mutations were not compiled: %+v", policy.GetResponse())
	}
}

func TestCompileRejectsInvalidHeaderTransformations(t *testing.T) {
	withPolicy := func(policy string) string {
		return strings.Replace(validConfig, "        cluster: backend\n", "        cluster: backend\n"+policy, 1)
	}
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{name: "empty", config: withPolicy("        header_transformations: {}\n"), wantErr: "must contain at least one request or response mutation"},
		{name: "uppercase name", config: withPolicy("        header_transformations:\n          request:\n            - operation: set\n              name: X-Route-Tier\n              value: gold\n"), wantErr: "canonical lowercase HTTP field-name"},
		{name: "duplicate name", config: withPolicy("        header_transformations:\n          request:\n            - operation: remove\n              name: x-drop\n            - operation: set\n              name: x-drop\n              value: replacement\n"), wantErr: "duplicate field name"},
		{name: "framing field", config: withPolicy("        header_transformations:\n          request:\n            - operation: set\n              name: content-length\n              value: '1'\n"), wantErr: "owned by HTTP framing"},
		{name: "WebSocket proof field", config: withPolicy("        header_transformations:\n          request:\n            - operation: set\n              name: sec-websocket-key\n              value: embedded\n"), wantErr: "owned by HTTP framing"},
		{name: "trace propagation field", config: withPolicy("        header_transformations:\n          request:\n            - operation: remove\n              name: traceparent\n"), wantErr: "owned by HTTP framing"},
		{name: "forwarding identity", config: withPolicy("        header_transformations:\n          request:\n            - operation: remove\n              name: x-forwarded-for\n"), wantErr: "owned by HTTP framing"},
		{name: "CORS response", config: withPolicy("        header_transformations:\n          response:\n            - operation: set\n              name: access-control-allow-origin\n              value: '*'\n"), wantErr: "owned by HTTP framing"},
		{name: "credential injection", config: withPolicy("        header_transformations:\n          request:\n            - operation: set\n              name: authorization\n              value: Bearer-static\n"), wantErr: "credential-bearing fields may only be removed"},
		{name: "remove value", config: withPolicy("        header_transformations:\n          response:\n            - operation: remove\n              name: server\n              value: unexpected\n"), wantErr: "value: must be empty for remove"},
		{name: "missing set value", config: withPolicy("        header_transformations:\n          response:\n            - operation: set\n              name: server\n"), wantErr: "value: must contain 1"},
		{name: "unknown operation", config: withPolicy("        header_transformations:\n          response:\n            - operation: replace\n              name: server\n              value: gateway\n"), wantErr: "operation: must be set, append, or remove"},
		{name: "local action", config: strings.Replace(withPolicy("        header_transformations:\n          response:\n            - operation: remove\n              name: server\n"), "        cluster: backend\n", "        fixed_response:\n          status_code: 204\n", 1), wantErr: "supported only on reverse-proxy routes"},
		{name: "API key injection", config: withPolicy("        api_key_auth:\n          credentials_secret: keys.txt\n        header_transformations:\n          request:\n            - operation: set\n              name: x-api-key\n              value: embedded\n"), wantErr: "credential-bearing fields may only be removed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(test.config))
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Compile() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}

	tooMany := "        header_transformations:\n          request:\n"
	for index := range 17 {
		tooMany += fmt.Sprintf("            - operation: remove\n              name: x-drop-%d\n", index)
	}
	if _, err := Compile(strings.NewReader(withPolicy(tooMany))); err == nil || !strings.Contains(err.Error(), "must not contain more than 16 mutations") {
		t.Fatalf("Compile() too-many error = %v", err)
	}

	overBudget := "        header_transformations:\n          response:\n"
	for index := range 5 {
		overBudget += fmt.Sprintf("            - operation: set\n              name: x-large-%d\n              value: %s\n", index, strings.Repeat("a", 4096))
	}
	if _, err := Compile(strings.NewReader(withPolicy(overBudget))); err == nil || !strings.Contains(err.Error(), "must not exceed 16384 bytes") {
		t.Fatalf("Compile() budget error = %v", err)
	}
}

func TestCompileRouteRewrite(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"        cluster: backend\n",
		`        cluster: backend
        rewrite:
          host: orders.internal.test
          port: 9443
          path_prefix: /v2
`,
		1,
	)
	rewrite := compileForTest(t, input).GetVirtualHosts()[0].GetRoutes()[0].GetRewrite()
	if rewrite == nil || rewrite.GetHost() != "orders.internal.test" ||
		rewrite.GetPort() != 9443 || rewrite.GetPathPrefix() != "/v2" {
		t.Fatalf("unexpected compiled route rewrite: %+v", rewrite)
	}
	if _, ok := rewrite.GetPathRewrite().(*bonvoyagev1.RouteRewrite_PathPrefix); !ok {
		t.Fatalf("route rewrite did not retain its prefix operation: %+v", rewrite)
	}

	fullPathInput := strings.Replace(validConfig, "          path_prefix: /api\n", "          path_exact: /catalog\n", 1)
	fullPathInput = strings.Replace(
		fullPathInput,
		"        cluster: backend\n",
		"        cluster: backend\n        rewrite:\n          path: /internal/catalog\n",
		1,
	)
	fullPath := compileForTest(t, fullPathInput).GetVirtualHosts()[0].GetRoutes()[0].GetRewrite()
	if fullPath.GetPath() != "/internal/catalog" || fullPath.GetHost() != "" {
		t.Fatalf("unexpected full-path rewrite: %+v", fullPath)
	}
}

func TestCompileRejectsInvalidRouteRewrite(t *testing.T) {
	withRewrite := func(policy string) string {
		return strings.Replace(validConfig, "        cluster: backend\n", "        cluster: backend\n        rewrite:\n"+policy, 1)
	}
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{name: "empty", config: withRewrite("          {}\n"), wantErr: "must contain a host or path rewrite"},
		{name: "both path forms", config: withRewrite("          path: /v2\n          path_prefix: /v3\n"), wantErr: "path and path_prefix cannot be configured together"},
		{name: "port without host", config: withRewrite("          port: 8443\n          path: /v2\n"), wantErr: "port: requires host"},
		{name: "zero port", config: withRewrite("          host: api.internal.test\n          port: 0\n"), wantErr: "port: must be between 1 and 65535"},
		{name: "uppercase host", config: withRewrite("          host: API.internal.test\n"), wantErr: "host: must be canonical lowercase"},
		{name: "unbracketed IPv6", config: withRewrite("          host: '2001:db8::10'\n"), wantErr: "IPv6 literal must be bracketed"},
		{name: "prefix on exact match", config: strings.Replace(withRewrite("          path_prefix: /v2\n"), "          path_prefix: /api\n", "          path_exact: /api\n", 1), wantErr: "requires a path_prefix route match"},
		{name: "slash mismatch", config: withRewrite("          path_prefix: /v2/\n"), wantErr: "must preserve the matched prefix trailing-slash form"},
		{name: "query mutation", config: withRewrite("          path: /v2?source=legacy\n"), wantErr: "outside the bounded RFC 3986 set"},
		{name: "invalid escape", config: withRewrite("          path: /bad%GG\n"), wantErr: "invalid percent triplet"},
		{name: "network path", config: withRewrite("          path: //evil.example\n"), wantErr: "must start with one /"},
		{name: "local action", config: strings.Replace(withRewrite("          host: api.internal.test\n"), "        cluster: backend\n", "        fixed_response:\n          status_code: 204\n", 1), wantErr: "supported only on reverse-proxy routes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(test.config))
			assertErrorContains(t, err, test.wantErr)
		})
	}

	overLimit := strings.Replace(validConfig, "  max_request_header_bytes: 32768\n", "  max_request_header_bytes: 1024\n", 1)
	overLimit = strings.Replace(
		overLimit,
		"        cluster: backend\n",
		"        cluster: backend\n        rewrite:\n          path: /"+strings.Repeat("a", 1024)+"\n",
		1,
	)
	_, err := Compile(strings.NewReader(overLimit))
	assertErrorContains(t, err, "must not exceed runtime_limits.max_request_header_bytes")
}

func TestCompileRedirectActions(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		wantStatus uint32
		wantScheme string
		wantHost   string
		wantPort   uint32
		wantPath   string
		wantQuery  string
	}{
		{
			name: "relative",
			config: `        redirect:
          status_code: 307
          path: /v2/orders
          query: source=legacy
`,
			wantStatus: 307,
			wantPath:   "/v2/orders",
			wantQuery:  "source=legacy",
		},
		{
			name: "absolute DNS",
			config: `        redirect:
          status_code: 308
          scheme: https
          host: api-v2.example.test
          port: 9443
          path: /v2/orders
`,
			wantStatus: 308,
			wantScheme: "https",
			wantHost:   "api-v2.example.test",
			wantPort:   9443,
			wantPath:   "/v2/orders",
		},
		{
			name: "canonical IPv6",
			config: `        redirect:
          status_code: 301
          scheme: http
          host: "2001:db8::10"
          port: 8080
          path: /moved/%7Eowner
          query: via=ipv6&ok=true
`,
			wantStatus: 301,
			wantScheme: "http",
			wantHost:   "[2001:db8::10]",
			wantPort:   8080,
			wantPath:   "/moved/%7Eowner",
			wantQuery:  "via=ipv6&ok=true",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := strings.Replace(validConfig, "        cluster: backend\n", test.config, 1)
			route := compileForTest(t, input).GetVirtualHosts()[0].GetRoutes()[0]
			redirect := route.GetRedirect()
			if redirect == nil {
				t.Fatal("compiled redirect is nil")
			}
			if redirect.GetStatusCode() != test.wantStatus ||
				redirect.GetScheme() != test.wantScheme ||
				redirect.GetHost() != test.wantHost ||
				redirect.GetPort() != test.wantPort ||
				redirect.GetPath() != test.wantPath ||
				redirect.GetQuery() != test.wantQuery {
				t.Fatalf("compiled redirect = %+v", redirect)
			}
			if route.GetClusterName() != "" || route.GetFixedResponse() != nil {
				t.Fatalf("redirect route retained another action: %+v", route)
			}
		})
	}
}

func TestCompileRejectsInvalidRedirectActions(t *testing.T) {
	withRedirect := func(redirect string) string {
		return strings.Replace(validConfig, "        cluster: backend\n", redirect, 1)
	}
	tests := []struct {
		name     string
		redirect string
		wantErr  string
	}{
		{name: "unsupported status", redirect: "        redirect:\n          status_code: 300\n          path: /moved\n", wantErr: "redirect.status_code: must be one of"},
		{name: "missing path", redirect: "        redirect:\n          status_code: 308\n", wantErr: "redirect.path: must start with one /"},
		{name: "network path", redirect: "        redirect:\n          status_code: 308\n          path: //evil.example\n", wantErr: "redirect.path: must start with one /"},
		{name: "space in path", redirect: "        redirect:\n          status_code: 308\n          path: '/bad path'\n", wantErr: "redirect.path: contains a character outside"},
		{name: "fragment in path", redirect: "        redirect:\n          status_code: 308\n          path: '/bad#fragment'\n", wantErr: "redirect.path: contains a character outside"},
		{name: "backslash in path", redirect: "        redirect:\n          status_code: 308\n          path: '/bad\\path'\n", wantErr: "redirect.path: contains a character outside"},
		{name: "invalid path escape", redirect: "        redirect:\n          status_code: 308\n          path: /bad%2\n", wantErr: "redirect.path: contains an invalid percent triplet"},
		{name: "leading query marker", redirect: "        redirect:\n          status_code: 308\n          path: /moved\n          query: '?source=legacy'\n", wantErr: "redirect.query: must not start with ?"},
		{name: "invalid query escape", redirect: "        redirect:\n          status_code: 308\n          path: /moved\n          query: source=%GG\n", wantErr: "redirect.query: contains an invalid percent triplet"},
		{name: "scheme without host", redirect: "        redirect:\n          status_code: 308\n          scheme: https\n          path: /moved\n", wantErr: "redirect: scheme and host must be configured together"},
		{name: "host without scheme", redirect: "        redirect:\n          status_code: 308\n          host: api.example.test\n          path: /moved\n", wantErr: "redirect: scheme and host must be configured together"},
		{name: "relative port", redirect: "        redirect:\n          status_code: 308\n          port: 443\n          path: /moved\n", wantErr: "redirect.port: requires scheme and host"},
		{name: "zero absolute port", redirect: "        redirect:\n          status_code: 308\n          scheme: https\n          host: api.example.test\n          port: 0\n          path: /moved\n", wantErr: "redirect.port: must be between 1 and 65535"},
		{name: "uppercase scheme", redirect: "        redirect:\n          status_code: 308\n          scheme: HTTPS\n          host: api.example.test\n          path: /moved\n", wantErr: "redirect.scheme: must be exactly http or https"},
		{name: "uppercase host", redirect: "        redirect:\n          status_code: 308\n          scheme: https\n          host: API.example.test\n          path: /moved\n", wantErr: "redirect.host: must be canonical lowercase"},
		{name: "wildcard host", redirect: "        redirect:\n          status_code: 308\n          scheme: https\n          host: '*.example.test'\n          path: /moved\n", wantErr: "redirect.host: must be a canonical DNS name"},
		{name: "userinfo host", redirect: "        redirect:\n          status_code: 308\n          scheme: https\n          host: 'user@example.test'\n          path: /moved\n", wantErr: "redirect.host: must be a canonical DNS name"},
		{name: "port overflow", redirect: "        redirect:\n          status_code: 308\n          scheme: https\n          host: api.example.test\n          port: 65536\n          path: /moved\n", wantErr: "redirect.port: must be between 1 and 65535"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(withRedirect(test.redirect)))
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

func TestCompileLoadBalancingAndPassiveHealth(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   bonvoyagev1.LoadBalancingPolicy
	}{
		{name: "round robin", policy: "round_robin", want: bonvoyagev1.LoadBalancingPolicy_LOAD_BALANCING_POLICY_ROUND_ROBIN},
		{name: "least request", policy: "least_request", want: bonvoyagev1.LoadBalancingPolicy_LOAD_BALANCING_POLICY_LEAST_REQUEST},
		{name: "random", policy: "random", want: bonvoyagev1.LoadBalancingPolicy_LOAD_BALANCING_POLICY_RANDOM},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := strings.Replace(validConfig, "load_balancing_policy: round_robin", "load_balancing_policy: "+test.policy, 1)
			input = strings.Replace(
				input,
				"    max_pending_requests_per_shard: 256\n",
				"    max_pending_requests_per_shard: 256\n    max_concurrent_requests_per_endpoint: 64\n    passive_health:\n      consecutive_failures: 3\n      ejection_time_ms: 2500\n      max_ejection_percent: 75\n      consecutive_successes: 2\n",
				1,
			)
			compiled := compileForTest(t, input)
			cluster := compiled.GetClusters()[0]
			if cluster.GetLoadBalancingPolicy() != test.want {
				t.Fatalf("load balancing policy = %v, want %v", cluster.GetLoadBalancingPolicy(), test.want)
			}
			if cluster.GetMaxConcurrentRequestsPerEndpoint() != 64 {
				t.Fatalf("endpoint concurrency limit = %d, want 64", cluster.GetMaxConcurrentRequestsPerEndpoint())
			}
			health := cluster.GetPassiveHealth()
			if health.GetConsecutiveFailures() != 3 || health.GetEjectionTimeMs() != 2500 || health.GetMaxEjectionPercent() != 75 || health.GetConsecutiveSuccesses() != 2 {
				t.Fatalf("unexpected passive health policy: %+v", health)
			}
		})
	}
}

func TestCompilePassiveHealthAppliesDefaults(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"    max_pending_requests_per_shard: 256\n",
		"    max_pending_requests_per_shard: 256\n    passive_health: {}\n",
		1,
	)
	health := compileForTest(t, input).GetClusters()[0].GetPassiveHealth()
	if health.GetConsecutiveFailures() != defaultPassiveFailureCount ||
		health.GetEjectionTimeMs() != defaultPassiveEjectionTimeMS ||
		health.GetMaxEjectionPercent() != defaultMaxEjectionPercent ||
		health.GetConsecutiveSuccesses() != defaultPassiveSuccessCount {
		t.Fatalf("passive health defaults were not applied: %+v", health)
	}
}

func TestCompileActiveHealthAndDNSRefresh(t *testing.T) {
	maintenanceBlock := `    active_health:
      path: /ready?source=bonvoyage
      interval_ms: 2500
      timeout_ms: 750
      healthy_threshold: 3
      unhealthy_threshold: 4
      expected_status_min: 204
      expected_status_max: 299
      host: HEALTH.UPSTREAM.TEST
    dns_refresh:
      refresh_interval_ms: 15000
      resolve_timeout_ms: 800
`
	input := strings.Replace(validConfig, "    endpoints:\n", maintenanceBlock+"    endpoints:\n", 1)
	cluster := compileForTest(t, input).GetClusters()[0]
	health := cluster.GetActiveHealth()
	if health.GetPath() != "/ready?source=bonvoyage" ||
		health.GetIntervalMs() != 2500 || health.GetTimeoutMs() != 750 ||
		health.GetHealthyThreshold() != 3 || health.GetUnhealthyThreshold() != 4 ||
		health.GetExpectedStatusMin() != 204 || health.GetExpectedStatusMax() != 299 ||
		health.GetHost() != "health.upstream.test" {
		t.Fatalf("unexpected active health policy: %+v", health)
	}
	dns := cluster.GetDnsRefresh()
	if dns.GetRefreshIntervalMs() != 15000 || dns.GetResolveTimeoutMs() != 800 {
		t.Fatalf("unexpected DNS refresh policy: %+v", dns)
	}
}

func TestCompileMaintenancePoliciesApplyDefaults(t *testing.T) {
	input := strings.Replace(
		validConfig,
		"    endpoints:\n",
		"    active_health: {}\n    dns_refresh: {}\n    endpoints:\n",
		1,
	)
	cluster := compileForTest(t, input).GetClusters()[0]
	health := cluster.GetActiveHealth()
	if health.GetPath() != defaultActiveHealthPath ||
		health.GetIntervalMs() != defaultActiveHealthIntervalMS ||
		health.GetTimeoutMs() != defaultActiveHealthTimeoutMS ||
		health.GetHealthyThreshold() != defaultActiveHealthyThreshold ||
		health.GetUnhealthyThreshold() != defaultActiveFailureThreshold ||
		health.GetExpectedStatusMin() != defaultActiveStatusMinimum ||
		health.GetExpectedStatusMax() != defaultActiveStatusMaximum {
		t.Fatalf("active health defaults were not applied: %+v", health)
	}
	dns := cluster.GetDnsRefresh()
	if dns.GetRefreshIntervalMs() != defaultDNSRefreshIntervalMS ||
		dns.GetResolveTimeoutMs() != defaultDNSResolveTimeoutMS {
		t.Fatalf("DNS refresh defaults were not applied: %+v", dns)
	}
}

func TestCompileRetryPolicyAndBudget(t *testing.T) {
	retryBlock := `    retry:
      max_attempts: 3
      per_try_timeout_ms: 250
      retryable_methods: [PUT, GET]
      budget:
        capacity: 20
        refill_tokens_per_second: 4
        max_concurrent_retries_per_shard: 7
`
	input := strings.Replace(validConfig, "    endpoints:\n", retryBlock+"    endpoints:\n", 1)
	retry := compileForTest(t, input).GetClusters()[0].GetRetry()
	if retry.GetMaxAttempts() != 3 || retry.GetPerTryTimeoutMs() != 250 ||
		strings.Join(retry.GetRetryableMethods(), ",") != "GET,PUT" {
		t.Fatalf("unexpected retry policy: %+v", retry)
	}
	budget := retry.GetBudget()
	if budget.GetCapacity() != 20 || budget.GetRefillTokensPerSecond() != 4 ||
		budget.GetMaxConcurrentRetriesPerShard() != 7 {
		t.Fatalf("unexpected retry budget: %+v", budget)
	}
}

func TestCompileRetryPolicyAppliesSafeDefaults(t *testing.T) {
	input := strings.Replace(validConfig, "    endpoints:\n", "    retry: {}\n    endpoints:\n", 1)
	retry := compileForTest(t, input).GetClusters()[0].GetRetry()
	if retry.GetMaxAttempts() != defaultRetryMaxAttempts ||
		retry.GetPerTryTimeoutMs() != defaultRetryPerTryTimeoutMS ||
		strings.Join(retry.GetRetryableMethods(), ",") != "GET,HEAD,OPTIONS" {
		t.Fatalf("retry defaults were not applied: %+v", retry)
	}
	budget := retry.GetBudget()
	if budget.GetCapacity() != defaultRetryBudgetCapacity ||
		budget.GetRefillTokensPerSecond() != defaultRetryRefillPerSecond ||
		budget.GetMaxConcurrentRetriesPerShard() != defaultMaxConcurrentRetries {
		t.Fatalf("retry budget defaults were not applied: %+v", budget)
	}
}

func TestCompileDownstreamTLSReferences(t *testing.T) {
	tlsBlock := `    downstream_tls:
      certificate_chain_secret: server-chain.pem
      private_key_secret: server-key.pem
      trust_bundle_secret: client-ca.pem
      require_client_certificate: true
`
	input := strings.Replace(validConfig, "    virtual_hosts: [default]\n", "    virtual_hosts: [default]\n"+tlsBlock, 1)
	compiled := compileForTest(t, input)
	tls := compiled.GetListeners()[0].GetDownstreamTls()
	if tls.GetCertificateChainSecret() != "server-chain.pem" ||
		tls.GetPrivateKeySecret() != "server-key.pem" ||
		tls.GetTrustBundleSecret() != "client-ca.pem" ||
		!tls.GetRequireClientCertificate() {
		t.Fatalf("unexpected downstream TLS config: %+v", tls)
	}
}

func TestCompileTLSHTTP2Listener(t *testing.T) {
	tlsBlock := `    downstream_tls:
      certificate_chain_secret: server-chain.pem
      private_key_secret: server-key.pem
`
	input := strings.Replace(validConfig, "    protocol: http1\n", "    protocol: http2\n", 1)
	input = strings.Replace(input, "    virtual_hosts: [default]\n", "    virtual_hosts: [default]\n"+tlsBlock, 1)
	compiled := compileForTest(t, input)
	if got := compiled.GetListeners()[0].GetProtocol(); got != bonvoyagev1.Protocol_PROTOCOL_HTTP2 {
		t.Fatalf("listener protocol = %v, want HTTP2", got)
	}
}

func TestCompileTrustedProxyPolicy(t *testing.T) {
	policyBlock := `    trusted_proxy:
      trusted_cidrs:
        - " 10.0.0.0/8 "
        - "2001:db8::/32"
`
	input := strings.Replace(validConfig, "    virtual_hosts: [default]\n", "    virtual_hosts: [default]\n"+policyBlock, 1)
	trusted := compileForTest(t, input).GetListeners()[0].GetTrustedProxy()
	if got := strings.Join(trusted.GetTrustedCidrs(), ","); got != "10.0.0.0/8,2001:db8::/32" {
		t.Fatalf("trusted CIDRs = %q, want canonical IPv4 and IPv6 networks", got)
	}
}

func TestCompileUpstreamTLSReferences(t *testing.T) {
	tlsBlock := `    upstream_tls:
      server_name: API.UPSTREAM.EXAMPLE
      trust_bundle_secret: upstream-ca.pem
      certificate_chain_secret: gateway-client.pem
      private_key_secret: gateway-client-key.pem
`
	input := strings.Replace(validConfig, "    endpoints:\n", tlsBlock+"    endpoints:\n", 1)
	compiled := compileForTest(t, input)
	tls := compiled.GetClusters()[0].GetUpstreamTls()
	if tls.GetServerName() != "api.upstream.example" ||
		tls.GetTrustBundleSecret() != "upstream-ca.pem" ||
		tls.GetCertificateChainSecret() != "gateway-client.pem" ||
		tls.GetPrivateKeySecret() != "gateway-client-key.pem" {
		t.Fatalf("unexpected upstream TLS config: %+v", tls)
	}
}

func TestCompileUpstreamHTTP2Cluster(t *testing.T) {
	tlsAndProtocolBlock := `    protocol: http2
    max_http2_streams_per_connection: 321
    upstream_tls:
      server_name: API.UPSTREAM.EXAMPLE
      trust_bundle_secret: upstream-ca.pem
`
	input := strings.Replace(validConfig, "    endpoints:\n", tlsAndProtocolBlock+"    endpoints:\n", 1)
	cluster := compileForTest(t, input).GetClusters()[0]
	if cluster.GetProtocol() != bonvoyagev1.Protocol_PROTOCOL_HTTP2 {
		t.Fatalf("cluster protocol = %v, want HTTP2", cluster.GetProtocol())
	}
	if cluster.GetMaxHttp2StreamsPerConnection() != 321 {
		t.Fatalf("HTTP/2 stream limit = %d, want 321", cluster.GetMaxHttp2StreamsPerConnection())
	}
	input = strings.Replace(input, "    max_http2_streams_per_connection: 321\n", "", 1)
	if got := compileForTest(t, input).GetClusters()[0].GetMaxHttp2StreamsPerConnection(); got != defaultMaxHTTP2Streams {
		t.Fatalf("default HTTP/2 stream limit = %d, want %d", got, defaultMaxHTTP2Streams)
	}
}

func TestCompileRoutePredicates(t *testing.T) {
	predicates := `          safe_regex: /api/[0-9]+
          methods: [POST, GET]
          headers:
            - name: X-Release
              exact: beta
            - name: X-Blocked
              present: false
          query_parameters:
            - name: tenant
              exact: acme
            - name: debug
              present: false`
	input := strings.Replace(validConfig, "          path_prefix: /api", predicates, 1)
	compiled := compileForTest(t, input)
	match := compiled.GetVirtualHosts()[0].GetRoutes()[0].GetMatch()
	if match.GetSafeRegex() != "/api/[0-9]+" ||
		len(match.GetMethods()) != 2 || match.GetMethods()[0] != "GET" || match.GetMethods()[1] != "POST" {
		t.Fatalf("unexpected path or normalized methods: %+v", match)
	}
	if got := match.GetHeaders(); len(got) != 2 || got[0].GetName() != "x-blocked" || got[0].GetPresent() || got[1].GetExact() != "beta" {
		t.Fatalf("unexpected normalized header predicates: %+v", got)
	}
	if got := match.GetQueryParameters(); len(got) != 2 || got[0].GetName() != "debug" || got[0].GetPresent() || got[1].GetExact() != "acme" {
		t.Fatalf("unexpected normalized query predicates: %+v", got)
	}
}

func TestCompileRejectsMalformedUnknownAndBoundedInput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "malformed", input: "server: [", wantErr: "parse YAML"},
		{name: "unknown field", input: strings.Replace(validConfig, "  node_id: node-1", "  node_id: node-1\n  mystery: true", 1), wantErr: "field mystery not found"},
		{name: "multiple documents", input: validConfig + "---\n{}\n", wantErr: "multiple documents"},
		{name: "alias", input: strings.Replace(validConfig, "domains: [\"*\"]", "domains: &domains [\"*\"]", 1) + "alias: *domains\n", wantErr: "aliases"},
		{name: "merge key", input: strings.Replace(validConfig, "  node_id: node-1", "  <<: {node_id: node-1}\n  node_id: node-1", 1), wantErr: "merge keys"},
		{name: "excessive nesting", input: strings.Repeat("[", maxYAMLDepth+1) + "0" + strings.Repeat("]", maxYAMLDepth+1), wantErr: "nesting limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(test.input))
			assertErrorContains(t, err, test.wantErr)
		})
	}

	_, err := Compile(strings.NewReader(strings.Repeat("x", int(MaxConfigBytes)+1)))
	assertErrorContains(t, err, "exceeds 1048576-byte limit")
}

func TestInspectSchemaVersionUsesSafeParsingWithoutSemanticValidation(t *testing.T) {
	semanticallyInvalid := strings.Replace(validConfig, "cluster: backend", "cluster: missing", 1)
	version, err := InspectSchemaVersion(strings.NewReader(semanticallyInvalid))
	if err != nil || version == nil || *version != 1 {
		t.Fatalf("InspectSchemaVersion() version=%v error=%v, want 1", version, err)
	}

	versionTwo := strings.Replace(validConfig, "schema_version: 1", "schema_version: 2", 1)
	version, err = InspectSchemaVersion(strings.NewReader(versionTwo))
	if err != nil || version == nil || *version != 2 {
		t.Fatalf("InspectSchemaVersion() version=%v error=%v, want 2", version, err)
	}

	missing := strings.Replace(validConfig, "  schema_version: 1\n", "", 1)
	version, err = InspectSchemaVersion(strings.NewReader(missing))
	if err != nil || version != nil {
		t.Fatalf("InspectSchemaVersion() version=%v error=%v, want missing version", version, err)
	}
}

func TestInspectSchemaVersionRejectsUnsafeYAML(t *testing.T) {
	for name, input := range map[string]string{
		"malformed": "server: [",
		"multiple":  validConfig + "---\n{}\n",
		"alias": strings.Replace(validConfig, "domains: [\"*\"]", "domains: &domains [\"*\"]", 1) +
			"alias: *domains\n",
		"merge": strings.Replace(
			validConfig, "  node_id: node-1", "  <<: {node_id: node-1}\n  node_id: node-1", 1,
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := InspectSchemaVersion(strings.NewReader(input)); err == nil {
				t.Fatal("unsafe YAML was accepted")
			}
		})
	}
}

func TestCompileRejectsInvalidReferencesDuplicatesAndUnsupportedFeatures(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name: "unsupported upstream protocol",
			mutate: func(input string) string {
				return strings.Replace(input, "    load_balancing_policy:", "    protocol: http3\n    load_balancing_policy:", 1)
			},
			wantErr: "protocol: \"http3\" is unsupported",
		},
		{
			name: "HTTP/2 upstream without TLS",
			mutate: func(input string) string {
				return strings.Replace(input, "    load_balancing_policy:", "    protocol: http2\n    load_balancing_policy:", 1)
			},
			wantErr: "HTTP/2 requires upstream_tls",
		},
		{
			name: "HTTP/2 stream limit on HTTP/1 cluster",
			mutate: func(input string) string {
				return strings.Replace(input, "    max_pending_requests_per_shard: 256", "    max_pending_requests_per_shard: 256\n    max_http2_streams_per_connection: 100", 1)
			},
			wantErr: "max_http2_streams_per_connection: is only valid when protocol is http2",
		},
		{
			name: "zero HTTP/2 stream limit",
			mutate: func(input string) string {
				return strings.Replace(input, "    max_pending_requests_per_shard: 256", "    protocol: http2\n    max_pending_requests_per_shard: 256\n    max_http2_streams_per_connection: 0\n    upstream_tls:\n      server_name: upstream.example.test\n      trust_bundle_secret: upstream-ca.pem", 1)
			},
			wantErr: "max_http2_streams_per_connection: must be between 1 and 1000",
		},
		{
			name: "excessive HTTP/2 stream limit",
			mutate: func(input string) string {
				return strings.Replace(input, "    max_pending_requests_per_shard: 256", "    protocol: http2\n    max_pending_requests_per_shard: 256\n    max_http2_streams_per_connection: 1001\n    upstream_tls:\n      server_name: upstream.example.test\n      trust_bundle_secret: upstream-ca.pem", 1)
			},
			wantErr: "max_http2_streams_per_connection: must be between 1 and 1000",
		},
		{
			name: "duplicate listener",
			mutate: func(input string) string {
				listener := `  - name: http
    address: 127.0.0.1
    port: 8082
    protocol: http1
    virtual_hosts: [default]
`
				return strings.Replace(input, "virtual_hosts:\n", listener+"virtual_hosts:\n", 1)
			},
			wantErr: `listeners[1].name: duplicate name "http"`,
		},
		{
			name: "unknown virtual host",
			mutate: func(input string) string {
				return strings.Replace(input, "virtual_hosts: [default]", "virtual_hosts: [missing]", 1)
			},
			wantErr: `references unknown virtual host "missing"`,
		},
		{
			name: "duplicate route",
			mutate: func(input string) string {
				route := `      - name: api
        match:
          path_exact: /other
        cluster: backend
`
				return strings.Replace(input, "clusters:\n", route+"clusters:\n", 1)
			},
			wantErr: `duplicate name "api"`,
		},
		{
			name: "duplicate route binding",
			mutate: func(input string) string {
				route := `      - name: api-copy
        match:
          path_prefix: /api
        cluster: backend
`
				return strings.Replace(input, "clusters:\n", route+"clusters:\n", 1)
			},
			wantErr: `duplicate normalized route match`,
		},
		{
			name: "unconditional route shadows later predicate route",
			mutate: func(input string) string {
				route := `      - name: api-get
        match:
          path_prefix: /api
          methods: [GET]
        cluster: backend
`
				return strings.Replace(input, "clusters:\n", route+"clusters:\n", 1)
			},
			wantErr: "unreachable because an earlier route with the same path matcher has no predicates",
		},
		{
			name: "unknown cluster",
			mutate: func(input string) string {
				return strings.Replace(input, "cluster: backend", "cluster: missing", 1)
			},
			wantErr: `references unknown cluster "missing"`,
		},
		{
			name: "missing route action",
			mutate: func(input string) string {
				return strings.Replace(input, "        cluster: backend\n", "", 1)
			},
			wantErr: "exactly one of cluster, weighted_clusters, fixed_response, or redirect is required",
		},
		{
			name: "multiple route actions",
			mutate: func(input string) string {
				return strings.Replace(input, "        cluster: backend", "        cluster: backend\n        fixed_response:\n          status_code: 200", 1)
			},
			wantErr: "exactly one of cluster, weighted_clusters, fixed_response, or redirect is required",
		},
		{
			name: "cluster and redirect actions",
			mutate: func(input string) string {
				return strings.Replace(input, "        cluster: backend", "        cluster: backend\n        redirect:\n          status_code: 308\n          path: /moved", 1)
			},
			wantErr: "exactly one of cluster, weighted_clusters, fixed_response, or redirect is required",
		},
		{
			name: "zero route concurrency",
			mutate: func(input string) string {
				return strings.Replace(input, "        cluster: backend", "        cluster: backend\n        max_concurrent_requests_per_shard: 0", 1)
			},
			wantErr: "max_concurrent_requests_per_shard: must be between 1 and 2000000",
		},
		{
			name: "incomplete local rate limit",
			mutate: func(input string) string {
				return strings.Replace(input, "        cluster: backend", "        cluster: backend\n        local_rate_limit:\n          capacity: 10", 1)
			},
			wantErr: "local_rate_limit: capacity and refill_tokens_per_second are required",
		},
		{
			name: "unbounded local rate limit",
			mutate: func(input string) string {
				return strings.Replace(input, "        cluster: backend", "        cluster: backend\n        local_rate_limit:\n          capacity: 1000001\n          refill_tokens_per_second: 1", 1)
			},
			wantErr: "local_rate_limit.capacity: must be between 1 and 1000000",
		},
		{
			name: "API key secret traversal",
			mutate: func(input string) string {
				return strings.Replace(input, "        cluster: backend", "        cluster: backend\n        api_key_auth:\n          credentials_secret: ../api-keys.txt", 1)
			},
			wantErr: "api_key_auth.credentials_secret: must be a safe secret filename",
		},
		{
			name: "reserved API key header",
			mutate: func(input string) string {
				return strings.Replace(input, "        cluster: backend", "        cluster: backend\n        api_key_auth:\n          header_name: X-Forwarded-For\n          credentials_secret: api-keys.txt", 1)
			},
			wantErr: "api_key_auth.header_name: must not use a hop-by-hop or forwarding identity field",
		},
		{
			name: "API key header route predicate",
			mutate: func(input string) string {
				input = strings.Replace(input, "          path_prefix: /api", "          path_prefix: /api\n          headers:\n            - name: x-api-key\n              present: true", 1)
				return strings.Replace(input, "        cluster: backend", "        cluster: backend\n        api_key_auth:\n          credentials_secret: api-keys.txt", 1)
			},
			wantErr: "api_key_auth.header_name: must not duplicate a route header predicate",
		},
		{
			name: "cleartext http2 listener",
			mutate: func(input string) string {
				return strings.Replace(input, "protocol: http1", "protocol: http2", 1)
			},
			wantErr: "HTTP/2 requires downstream_tls for explicit h2 ALPN",
		},
		{
			name: "trusted proxy host bits",
			mutate: func(input string) string {
				block := "    trusted_proxy:\n      trusted_cidrs: [10.0.0.1/8]\n"
				return strings.Replace(input, "    virtual_hosts: [default]\n", "    virtual_hosts: [default]\n"+block, 1)
			},
			wantErr: "must be a canonical numeric IPv4 or IPv6 CIDR",
		},
		{
			name: "duplicate trusted proxy CIDR",
			mutate: func(input string) string {
				block := "    trusted_proxy:\n      trusted_cidrs: [2001:db8::/32, 2001:0db8::/32]\n"
				return strings.Replace(input, "    virtual_hosts: [default]\n", "    virtual_hosts: [default]\n"+block, 1)
			},
			wantErr: "duplicate trusted CIDR",
		},
		{
			name: "TLS secret traversal",
			mutate: func(input string) string {
				block := "    downstream_tls:\n      certificate_chain_secret: ../server.pem\n      private_key_secret: server-key.pem\n"
				return strings.Replace(input, "    virtual_hosts: [default]\n", "    virtual_hosts: [default]\n"+block, 1)
			},
			wantErr: "certificate_chain_secret: must be a safe secret filename",
		},
		{
			name: "mTLS missing trust bundle",
			mutate: func(input string) string {
				block := "    downstream_tls:\n      certificate_chain_secret: server-chain.pem\n      private_key_secret: server-key.pem\n      require_client_certificate: true\n"
				return strings.Replace(input, "    virtual_hosts: [default]\n", "    virtual_hosts: [default]\n"+block, 1)
			},
			wantErr: "require_client_certificate and trust_bundle_secret must be configured together",
		},
		{
			name: "upstream TLS IP server name",
			mutate: func(input string) string {
				block := "    upstream_tls:\n      server_name: 127.0.0.1\n      trust_bundle_secret: upstream-ca.pem\n"
				return strings.Replace(input, "    endpoints:\n", block+"    endpoints:\n", 1)
			},
			wantErr: "server_name: must be a DNS hostname",
		},
		{
			name: "upstream TLS missing trust bundle",
			mutate: func(input string) string {
				block := "    upstream_tls:\n      server_name: upstream.example.test\n"
				return strings.Replace(input, "    endpoints:\n", block+"    endpoints:\n", 1)
			},
			wantErr: "trust_bundle_secret: must be a safe secret filename",
		},
		{
			name: "upstream TLS secret traversal",
			mutate: func(input string) string {
				block := "    upstream_tls:\n      server_name: upstream.example.test\n      trust_bundle_secret: ../upstream-ca.pem\n"
				return strings.Replace(input, "    endpoints:\n", block+"    endpoints:\n", 1)
			},
			wantErr: "trust_bundle_secret: must be a safe secret filename",
		},
		{
			name: "upstream mTLS missing private key",
			mutate: func(input string) string {
				block := "    upstream_tls:\n      server_name: upstream.example.test\n      trust_bundle_secret: upstream-ca.pem\n      certificate_chain_secret: gateway-client.pem\n"
				return strings.Replace(input, "    endpoints:\n", block+"    endpoints:\n", 1)
			},
			wantErr: "certificate_chain_secret and private_key_secret must be configured together",
		},
		{
			name: "invalid safe regex",
			mutate: func(input string) string {
				return strings.Replace(input, "path_prefix: /api", "safe_regex: '('", 1)
			},
			wantErr: "safe_regex: invalid RE2 expression",
		},
		{
			name: "lowercase route method",
			mutate: func(input string) string {
				return strings.Replace(input, "          path_prefix: /api", "          path_prefix: /api\n          methods: [get]", 1)
			},
			wantErr: "must use uppercase canonical form",
		},
		{
			name: "header predicate without value match",
			mutate: func(input string) string {
				return strings.Replace(input, "          path_prefix: /api", "          path_prefix: /api\n          headers:\n            - name: x-release", 1)
			},
			wantErr: "exactly one of exact or present is required",
		},
		{
			name: "duplicate normalized header predicate",
			mutate: func(input string) string {
				return strings.Replace(input, "          path_prefix: /api", "          path_prefix: /api\n          headers:\n            - {name: X-Release, present: true}\n            - {name: x-release, exact: beta}", 1)
			},
			wantErr: "duplicate normalized header name",
		},
		{
			name: "query predicate without value match",
			mutate: func(input string) string {
				return strings.Replace(input, "          path_prefix: /api", "          path_prefix: /api\n          query_parameters:\n            - name: tenant", 1)
			},
			wantErr: "exactly one of exact or present is required",
		},
		{
			name: "unsupported load balancing",
			mutate: func(input string) string {
				return strings.Replace(input, "load_balancing_policy: round_robin", "load_balancing_policy: maglev", 1)
			},
			wantErr: "unsupported; use round_robin, least_request, or random",
		},
		{
			name: "passive health failure threshold too high",
			mutate: func(input string) string {
				return strings.Replace(input, "    max_pending_requests_per_shard: 256", "    max_pending_requests_per_shard: 256\n    passive_health:\n      consecutive_failures: 101", 1)
			},
			wantErr: "passive_health.consecutive_failures: must be between 1 and 100",
		},
		{
			name: "passive health ejection time too low",
			mutate: func(input string) string {
				return strings.Replace(input, "    max_pending_requests_per_shard: 256", "    max_pending_requests_per_shard: 256\n    passive_health:\n      ejection_time_ms: 99", 1)
			},
			wantErr: "passive_health.ejection_time_ms: must be between 100 and 300000",
		},
		{
			name: "passive health recovery threshold too high",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    passive_health:\n      consecutive_successes: 101\n    endpoints:\n", 1)
			},
			wantErr: "passive_health.consecutive_successes: must be between 1 and 100",
		},
		{
			name: "endpoint concurrency exceeds cluster admission",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    max_concurrent_requests_per_endpoint: 385\n    endpoints:\n", 1)
			},
			wantErr: "max_concurrent_requests_per_endpoint: must not exceed the cluster connection-plus-pending admission limit",
		},
		{
			name: "active health path contains fragment",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    active_health:\n      path: /healthz#fragment\n    endpoints:\n", 1)
			},
			wantErr: "active_health.path: must be an absolute origin-form path",
		},
		{
			name: "active health timeout exceeds interval",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    active_health:\n      interval_ms: 1000\n      timeout_ms: 1001\n    endpoints:\n", 1)
			},
			wantErr: "active_health.timeout_ms: must not exceed interval_ms",
		},
		{
			name: "active health threshold too high",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    active_health:\n      unhealthy_threshold: 101\n    endpoints:\n", 1)
			},
			wantErr: "active_health.unhealthy_threshold: must be between 1 and 100",
		},
		{
			name: "active health status range reversed",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    active_health:\n      expected_status_min: 500\n      expected_status_max: 299\n    endpoints:\n", 1)
			},
			wantErr: "status range must be ordered between 200 and 599",
		},
		{
			name: "active health host contains port",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    active_health:\n      host: health.example.test:8080\n    endpoints:\n", 1)
			},
			wantErr: "active_health.host: must be an IP address or DNS hostname without a port",
		},
		{
			name: "DNS refresh interval too low",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    dns_refresh:\n      refresh_interval_ms: 999\n    endpoints:\n", 1)
			},
			wantErr: "dns_refresh.refresh_interval_ms: must be between 1000 and 3600000",
		},
		{
			name: "DNS timeout exceeds interval",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    dns_refresh:\n      refresh_interval_ms: 1000\n      resolve_timeout_ms: 1001\n    endpoints:\n", 1)
			},
			wantErr: "dns_refresh.resolve_timeout_ms: must not exceed refresh_interval_ms",
		},
		{
			name: "DNS refresh without hostname endpoint",
			mutate: func(input string) string {
				input = strings.Replace(input, "address: upstream", "address: 127.0.0.1", 1)
				return strings.Replace(input, "    endpoints:\n", "    dns_refresh: {}\n    endpoints:\n", 1)
			},
			wantErr: "dns_refresh: requires at least one DNS hostname endpoint",
		},
		{
			name: "retry attempts exceed bound",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    retry:\n      max_attempts: 6\n    endpoints:\n", 1)
			},
			wantErr: "retry.max_attempts: must be between 2 and 5",
		},
		{
			name: "retry timeout exceeds request timeout",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    retry:\n      per_try_timeout_ms: 15001\n    endpoints:\n", 1)
			},
			wantErr: "retry.per_try_timeout_ms: must not exceed runtime_limits.request_timeout_ms",
		},
		{
			name: "non-idempotent retry method",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    retry:\n      retryable_methods: [POST]\n    endpoints:\n", 1)
			},
			wantErr: "POST\" is not an enabled idempotent retry method",
		},
		{
			name: "zero retry budget capacity",
			mutate: func(input string) string {
				return strings.Replace(input, "    endpoints:\n", "    retry:\n      budget:\n        capacity: 0\n    endpoints:\n", 1)
			},
			wantErr: "retry.budget.capacity: must be between 1 and 1000000",
		},
		{
			name: "too many endpoints",
			mutate: func(input string) string {
				endpoint := "      - name: backend-1\n        address: upstream\n        port: 8081\n        weight: 1\n"
				return strings.Replace(input, endpoint, strings.Repeat(endpoint, maxEndpointCount+1), 1)
			},
			wantErr: "endpoints: must not contain more than 4096 endpoints",
		},
		{
			name: "zero endpoint weight",
			mutate: func(input string) string {
				return strings.Replace(input, "weight: 1", "weight: 0", 1)
			},
			wantErr: "weight: must be between 1 and 4096",
		},
		{
			name: "zero body limit",
			mutate: func(input string) string {
				return strings.Replace(input, "max_request_body_bytes: 10485760", "max_request_body_bytes: 0", 1)
			},
			wantErr: "max_request_body_bytes: must be between 1",
		},
		{
			name: "small upstream response header limit",
			mutate: func(input string) string {
				return strings.Replace(input, "max_upstream_response_header_bytes: 32768", "max_upstream_response_header_bytes: 1023", 1)
			},
			wantErr: "max_upstream_response_header_bytes: must be between 1024",
		},
		{
			name: "small upstream chunk metadata limit",
			mutate: func(input string) string {
				return strings.Replace(input, "max_upstream_chunk_metadata_bytes: 32768", "max_upstream_chunk_metadata_bytes: 1023", 1)
			},
			wantErr: "max_upstream_chunk_metadata_bytes: must be between 1024",
		},
		{
			name: "zero downstream connection limit",
			mutate: func(input string) string {
				return strings.Replace(input, "max_downstream_connections_per_shard: 16384", "max_downstream_connections_per_shard: 0", 1)
			},
			wantErr: "max_downstream_connections_per_shard: must be between 1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(strings.NewReader(test.mutate(validConfig)))
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

func TestWriteFileAtomicReplacesAndPreservesOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.pb")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if err := WriteFileAtomic(path, []byte("new")); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	assertFileContents(t, path, "new")

	renameErr := errors.New("injected rename failure")
	err := writeFileAtomic(path, []byte("partial"), func(string, string) error { return renameErr })
	if !errors.Is(err, renameErr) {
		t.Fatalf("writeFileAtomic() error = %v, want injected rename error", err)
	}
	assertFileContents(t, path, "new")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "snapshot.pb" {
		t.Fatalf("temporary output was not cleaned up: %v", entries)
	}
}

func FuzzCompile(f *testing.F) {
	f.Add([]byte(validConfig))
	f.Add([]byte("server: ["))
	f.Add([]byte("---\n{}\n---\n{}\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if int64(len(input)) > MaxConfigBytes {
			t.Skip()
		}
		compiled, err := Compile(bytes.NewReader(input))
		if err != nil {
			return
		}
		if _, err := MarshalDeterministic(compiled); err != nil {
			t.Fatalf("validated snapshot did not marshal: %v", err)
		}
	})
}

func compileForTest(t *testing.T, input string) *bonvoyagev1.Snapshot {
	t.Helper()
	compiled, err := Compile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return compiled
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if string(got) != want {
		t.Fatalf("file contents = %q, want %q", got, want)
	}
}
