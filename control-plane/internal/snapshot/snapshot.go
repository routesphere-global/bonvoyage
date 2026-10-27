// Package snapshot compiles the local BonVoyage YAML model into the immutable
// protobuf consumed by data-plane shards.
package snapshot

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

const (
	// CompilerVersion identifies the semantic compiler and deterministic
	// artifact contract shared by control-plane and offline authoring surfaces.
	CompilerVersion = "bonvoyage-control-plane-phase4-admin-v1"

	// MaxConfigBytes bounds memory consumed before the YAML is parsed.
	MaxConfigBytes int64 = 1 << 20

	defaultConnectTimeoutMS       uint32 = 1_000
	defaultMaxConnectionsPerShard uint32 = 128
	defaultMaxPendingPerShard     uint32 = 256
	defaultMaxHTTP2Streams        uint32 = 100
	defaultMaxHeaderBytes         uint32 = 32 << 10
	defaultMaxBodyBytes           uint64 = 10 << 20
	defaultMaxUpstreamHeaderBytes uint32 = 32 << 10
	defaultMaxUpstreamChunkBytes  uint32 = 32 << 10
	defaultRequestTimeoutMS       uint32 = 15_000
	defaultIdleTimeoutMS          uint32 = 60_000
	defaultMaxDownstreamPerShard  uint32 = 16_384
	maxTrustedProxyCIDRs                 = 64
	defaultPassiveFailureCount    uint32 = 5
	defaultPassiveEjectionTimeMS  uint32 = 30_000
	defaultMaxEjectionPercent     uint32 = 50
	defaultPassiveSuccessCount    uint32 = 1
	defaultActiveHealthPath              = "/healthz"
	defaultActiveHealthIntervalMS uint32 = 5_000
	defaultActiveHealthTimeoutMS  uint32 = 1_000
	defaultActiveHealthyThreshold uint32 = 2
	defaultActiveFailureThreshold uint32 = 3
	defaultActiveStatusMinimum    uint32 = 200
	defaultActiveStatusMaximum    uint32 = 399
	defaultDNSRefreshIntervalMS   uint32 = 30_000
	defaultDNSResolveTimeoutMS    uint32 = 1_000
	defaultRetryMaxAttempts       uint32 = 2
	defaultRetryPerTryTimeoutMS   uint32 = 1_000
	defaultRetryBudgetCapacity    uint32 = 100
	defaultRetryRefillPerSecond   uint32 = 10
	defaultMaxConcurrentRetries   uint32 = 16
	defaultAPIKeyHeader                  = "x-api-key"
	defaultCORSMaxAgeSeconds      uint32 = 600
	defaultWebSocketIdleTimeoutMS uint32 = 60_000

	maxHeaderBytes                     uint32 = 1 << 20
	maxBodyBytes                       uint64 = 1 << 30
	maxConnectTimeoutMS                uint32 = 60_000
	maxRequestTimeoutMS                uint32 = 300_000
	maxIdleTimeoutMS                   uint32 = 3_600_000
	maxConnectionsPerShard             uint32 = 1_000_000
	maxPendingPerShard                 uint32 = 1_000_000
	maxDownstreamPerShard              uint32 = 1_000_000
	maxEndpointCount                          = 4_096
	maxEndpointWeight                  uint32 = 4_096
	maxPassiveFailureCount             uint32 = 100
	maxPassiveEjectionMS               uint32 = 300_000
	maxPassiveSuccessCount             uint32 = 100
	maxConcurrentPerEndpoint           uint32 = 2_000_000
	maxHTTP2StreamsPerConnection       uint32 = 1_000
	maxActiveHealthIntervalMS          uint32 = 300_000
	maxActiveHealthTimeoutMS           uint32 = 10_000
	maxActiveHealthThreshold           uint32 = 100
	maxDNSRefreshIntervalMS            uint32 = 3_600_000
	maxDNSResolveTimeoutMS             uint32 = 10_000
	maxRetryAttempts                   uint32 = 5
	maxRetryBudgetCapacity             uint32 = 1_000_000
	maxRetryRefillPerSecond            uint32 = 1_000_000
	maxConcurrentRetries               uint32 = 1_000_000
	maxRouteConcurrency                uint32 = 2_000_000
	maxRouteRateLimit                  uint32 = 1_000_000
	maxFixedResponseBytes                     = 1 << 20
	maxJWTIssuerBytes                         = 1 << 10
	maxJWTAudienceBytes                       = 256
	maxJWTTypeBytes                           = 64
	maxJWTAlgorithms                          = 3
	maxJWTClockSkewSeconds             uint32 = 300
	maxJWTTokenLifetime                uint32 = 86_400
	maxJWTPolicyEntries                       = 16
	maxJWTScopeBytes                          = 128
	maxJWTClaimNameBytes                      = 64
	maxJWTClaimValueBytes                     = 256
	maxSourceIPCIDRs                          = 64
	maxCORSOrigins                            = 32
	maxCORSHeaders                            = 32
	maxCORSOriginBytes                        = 512
	maxCORSMaxAgeSeconds               uint32 = 86_400
	maxRequestContentTypes                    = 16
	maxRequestContentTypeBytes                = 128
	maxRouteMethods                           = 16
	maxRoutePredicates                        = 16
	maxRouteMethodBytes                       = 32
	maxRoutePathBytes                         = 4 << 10
	maxSafeRegexBytes                         = 1 << 10
	maxHeaderNameBytes                        = 128
	maxHeaderMutationValueBytes               = 4 << 10
	maxHeaderMutationsPerDirection            = 16
	maxHeaderMutationBytesPerDirection        = 16 << 10
	maxWeightedClustersPerRoute               = 16
	maxWeightedClusterTotal            uint32 = 4096
	maxQueryNameBytes                         = 256
	maxPredicateValueBytes                    = 4 << 10
	maxYAMLDepth                              = 64
	maxYAMLNodes                              = 100_000
)

var (
	namePattern            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	semanticVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	idempotentRetryMethods = map[string]struct{}{
		"DELETE":  {},
		"GET":     {},
		"HEAD":    {},
		"OPTIONS": {},
		"PUT":     {},
	}
	reservedAPIKeyHeaders = map[string]struct{}{
		"cf-connecting-ip":  {},
		"client-ip":         {},
		"connection":        {},
		"content-length":    {},
		"forwarded":         {},
		"host":              {},
		"proxy-connection":  {},
		"te":                {},
		"trailer":           {},
		"transfer-encoding": {},
		"true-client-ip":    {},
		"upgrade":           {},
		"x-real-ip":         {},
	}
	jwtAlgorithms = map[string]bonvoyagev1.JwtAlgorithm{
		"RS256": bonvoyagev1.JwtAlgorithm_JWT_ALGORITHM_RS256,
		"PS256": bonvoyagev1.JwtAlgorithm_JWT_ALGORITHM_PS256,
		"ES256": bonvoyagev1.JwtAlgorithm_JWT_ALGORITHM_ES256,
	}
	reservedJWTClaims = map[string]struct{}{
		"iss":   {},
		"aud":   {},
		"exp":   {},
		"nbf":   {},
		"iat":   {},
		"scope": {},
		"sub":   {},
	}
	reservedCORSRequestHeaders = map[string]struct{}{
		"access-control-request-headers": {},
		"access-control-request-method":  {},
		"connection":                     {},
		"content-length":                 {},
		"host":                           {},
		"origin":                         {},
		"proxy-connection":               {},
		"te":                             {},
		"trailer":                        {},
		"transfer-encoding":              {},
		"upgrade":                        {},
	}
	forbiddenCORSExposedHeaders = map[string]struct{}{
		"set-cookie":  {},
		"set-cookie2": {},
	}
	protocolOwnedMutationHeaders = map[string]struct{}{
		"connection":               {},
		"content-length":           {},
		"host":                     {},
		"keep-alive":               {},
		"proxy-connection":         {},
		"sec-websocket-accept":     {},
		"sec-websocket-extensions": {},
		"sec-websocket-key":        {},
		"sec-websocket-protocol":   {},
		"sec-websocket-version":    {},
		"te":                       {},
		"traceparent":              {},
		"tracestate":               {},
		"baggage":                  {},
		"trailer":                  {},
		"transfer-encoding":        {},
		"upgrade":                  {},
	}
	forwardingIdentityHeaders = map[string]struct{}{
		"cf-connecting-ip": {},
		"client-ip":        {},
		"forwarded":        {},
		"true-client-ip":   {},
		"x-real-ip":        {},
	}
	credentialBearingHeaders = map[string]struct{}{
		"authorization":       {},
		"cookie":              {},
		"proxy-authorization": {},
		"set-cookie":          {},
		"set-cookie2":         {},
	}
)

type document struct {
	Server       serverConfig        `yaml:"server"`
	Snapshot     snapshotConfig      `yaml:"snapshot"`
	Listeners    []listenerConfig    `yaml:"listeners"`
	VirtualHosts []virtualHostConfig `yaml:"virtual_hosts"`
	Clusters     []clusterConfig     `yaml:"clusters"`
	Runtime      *runtimeLimits      `yaml:"runtime_limits"`
}

type serverConfig struct {
	NodeID      string `yaml:"node_id"`
	AdminAddr   string `yaml:"admin_addr"`
	MetricsAddr string `yaml:"metrics_addr"`
}

type snapshotConfig struct {
	SchemaVersion           *uint32 `yaml:"schema_version"`
	SnapshotID              string  `yaml:"snapshot_id"`
	Generation              *uint64 `yaml:"generation"`
	MinimumDataplaneVersion string  `yaml:"minimum_dataplane_version"`
}

type listenerConfig struct {
	Name          string               `yaml:"name"`
	Address       string               `yaml:"address"`
	Port          uint32               `yaml:"port"`
	Protocol      string               `yaml:"protocol"`
	VirtualHosts  []string             `yaml:"virtual_hosts"`
	DownstreamTLS *downstreamTLSConfig `yaml:"downstream_tls"`
	TrustedProxy  *trustedProxyConfig  `yaml:"trusted_proxy"`
}

type downstreamTLSConfig struct {
	CertificateChainSecret   string `yaml:"certificate_chain_secret"`
	PrivateKeySecret         string `yaml:"private_key_secret"`
	TrustBundleSecret        string `yaml:"trust_bundle_secret"`
	RequireClientCertificate bool   `yaml:"require_client_certificate"`
}

type trustedProxyConfig struct {
	TrustedCIDRs []string `yaml:"trusted_cidrs"`
}

type virtualHostConfig struct {
	Name    string        `yaml:"name"`
	Domains []string      `yaml:"domains"`
	Routes  []routeConfig `yaml:"routes"`
}

type routeConfig struct {
	Name                          string                       `yaml:"name"`
	Match                         routeMatchConfig             `yaml:"match"`
	Cluster                       string                       `yaml:"cluster"`
	WeightedClusters              []weightedClusterConfig      `yaml:"weighted_clusters"`
	FixedResponse                 *fixedResponseConfig         `yaml:"fixed_response"`
	MaxConcurrentRequestsPerShard *uint32                      `yaml:"max_concurrent_requests_per_shard"`
	LocalRateLimit                *localRateLimitConfig        `yaml:"local_rate_limit"`
	APIKeyAuth                    *apiKeyAuthConfig            `yaml:"api_key_auth"`
	JWTAuth                       *jwtAuthConfig               `yaml:"jwt_auth"`
	SourceIPPolicy                *sourceIPPolicyConfig        `yaml:"source_ip_policy"`
	CORS                          *corsPolicyConfig            `yaml:"cors"`
	RequestContent                *requestContentConfig        `yaml:"request_content"`
	Redirect                      *redirectConfig              `yaml:"redirect"`
	HeaderTransformations         *headerTransformationsConfig `yaml:"header_transformations"`
	Rewrite                       *routeRewriteConfig          `yaml:"rewrite"`
	WebSocket                     *webSocketConfig             `yaml:"websocket"`
}

type webSocketConfig struct {
	IdleTimeoutMS *uint32 `yaml:"idle_timeout_ms"`
}

type weightedClusterConfig struct {
	Cluster string `yaml:"cluster"`
	Weight  uint32 `yaml:"weight"`
}

type apiKeyAuthConfig struct {
	HeaderName        string `yaml:"header_name"`
	CredentialsSecret string `yaml:"credentials_secret"`
}

type jwtAuthConfig struct {
	JWKSSecret              string                `yaml:"jwks_secret"`
	Issuer                  string                `yaml:"issuer"`
	Audience                string                `yaml:"audience"`
	RequiredType            string                `yaml:"required_type"`
	Algorithms              []string              `yaml:"algorithms"`
	ClockSkewSeconds        uint32                `yaml:"clock_skew_seconds"`
	MaxTokenLifetimeSeconds *uint32               `yaml:"max_token_lifetime_seconds"`
	RequiredScopes          []string              `yaml:"required_scopes"`
	RequiredClaims          []jwtClaimMatchConfig `yaml:"required_claims"`
	VerificationRateLimit   *localRateLimitConfig `yaml:"verification_rate_limit"`
}

type jwtClaimMatchConfig struct {
	Name  string `yaml:"name"`
	Exact string `yaml:"exact"`
}

type sourceIPPolicyConfig struct {
	AllowCIDRs []string `yaml:"allow_cidrs"`
	DenyCIDRs  []string `yaml:"deny_cidrs"`
}

type corsPolicyConfig struct {
	AllowAnyOrigin   bool     `yaml:"allow_any_origin"`
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	ExposedHeaders   []string `yaml:"exposed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	MaxAgeSeconds    *uint32  `yaml:"max_age_seconds"`
}

type requestContentConfig struct {
	MaxBodyBytes        *uint64  `yaml:"max_body_bytes"`
	AllowedContentTypes []string `yaml:"allowed_content_types"`
}

type localRateLimitConfig struct {
	Capacity              *uint32 `yaml:"capacity"`
	RefillTokensPerSecond *uint32 `yaml:"refill_tokens_per_second"`
}

type fixedResponseConfig struct {
	StatusCode  uint32 `yaml:"status_code"`
	Body        string `yaml:"body"`
	ContentType string `yaml:"content_type"`
}

type redirectConfig struct {
	StatusCode uint32  `yaml:"status_code"`
	Scheme     string  `yaml:"scheme"`
	Host       string  `yaml:"host"`
	Port       *uint32 `yaml:"port"`
	Path       string  `yaml:"path"`
	Query      string  `yaml:"query"`
}

type routeRewriteConfig struct {
	Host       string  `yaml:"host"`
	Port       *uint32 `yaml:"port"`
	Path       *string `yaml:"path"`
	PathPrefix *string `yaml:"path_prefix"`
}

type headerTransformationsConfig struct {
	Request  []headerMutationConfig `yaml:"request"`
	Response []headerMutationConfig `yaml:"response"`
}

type headerMutationConfig struct {
	Operation string `yaml:"operation"`
	Name      string `yaml:"name"`
	Value     string `yaml:"value"`
}

type routeMatchConfig struct {
	PathExact       *string             `yaml:"path_exact"`
	PathPrefix      *string             `yaml:"path_prefix"`
	SafeRegex       *string             `yaml:"safe_regex"`
	Methods         []string            `yaml:"methods"`
	Headers         []headerMatchConfig `yaml:"headers"`
	QueryParameters []queryMatchConfig  `yaml:"query_parameters"`
}

type headerMatchConfig struct {
	Name    string  `yaml:"name"`
	Exact   *string `yaml:"exact"`
	Present *bool   `yaml:"present"`
}

type queryMatchConfig struct {
	Name    string  `yaml:"name"`
	Exact   *string `yaml:"exact"`
	Present *bool   `yaml:"present"`
}

type clusterConfig struct {
	Name                       string               `yaml:"name"`
	Protocol                   string               `yaml:"protocol"`
	Endpoints                  []endpointConfig     `yaml:"endpoints"`
	LoadBalancingPolicy        string               `yaml:"load_balancing_policy"`
	ConnectTimeoutMS           *uint32              `yaml:"connect_timeout_ms"`
	MaxConnectionsPerShard     *uint32              `yaml:"max_connections_per_shard"`
	MaxPendingRequestsPerShard *uint32              `yaml:"max_pending_requests_per_shard"`
	MaxConcurrentPerEndpoint   *uint32              `yaml:"max_concurrent_requests_per_endpoint"`
	MaxHTTP2Streams            *uint32              `yaml:"max_http2_streams_per_connection"`
	UpstreamTLS                *upstreamTLSConfig   `yaml:"upstream_tls"`
	PassiveHealth              *passiveHealthConfig `yaml:"passive_health"`
	ActiveHealth               *activeHealthConfig  `yaml:"active_health"`
	DNSRefresh                 *dnsRefreshConfig    `yaml:"dns_refresh"`
	Retry                      *retryConfig         `yaml:"retry"`
}

type retryConfig struct {
	MaxAttempts      *uint32            `yaml:"max_attempts"`
	PerTryTimeoutMS  *uint32            `yaml:"per_try_timeout_ms"`
	RetryableMethods []string           `yaml:"retryable_methods"`
	Budget           *retryBudgetConfig `yaml:"budget"`
}

type retryBudgetConfig struct {
	Capacity                     *uint32 `yaml:"capacity"`
	RefillTokensPerSecond        *uint32 `yaml:"refill_tokens_per_second"`
	MaxConcurrentRetriesPerShard *uint32 `yaml:"max_concurrent_retries_per_shard"`
}

type passiveHealthConfig struct {
	ConsecutiveFailures  *uint32 `yaml:"consecutive_failures"`
	EjectionTimeMS       *uint32 `yaml:"ejection_time_ms"`
	MaxEjectionPercent   *uint32 `yaml:"max_ejection_percent"`
	ConsecutiveSuccesses *uint32 `yaml:"consecutive_successes"`
}

type activeHealthConfig struct {
	Path               *string `yaml:"path"`
	IntervalMS         *uint32 `yaml:"interval_ms"`
	TimeoutMS          *uint32 `yaml:"timeout_ms"`
	HealthyThreshold   *uint32 `yaml:"healthy_threshold"`
	UnhealthyThreshold *uint32 `yaml:"unhealthy_threshold"`
	ExpectedStatusMin  *uint32 `yaml:"expected_status_min"`
	ExpectedStatusMax  *uint32 `yaml:"expected_status_max"`
	Host               string  `yaml:"host"`
}

type dnsRefreshConfig struct {
	RefreshIntervalMS *uint32 `yaml:"refresh_interval_ms"`
	ResolveTimeoutMS  *uint32 `yaml:"resolve_timeout_ms"`
}

type upstreamTLSConfig struct {
	ServerName             string `yaml:"server_name"`
	TrustBundleSecret      string `yaml:"trust_bundle_secret"`
	CertificateChainSecret string `yaml:"certificate_chain_secret"`
	PrivateKeySecret       string `yaml:"private_key_secret"`
}

type endpointConfig struct {
	Name    string  `yaml:"name"`
	Address string  `yaml:"address"`
	Port    uint32  `yaml:"port"`
	Weight  *uint32 `yaml:"weight"`
}

type runtimeLimits struct {
	MaxRequestHeaderBytes            *uint32 `yaml:"max_request_header_bytes"`
	MaxRequestBodyBytes              *uint64 `yaml:"max_request_body_bytes"`
	MaxUpstreamResponseHeaderBytes   *uint32 `yaml:"max_upstream_response_header_bytes"`
	MaxUpstreamChunkMetadataBytes    *uint32 `yaml:"max_upstream_chunk_metadata_bytes"`
	RequestTimeoutMS                 *uint32 `yaml:"request_timeout_ms"`
	DownstreamIdleTimeoutMS          *uint32 `yaml:"downstream_idle_timeout_ms"`
	MaxDownstreamConnectionsPerShard *uint32 `yaml:"max_downstream_connections_per_shard"`
}

// CompileFile reads and compiles a YAML file using the fixed input-size limit.
func CompileFile(path string) (*bonvoyagev1.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	compiled, err := Compile(f)
	if err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	return compiled, nil
}

// Compile parses, validates, defaults, and converts one YAML document.
func Compile(r io.Reader) (*bonvoyagev1.Snapshot, error) {
	data, err := readBounded(r, MaxConfigBytes)
	if err != nil {
		return nil, err
	}

	if err := rejectAliasesAndMultipleDocuments(data); err != nil {
		return nil, err
	}

	var cfg document
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	if err := ensureSingleDocument(decoder); err != nil {
		return nil, err
	}

	return compileDocument(&cfg)
}

// InspectSchemaVersion parses one bounded, structurally safe YAML document
// without applying the current schema's semantic validation. Migration uses
// this boundary to identify an older input before selecting a reviewed
// version-to-version transform.
func InspectSchemaVersion(r io.Reader) (*uint32, error) {
	data, err := readBounded(r, MaxConfigBytes)
	if err != nil {
		return nil, err
	}
	if err := rejectAliasesAndMultipleDocuments(data); err != nil {
		return nil, err
	}

	var envelope struct {
		Snapshot struct {
			SchemaVersion *uint32 `yaml:"schema_version"`
		} `yaml:"snapshot"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	if err := ensureSingleDocument(decoder); err != nil {
		return nil, err
	}
	return envelope.Snapshot.SchemaVersion, nil
}

// MarshalDeterministic serializes a compiled snapshot reproducibly.
func MarshalDeterministic(compiled *bonvoyagev1.Snapshot) ([]byte, error) {
	if compiled == nil {
		return nil, errors.New("marshal snapshot: snapshot is nil")
	}
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(compiled)
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	return data, nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	if r == nil {
		return nil, errors.New("read config: reader is nil")
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("read config: input exceeds %d-byte limit", limit)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("parse YAML: document is empty")
	}
	return data, nil
}

func rejectAliasesAndMultipleDocuments(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	if err := validateYAMLTree(&root, 0, new(int)); err != nil {
		return err
	}
	return ensureSingleDocument(decoder)
}

func validateYAMLTree(node *yaml.Node, depth int, nodes *int) error {
	*nodes = *nodes + 1
	if *nodes > maxYAMLNodes {
		return fmt.Errorf("parse YAML: document exceeds %d-node limit", maxYAMLNodes)
	}
	if depth > maxYAMLDepth {
		return fmt.Errorf("parse YAML: document exceeds %d-level nesting limit", maxYAMLDepth)
	}
	if node.Kind == yaml.AliasNode {
		return errors.New("parse YAML: aliases and merge keys are not supported")
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Value == "<<" {
				return errors.New("parse YAML: aliases and merge keys are not supported")
			}
		}
	}
	for _, child := range node.Content {
		if err := validateYAMLTree(child, depth+1, nodes); err != nil {
			return err
		}
	}
	return nil
}

func ensureSingleDocument(decoder *yaml.Decoder) error {
	var extra yaml.Node
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	return errors.New("parse YAML: multiple documents are not supported")
}

func compileDocument(cfg *document) (*bonvoyagev1.Snapshot, error) {
	if err := validateServer(cfg.Server); err != nil {
		return nil, err
	}
	if cfg.Snapshot.SchemaVersion == nil {
		return nil, errors.New("snapshot.schema_version: required")
	}
	if *cfg.Snapshot.SchemaVersion != 1 {
		return nil, fmt.Errorf("snapshot.schema_version: got %d, only version 1 is supported", *cfg.Snapshot.SchemaVersion)
	}
	if err := validateName("snapshot.snapshot_id", cfg.Snapshot.SnapshotID); err != nil {
		return nil, err
	}
	if cfg.Snapshot.Generation == nil || *cfg.Snapshot.Generation == 0 {
		return nil, errors.New("snapshot.generation: must be greater than zero")
	}
	minimumVersion := strings.TrimSpace(cfg.Snapshot.MinimumDataplaneVersion)
	if minimumVersion == "" {
		minimumVersion = "0.2.0"
	}
	if !semanticVersionPattern.MatchString(minimumVersion) {
		return nil, errors.New("snapshot.minimum_dataplane_version: must be a major.minor.patch version")
	}

	virtualHostNames := make(map[string]struct{}, len(cfg.VirtualHosts))
	clusterNames := make(map[string]struct{}, len(cfg.Clusters))
	if len(cfg.VirtualHosts) == 0 {
		return nil, errors.New("virtual_hosts: at least one virtual host is required")
	}
	if len(cfg.Clusters) == 0 {
		return nil, errors.New("clusters: at least one cluster is required")
	}
	for i, item := range cfg.VirtualHosts {
		path := fmt.Sprintf("virtual_hosts[%d].name", i)
		if err := addUniqueName(virtualHostNames, path, item.Name); err != nil {
			return nil, err
		}
	}
	for i, item := range cfg.Clusters {
		path := fmt.Sprintf("clusters[%d].name", i)
		if err := addUniqueName(clusterNames, path, item.Name); err != nil {
			return nil, err
		}
	}

	listeners, err := compileListeners(cfg.Listeners, virtualHostNames)
	if err != nil {
		return nil, err
	}
	limits, err := compileRuntimeLimits(cfg.Runtime)
	if err != nil {
		return nil, err
	}
	virtualHosts, err := compileVirtualHosts(
		cfg.VirtualHosts, clusterNames, limits.GetMaxRequestBodyBytes(),
		limits.GetMaxRequestHeaderBytes())
	if err != nil {
		return nil, err
	}
	clusters, err := compileClusters(cfg.Clusters, limits.GetRequestTimeoutMs())
	if err != nil {
		return nil, err
	}
	if err := validateWebSocketTopology(listeners, virtualHosts, clusters); err != nil {
		return nil, err
	}

	return &bonvoyagev1.Snapshot{
		SnapshotId:              cfg.Snapshot.SnapshotID,
		Generation:              *cfg.Snapshot.Generation,
		MinimumDataplaneVersion: minimumVersion,
		Listeners:               listeners,
		VirtualHosts:            virtualHosts,
		Clusters:                clusters,
		RuntimeLimits:           limits,
		SchemaVersion:           *cfg.Snapshot.SchemaVersion,
	}, nil
}

func validateServer(server serverConfig) error {
	if err := validateName("server.node_id", server.NodeID); err != nil {
		return err
	}
	if err := validateSocketAddress("server.admin_addr", server.AdminAddr); err != nil {
		return err
	}
	return validateSocketAddress("server.metrics_addr", server.MetricsAddr)
}

func validateSocketAddress(path, address string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || host == "" {
		return fmt.Errorf("%s: must be a host:port address", path)
	}
	if err := validateEndpointAddress(path, host); err != nil {
		return fmt.Errorf("%s: host must be an IP address or DNS hostname", path)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("%s: port must be between 1 and 65535", path)
	}
	return nil
}

func compileListeners(items []listenerConfig, virtualHosts map[string]struct{}) ([]*bonvoyagev1.Listener, error) {
	if len(items) == 0 {
		return nil, errors.New("listeners: at least one listener is required")
	}
	names := make(map[string]struct{}, len(items))
	bindings := make(map[string]struct{}, len(items))
	result := make([]*bonvoyagev1.Listener, 0, len(items))
	for i, item := range items {
		base := fmt.Sprintf("listeners[%d]", i)
		if err := addUniqueName(names, base+".name", item.Name); err != nil {
			return nil, err
		}
		address := strings.TrimSpace(item.Address)
		if err := validateEndpointAddress(base+".address", address); err != nil {
			return nil, err
		}
		if item.Port == 0 || item.Port > 65_535 {
			return nil, fmt.Errorf("%s.port: must be between 1 and 65535", base)
		}
		binding := net.JoinHostPort(strings.ToLower(address), strconv.FormatUint(uint64(item.Port), 10))
		if _, exists := bindings[binding]; exists {
			return nil, fmt.Errorf("%s: duplicate listener binding %q", base, binding)
		}
		bindings[binding] = struct{}{}
		var protocol bonvoyagev1.Protocol
		switch item.Protocol {
		case "http1":
			protocol = bonvoyagev1.Protocol_PROTOCOL_HTTP1
		case "http2":
			if item.DownstreamTLS == nil {
				return nil, fmt.Errorf("%s.protocol: HTTP/2 requires downstream_tls for explicit h2 ALPN", base)
			}
			protocol = bonvoyagev1.Protocol_PROTOCOL_HTTP2
		default:
			return nil, fmt.Errorf("%s.protocol: %q is unsupported; use http1 or TLS http2", base, item.Protocol)
		}
		if len(item.VirtualHosts) == 0 {
			return nil, fmt.Errorf("%s.virtual_hosts: at least one reference is required", base)
		}
		seenRefs := make(map[string]struct{}, len(item.VirtualHosts))
		for j, ref := range item.VirtualHosts {
			path := fmt.Sprintf("%s.virtual_hosts[%d]", base, j)
			if _, exists := virtualHosts[ref]; !exists {
				return nil, fmt.Errorf("%s: references unknown virtual host %q", path, ref)
			}
			if _, exists := seenRefs[ref]; exists {
				return nil, fmt.Errorf("%s: duplicate virtual host reference %q", path, ref)
			}
			seenRefs[ref] = struct{}{}
		}
		var downstreamTLS *bonvoyagev1.DownstreamTls
		if item.DownstreamTLS != nil {
			certificateChain := strings.TrimSpace(item.DownstreamTLS.CertificateChainSecret)
			privateKey := strings.TrimSpace(item.DownstreamTLS.PrivateKeySecret)
			trustBundle := strings.TrimSpace(item.DownstreamTLS.TrustBundleSecret)
			if !namePattern.MatchString(certificateChain) {
				return nil, fmt.Errorf("%s.downstream_tls.certificate_chain_secret: must be a safe secret filename", base)
			}
			if !namePattern.MatchString(privateKey) {
				return nil, fmt.Errorf("%s.downstream_tls.private_key_secret: must be a safe secret filename", base)
			}
			hasTrustBundle := trustBundle != ""
			if hasTrustBundle && !namePattern.MatchString(trustBundle) {
				return nil, fmt.Errorf("%s.downstream_tls.trust_bundle_secret: must be a safe secret filename", base)
			}
			if item.DownstreamTLS.RequireClientCertificate != hasTrustBundle {
				return nil, fmt.Errorf("%s.downstream_tls: require_client_certificate and trust_bundle_secret must be configured together", base)
			}
			downstreamTLS = &bonvoyagev1.DownstreamTls{
				CertificateChainSecret:   certificateChain,
				PrivateKeySecret:         privateKey,
				TrustBundleSecret:        trustBundle,
				RequireClientCertificate: item.DownstreamTLS.RequireClientCertificate,
			}
		}
		var trustedProxy *bonvoyagev1.TrustedProxyPolicy
		if item.TrustedProxy != nil {
			if len(item.TrustedProxy.TrustedCIDRs) == 0 || len(item.TrustedProxy.TrustedCIDRs) > maxTrustedProxyCIDRs {
				return nil, fmt.Errorf("%s.trusted_proxy.trusted_cidrs: must contain between 1 and %d entries", base, maxTrustedProxyCIDRs)
			}
			trustedCIDRs := make([]string, 0, len(item.TrustedProxy.TrustedCIDRs))
			seenCIDRs := make(map[string]struct{}, len(item.TrustedProxy.TrustedCIDRs))
			for j, raw := range item.TrustedProxy.TrustedCIDRs {
				path := fmt.Sprintf("%s.trusted_proxy.trusted_cidrs[%d]", base, j)
				value := strings.TrimSpace(raw)
				ip, network, err := net.ParseCIDR(value)
				if err != nil || !ip.Equal(network.IP) || (ip.To4() != nil && strings.Contains(value, ":")) {
					return nil, fmt.Errorf("%s: must be a canonical numeric IPv4 or IPv6 CIDR", path)
				}
				canonical := network.String()
				if _, exists := seenCIDRs[canonical]; exists {
					return nil, fmt.Errorf("%s: duplicate trusted CIDR %q", path, canonical)
				}
				seenCIDRs[canonical] = struct{}{}
				trustedCIDRs = append(trustedCIDRs, canonical)
			}
			trustedProxy = &bonvoyagev1.TrustedProxyPolicy{TrustedCidrs: trustedCIDRs}
		}
		result = append(result, &bonvoyagev1.Listener{
			Name:             item.Name,
			Address:          address,
			Port:             item.Port,
			Protocol:         protocol,
			VirtualHostNames: append([]string(nil), item.VirtualHosts...),
			DownstreamTls:    downstreamTLS,
			TrustedProxy:     trustedProxy,
		})
	}
	return result, nil
}

func compileVirtualHosts(items []virtualHostConfig, clusters map[string]struct{}, globalMaxBodyBytes uint64, globalMaxRequestHeaderBytes uint32) ([]*bonvoyagev1.VirtualHost, error) {
	claimedDomains := make(map[string]string)
	result := make([]*bonvoyagev1.VirtualHost, 0, len(items))
	for i, item := range items {
		base := fmt.Sprintf("virtual_hosts[%d]", i)
		if len(item.Domains) == 0 {
			return nil, fmt.Errorf("%s.domains: at least one domain is required", base)
		}
		domains := make([]string, 0, len(item.Domains))
		for j, rawDomain := range item.Domains {
			path := fmt.Sprintf("%s.domains[%d]", base, j)
			domain, err := normalizeDomain(rawDomain)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			if owner, exists := claimedDomains[domain]; exists {
				return nil, fmt.Errorf("%s: domain %q is already owned by virtual host %q", path, domain, owner)
			}
			claimedDomains[domain] = item.Name
			domains = append(domains, domain)
		}
		if len(item.Routes) == 0 {
			return nil, fmt.Errorf("%s.routes: at least one route is required", base)
		}
		routeNames := make(map[string]struct{}, len(item.Routes))
		routeBindings := make(map[string]struct{}, len(item.Routes))
		unconditionalPathBindings := make(map[string]struct{}, len(item.Routes))
		routes := make([]*bonvoyagev1.Route, 0, len(item.Routes))
		for j, route := range item.Routes {
			routeBase := fmt.Sprintf("%s.routes[%d]", base, j)
			if err := addUniqueName(routeNames, routeBase+".name", route.Name); err != nil {
				return nil, err
			}
			if route.APIKeyAuth != nil && route.JWTAuth != nil {
				return nil, fmt.Errorf("%s: api_key_auth and jwt_auth cannot be configured together", routeBase)
			}
			hasCluster := route.Cluster != ""
			hasWeightedClusters := len(route.WeightedClusters) != 0
			hasFixedResponse := route.FixedResponse != nil
			hasRedirect := route.Redirect != nil
			if boolCount(hasCluster, hasWeightedClusters, hasFixedResponse, hasRedirect) != 1 {
				return nil, fmt.Errorf("%s: exactly one of cluster, weighted_clusters, fixed_response, or redirect is required", routeBase)
			}
			hasProxyAction := hasCluster || hasWeightedClusters
			if route.HeaderTransformations != nil && !hasProxyAction {
				return nil, fmt.Errorf("%s.header_transformations: is supported only on reverse-proxy routes", routeBase)
			}
			if route.Rewrite != nil && !hasProxyAction {
				return nil, fmt.Errorf("%s.rewrite: is supported only on reverse-proxy routes", routeBase)
			}
			if route.WebSocket != nil && !hasProxyAction {
				return nil, fmt.Errorf("%s.websocket: is supported only on reverse-proxy routes", routeBase)
			}
			if route.WebSocket != nil && route.MaxConcurrentRequestsPerShard == nil {
				return nil, fmt.Errorf("%s.max_concurrent_requests_per_shard: is required for a bounded WebSocket route", routeBase)
			}
			if hasCluster {
				if _, exists := clusters[route.Cluster]; !exists {
					return nil, fmt.Errorf("%s.cluster: references unknown cluster %q", routeBase, route.Cluster)
				}
			}
			weightedClusters := make([]*bonvoyagev1.WeightedCluster, 0, len(route.WeightedClusters))
			if hasWeightedClusters {
				if len(route.WeightedClusters) < 2 || len(route.WeightedClusters) > maxWeightedClustersPerRoute {
					return nil, fmt.Errorf("%s.weighted_clusters: must contain between 2 and %d entries", routeBase, maxWeightedClustersPerRoute)
				}
				seenClusters := make(map[string]struct{}, len(route.WeightedClusters))
				var totalWeight uint32
				for index, target := range route.WeightedClusters {
					targetBase := fmt.Sprintf("%s.weighted_clusters[%d]", routeBase, index)
					if _, exists := clusters[target.Cluster]; !exists {
						return nil, fmt.Errorf("%s.cluster: references unknown cluster %q", targetBase, target.Cluster)
					}
					if _, exists := seenClusters[target.Cluster]; exists {
						return nil, fmt.Errorf("%s.cluster: duplicate cluster %q", targetBase, target.Cluster)
					}
					seenClusters[target.Cluster] = struct{}{}
					if target.Weight == 0 || target.Weight > maxWeightedClusterTotal {
						return nil, fmt.Errorf("%s.weight: must be between 1 and %d", targetBase, maxWeightedClusterTotal)
					}
					if totalWeight > maxWeightedClusterTotal-target.Weight {
						return nil, fmt.Errorf("%s.weighted_clusters: total weight must not exceed %d", routeBase, maxWeightedClusterTotal)
					}
					totalWeight += target.Weight
					weightedClusters = append(weightedClusters, &bonvoyagev1.WeightedCluster{
						ClusterName: target.Cluster,
						Weight:      target.Weight,
					})
				}
			}
			match, err := compileRouteMatch(routeBase+".match", route.Match)
			if err != nil {
				return nil, err
			}
			bindingBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(match)
			if err != nil {
				return nil, fmt.Errorf("%s.match: serialize canonical route match: %w", routeBase, err)
			}
			binding := string(bindingBytes)
			if _, exists := routeBindings[binding]; exists {
				return nil, fmt.Errorf("%s.match: duplicate normalized route match", routeBase)
			}
			routeBindings[binding] = struct{}{}
			pathBinding := routePathBinding(match)
			if _, shadowed := unconditionalPathBindings[pathBinding]; shadowed {
				return nil, fmt.Errorf("%s.match: unreachable because an earlier route with the same path matcher has no predicates", routeBase)
			}
			if routeMatchIsUnconditional(match) {
				unconditionalPathBindings[pathBinding] = struct{}{}
			}
			compiledRoute := &bonvoyagev1.Route{
				Name:             route.Name,
				Match:            match,
				ClusterName:      route.Cluster,
				WeightedClusters: weightedClusters,
			}
			if route.WebSocket != nil {
				idleTimeout := valueOrDefault(route.WebSocket.IdleTimeoutMS, defaultWebSocketIdleTimeoutMS)
				if err := validateUint32Range(routeBase+".websocket.idle_timeout_ms", idleTimeout, 1_000, maxIdleTimeoutMS); err != nil {
					return nil, err
				}
				if len(match.GetMethods()) != 0 && !slices.Contains(match.GetMethods(), "GET") {
					return nil, fmt.Errorf("%s.match.methods: a WebSocket route must permit GET", routeBase)
				}
				compiledRoute.Websocket = &bonvoyagev1.WebSocketPolicy{IdleTimeoutMs: idleTimeout}
			}
			if route.Rewrite != nil {
				rewrite, err := compileRouteRewrite(
					routeBase+".rewrite", route.Rewrite, match,
					globalMaxRequestHeaderBytes)
				if err != nil {
					return nil, err
				}
				compiledRoute.Rewrite = rewrite
			}
			if route.MaxConcurrentRequestsPerShard != nil {
				value := *route.MaxConcurrentRequestsPerShard
				if value == 0 || value > maxRouteConcurrency {
					return nil, fmt.Errorf("%s.max_concurrent_requests_per_shard: must be between 1 and %d", routeBase, maxRouteConcurrency)
				}
				compiledRoute.MaxConcurrentRequestsPerShard = value
			}
			if route.LocalRateLimit != nil {
				if route.LocalRateLimit.Capacity == nil || route.LocalRateLimit.RefillTokensPerSecond == nil {
					return nil, fmt.Errorf("%s.local_rate_limit: capacity and refill_tokens_per_second are required", routeBase)
				}
				capacity := *route.LocalRateLimit.Capacity
				refill := *route.LocalRateLimit.RefillTokensPerSecond
				if capacity == 0 || capacity > maxRouteRateLimit {
					return nil, fmt.Errorf("%s.local_rate_limit.capacity: must be between 1 and %d", routeBase, maxRouteRateLimit)
				}
				if refill == 0 || refill > maxRouteRateLimit {
					return nil, fmt.Errorf("%s.local_rate_limit.refill_tokens_per_second: must be between 1 and %d", routeBase, maxRouteRateLimit)
				}
				compiledRoute.LocalRateLimit = &bonvoyagev1.LocalRateLimit{
					Capacity:              capacity,
					RefillTokensPerSecond: refill,
				}
			}
			if route.APIKeyAuth != nil {
				headerName := route.APIKeyAuth.HeaderName
				if headerName == "" {
					headerName = defaultAPIKeyHeader
				} else if strings.TrimSpace(headerName) != headerName {
					return nil, fmt.Errorf("%s.api_key_auth.header_name: must not contain surrounding whitespace", routeBase)
				}
				headerName = strings.ToLower(headerName)
				if len(headerName) > maxHeaderNameBytes || !validHTTPToken(headerName) {
					return nil, fmt.Errorf("%s.api_key_auth.header_name: must be an HTTP field-name no longer than %d bytes", routeBase, maxHeaderNameBytes)
				}
				if _, reserved := reservedAPIKeyHeaders[headerName]; reserved || strings.HasPrefix(headerName, "x-forwarded-") {
					return nil, fmt.Errorf("%s.api_key_auth.header_name: must not use a hop-by-hop or forwarding identity field", routeBase)
				}
				for _, predicate := range match.GetHeaders() {
					if predicate.GetName() == headerName {
						return nil, fmt.Errorf("%s.api_key_auth.header_name: must not duplicate a route header predicate", routeBase)
					}
				}
				credentialsSecret := route.APIKeyAuth.CredentialsSecret
				if strings.TrimSpace(credentialsSecret) != credentialsSecret {
					return nil, fmt.Errorf("%s.api_key_auth.credentials_secret: must not contain surrounding whitespace", routeBase)
				}
				if !namePattern.MatchString(credentialsSecret) {
					return nil, fmt.Errorf("%s.api_key_auth.credentials_secret: must be a safe secret filename", routeBase)
				}
				compiledRoute.ApiKeyAuth = &bonvoyagev1.ApiKeyAuth{
					HeaderName:        headerName,
					CredentialsSecret: credentialsSecret,
				}
			}
			if route.JWTAuth != nil {
				jwtAuth, err := compileJWTAuth(routeBase+".jwt_auth", route.JWTAuth)
				if err != nil {
					return nil, err
				}
				compiledRoute.JwtAuth = jwtAuth
			}
			if route.SourceIPPolicy != nil {
				sourceIPPolicy, err := compileSourceIPPolicy(
					routeBase+".source_ip_policy", route.SourceIPPolicy)
				if err != nil {
					return nil, err
				}
				compiledRoute.SourceIpPolicy = sourceIPPolicy
			}
			if route.CORS != nil {
				corsPolicy, err := compileCORSPolicy(
					routeBase+".cors", route.CORS, match)
				if err != nil {
					return nil, err
				}
				compiledRoute.Cors = corsPolicy
			}
			if route.RequestContent != nil {
				requestContent, err := compileRequestContentPolicy(
					routeBase+".request_content", route.RequestContent,
					globalMaxBodyBytes)
				if err != nil {
					return nil, err
				}
				for _, predicate := range match.GetHeaders() {
					if predicate.GetName() == "content-type" {
						return nil, fmt.Errorf("%s.request_content: must not duplicate a Content-Type route predicate", routeBase)
					}
				}
				if compiledRoute.GetApiKeyAuth().GetHeaderName() == "content-type" {
					return nil, fmt.Errorf("%s.request_content: Content-Type cannot carry an API key", routeBase)
				}
				compiledRoute.RequestContent = requestContent
			}
			if route.HeaderTransformations != nil {
				apiKeyHeader := compiledRoute.GetApiKeyAuth().GetHeaderName()
				headerTransformations, err := compileHeaderTransformations(
					routeBase+".header_transformations",
					route.HeaderTransformations, apiKeyHeader)
				if err != nil {
					return nil, err
				}
				compiledRoute.HeaderTransformations = headerTransformations
			}
			if hasFixedResponse {
				fixedResponse, err := compileFixedResponse(routeBase+".fixed_response", route.FixedResponse)
				if err != nil {
					return nil, err
				}
				compiledRoute.FixedResponse = fixedResponse
			}
			if hasRedirect {
				redirect, err := compileRedirect(routeBase+".redirect", route.Redirect)
				if err != nil {
					return nil, err
				}
				compiledRoute.Redirect = redirect
			}
			routes = append(routes, compiledRoute)
		}
		result = append(result, &bonvoyagev1.VirtualHost{Name: item.Name, Domains: domains, Routes: routes})
	}
	return result, nil
}

func compileJWTAuth(path string, policy *jwtAuthConfig) (*bonvoyagev1.JwtAuth, error) {
	jwksSecret := policy.JWKSSecret
	if strings.TrimSpace(jwksSecret) != jwksSecret {
		return nil, fmt.Errorf("%s.jwks_secret: must not contain surrounding whitespace", path)
	}
	if !namePattern.MatchString(jwksSecret) {
		return nil, fmt.Errorf("%s.jwks_secret: must be a safe secret filename", path)
	}

	issuer := policy.Issuer
	if strings.TrimSpace(issuer) != issuer {
		return nil, fmt.Errorf("%s.issuer: must not contain surrounding whitespace", path)
	}
	if len(issuer) == 0 || len(issuer) > maxJWTIssuerBytes || !validVisibleText(issuer) {
		return nil, fmt.Errorf("%s.issuer: must contain between 1 and %d bytes of visible text", path, maxJWTIssuerBytes)
	}
	issuerURL, err := url.ParseRequestURI(issuer)
	if err != nil || !strings.EqualFold(issuerURL.Scheme, "https") ||
		issuerURL.Host == "" || issuerURL.User != nil {
		return nil, fmt.Errorf("%s.issuer: must be an HTTPS URI-like value", path)
	}

	audience := policy.Audience
	if strings.TrimSpace(audience) != audience {
		return nil, fmt.Errorf("%s.audience: must not contain surrounding whitespace", path)
	}
	if len(audience) == 0 || len(audience) > maxJWTAudienceBytes || !validVisibleText(audience) {
		return nil, fmt.Errorf("%s.audience: must contain between 1 and %d bytes of visible text", path, maxJWTAudienceBytes)
	}

	if len(policy.RequiredType) == 0 || len(policy.RequiredType) > maxJWTTypeBytes || !validHTTPToken(policy.RequiredType) {
		return nil, fmt.Errorf("%s.required_type: must be an HTTP token between 1 and %d bytes", path, maxJWTTypeBytes)
	}
	if len(policy.Algorithms) == 0 || len(policy.Algorithms) > maxJWTAlgorithms {
		return nil, fmt.Errorf("%s.algorithms: must contain between 1 and %d unique algorithms", path, maxJWTAlgorithms)
	}
	algorithms := make([]bonvoyagev1.JwtAlgorithm, 0, len(policy.Algorithms))
	seenAlgorithms := make(map[string]struct{}, len(policy.Algorithms))
	for index, algorithm := range policy.Algorithms {
		compiled, supported := jwtAlgorithms[algorithm]
		if !supported {
			return nil, fmt.Errorf("%s.algorithms[%d]: unsupported; use RS256, PS256, or ES256", path, index)
		}
		if _, duplicate := seenAlgorithms[algorithm]; duplicate {
			return nil, fmt.Errorf("%s.algorithms[%d]: duplicate algorithm %q", path, index, algorithm)
		}
		seenAlgorithms[algorithm] = struct{}{}
		algorithms = append(algorithms, compiled)
	}

	if policy.ClockSkewSeconds > maxJWTClockSkewSeconds {
		return nil, fmt.Errorf("%s.clock_skew_seconds: must not exceed %d", path, maxJWTClockSkewSeconds)
	}
	if policy.MaxTokenLifetimeSeconds == nil {
		return nil, fmt.Errorf("%s.max_token_lifetime_seconds: is required", path)
	}
	maxTokenLifetime := *policy.MaxTokenLifetimeSeconds
	if maxTokenLifetime == 0 || maxTokenLifetime > maxJWTTokenLifetime {
		return nil, fmt.Errorf("%s.max_token_lifetime_seconds: must be between 1 and %d", path, maxJWTTokenLifetime)
	}
	if policy.VerificationRateLimit == nil ||
		policy.VerificationRateLimit.Capacity == nil ||
		policy.VerificationRateLimit.RefillTokensPerSecond == nil {
		return nil, fmt.Errorf("%s.verification_rate_limit: capacity and refill_tokens_per_second are required", path)
	}
	verificationCapacity := *policy.VerificationRateLimit.Capacity
	if verificationCapacity == 0 || verificationCapacity > maxRouteRateLimit {
		return nil, fmt.Errorf("%s.verification_rate_limit.capacity: must be between 1 and %d", path, maxRouteRateLimit)
	}
	verificationRefill := *policy.VerificationRateLimit.RefillTokensPerSecond
	if verificationRefill == 0 || verificationRefill > maxRouteRateLimit {
		return nil, fmt.Errorf("%s.verification_rate_limit.refill_tokens_per_second: must be between 1 and %d", path, maxRouteRateLimit)
	}

	if len(policy.RequiredScopes) > maxJWTPolicyEntries {
		return nil, fmt.Errorf("%s.required_scopes: must not contain more than %d entries", path, maxJWTPolicyEntries)
	}
	seenScopes := make(map[string]struct{}, len(policy.RequiredScopes))
	for index, scope := range policy.RequiredScopes {
		if strings.TrimSpace(scope) != scope {
			return nil, fmt.Errorf("%s.required_scopes[%d]: must not contain surrounding whitespace", path, index)
		}
		if len(scope) == 0 || len(scope) > maxJWTScopeBytes || !validVisibleASCII(scope, false) {
			return nil, fmt.Errorf("%s.required_scopes[%d]: must contain between 1 and %d visible ASCII bytes without whitespace", path, index, maxJWTScopeBytes)
		}
		if _, duplicate := seenScopes[scope]; duplicate {
			return nil, fmt.Errorf("%s.required_scopes[%d]: duplicate scope %q", path, index, scope)
		}
		seenScopes[scope] = struct{}{}
	}

	if len(policy.RequiredClaims) > maxJWTPolicyEntries {
		return nil, fmt.Errorf("%s.required_claims: must not contain more than %d entries", path, maxJWTPolicyEntries)
	}
	claims := make([]*bonvoyagev1.JwtClaimMatch, 0, len(policy.RequiredClaims))
	seenClaimNames := make(map[string]struct{}, len(policy.RequiredClaims))
	for index, claim := range policy.RequiredClaims {
		claimPath := fmt.Sprintf("%s.required_claims[%d]", path, index)
		if len(claim.Name) == 0 || len(claim.Name) > maxJWTClaimNameBytes || !validHTTPToken(claim.Name) {
			return nil, fmt.Errorf("%s.name: must be an HTTP token between 1 and %d bytes", claimPath, maxJWTClaimNameBytes)
		}
		if _, reserved := reservedJWTClaims[claim.Name]; reserved {
			return nil, fmt.Errorf("%s.name: claim %q is owned by the base JWT policy", claimPath, claim.Name)
		}
		if _, duplicate := seenClaimNames[claim.Name]; duplicate {
			return nil, fmt.Errorf("%s.name: duplicate claim name %q", claimPath, claim.Name)
		}
		seenClaimNames[claim.Name] = struct{}{}
		if strings.TrimSpace(claim.Exact) != claim.Exact {
			return nil, fmt.Errorf("%s.exact: must not contain surrounding whitespace", claimPath)
		}
		if len(claim.Exact) == 0 || len(claim.Exact) > maxJWTClaimValueBytes || !validVisibleASCII(claim.Exact, true) {
			return nil, fmt.Errorf("%s.exact: must contain between 1 and %d bytes of visible ASCII text", claimPath, maxJWTClaimValueBytes)
		}
		claims = append(claims, &bonvoyagev1.JwtClaimMatch{Name: claim.Name, Exact: claim.Exact})
	}

	return &bonvoyagev1.JwtAuth{
		JwksSecret:              jwksSecret,
		Issuer:                  issuer,
		Audience:                audience,
		RequiredType:            policy.RequiredType,
		Algorithms:              algorithms,
		ClockSkewSeconds:        policy.ClockSkewSeconds,
		MaxTokenLifetimeSeconds: maxTokenLifetime,
		RequiredScopes:          append([]string(nil), policy.RequiredScopes...),
		RequiredClaims:          claims,
		VerificationRateLimit: &bonvoyagev1.LocalRateLimit{
			Capacity:              verificationCapacity,
			RefillTokensPerSecond: verificationRefill,
		},
	}, nil
}

func compileSourceIPPolicy(path string, policy *sourceIPPolicyConfig) (*bonvoyagev1.SourceIpPolicy, error) {
	if policy.AllowCIDRs != nil && len(policy.AllowCIDRs) == 0 {
		return nil, fmt.Errorf("%s.allow_cidrs: must not be empty when configured", path)
	}
	if policy.DenyCIDRs != nil && len(policy.DenyCIDRs) == 0 {
		return nil, fmt.Errorf("%s.deny_cidrs: must not be empty when configured", path)
	}
	total := len(policy.AllowCIDRs) + len(policy.DenyCIDRs)
	if total == 0 || total > maxSourceIPCIDRs {
		return nil, fmt.Errorf("%s: must contain between 1 and %d total CIDRs", path, maxSourceIPCIDRs)
	}

	compileList := func(field string, values []string) ([]string, map[string]struct{}, error) {
		compiled := make([]string, 0, len(values))
		seen := make(map[string]struct{}, len(values))
		for index, raw := range values {
			entryPath := fmt.Sprintf("%s.%s[%d]", path, field, index)
			value := strings.TrimSpace(raw)
			ip, network, err := net.ParseCIDR(value)
			if err != nil || !ip.Equal(network.IP) ||
				(ip.To4() != nil && strings.Contains(value, ":")) {
				return nil, nil, fmt.Errorf("%s: must be a canonical numeric IPv4 or IPv6 CIDR", entryPath)
			}
			canonical := network.String()
			if _, exists := seen[canonical]; exists {
				return nil, nil, fmt.Errorf("%s: duplicate source IP CIDR %q", entryPath, canonical)
			}
			seen[canonical] = struct{}{}
			compiled = append(compiled, canonical)
		}
		return compiled, seen, nil
	}

	allowCIDRs, allowSet, err := compileList("allow_cidrs", policy.AllowCIDRs)
	if err != nil {
		return nil, err
	}
	denyCIDRs, denySet, err := compileList("deny_cidrs", policy.DenyCIDRs)
	if err != nil {
		return nil, err
	}
	for cidr := range allowSet {
		if _, exists := denySet[cidr]; exists {
			return nil, fmt.Errorf("%s: CIDR %q cannot appear in both allow_cidrs and deny_cidrs", path, cidr)
		}
	}

	return &bonvoyagev1.SourceIpPolicy{
		AllowCidrs: allowCIDRs,
		DenyCidrs:  denyCIDRs,
	}, nil
}

func compileCORSPolicy(path string, policy *corsPolicyConfig, routeMatch *bonvoyagev1.RouteMatch) (*bonvoyagev1.CorsPolicy, error) {
	if policy.AllowAnyOrigin {
		if len(policy.AllowedOrigins) != 0 {
			return nil, fmt.Errorf("%s: allow_any_origin and allowed_origins cannot be configured together", path)
		}
		if policy.AllowCredentials {
			return nil, fmt.Errorf("%s: allow_credentials cannot be combined with allow_any_origin", path)
		}
	} else if len(policy.AllowedOrigins) == 0 {
		return nil, fmt.Errorf("%s.allowed_origins: at least one exact origin is required unless allow_any_origin is true", path)
	}
	if len(policy.AllowedOrigins) > maxCORSOrigins {
		return nil, fmt.Errorf("%s.allowed_origins: must not contain more than %d origins", path, maxCORSOrigins)
	}

	origins := make([]string, 0, len(policy.AllowedOrigins))
	seenOrigins := make(map[string]struct{}, len(policy.AllowedOrigins))
	for index, raw := range policy.AllowedOrigins {
		entryPath := fmt.Sprintf("%s.allowed_origins[%d]", path, index)
		origin, err := normalizeCORSOrigin(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entryPath, err)
		}
		if _, duplicate := seenOrigins[origin]; duplicate {
			return nil, fmt.Errorf("%s: duplicate normalized origin %q", entryPath, origin)
		}
		seenOrigins[origin] = struct{}{}
		origins = append(origins, origin)
	}
	sort.Strings(origins)

	if len(routeMatch.GetHeaders()) != 0 {
		return nil, fmt.Errorf("%s: routes with CORS cannot use ordinary header match predicates", path)
	}
	if len(policy.AllowedMethods) == 0 || len(policy.AllowedMethods) > maxRouteMethods {
		return nil, fmt.Errorf("%s.allowed_methods: must contain between 1 and %d methods", path, maxRouteMethods)
	}
	routeMethods := make(map[string]struct{}, len(routeMatch.GetMethods()))
	for _, method := range routeMatch.GetMethods() {
		routeMethods[method] = struct{}{}
	}
	methods := make([]string, 0, len(policy.AllowedMethods))
	seenMethods := make(map[string]struct{}, len(policy.AllowedMethods))
	for index, method := range policy.AllowedMethods {
		entryPath := fmt.Sprintf("%s.allowed_methods[%d]", path, index)
		if method == "*" || len(method) > maxRouteMethodBytes || !validHTTPToken(method) || method != strings.ToUpper(method) {
			return nil, fmt.Errorf("%s: must be an uppercase HTTP method token no longer than %d bytes", entryPath, maxRouteMethodBytes)
		}
		if _, duplicate := seenMethods[method]; duplicate {
			return nil, fmt.Errorf("%s: duplicate method %q", entryPath, method)
		}
		if len(routeMethods) != 0 {
			if _, routed := routeMethods[method]; !routed {
				return nil, fmt.Errorf("%s: method %q is not accepted by the route matcher", entryPath, method)
			}
		}
		seenMethods[method] = struct{}{}
		methods = append(methods, method)
	}
	sort.Strings(methods)

	compileHeaders := func(field string, values []string, exposed bool) ([]string, error) {
		if len(values) > maxCORSHeaders {
			return nil, fmt.Errorf("%s.%s: must not contain more than %d field names", path, field, maxCORSHeaders)
		}
		compiled := make([]string, 0, len(values))
		seen := make(map[string]struct{}, len(values))
		for index, raw := range values {
			entryPath := fmt.Sprintf("%s.%s[%d]", path, field, index)
			name := strings.ToLower(raw)
			if name == "*" || len(name) > maxHeaderNameBytes || !validHTTPToken(name) {
				return nil, fmt.Errorf("%s: must be an explicit HTTP field-name no longer than %d bytes", entryPath, maxHeaderNameBytes)
			}
			if strings.HasPrefix(name, "access-control-") {
				return nil, fmt.Errorf("%s: Access-Control-* fields are owned by the CORS policy", entryPath)
			}
			if exposed {
				if _, forbidden := forbiddenCORSExposedHeaders[name]; forbidden {
					return nil, fmt.Errorf("%s: %q cannot be exposed to browser code", entryPath, name)
				}
			} else if _, reserved := reservedCORSRequestHeaders[name]; reserved {
				return nil, fmt.Errorf("%s: %q is controlled by the HTTP or CORS protocol", entryPath, name)
			}
			if _, duplicate := seen[name]; duplicate {
				return nil, fmt.Errorf("%s: duplicate normalized field name %q", entryPath, name)
			}
			seen[name] = struct{}{}
			compiled = append(compiled, name)
		}
		sort.Strings(compiled)
		return compiled, nil
	}

	allowedHeaders, err := compileHeaders("allowed_headers", policy.AllowedHeaders, false)
	if err != nil {
		return nil, err
	}
	exposedHeaders, err := compileHeaders("exposed_headers", policy.ExposedHeaders, true)
	if err != nil {
		return nil, err
	}
	maxAge := defaultCORSMaxAgeSeconds
	if policy.MaxAgeSeconds != nil {
		maxAge = *policy.MaxAgeSeconds
	}
	if maxAge > maxCORSMaxAgeSeconds {
		return nil, fmt.Errorf("%s.max_age_seconds: must not exceed %d", path, maxCORSMaxAgeSeconds)
	}

	return &bonvoyagev1.CorsPolicy{
		AllowAnyOrigin:   policy.AllowAnyOrigin,
		AllowedOrigins:   origins,
		AllowedMethods:   methods,
		AllowedHeaders:   allowedHeaders,
		ExposedHeaders:   exposedHeaders,
		AllowCredentials: policy.AllowCredentials,
		MaxAgeSeconds:    maxAge,
	}, nil
}

func normalizeCORSOrigin(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) < len("http://a") || len(value) > maxCORSOriginBytes {
		return "", fmt.Errorf("must contain between 8 and %d bytes", maxCORSOriginBytes)
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" {
		return "", errors.New("must be an absolute HTTP or HTTPS origin")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("must use the http or https scheme")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("must not contain a path, query, or fragment")
	}
	if strings.HasSuffix(parsed.Host, ":") || strings.Contains(parsed.Host, "%") {
		return "", errors.New("contains an invalid host or port")
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", errors.New("must contain a host")
	}
	if ip := net.ParseIP(hostname); ip != nil {
		hostname = strings.ToLower(ip.String())
	} else if !validHost(hostname) {
		return "", errors.New("contains an invalid DNS host")
	}

	portText := parsed.Port()
	if portText != "" {
		port, parseErr := strconv.ParseUint(portText, 10, 16)
		if parseErr != nil || port == 0 {
			return "", errors.New("contains an invalid TCP port")
		}
		if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
			portText = ""
		} else {
			portText = strconv.FormatUint(port, 10)
		}
	}
	authority := hostname
	if strings.Contains(hostname, ":") {
		authority = "[" + hostname + "]"
	}
	if portText != "" {
		authority += ":" + portText
	}
	return scheme + "://" + authority, nil
}

func compileRequestContentPolicy(path string, policy *requestContentConfig, globalMaxBodyBytes uint64) (*bonvoyagev1.RequestContentPolicy, error) {
	if policy.MaxBodyBytes == nil && len(policy.AllowedContentTypes) == 0 {
		return nil, fmt.Errorf("%s: at least one of max_body_bytes or allowed_content_types is required", path)
	}
	var maximum uint64
	if policy.MaxBodyBytes != nil {
		maximum = *policy.MaxBodyBytes
		if maximum == 0 || maximum > globalMaxBodyBytes {
			return nil, fmt.Errorf("%s.max_body_bytes: must be between 1 and runtime_limits.max_request_body_bytes (%d)", path, globalMaxBodyBytes)
		}
	}
	if len(policy.AllowedContentTypes) > maxRequestContentTypes {
		return nil, fmt.Errorf("%s.allowed_content_types: must not contain more than %d media types", path, maxRequestContentTypes)
	}
	contentTypes := make([]string, 0, len(policy.AllowedContentTypes))
	seen := make(map[string]struct{}, len(policy.AllowedContentTypes))
	for index, raw := range policy.AllowedContentTypes {
		entryPath := fmt.Sprintf("%s.allowed_content_types[%d]", path, index)
		if raw != strings.ToLower(raw) || strings.TrimSpace(raw) != raw || len(raw) > maxRequestContentTypeBytes {
			return nil, fmt.Errorf("%s: must be a canonical lowercase media type no longer than %d bytes", entryPath, maxRequestContentTypeBytes)
		}
		mediaType, parameters, err := mime.ParseMediaType(raw)
		if err != nil || mediaType != raw || len(parameters) != 0 || strings.Contains(raw, "*") {
			return nil, fmt.Errorf("%s: must be an exact base media type without wildcards or parameters", entryPath)
		}
		if _, duplicate := seen[mediaType]; duplicate {
			return nil, fmt.Errorf("%s: duplicate media type %q", entryPath, mediaType)
		}
		seen[mediaType] = struct{}{}
		contentTypes = append(contentTypes, mediaType)
	}
	sort.Strings(contentTypes)
	return &bonvoyagev1.RequestContentPolicy{
		MaxBodyBytes:        maximum,
		AllowedContentTypes: contentTypes,
	}, nil
}

func routePathBinding(match *bonvoyagev1.RouteMatch) string {
	switch pathMatch := match.GetPathMatch().(type) {
	case *bonvoyagev1.RouteMatch_PathExact:
		return "exact:" + pathMatch.PathExact
	case *bonvoyagev1.RouteMatch_PathPrefix:
		return "prefix:" + pathMatch.PathPrefix
	case *bonvoyagev1.RouteMatch_SafeRegex:
		return "regex:" + pathMatch.SafeRegex
	default:
		return ""
	}
}

func routeMatchIsUnconditional(match *bonvoyagev1.RouteMatch) bool {
	return len(match.GetMethods()) == 0 && len(match.GetHeaders()) == 0 && len(match.GetQueryParameters()) == 0
}

func compileFixedResponse(path string, response *fixedResponseConfig) (*bonvoyagev1.FixedResponse, error) {
	if response.StatusCode < 200 || response.StatusCode > 599 {
		return nil, fmt.Errorf("%s.status_code: must be between 200 and 599", path)
	}
	if len(response.Body) > maxFixedResponseBytes {
		return nil, fmt.Errorf("%s.body: must not exceed %d bytes", path, maxFixedResponseBytes)
	}
	contentType := strings.TrimSpace(response.ContentType)
	if contentType == "" && response.Body != "" {
		contentType = "text/plain"
	}
	if strings.IndexFunc(contentType, func(char rune) bool { return char < 0x20 || char == 0x7f }) >= 0 {
		return nil, fmt.Errorf("%s.content_type: must not contain control characters", path)
	}
	return &bonvoyagev1.FixedResponse{
		StatusCode:  response.StatusCode,
		Body:        response.Body,
		ContentType: contentType,
	}, nil
}

func compileHeaderTransformations(path string, policy *headerTransformationsConfig, apiKeyHeader string) (*bonvoyagev1.HeaderTransformations, error) {
	if len(policy.Request) == 0 && len(policy.Response) == 0 {
		return nil, fmt.Errorf("%s: must contain at least one request or response mutation", path)
	}
	request, err := compileHeaderMutations(path+".request", policy.Request, apiKeyHeader)
	if err != nil {
		return nil, err
	}
	response, err := compileHeaderMutations(path+".response", policy.Response, "")
	if err != nil {
		return nil, err
	}
	return &bonvoyagev1.HeaderTransformations{Request: request, Response: response}, nil
}

func compileHeaderMutations(path string, configured []headerMutationConfig, apiKeyHeader string) ([]*bonvoyagev1.HeaderMutation, error) {
	if len(configured) > maxHeaderMutationsPerDirection {
		return nil, fmt.Errorf("%s: must not contain more than %d mutations", path, maxHeaderMutationsPerDirection)
	}
	result := make([]*bonvoyagev1.HeaderMutation, 0, len(configured))
	names := make(map[string]struct{}, len(configured))
	configuredBytes := 0
	for index, item := range configured {
		itemPath := fmt.Sprintf("%s[%d]", path, index)
		name := item.Name
		if name != strings.ToLower(name) || len(name) == 0 || len(name) > maxHeaderNameBytes || !validHTTPToken(name) {
			return nil, fmt.Errorf("%s.name: must be a canonical lowercase HTTP field-name no longer than %d bytes", itemPath, maxHeaderNameBytes)
		}
		if _, duplicate := names[name]; duplicate {
			return nil, fmt.Errorf("%s.name: duplicate field name %q", itemPath, name)
		}
		names[name] = struct{}{}
		_, protocolOwned := protocolOwnedMutationHeaders[name]
		_, forwardingOwned := forwardingIdentityHeaders[name]
		if protocolOwned || forwardingOwned || strings.HasPrefix(name, "x-forwarded-") || name == "origin" || strings.HasPrefix(name, "access-control-") {
			return nil, fmt.Errorf("%s.name: %q is owned by HTTP framing, tracing, forwarding identity, or CORS policy", itemPath, name)
		}

		var operation bonvoyagev1.HeaderMutationOperation
		switch item.Operation {
		case "set":
			operation = bonvoyagev1.HeaderMutationOperation_HEADER_MUTATION_OPERATION_SET
		case "append":
			operation = bonvoyagev1.HeaderMutationOperation_HEADER_MUTATION_OPERATION_APPEND
		case "remove":
			operation = bonvoyagev1.HeaderMutationOperation_HEADER_MUTATION_OPERATION_REMOVE
		default:
			return nil, fmt.Errorf("%s.operation: must be set, append, or remove", itemPath)
		}

		if operation == bonvoyagev1.HeaderMutationOperation_HEADER_MUTATION_OPERATION_REMOVE {
			if item.Value != "" {
				return nil, fmt.Errorf("%s.value: must be empty for remove", itemPath)
			}
		} else {
			if len(item.Value) == 0 || len(item.Value) > maxHeaderMutationValueBytes || !validTrimmedVisibleASCII(item.Value) {
				return nil, fmt.Errorf("%s.value: must contain 1 to %d trimmed visible ASCII bytes", itemPath, maxHeaderMutationValueBytes)
			}
			_, credentialBearing := credentialBearingHeaders[name]
			if credentialBearing || apiKeyHeader != "" && name == apiKeyHeader {
				return nil, fmt.Errorf("%s.name: credential-bearing fields may only be removed", itemPath)
			}
		}
		if configuredBytes+len(name)+len(item.Value) > maxHeaderMutationBytesPerDirection {
			return nil, fmt.Errorf("%s: configured names and values must not exceed %d bytes", path, maxHeaderMutationBytesPerDirection)
		}
		configuredBytes += len(name) + len(item.Value)
		result = append(result, &bonvoyagev1.HeaderMutation{
			Operation: operation,
			Name:      name,
			Value:     item.Value,
		})
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].GetName() < result[right].GetName()
	})
	return result, nil
}

func validTrimmedVisibleASCII(value string) bool {
	if len(value) == 0 || value[0] <= 0x20 || value[len(value)-1] <= 0x20 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func compileRedirect(path string, redirect *redirectConfig) (*bonvoyagev1.RedirectResponse, error) {
	switch redirect.StatusCode {
	case 301, 302, 303, 307, 308:
	default:
		return nil, fmt.Errorf("%s.status_code: must be one of 301, 302, 303, 307, or 308", path)
	}

	if err := validateRedirectComponent(path+".path", redirect.Path, true); err != nil {
		return nil, err
	}
	if len(redirect.Query) > maxRoutePathBytes {
		return nil, fmt.Errorf("%s.query: must not exceed %d bytes", path, maxRoutePathBytes)
	}
	if redirect.Query != "" {
		if redirect.Query[0] == '?' {
			return nil, fmt.Errorf("%s.query: must not start with ?", path)
		}
		if err := validateRedirectComponent(path+".query", redirect.Query, false); err != nil {
			return nil, err
		}
	}

	hasScheme := redirect.Scheme != ""
	hasHost := redirect.Host != ""
	if hasScheme != hasHost {
		return nil, fmt.Errorf("%s: scheme and host must be configured together", path)
	}
	if !hasScheme && redirect.Port != nil {
		return nil, fmt.Errorf("%s.port: requires scheme and host", path)
	}
	var port uint32
	if redirect.Port != nil {
		port = *redirect.Port
		if port == 0 || port > 65535 {
			return nil, fmt.Errorf("%s.port: must be between 1 and 65535", path)
		}
	}

	scheme := redirect.Scheme
	host := redirect.Host
	if hasScheme {
		if scheme != "http" && scheme != "https" {
			return nil, fmt.Errorf("%s.scheme: must be exactly http or https", path)
		}
		if strings.ToLower(host) != host || strings.TrimSpace(host) != host {
			return nil, fmt.Errorf("%s.host: must be canonical lowercase without whitespace", path)
		}
		unbracketed := host
		if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
			if !strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]") {
				return nil, fmt.Errorf("%s.host: contains mismatched IPv6 brackets", path)
			}
			unbracketed = host[1 : len(host)-1]
		}
		if ip := net.ParseIP(unbracketed); ip != nil {
			canonical := strings.ToLower(ip.String())
			if canonical != unbracketed {
				return nil, fmt.Errorf("%s.host: IP literal must be canonical", path)
			}
			if strings.Contains(canonical, ":") {
				host = "[" + canonical + "]"
			} else if host != canonical {
				return nil, fmt.Errorf("%s.host: IPv4 literal must not be bracketed", path)
			}
		} else if strings.ContainsAny(host, "[]:") || !validHost(host) {
			return nil, fmt.Errorf("%s.host: must be a canonical DNS name or numeric IP literal", path)
		}
	}

	locationLength := len(redirect.Path)
	if redirect.Query != "" {
		locationLength += 1 + len(redirect.Query)
	}
	if hasScheme {
		locationLength += len(scheme) + 3 + len(host)
		if port != 0 {
			locationLength += 1 + len(strconv.FormatUint(uint64(port), 10))
		}
	}
	if locationLength > 8192 {
		return nil, fmt.Errorf("%s: prepared Location must not exceed 8192 bytes", path)
	}

	return &bonvoyagev1.RedirectResponse{
		StatusCode: redirect.StatusCode,
		Scheme:     scheme,
		Host:       host,
		Port:       port,
		Path:       redirect.Path,
		Query:      redirect.Query,
	}, nil
}

func compileRouteRewrite(path string, rewrite *routeRewriteConfig, match *bonvoyagev1.RouteMatch, globalMaxRequestHeaderBytes uint32) (*bonvoyagev1.RouteRewrite, error) {
	hasHost := rewrite.Host != ""
	hasPath := rewrite.Path != nil
	hasPathPrefix := rewrite.PathPrefix != nil
	if !hasHost && !hasPath && !hasPathPrefix {
		return nil, fmt.Errorf("%s: must contain a host or path rewrite", path)
	}
	if hasPath && hasPathPrefix {
		return nil, fmt.Errorf("%s: path and path_prefix cannot be configured together", path)
	}
	if !hasHost && rewrite.Port != nil {
		return nil, fmt.Errorf("%s.port: requires host", path)
	}

	var port uint32
	if rewrite.Port != nil {
		port = *rewrite.Port
		if port == 0 || port > 65_535 {
			return nil, fmt.Errorf("%s.port: must be between 1 and 65535", path)
		}
	}

	host := rewrite.Host
	if hasHost {
		if strings.ToLower(host) != host || strings.TrimSpace(host) != host {
			return nil, fmt.Errorf("%s.host: must be canonical lowercase without whitespace", path)
		}
		unbracketed := host
		if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
			if !strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]") {
				return nil, fmt.Errorf("%s.host: contains mismatched IPv6 brackets", path)
			}
			unbracketed = host[1 : len(host)-1]
		}
		if ip := net.ParseIP(unbracketed); ip != nil {
			canonical := strings.ToLower(ip.String())
			if canonical != unbracketed {
				return nil, fmt.Errorf("%s.host: IP literal must be canonical", path)
			}
			if strings.Contains(canonical, ":") {
				if host != "["+canonical+"]" {
					return nil, fmt.Errorf("%s.host: IPv6 literal must be bracketed", path)
				}
			} else if host != canonical {
				return nil, fmt.Errorf("%s.host: IPv4 literal must not be bracketed", path)
			}
		} else if strings.ContainsAny(host, "[]:") || !validHost(host) {
			return nil, fmt.Errorf("%s.host: must be a canonical DNS name or numeric IP literal", path)
		}
	}

	compiled := &bonvoyagev1.RouteRewrite{Host: host, Port: port}
	if hasPath || hasPathPrefix {
		replacement := rewrite.Path
		field := ".path"
		if hasPathPrefix {
			replacement = rewrite.PathPrefix
			field = ".path_prefix"
		}
		if err := validateRedirectComponent(path+field, *replacement, true); err != nil {
			return nil, err
		}
		if uint64(len(*replacement)) > uint64(globalMaxRequestHeaderBytes) {
			return nil, fmt.Errorf("%s%s: must not exceed runtime_limits.max_request_header_bytes", path, field)
		}
		if hasPathPrefix {
			matchedPrefix, ok := match.GetPathMatch().(*bonvoyagev1.RouteMatch_PathPrefix)
			if !ok {
				return nil, fmt.Errorf("%s.path_prefix: requires a path_prefix route match", path)
			}
			if strings.HasSuffix(matchedPrefix.PathPrefix, "/") != strings.HasSuffix(*replacement, "/") {
				return nil, fmt.Errorf("%s.path_prefix: must preserve the matched prefix trailing-slash form", path)
			}
			compiled.PathRewrite = &bonvoyagev1.RouteRewrite_PathPrefix{PathPrefix: *replacement}
		} else {
			compiled.PathRewrite = &bonvoyagev1.RouteRewrite_Path{Path: *replacement}
		}
	}
	return compiled, nil
}

func validateRedirectComponent(path, value string, isPath bool) error {
	if isPath {
		if value == "" || value[0] != '/' || strings.HasPrefix(value, "//") {
			return fmt.Errorf("%s: must start with one /", path)
		}
		if len(value) > maxRoutePathBytes {
			return fmt.Errorf("%s: must not exceed %d bytes", path, maxRoutePathBytes)
		}
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char == '%' {
			if index+2 >= len(value) || !isHex(value[index+1]) || !isHex(value[index+2]) {
				return fmt.Errorf("%s: contains an invalid percent triplet", path)
			}
			index += 2
			continue
		}
		if isRFC3986Unreserved(char) || strings.ContainsRune("!$&'()*+,;=:@/", rune(char)) || (!isPath && char == '?') {
			continue
		}
		return fmt.Errorf("%s: contains a character outside the bounded RFC 3986 set", path)
	}
	return nil
}

func isHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func isRFC3986Unreserved(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || strings.ContainsRune("-._~", rune(value))
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func compileRouteMatch(path string, match routeMatchConfig) (*bonvoyagev1.RouteMatch, error) {
	count := 0
	if match.PathExact != nil {
		count++
	}
	if match.PathPrefix != nil {
		count++
	}
	if match.SafeRegex != nil {
		count++
	}
	if count != 1 {
		return nil, fmt.Errorf("%s: exactly one of path_exact, path_prefix, or safe_regex is required", path)
	}

	compiled := &bonvoyagev1.RouteMatch{}
	if match.PathExact != nil {
		if err := validatePath(path+".path_exact", *match.PathExact); err != nil {
			return nil, err
		}
		compiled.PathMatch = &bonvoyagev1.RouteMatch_PathExact{PathExact: *match.PathExact}
	} else if match.PathPrefix != nil {
		if err := validatePath(path+".path_prefix", *match.PathPrefix); err != nil {
			return nil, err
		}
		compiled.PathMatch = &bonvoyagev1.RouteMatch_PathPrefix{PathPrefix: *match.PathPrefix}
	} else {
		if len(*match.SafeRegex) == 0 || len(*match.SafeRegex) > maxSafeRegexBytes {
			return nil, fmt.Errorf("%s.safe_regex: must contain between 1 and %d bytes", path, maxSafeRegexBytes)
		}
		if strings.ContainsAny(*match.SafeRegex, "\r\n") {
			return nil, fmt.Errorf("%s.safe_regex: must not contain CR or LF", path)
		}
		if _, err := regexp.Compile(*match.SafeRegex); err != nil {
			return nil, fmt.Errorf("%s.safe_regex: invalid RE2 expression: %w", path, err)
		}
		compiled.PathMatch = &bonvoyagev1.RouteMatch_SafeRegex{SafeRegex: *match.SafeRegex}
	}

	methods, err := compileMethods(path+".methods", match.Methods)
	if err != nil {
		return nil, err
	}
	headers, err := compileHeaderMatches(path+".headers", match.Headers)
	if err != nil {
		return nil, err
	}
	queryParameters, err := compileQueryMatches(path+".query_parameters", match.QueryParameters)
	if err != nil {
		return nil, err
	}
	compiled.Methods = methods
	compiled.Headers = headers
	compiled.QueryParameters = queryParameters
	return compiled, nil
}

func compileMethods(path string, methods []string) ([]string, error) {
	if len(methods) > maxRouteMethods {
		return nil, fmt.Errorf("%s: must not contain more than %d methods", path, maxRouteMethods)
	}
	seen := make(map[string]struct{}, len(methods))
	compiled := make([]string, 0, len(methods))
	for i, method := range methods {
		itemPath := fmt.Sprintf("%s[%d]", path, i)
		if len(method) == 0 || len(method) > maxRouteMethodBytes || !validHTTPToken(method) {
			return nil, fmt.Errorf("%s: must be an HTTP token no longer than %d bytes", itemPath, maxRouteMethodBytes)
		}
		if method != strings.ToUpper(method) {
			return nil, fmt.Errorf("%s: must use uppercase canonical form", itemPath)
		}
		if _, exists := seen[method]; exists {
			return nil, fmt.Errorf("%s: duplicate method %q", itemPath, method)
		}
		seen[method] = struct{}{}
		compiled = append(compiled, method)
	}
	sort.Strings(compiled)
	return compiled, nil
}

func compileRetryableMethods(path string, methods []string) ([]string, error) {
	if len(methods) == 0 {
		methods = []string{"GET", "HEAD", "OPTIONS"}
	}
	compiled, err := compileMethods(path, methods)
	if err != nil {
		return nil, err
	}
	for i, method := range compiled {
		if _, allowed := idempotentRetryMethods[method]; !allowed {
			return nil, fmt.Errorf("%s[%d]: %q is not an enabled idempotent retry method", path, i, method)
		}
	}
	return compiled, nil
}

func compileHeaderMatches(path string, matches []headerMatchConfig) ([]*bonvoyagev1.HeaderMatch, error) {
	if len(matches) > maxRoutePredicates {
		return nil, fmt.Errorf("%s: must not contain more than %d predicates", path, maxRoutePredicates)
	}
	seen := make(map[string]struct{}, len(matches))
	compiled := make([]*bonvoyagev1.HeaderMatch, 0, len(matches))
	for i, match := range matches {
		itemPath := fmt.Sprintf("%s[%d]", path, i)
		name := strings.ToLower(match.Name)
		if len(name) == 0 || len(name) > maxHeaderNameBytes || !validHTTPToken(name) {
			return nil, fmt.Errorf("%s.name: must be an HTTP field-name no longer than %d bytes", itemPath, maxHeaderNameBytes)
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("%s.name: duplicate normalized header name %q", itemPath, name)
		}
		seen[name] = struct{}{}
		valueMatch, err := compileValueMatch(itemPath, match.Exact, match.Present)
		if err != nil {
			return nil, err
		}
		compiledMatch := &bonvoyagev1.HeaderMatch{Name: name}
		if valueMatch.exact != nil {
			compiledMatch.ValueMatch = &bonvoyagev1.HeaderMatch_Exact{Exact: *valueMatch.exact}
		} else {
			compiledMatch.ValueMatch = &bonvoyagev1.HeaderMatch_Present{Present: valueMatch.present}
		}
		compiled = append(compiled, compiledMatch)
	}
	sort.Slice(compiled, func(i, j int) bool { return compiled[i].GetName() < compiled[j].GetName() })
	return compiled, nil
}

func compileQueryMatches(path string, matches []queryMatchConfig) ([]*bonvoyagev1.QueryParameterMatch, error) {
	if len(matches) > maxRoutePredicates {
		return nil, fmt.Errorf("%s: must not contain more than %d predicates", path, maxRoutePredicates)
	}
	seen := make(map[string]struct{}, len(matches))
	compiled := make([]*bonvoyagev1.QueryParameterMatch, 0, len(matches))
	for i, match := range matches {
		itemPath := fmt.Sprintf("%s[%d]", path, i)
		if len(match.Name) == 0 || len(match.Name) > maxQueryNameBytes || containsControl(match.Name) {
			return nil, fmt.Errorf("%s.name: must contain between 1 and %d bytes without controls", itemPath, maxQueryNameBytes)
		}
		if _, exists := seen[match.Name]; exists {
			return nil, fmt.Errorf("%s.name: duplicate query parameter name %q", itemPath, match.Name)
		}
		seen[match.Name] = struct{}{}
		valueMatch, err := compileValueMatch(itemPath, match.Exact, match.Present)
		if err != nil {
			return nil, err
		}
		compiledMatch := &bonvoyagev1.QueryParameterMatch{Name: match.Name}
		if valueMatch.exact != nil {
			compiledMatch.ValueMatch = &bonvoyagev1.QueryParameterMatch_Exact{Exact: *valueMatch.exact}
		} else {
			compiledMatch.ValueMatch = &bonvoyagev1.QueryParameterMatch_Present{Present: valueMatch.present}
		}
		compiled = append(compiled, compiledMatch)
	}
	sort.Slice(compiled, func(i, j int) bool { return compiled[i].GetName() < compiled[j].GetName() })
	return compiled, nil
}

type compiledValueMatch struct {
	exact   *string
	present bool
}

func compileValueMatch(path string, exact *string, present *bool) (compiledValueMatch, error) {
	if (exact == nil) == (present == nil) {
		return compiledValueMatch{}, fmt.Errorf("%s: exactly one of exact or present is required", path)
	}
	if exact != nil {
		if len(*exact) > maxPredicateValueBytes || containsControl(*exact) {
			return compiledValueMatch{}, fmt.Errorf("%s.exact: must not exceed %d bytes or contain controls", path, maxPredicateValueBytes)
		}
		return compiledValueMatch{exact: exact}, nil
	}
	return compiledValueMatch{present: *present}, nil
}

func compileClusters(items []clusterConfig, requestTimeoutMS uint32) ([]*bonvoyagev1.Cluster, error) {
	result := make([]*bonvoyagev1.Cluster, 0, len(items))
	for i, item := range items {
		base := fmt.Sprintf("clusters[%d]", i)
		var protocol bonvoyagev1.Protocol
		switch item.Protocol {
		case "", "http1":
			protocol = bonvoyagev1.Protocol_PROTOCOL_HTTP1
		case "http2":
			protocol = bonvoyagev1.Protocol_PROTOCOL_HTTP2
		default:
			return nil, fmt.Errorf("%s.protocol: %q is unsupported; use http1 or TLS http2", base, item.Protocol)
		}
		var loadBalancingPolicy bonvoyagev1.LoadBalancingPolicy
		switch item.LoadBalancingPolicy {
		case "round_robin":
			loadBalancingPolicy = bonvoyagev1.LoadBalancingPolicy_LOAD_BALANCING_POLICY_ROUND_ROBIN
		case "least_request":
			loadBalancingPolicy = bonvoyagev1.LoadBalancingPolicy_LOAD_BALANCING_POLICY_LEAST_REQUEST
		case "random":
			loadBalancingPolicy = bonvoyagev1.LoadBalancingPolicy_LOAD_BALANCING_POLICY_RANDOM
		default:
			return nil, fmt.Errorf("%s.load_balancing_policy: %q is unsupported; use round_robin, least_request, or random", base, item.LoadBalancingPolicy)
		}
		if len(item.Endpoints) == 0 {
			return nil, fmt.Errorf("%s.endpoints: at least one endpoint is required", base)
		}
		if len(item.Endpoints) > maxEndpointCount {
			return nil, fmt.Errorf("%s.endpoints: must not contain more than %d endpoints", base, maxEndpointCount)
		}
		connectTimeout := valueOrDefault(item.ConnectTimeoutMS, defaultConnectTimeoutMS)
		connections := valueOrDefault(item.MaxConnectionsPerShard, defaultMaxConnectionsPerShard)
		pending := valueOrDefault(item.MaxPendingRequestsPerShard, defaultMaxPendingPerShard)
		var maxHTTP2Streams uint32
		if protocol == bonvoyagev1.Protocol_PROTOCOL_HTTP2 {
			maxHTTP2Streams = valueOrDefault(item.MaxHTTP2Streams, defaultMaxHTTP2Streams)
		} else if item.MaxHTTP2Streams != nil {
			return nil, fmt.Errorf("%s.max_http2_streams_per_connection: is only valid when protocol is http2", base)
		}
		admissionLimit := uint64(connections) + uint64(pending)
		endpointConcurrency := uint32(admissionLimit)
		if item.MaxConcurrentPerEndpoint != nil {
			endpointConcurrency = *item.MaxConcurrentPerEndpoint
		}
		if err := validateUint32Range(base+".connect_timeout_ms", connectTimeout, 1, maxConnectTimeoutMS); err != nil {
			return nil, err
		}
		if err := validateUint32Range(base+".max_connections_per_shard", connections, 1, maxConnectionsPerShard); err != nil {
			return nil, err
		}
		if uint64(connections) < uint64(len(item.Endpoints)) {
			return nil, fmt.Errorf("%s.max_connections_per_shard: must be at least the endpoint count", base)
		}
		if err := validateUint32Range(base+".max_pending_requests_per_shard", pending, 1, maxPendingPerShard); err != nil {
			return nil, err
		}
		if protocol == bonvoyagev1.Protocol_PROTOCOL_HTTP2 {
			if err := validateUint32Range(base+".max_http2_streams_per_connection", maxHTTP2Streams, 1, maxHTTP2StreamsPerConnection); err != nil {
				return nil, err
			}
		}
		if err := validateUint32Range(base+".max_concurrent_requests_per_endpoint", endpointConcurrency, 1, maxConcurrentPerEndpoint); err != nil {
			return nil, err
		}
		if uint64(endpointConcurrency) > admissionLimit {
			return nil, fmt.Errorf("%s.max_concurrent_requests_per_endpoint: must not exceed the cluster connection-plus-pending admission limit", base)
		}

		var upstreamTLS *bonvoyagev1.UpstreamTls
		if item.UpstreamTLS != nil {
			serverName, err := normalizeTLSServerName(item.UpstreamTLS.ServerName)
			if err != nil {
				return nil, fmt.Errorf("%s.upstream_tls.server_name: %w", base, err)
			}
			trustBundle := strings.TrimSpace(item.UpstreamTLS.TrustBundleSecret)
			if !namePattern.MatchString(trustBundle) {
				return nil, fmt.Errorf("%s.upstream_tls.trust_bundle_secret: must be a safe secret filename", base)
			}
			certificateChain := strings.TrimSpace(item.UpstreamTLS.CertificateChainSecret)
			privateKey := strings.TrimSpace(item.UpstreamTLS.PrivateKeySecret)
			if (certificateChain == "") != (privateKey == "") {
				return nil, fmt.Errorf("%s.upstream_tls: certificate_chain_secret and private_key_secret must be configured together", base)
			}
			if certificateChain != "" && !namePattern.MatchString(certificateChain) {
				return nil, fmt.Errorf("%s.upstream_tls.certificate_chain_secret: must be a safe secret filename", base)
			}
			if privateKey != "" && !namePattern.MatchString(privateKey) {
				return nil, fmt.Errorf("%s.upstream_tls.private_key_secret: must be a safe secret filename", base)
			}
			upstreamTLS = &bonvoyagev1.UpstreamTls{
				ServerName:             serverName,
				TrustBundleSecret:      trustBundle,
				CertificateChainSecret: certificateChain,
				PrivateKeySecret:       privateKey,
			}
		}
		if protocol == bonvoyagev1.Protocol_PROTOCOL_HTTP2 && upstreamTLS == nil {
			return nil, fmt.Errorf("%s.protocol: HTTP/2 requires upstream_tls for explicit h2 ALPN", base)
		}

		var passiveHealth *bonvoyagev1.PassiveHealthPolicy
		if item.PassiveHealth != nil {
			failures := valueOrDefault(item.PassiveHealth.ConsecutiveFailures, defaultPassiveFailureCount)
			ejectionTime := valueOrDefault(item.PassiveHealth.EjectionTimeMS, defaultPassiveEjectionTimeMS)
			maxEjection := valueOrDefault(item.PassiveHealth.MaxEjectionPercent, defaultMaxEjectionPercent)
			successes := valueOrDefault(item.PassiveHealth.ConsecutiveSuccesses, defaultPassiveSuccessCount)
			if err := validateUint32Range(base+".passive_health.consecutive_failures", failures, 1, maxPassiveFailureCount); err != nil {
				return nil, err
			}
			if err := validateUint32Range(base+".passive_health.ejection_time_ms", ejectionTime, 100, maxPassiveEjectionMS); err != nil {
				return nil, err
			}
			if err := validateUint32Range(base+".passive_health.max_ejection_percent", maxEjection, 1, 100); err != nil {
				return nil, err
			}
			if err := validateUint32Range(base+".passive_health.consecutive_successes", successes, 1, maxPassiveSuccessCount); err != nil {
				return nil, err
			}
			passiveHealth = &bonvoyagev1.PassiveHealthPolicy{
				ConsecutiveFailures:  failures,
				EjectionTimeMs:       ejectionTime,
				MaxEjectionPercent:   maxEjection,
				ConsecutiveSuccesses: successes,
			}
		}

		var activeHealth *bonvoyagev1.ActiveHealthPolicy
		if item.ActiveHealth != nil {
			path := defaultActiveHealthPath
			if item.ActiveHealth.Path != nil {
				path = *item.ActiveHealth.Path
			}
			if err := validateHealthCheckPath(base+".active_health.path", path); err != nil {
				return nil, err
			}
			interval := valueOrDefault(item.ActiveHealth.IntervalMS, defaultActiveHealthIntervalMS)
			timeout := valueOrDefault(item.ActiveHealth.TimeoutMS, defaultActiveHealthTimeoutMS)
			healthyThreshold := valueOrDefault(item.ActiveHealth.HealthyThreshold, defaultActiveHealthyThreshold)
			unhealthyThreshold := valueOrDefault(item.ActiveHealth.UnhealthyThreshold, defaultActiveFailureThreshold)
			statusMinimum := valueOrDefault(item.ActiveHealth.ExpectedStatusMin, defaultActiveStatusMinimum)
			statusMaximum := valueOrDefault(item.ActiveHealth.ExpectedStatusMax, defaultActiveStatusMaximum)
			if err := validateUint32Range(base+".active_health.interval_ms", interval, 1_000, maxActiveHealthIntervalMS); err != nil {
				return nil, err
			}
			if err := validateUint32Range(base+".active_health.timeout_ms", timeout, 100, maxActiveHealthTimeoutMS); err != nil {
				return nil, err
			}
			if timeout > interval {
				return nil, fmt.Errorf("%s.active_health.timeout_ms: must not exceed interval_ms", base)
			}
			if err := validateUint32Range(base+".active_health.healthy_threshold", healthyThreshold, 1, maxActiveHealthThreshold); err != nil {
				return nil, err
			}
			if err := validateUint32Range(base+".active_health.unhealthy_threshold", unhealthyThreshold, 1, maxActiveHealthThreshold); err != nil {
				return nil, err
			}
			if statusMinimum < 200 || statusMaximum > 599 || statusMinimum > statusMaximum {
				return nil, fmt.Errorf("%s.active_health.expected_status_min: status range must be ordered between 200 and 599", base)
			}
			host := strings.ToLower(strings.TrimSpace(item.ActiveHealth.Host))
			if host != "" {
				if err := validateEndpointAddress(base+".active_health.host", host); err != nil {
					return nil, err
				}
			}
			activeHealth = &bonvoyagev1.ActiveHealthPolicy{
				Path: path, IntervalMs: interval, TimeoutMs: timeout,
				HealthyThreshold: healthyThreshold, UnhealthyThreshold: unhealthyThreshold,
				ExpectedStatusMin: statusMinimum, ExpectedStatusMax: statusMaximum,
				Host: host,
			}
		}

		var dnsRefresh *bonvoyagev1.DnsRefreshPolicy
		if item.DNSRefresh != nil {
			interval := valueOrDefault(item.DNSRefresh.RefreshIntervalMS, defaultDNSRefreshIntervalMS)
			timeout := valueOrDefault(item.DNSRefresh.ResolveTimeoutMS, defaultDNSResolveTimeoutMS)
			if err := validateUint32Range(base+".dns_refresh.refresh_interval_ms", interval, 1_000, maxDNSRefreshIntervalMS); err != nil {
				return nil, err
			}
			if err := validateUint32Range(base+".dns_refresh.resolve_timeout_ms", timeout, 100, maxDNSResolveTimeoutMS); err != nil {
				return nil, err
			}
			if timeout > interval {
				return nil, fmt.Errorf("%s.dns_refresh.resolve_timeout_ms: must not exceed refresh_interval_ms", base)
			}
			dnsRefresh = &bonvoyagev1.DnsRefreshPolicy{
				RefreshIntervalMs: interval,
				ResolveTimeoutMs:  timeout,
			}
		}

		var retry *bonvoyagev1.RetryPolicy
		if item.Retry != nil {
			maxAttempts := valueOrDefault(item.Retry.MaxAttempts, defaultRetryMaxAttempts)
			perTryTimeout := valueOrDefault(item.Retry.PerTryTimeoutMS, defaultRetryPerTryTimeoutMS)
			if err := validateUint32Range(base+".retry.max_attempts", maxAttempts, 2, maxRetryAttempts); err != nil {
				return nil, err
			}
			if err := validateUint32Range(base+".retry.per_try_timeout_ms", perTryTimeout, 10, maxConnectTimeoutMS); err != nil {
				return nil, err
			}
			if perTryTimeout > requestTimeoutMS {
				return nil, fmt.Errorf("%s.retry.per_try_timeout_ms: must not exceed runtime_limits.request_timeout_ms", base)
			}
			methods, err := compileRetryableMethods(base+".retry.retryable_methods", item.Retry.RetryableMethods)
			if err != nil {
				return nil, err
			}

			budgetConfig := item.Retry.Budget
			if budgetConfig == nil {
				budgetConfig = &retryBudgetConfig{}
			}
			capacity := valueOrDefault(budgetConfig.Capacity, defaultRetryBudgetCapacity)
			refill := valueOrDefault(budgetConfig.RefillTokensPerSecond, defaultRetryRefillPerSecond)
			concurrent := valueOrDefault(budgetConfig.MaxConcurrentRetriesPerShard, defaultMaxConcurrentRetries)
			if err := validateUint32Range(base+".retry.budget.capacity", capacity, 1, maxRetryBudgetCapacity); err != nil {
				return nil, err
			}
			if err := validateUint32Range(base+".retry.budget.refill_tokens_per_second", refill, 1, maxRetryRefillPerSecond); err != nil {
				return nil, err
			}
			if err := validateUint32Range(base+".retry.budget.max_concurrent_retries_per_shard", concurrent, 1, maxConcurrentRetries); err != nil {
				return nil, err
			}
			retry = &bonvoyagev1.RetryPolicy{
				MaxAttempts:      maxAttempts,
				PerTryTimeoutMs:  perTryTimeout,
				RetryableMethods: methods,
				Budget: &bonvoyagev1.RetryBudget{
					Capacity:                     capacity,
					RefillTokensPerSecond:        refill,
					MaxConcurrentRetriesPerShard: concurrent,
				},
			}
		}

		endpointNames := make(map[string]struct{}, len(item.Endpoints))
		endpoints := make([]*bonvoyagev1.Endpoint, 0, len(item.Endpoints))
		var totalWeight uint64
		dnsEndpointCount := 0
		for j, endpoint := range item.Endpoints {
			endpointBase := fmt.Sprintf("%s.endpoints[%d]", base, j)
			if err := addUniqueName(endpointNames, endpointBase+".name", endpoint.Name); err != nil {
				return nil, err
			}
			address := strings.TrimSpace(endpoint.Address)
			if err := validateEndpointAddress(endpointBase+".address", address); err != nil {
				return nil, err
			}
			if net.ParseIP(address) == nil {
				dnsEndpointCount++
			}
			if endpoint.Port == 0 || endpoint.Port > 65_535 {
				return nil, fmt.Errorf("%s.port: must be between 1 and 65535", endpointBase)
			}
			weight := valueOrDefault(endpoint.Weight, uint32(1))
			if err := validateUint32Range(endpointBase+".weight", weight, 1, maxEndpointWeight); err != nil {
				return nil, err
			}
			totalWeight += uint64(weight)
			if totalWeight > uint64(maxEndpointWeight) {
				return nil, fmt.Errorf("%s.endpoints: total weight must not exceed %d", base, maxEndpointWeight)
			}
			endpoints = append(endpoints, &bonvoyagev1.Endpoint{
				Name: endpoint.Name, Address: address, Port: endpoint.Port, Weight: weight,
			})
		}
		if dnsRefresh != nil && dnsEndpointCount == 0 {
			return nil, fmt.Errorf("%s.dns_refresh: requires at least one DNS hostname endpoint", base)
		}
		result = append(result, &bonvoyagev1.Cluster{
			Name:                             item.Name,
			Protocol:                         protocol,
			Endpoints:                        endpoints,
			LoadBalancingPolicy:              loadBalancingPolicy,
			ConnectTimeoutMs:                 connectTimeout,
			MaxConnectionsPerShard:           connections,
			MaxPendingRequestsPerShard:       pending,
			MaxConcurrentRequestsPerEndpoint: endpointConcurrency,
			MaxHttp2StreamsPerConnection:     maxHTTP2Streams,
			UpstreamTls:                      upstreamTLS,
			PassiveHealth:                    passiveHealth,
			ActiveHealth:                     activeHealth,
			DnsRefresh:                       dnsRefresh,
			Retry:                            retry,
		})
	}
	return result, nil
}

func validateWebSocketTopology(listeners []*bonvoyagev1.Listener, virtualHosts []*bonvoyagev1.VirtualHost, clusters []*bonvoyagev1.Cluster) error {
	clusterProtocols := make(map[string]bonvoyagev1.Protocol, len(clusters))
	for _, cluster := range clusters {
		clusterProtocols[cluster.GetName()] = cluster.GetProtocol()
	}
	webSocketHosts := make(map[string]struct{})
	for hostIndex, host := range virtualHosts {
		for routeIndex, route := range host.GetRoutes() {
			if route.GetWebsocket() == nil {
				continue
			}
			webSocketHosts[host.GetName()] = struct{}{}
			base := fmt.Sprintf("virtual_hosts[%d].routes[%d].websocket", hostIndex, routeIndex)
			clusterNames := make([]string, 0, 1+len(route.GetWeightedClusters()))
			if route.GetClusterName() != "" {
				clusterNames = append(clusterNames, route.GetClusterName())
			}
			for _, target := range route.GetWeightedClusters() {
				clusterNames = append(clusterNames, target.GetClusterName())
			}
			for _, clusterName := range clusterNames {
				if clusterProtocols[clusterName] != bonvoyagev1.Protocol_PROTOCOL_HTTP1 {
					return fmt.Errorf("%s: cluster %q must use protocol http1", base, clusterName)
				}
			}
		}
	}
	for listenerIndex, listener := range listeners {
		if listener.GetProtocol() == bonvoyagev1.Protocol_PROTOCOL_HTTP1 {
			continue
		}
		for _, hostName := range listener.GetVirtualHostNames() {
			if _, exists := webSocketHosts[hostName]; exists {
				return fmt.Errorf("listeners[%d].protocol: virtual host %q contains a WebSocket route and requires http1", listenerIndex, hostName)
			}
		}
	}
	return nil
}

func compileRuntimeLimits(input *runtimeLimits) (*bonvoyagev1.RuntimeLimits, error) {
	if input == nil {
		input = &runtimeLimits{}
	}
	headerBytes := valueOrDefault(input.MaxRequestHeaderBytes, defaultMaxHeaderBytes)
	bodyBytes := valueOrDefault(input.MaxRequestBodyBytes, defaultMaxBodyBytes)
	upstreamHeaderBytes := valueOrDefault(input.MaxUpstreamResponseHeaderBytes, defaultMaxUpstreamHeaderBytes)
	upstreamChunkBytes := valueOrDefault(input.MaxUpstreamChunkMetadataBytes, defaultMaxUpstreamChunkBytes)
	requestTimeout := valueOrDefault(input.RequestTimeoutMS, defaultRequestTimeoutMS)
	idleTimeout := valueOrDefault(input.DownstreamIdleTimeoutMS, defaultIdleTimeoutMS)
	downstreamConnections := valueOrDefault(input.MaxDownstreamConnectionsPerShard, defaultMaxDownstreamPerShard)

	if err := validateUint32Range("runtime_limits.max_request_header_bytes", headerBytes, 1024, maxHeaderBytes); err != nil {
		return nil, err
	}
	if bodyBytes == 0 || bodyBytes > maxBodyBytes {
		return nil, fmt.Errorf("runtime_limits.max_request_body_bytes: must be between 1 and %d", maxBodyBytes)
	}
	if err := validateUint32Range("runtime_limits.max_upstream_chunk_metadata_bytes", upstreamChunkBytes, 1024, maxHeaderBytes); err != nil {
		return nil, err
	}
	if err := validateUint32Range("runtime_limits.max_upstream_response_header_bytes", upstreamHeaderBytes, 1024, maxHeaderBytes); err != nil {
		return nil, err
	}
	if err := validateUint32Range("runtime_limits.request_timeout_ms", requestTimeout, 1, maxRequestTimeoutMS); err != nil {
		return nil, err
	}
	if err := validateUint32Range("runtime_limits.downstream_idle_timeout_ms", idleTimeout, 1, maxIdleTimeoutMS); err != nil {
		return nil, err
	}
	if err := validateUint32Range("runtime_limits.max_downstream_connections_per_shard", downstreamConnections, 1, maxDownstreamPerShard); err != nil {
		return nil, err
	}
	return &bonvoyagev1.RuntimeLimits{
		MaxRequestHeaderBytes:            headerBytes,
		MaxRequestBodyBytes:              bodyBytes,
		MaxUpstreamResponseHeaderBytes:   upstreamHeaderBytes,
		MaxUpstreamChunkMetadataBytes:    upstreamChunkBytes,
		RequestTimeoutMs:                 requestTimeout,
		DownstreamIdleTimeoutMs:          idleTimeout,
		MaxDownstreamConnectionsPerShard: downstreamConnections,
	}, nil
}

func validateName(path, name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("%s: must match %s", path, namePattern.String())
	}
	return nil
}

func addUniqueName(names map[string]struct{}, path, name string) error {
	if err := validateName(path, name); err != nil {
		return err
	}
	if _, exists := names[name]; exists {
		return fmt.Errorf("%s: duplicate name %q", path, name)
	}
	names[name] = struct{}{}
	return nil
}

func normalizeDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	if domain == "*" {
		return domain, nil
	}
	if strings.HasPrefix(domain, "*.") {
		if validHost(domain[2:]) {
			return domain, nil
		}
		return "", fmt.Errorf("invalid wildcard domain %q", raw)
	}
	if strings.Contains(domain, "*") || !validHost(domain) {
		return "", fmt.Errorf("invalid exact domain %q", raw)
	}
	return domain, nil
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func normalizeTLSServerName(raw string) (string, error) {
	serverName := strings.ToLower(strings.TrimSpace(raw))
	if net.ParseIP(serverName) != nil || !validHost(serverName) {
		return "", errors.New("must be a DNS hostname, not a wildcard or IP address")
	}
	return serverName, nil
}

func validatePath(path, value string) error {
	if value == "" || value[0] != '/' {
		return fmt.Errorf("%s: must start with /", path)
	}
	if len(value) > maxRoutePathBytes {
		return fmt.Errorf("%s: must not exceed %d bytes", path, maxRoutePathBytes)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s: must not contain CR or LF", path)
	}
	return nil
}

func validateHealthCheckPath(path, value string) error {
	if err := validatePath(path, value); err != nil {
		return err
	}
	if strings.ContainsAny(value, " #\t") || containsControl(value) {
		return fmt.Errorf("%s: must be an absolute origin-form path without spaces, fragments, or controls", path)
	}
	return nil
}

func validHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if (char >= '0' && char <= '9') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') {
			continue
		}
		switch char {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func validVisibleText(value string) bool {
	return value != "" && strings.IndexFunc(value, func(char rune) bool {
		return !unicode.IsGraphic(char)
	}) == -1
}

func validVisibleASCII(value string, allowSpace bool) bool {
	minimum := byte(0x21)
	if allowSpace {
		minimum = 0x20
	}
	for index := 0; index < len(value); index++ {
		if value[index] < minimum || value[index] > 0x7e {
			return false
		}
	}
	return value != ""
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, func(char rune) bool {
		return char < 0x20 || char == 0x7f
	}) >= 0
}

func validateEndpointAddress(path, address string) error {
	address = strings.TrimSpace(address)
	if address == "" {
		return fmt.Errorf("%s: required", path)
	}
	if strings.ContainsAny(address, " \t\r\n/") || !validHost(strings.ToLower(address)) {
		return fmt.Errorf("%s: must be an IP address or DNS hostname without a port", path)
	}
	return nil
}

func validateUint32Range(path string, value, minimum, maximum uint32) error {
	if value < minimum || value > maximum {
		return fmt.Errorf("%s: must be between %d and %d", path, minimum, maximum)
	}
	return nil
}

func valueOrDefault[T uint32 | uint64](value *T, fallback T) T {
	if value == nil {
		return fallback
	}
	return *value
}

// WriteFileAtomic durably writes data and atomically replaces the destination.
func WriteFileAtomic(path string, data []byte) error {
	return writeFileAtomic(path, data, os.Rename)
}

func writeFileAtomic(path string, data []byte, rename func(string, string) error) (returnErr error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	temporary, err := os.CreateTemp(dir, "."+base+"-*")
	if err != nil {
		return fmt.Errorf("create temporary output in %q: %w", dir, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if returnErr != nil {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("set temporary output permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary output: %w", err)
	}
	if err := rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace output %q: %w", path, err)
	}

	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open output directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}
