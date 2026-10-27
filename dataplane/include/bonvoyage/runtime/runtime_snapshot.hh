#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "bonvoyage/http/request_header_lookup.hh"
#include "bonvoyage/runtime/client_identity.hh"
#include "bonvoyage/runtime/cors_policy.hh"
#include "bonvoyage/runtime/endpoint_selector.hh"
#include "bonvoyage/runtime/header_transformations.hh"
#include "bonvoyage/runtime/jwt_auth.hh"
#include "bonvoyage/runtime/request_content_policy.hh"
#include "bonvoyage/runtime/retry_policy.hh"
#include "bonvoyage/runtime/route_admission.hh"
#include "bonvoyage/runtime/route_rewrite.hh"
#include "bonvoyage/runtime/weighted_cluster_selector.hh"
#include "bonvoyage/v1/config.pb.h"

namespace re2 {
class RE2;
}

namespace bonvoyage::runtime {

/** Protocol limits prepared from an immutable configuration snapshot. */
struct RuntimeLimits final {
  /** Maximum simultaneously accepted downstream connections on one shard. */
  std::uint32_t max_downstream_connections_per_shard{16384U};

  /** Maximum bytes accepted for one downstream request-head section. */
  std::size_t max_request_header_bytes{32768U};

  /** Maximum decoded request-body bytes. */
  std::uint64_t max_request_body_bytes{10U * 1024U * 1024U};

  /** Maximum bytes accepted for one upstream HTTP/1 response head. */
  std::size_t max_upstream_response_header_bytes{32768U};

  /** Maximum cumulative chunk-size, extension, and trailer wire bytes. */
  std::size_t max_upstream_chunk_metadata_bytes{32768U};

  /** End-to-end request deadline in milliseconds. */
  std::uint32_t request_timeout_ms{15000U};

  /** Idle downstream read deadline in milliseconds. */
  std::uint32_t downstream_idle_timeout_ms{60000U};
};

/** A prepared endpoint owned by one shard-local cluster runtime. */
struct RuntimeEndpoint final {
  /** Configuration identity used in diagnostics. */
  std::string name;

  /** Resolved IPv4 or IPv6 literal used for shard-local connections. */
  std::string address;

  /** Upstream TCP port. */
  std::uint16_t port{};

  /** Relative selection weight expanded into the prepared schedule. */
  std::uint32_t weight{1U};

  /** True when address requires DNS resolution rather than literal parsing. */
  bool dns_hostname{false};
};

/** Prevalidated TLS client policy for one shard-local upstream pool. */
struct RuntimeUpstreamTls final {
  /** DNS identity sent as SNI and verified against the server certificate. */
  std::string server_name;

  /** PEM trust-bundle filename below the bootstrap secret directory. */
  std::string trust_bundle_secret;

  /** Optional PEM client certificate chain used for mutual TLS. */
  std::optional<std::string> certificate_chain_secret;

  /** Optional PEM client private key used for mutual TLS. */
  std::optional<std::string> private_key_secret;
};

/** Bounded coordinator-owned HTTP endpoint-probe policy. */
struct RuntimeActiveHealth final {
  /** Absolute origin-form target used with the fixed GET method. */
  std::string path{"/healthz"};

  /** Minimum interval between complete probe cycles. */
  std::uint32_t interval_ms{5000U};

  /** Per-probe deadline. */
  std::uint32_t timeout_ms{1000U};

  /** Consecutive successful probes required to recover an unhealthy endpoint. */
  std::uint32_t healthy_threshold{2U};

  /** Consecutive failed probes required to mark an endpoint unhealthy. */
  std::uint32_t unhealthy_threshold{3U};

  /** Inclusive lower accepted HTTP status. */
  std::uint16_t expected_status_min{200U};

  /** Inclusive upper accepted HTTP status. */
  std::uint16_t expected_status_max{399U};

  /** Optional Host field override without a port. */
  std::optional<std::string> host;
};

/** Bounded coordinator-owned refresh policy for DNS endpoint names. */
struct RuntimeDnsRefresh final {
  /** Minimum interval between complete DNS refresh cycles. */
  std::uint32_t refresh_interval_ms{30000U};

  /** C-ares resolver deadline for one lookup. */
  std::uint32_t resolve_timeout_ms{1000U};
};

/** Upstream application protocol selected by one prepared cluster. */
enum class RuntimeUpstreamProtocol {
  http1,  ///< HTTP/1.1, with optional TLS and `http/1.1` ALPN.
  http2   ///< HTTP/2 over TLS with mandatory `h2` ALPN.
};

/** A validated static upstream cluster. */
struct RuntimeCluster final {
  /** Configuration identity referenced by routes. */
  std::string name;

  /** Explicit upstream application protocol selected for this cluster. */
  RuntimeUpstreamProtocol protocol{RuntimeUpstreamProtocol::http1};

  /** Upstream connection deadline in milliseconds. */
  std::uint32_t connect_timeout_ms{1000U};

  /** Maximum live upstream connections owned by one shard. */
  std::uint32_t max_connections_per_shard{128U};

  /** Maximum requests waiting for upstream capacity on one shard. */
  std::uint32_t max_pending_requests_per_shard{256U};

  /** Maximum active selections for one endpoint on one shard. */
  std::uint32_t max_concurrent_requests_per_endpoint{384U};

  /** Maximum concurrent streams on one shard-local HTTP/2 connection. */
  std::uint32_t max_http2_streams_per_connection{100U};

  /** Prepared shard-local endpoint-selection policy. */
  RuntimeLoadBalancingPolicy load_balancing_policy{
      RuntimeLoadBalancingPolicy::round_robin};

  /** Optional bounded passive transport-failure policy. */
  std::optional<RuntimePassiveHealth> passive_health;

  /** Optional centralized active HTTP health policy. */
  std::optional<RuntimeActiveHealth> active_health;

  /** Optional centralized DNS refresh policy. */
  std::optional<RuntimeDnsRefresh> dns_refresh;

  /** Optional bounded pre-response-head retry policy. */
  std::optional<RuntimeRetryPolicy> retry;

  /** Verified upstream TLS policy, or no value for cleartext HTTP. */
  std::optional<RuntimeUpstreamTls> upstream_tls;

  /** Prepared static endpoints. */
  std::vector<RuntimeEndpoint> endpoints;
};

/** A normalized request-header predicate prepared for route matching. */
struct RuntimeHeaderMatch final {
  /** Lowercase header field name. */
  std::string name;

  /** Required exact value, or no value constraint for a presence predicate. */
  std::optional<std::string> exact;

  /** Required presence state when exact has no value. */
  bool present{true};
};

/** A normalized query-parameter predicate prepared for route matching. */
struct RuntimeQueryParameterMatch final {
  /** Percent-decoded, case-sensitive parameter name. */
  std::string name;

  /** Required decoded value, or no value constraint for presence matching. */
  std::optional<std::string> exact;

  /** Required presence state when exact has no value. */
  bool present{true};
};

/** Protocol-neutral allocation-free request-header lookup result. */
using RequestHeaderLookupResult = bonvoyage::http::RequestHeaderLookupResult;

/** Protocol-neutral request-header lookup callback. */
using RequestHeaderLookup = RequestHeaderLookupResult (*)(
    const void* context, std::string_view lowercase_name) noexcept;

/** A locally generated response that does not select an upstream cluster. */
struct RuntimeFixedResponse final {
  /** Response status code. */
  std::uint16_t status_code{200U};

  /** Complete response representation. */
  std::string body;

  /** Response Content-Type field value. */
  std::string content_type{"text/plain"};
};

/** A locally generated redirect with a snapshot-prepared Location value. */
struct RuntimeRedirectResponse final {
  /** Explicit redirect status code. */
  std::uint16_t status_code{308U};

  /** Complete origin-relative or absolute URI-reference. */
  std::string location;
};

/** Route-level API-key policy referencing mounted credential material. */
struct RuntimeApiKeyAuth final {
  /** Lowercase HTTP field name carrying the complete credential. */
  std::string header_name{"x-api-key"};

  /** Credential filename below the bootstrap secret directory. */
  std::string credentials_secret;
};

/** Route-level JWT policy referencing one locally mounted public JWKS. */
struct RuntimeJwtAuth final {
  /** Public JWKS filename below the bootstrap secret directory. */
  std::string jwks_secret;

  /** Exact token issuer. */
  std::string issuer;

  /** Required audience string or member of the token audience array. */
  std::string audience;

  /** Explicit token media type used to prevent cross-JWT confusion. */
  std::string required_type;

  /** Closed asymmetric algorithm allowlist. */
  std::vector<JwtAlgorithm> algorithms;

  /** Allowed expiration and not-before clock skew. */
  std::uint32_t clock_skew_seconds{};

  /** Maximum accepted difference between exp and iat. */
  std::uint32_t max_token_lifetime_seconds{};

  /** Scopes that every authenticated token must contain. */
  std::vector<std::string> required_scopes;

  /** Non-reserved string claims required by route authorization. */
  std::vector<JwtClaimRequirement> required_claims;

  /** Per-shard CPU budget protecting asymmetric verification work. */
  RuntimeLocalRateLimit verification_rate_limit;
};

/** Prevalidated references for one downstream TLS listener. */
struct RuntimeDownstreamTls final {
  /** PEM certificate chain filename below the bootstrap secret directory. */
  std::string certificate_chain_secret;

  /** PEM private-key filename below the bootstrap secret directory. */
  std::string private_key_secret;

  /** PEM client trust bundle required when mutual TLS is enabled. */
  std::optional<std::string> trust_bundle_secret;

  /** Whether a valid client certificate is mandatory during the handshake. */
  bool require_client_certificate{false};
};

/** Bounded RFC 6455 upgrade policy prepared for one HTTP/1 route. */
struct RuntimeWebSocketPolicy final {
  /** Maximum time without bytes in either tunnel direction. */
  std::uint32_t idle_timeout_ms{60000U};
};

/** A route action and its prevalidated request predicates. */
struct RuntimeRoute final {
  /** Globally unique index into this snapshot's shard-local route state. */
  std::size_t runtime_index{};

  /** Configuration identity used in diagnostics. */
  std::string name;

  /** Exact path, prepared prefix, or safe regular-expression source. */
  std::string path;

  /** True for exact matching; false for longest-prefix matching. */
  bool exact_path{false};

  /** Precompiled full-path RE2 program, or null for exact and prefix routes. */
  std::shared_ptr<const re2::RE2> safe_regex;

  /** Allowed methods, or an empty vector for any method. */
  std::vector<std::string> methods;

  /** All required request-header predicates. */
  std::vector<RuntimeHeaderMatch> headers;

  /** All required query-parameter predicates. */
  std::vector<RuntimeQueryParameterMatch> query_parameters;

  /** Selected cluster index for a reverse-proxy action. */
  std::optional<std::size_t> cluster_index;

  /** Prepared local response for a fixed-response action. */
  std::optional<RuntimeFixedResponse> fixed_response;

  /** Prepared local response for a redirect action. */
  std::optional<RuntimeRedirectResponse> redirect;

  /** Optional concurrency and token-bucket admission settings. */
  RuntimeRouteAdmissionPolicy admission;

  /** Optional static API-key authentication policy. */
  std::optional<RuntimeApiKeyAuth> api_key_auth;

  /** Optional static JWT authentication and authorization policy. */
  std::optional<RuntimeJwtAuth> jwt_auth;

  /** Optional static source-address allow and deny policy. */
  std::optional<SourceIpPolicy> source_ip_policy;

  /** Optional bounded browser cross-origin policy. */
  std::optional<CorsPolicy> cors;

  /** Optional route body-size and Content-Type policy. */
  std::optional<RequestContentPolicy> request_content;

  /** Optional bounded mutations for proxied request and response fields. */
  std::optional<HeaderTransformations> header_transformations;

  /** Optional immutable upstream authority and path rewrites. */
  std::optional<RouteRewrite> rewrite;

  /** Optional HTTP/1.1 WebSocket upgrade and tunnel policy. */
  std::optional<RuntimeWebSocketPolicy> websocket;
};

/** Input view used by the allocation-free route lookup path. */
struct RequestView final {
  /** Normalized authority without an optional port suffix. */
  std::string_view host;

  /** Request path without the query string. */
  std::string_view path;

  /** HTTP method token. */
  std::string_view method;

  /** Raw query text without the leading question mark. */
  std::string_view query;

  /** Protocol-owned header collection passed back to header_lookup. */
  const void* header_context{nullptr};

  /** Optional allocation-free lookup used only by header-bearing routes. */
  RequestHeaderLookup header_lookup{nullptr};
};

/** Non-owning result of a lookup in an immutable runtime snapshot. */
struct RouteMatch final {
  /** Matched route, or null when no route matched. */
  const RuntimeRoute* route{nullptr};

  /** Direct cluster, or null for misses, local actions, and weighted routes. */
  const RuntimeCluster* cluster{nullptr};
};

/** Downstream application protocol selected by one prepared listener. */
enum class RuntimeProtocol {
  http1,  ///< HTTP/1.1, with optional TLS and `http/1.1` ALPN.
  http2   ///< HTTP/2 over TLS with mandatory `h2` ALPN.
};

/** Listener metadata and the virtual hosts it is allowed to select. */
struct RuntimeListener final {
  /** Configuration identity used in diagnostics. */
  std::string name;

  /** Local bind address. */
  std::string address;

  /** Local TCP port. */
  std::uint16_t port{};

  /** Explicit downstream protocol; no implicit upgrade is performed. */
  RuntimeProtocol protocol{RuntimeProtocol::http1};

  /** TLS credentials and client-auth policy, or no value for cleartext. */
  std::optional<RuntimeDownstreamTls> downstream_tls;

  /** Optional precompiled networks allowed to assert client identity. */
  std::optional<TrustedProxyPolicy> trusted_proxy;

  /** Allowed virtual-host indices in configuration order. */
  std::vector<std::size_t> virtual_host_indices;
};

/**
 * Immutable, shard-local representation of a BonVoyage v1 Snapshot.
 *
 * compile() performs all reference and feature validation before listeners are
 * opened. match() only reads prepared structures and never crosses shards.
 */
class RuntimeSnapshot final {
 public:
  /** Compiles a wire snapshot or throws std::invalid_argument. */
  static RuntimeSnapshot compile(const bonvoyage::v1::Snapshot& snapshot);

  /** Decodes and compiles deterministic protobuf bytes. */
  static RuntimeSnapshot decode(std::string_view bytes);

  /**
   * Rejects snapshot capabilities that the live gateway has not integrated.
   *
   * This preflight is called before metrics, clusters, or listeners start so a
   * staged protocol cannot leave a partially initialized gateway behind.
   */
  void validate_live_gateway_capabilities() const;

  /** Finds an exact or longest-prefix route for one listener. */
  [[nodiscard]] RouteMatch match(std::size_t listener_index,
                                 const RequestView& request) const;

  /** Resolves a preflight by requested method without application headers. */
  [[nodiscard]] RouteMatch match_cors_preflight(
      std::size_t listener_index, const RequestView& request) const;

  /** Returns whether an SNI name belongs to a listener's virtual hosts. */
  [[nodiscard]] bool listener_accepts_server_name(
      std::size_t listener_index, std::string_view server_name) const;

  /** Compares an HTTP authority with the SNI DNS name on the connection. */
  [[nodiscard]] static bool authority_matches_server_name(
      std::string_view authority, std::string_view server_name);

  /** Returns the active snapshot identity. */
  [[nodiscard]] const std::string& snapshot_id() const noexcept {
    return snapshot_id_;
  }

  /** Returns the monotonically increasing snapshot generation. */
  [[nodiscard]] std::uint64_t generation() const noexcept {
    return generation_;
  }

  /** Returns prepared global request limits. */
  [[nodiscard]] const RuntimeLimits& limits() const noexcept { return limits_; }

  /** Returns prepared listener definitions. */
  [[nodiscard]] const std::vector<RuntimeListener>& listeners() const noexcept {
    return listeners_;
  }

  /** Returns prepared upstream clusters. */
  [[nodiscard]] const std::vector<RuntimeCluster>& clusters() const noexcept {
    return clusters_;
  }

  /** Returns admission policies indexed by RuntimeRoute::runtime_index. */
  [[nodiscard]] const std::vector<RuntimeRouteAdmissionPolicy>&
  route_admission_policies() const noexcept {
    return route_admission_policies_;
  }

  /** Returns API-key policies indexed by RuntimeRoute::runtime_index. */
  [[nodiscard]] const std::vector<std::optional<RuntimeApiKeyAuth>>&
  route_api_key_policies() const noexcept {
    return route_api_key_policies_;
  }

  /** Returns JWT policies indexed by RuntimeRoute::runtime_index. */
  [[nodiscard]] const std::vector<std::optional<RuntimeJwtAuth>>&
  route_jwt_policies() const noexcept {
    return route_jwt_policies_;
  }

  /** Returns weighted cluster targets indexed by RuntimeRoute::runtime_index. */
  [[nodiscard]] const std::vector<std::vector<RuntimeWeightedCluster>>&
  route_weighted_clusters() const noexcept {
    return route_weighted_clusters_;
  }

 private:
  struct TransparentStringHash final {
    using is_transparent = void;
    [[nodiscard]] std::size_t operator()(std::string_view value) const noexcept {
      return std::hash<std::string_view>{}(value);
    }
    [[nodiscard]] std::size_t operator()(const std::string& value) const noexcept {
      return (*this)(std::string_view(value));
    }
  };

  struct PrefixNode final {
    std::unordered_map<char, std::size_t> children;
    std::vector<std::size_t> routes;
  };

  struct RuntimeVirtualHost final {
    std::string name;
    std::vector<std::string> domains;
    std::vector<RuntimeRoute> routes;
    std::unordered_map<std::string, std::vector<std::size_t>,
                       TransparentStringHash, std::equal_to<>> exact_routes;
    std::vector<PrefixNode> prefix_trie;
    std::vector<std::size_t> regex_routes;
  };

  [[nodiscard]] const RuntimeVirtualHost* find_virtual_host(
      const RuntimeListener& listener, std::string_view host) const;
  [[nodiscard]] const RuntimeRoute* find_route(
      const RuntimeVirtualHost& virtual_host,
      const RequestView& request, bool cors_preflight) const;

  std::string snapshot_id_;
  std::uint64_t generation_{};
  RuntimeLimits limits_;
  std::vector<RuntimeListener> listeners_;
  std::vector<RuntimeVirtualHost> virtual_hosts_;
  std::vector<RuntimeCluster> clusters_;
  std::vector<RuntimeRouteAdmissionPolicy> route_admission_policies_;
  std::vector<std::optional<RuntimeApiKeyAuth>> route_api_key_policies_;
  std::vector<std::optional<RuntimeJwtAuth>> route_jwt_policies_;
  std::vector<std::vector<RuntimeWeightedCluster>> route_weighted_clusters_;
};

}  // namespace bonvoyage::runtime
