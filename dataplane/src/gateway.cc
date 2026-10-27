#include "bonvoyage/runtime/gateway.hh"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <fmt/format.h>
#include <seastar/core/abort_source.hh>
#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/coroutine/as_future.hh>
#include <seastar/core/file.hh>
#include <seastar/core/fstream.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/metrics.hh>
#include <seastar/core/metrics_registration.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/semaphore.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/timer.hh>
#include <seastar/core/when_all.hh>
#include <seastar/http/client.hh>
#include <seastar/http/common.hh>
#include <seastar/http/exception.hh>
#include <seastar/http/internal/content_source.hh>
#include <seastar/http/reply.hh>
#include <seastar/http/request.hh>
#include <seastar/http/request_parser.hh>
#include <seastar/net/api.hh>
#include <seastar/net/dns.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/net/packet.hh>
#include <seastar/net/tls.hh>
#include <seastar/util/defer.hh>
#include <seastar/util/log.hh>
#include <seastar/util/optimized_optional.hh>
#include <seastar/util/short_streams.hh>

#include <nghttp2/nghttp2.h>

#include "bonvoyage/http/http1_validation.hh"
#include "bonvoyage/http/grpc_protocol.hh"
#include "bonvoyage/http/http2_request_validation.hh"
#include "bonvoyage/http/http2_session.hh"
#include "bonvoyage/http/upstream_request_serializer.hh"
#include "bonvoyage/http/upstream_response_head_parser.hh"
#include "bonvoyage/http/websocket_protocol.hh"
#include "bonvoyage/runtime/access_log.hh"
#include "bonvoyage/runtime/api_key_auth.hh"
#include "bonvoyage/runtime/client_identity.hh"
#include "bonvoyage/runtime/endpoint_maintenance.hh"
#include "bonvoyage/runtime/jwt_auth.hh"
#include "bonvoyage/runtime/runtime_snapshot.hh"
#include "bonvoyage/runtime/trace_context.hh"
#include "bonvoyage/runtime/trace_exporter.hh"
#include "bonvoyage/runtime/upstream_http1_client.hh"
#include "bonvoyage/runtime/upstream_http2_client.hh"
#include "bonvoyage/version.hh"

namespace bonvoyage::runtime {
namespace {

using namespace std::chrono_literals;

seastar::logger gateway_log{"bonvoyage-gateway"};
constexpr auto kTlsHandshakeTimeout = 10s;
constexpr std::string_view kTlsPriority =
    "NORMAL:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2";
constexpr std::string_view kHttp11Alpn = "http/1.1";
constexpr std::string_view kHttp2Alpn = "h2";
constexpr std::size_t kDownstreamOutputBufferBytes = 8U * 1024U;
constexpr std::size_t kOwnershipTransferBodyThreshold =
    2U * kDownstreamOutputBufferBytes;
constexpr std::size_t kHttp2ResponseChunkBytes = 16U * 1024U;
constexpr auto kHttp2DrainTimeout = 5s;
constexpr std::size_t kMaintenanceConcurrency = 8U;

std::uint64_t unix_microseconds_now() noexcept {
  const auto value = std::chrono::duration_cast<std::chrono::microseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  return value > 0 ? static_cast<std::uint64_t>(value) : 0U;
}

std::uint64_t elapsed_microseconds(
    std::chrono::steady_clock::time_point started) noexcept {
  const auto value = std::chrono::duration_cast<std::chrono::microseconds>(
                         std::chrono::steady_clock::now() - started)
                         .count();
  return value > 0 ? static_cast<std::uint64_t>(value) : 0U;
}

void complete_trace_from_access_log(TraceSpanRecord& trace,
                                    const AccessLogRecord& access_log) noexcept {
  constexpr auto kNanosecondsPerMicrosecond = 1000U;
  const auto duration =
      access_log.duration_microseconds >
              std::numeric_limits<std::uint64_t>::max() /
                  kNanosecondsPerMicrosecond
          ? std::numeric_limits<std::uint64_t>::max()
          : access_log.duration_microseconds * kNanosecondsPerMicrosecond;
  trace.end_unix_nanoseconds =
      duration > std::numeric_limits<std::uint64_t>::max() -
                     trace.start_unix_nanoseconds
          ? std::numeric_limits<std::uint64_t>::max()
          : trace.start_unix_nanoseconds + duration;
  trace.snapshot_generation = access_log.snapshot_generation;
  trace.request_body_bytes = access_log.request_body_bytes;
  trace.response_body_bytes = access_log.response_body_bytes;
  trace.shard = access_log.shard;
  trace.status = access_log.status;
  trace.listener = access_log.listener;
  trace.route = access_log.route;
  trace.cluster = access_log.cluster;
  trace.protocol = access_log.protocol;
  trace.method = access_log.method;
  trace.action = access_log.action;
  trace.completion = access_log.completion;
}

class Overloaded final : public std::runtime_error {
 public:
  explicit Overloaded(const char* reason = "cluster request queue is full")
      : std::runtime_error(reason) {}
};

class NoHealthyUpstream final : public std::runtime_error {
 public:
  NoHealthyUpstream()
      : std::runtime_error("cluster has no eligible upstream endpoint") {}
};

class ConnectTimedOut final : public std::runtime_error {
 public:
  ConnectTimedOut() : std::runtime_error("upstream connect timed out") {}
};

class UpstreamAttemptTimedOut final : public std::runtime_error {
 public:
  UpstreamAttemptTimedOut()
      : std::runtime_error("upstream response head timed out") {}
};

class ResponseStarted final : public std::runtime_error {
 public:
  ResponseStarted() : std::runtime_error("downstream response already started") {}
};

struct GatewayStats final {
  GatewayStats()
      : request_latency_microseconds{
            0U,
            0.0,
            {{0U, 100.0},       {0U, 250.0},       {0U, 500.0},
             {0U, 1000.0},      {0U, 2500.0},      {0U, 5000.0},
             {0U, 10000.0},     {0U, 25000.0},     {0U, 50000.0},
             {0U, 100000.0},    {0U, 250000.0},    {0U, 500000.0},
             {0U, 1000000.0},   {0U, 2500000.0},   {0U, 5000000.0},
             {0U, 10000000.0},  {0U, 30000000.0},
             {0U, 300000000.0}},
            std::nullopt} {}

  void observe_request_latency(
      std::chrono::steady_clock::duration elapsed) noexcept {
    const auto microseconds = static_cast<double>(
        std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
    ++request_latency_microseconds.sample_count;
    request_latency_microseconds.sample_sum += microseconds;
    for (auto& bucket : request_latency_microseconds.buckets) {
      if (microseconds <= bucket.upper_bound) {
        ++bucket.count;
      }
    }
  }

  std::uint64_t requests_total{};
  std::uint64_t telemetry_contract_version{3U};
  std::uint64_t ready{};
  std::uint64_t snapshot_generation{};
  std::uint64_t configured_listeners{};
  std::uint64_t configured_routes{};
  std::uint64_t configured_clusters{};
  std::uint64_t configured_endpoints{};
  std::uint64_t responses_2xx{};
  std::uint64_t responses_3xx{};
  std::uint64_t responses_4xx{};
  std::uint64_t responses_5xx{};
  std::uint64_t route_misses{};
  std::uint64_t route_redirects{};
  std::uint64_t downstream_connections_accepted{};
  std::uint64_t downstream_connection_rejections{};
  std::uint64_t overload_rejections{};
  std::uint64_t route_overload_rejections{};
  std::uint64_t route_rate_limit_rejections{};
  std::uint64_t api_key_auth_successes{};
  std::uint64_t api_key_auth_rejections{};
  std::uint64_t jwt_auth_successes{};
  std::uint64_t jwt_auth_rejections{};
  std::uint64_t jwt_authorization_rejections{};
  std::uint64_t jwt_verification_overload_rejections{};
  std::uint64_t source_ip_policy_allows{};
  std::uint64_t source_ip_policy_rejections{};
  std::uint64_t cors_actual_allows{};
  std::uint64_t cors_preflight_successes{};
  std::uint64_t cors_rejections{};
  std::uint64_t request_content_policy_allows{};
  std::uint64_t request_content_type_rejections{};
  std::uint64_t request_body_limit_rejections{};
  std::uint64_t request_header_transformation_applications{};
  std::uint64_t response_header_transformation_applications{};
  std::uint64_t header_transformation_limit_rejections{};
  std::uint64_t request_authority_rewrite_applications{};
  std::uint64_t request_path_rewrite_applications{};
  std::uint64_t request_rewrite_limit_rejections{};
  std::uint64_t route_weighted_cluster_selections{};
  std::uint64_t trusted_proxy_client_ip_resolutions{};
  std::uint64_t forwarded_header_rejections{};
  std::uint64_t cluster_overload_rejections{};
  std::uint64_t endpoint_overload_rejections{};
  std::uint64_t upstream_failures{};
  std::uint64_t upstream_endpoint_selections{};
  std::uint64_t upstream_passive_failures{};
  std::uint64_t upstream_passive_ejections{};
  std::uint64_t upstream_passive_reactivations{};
  std::uint64_t upstream_no_eligible_endpoints{};
  std::uint64_t endpoint_circuit_opens{};
  std::uint64_t endpoint_circuit_half_open_transitions{};
  std::uint64_t endpoint_circuit_closes{};
  std::uint64_t endpoint_circuit_reopens{};
  std::uint64_t endpoint_circuit_probe_rejections{};
  std::uint64_t retry_attempts{};
  std::uint64_t retry_successes{};
  std::uint64_t retry_exhausted{};
  std::uint64_t retry_token_rejections{};
  std::uint64_t retry_concurrency_rejections{};
  std::uint64_t retry_per_try_timeouts{};
  std::uint64_t retry_commit_suppressions{};
  std::uint64_t retry_non_replayable_suppressions{};
  std::uint64_t active_health_checks{};
  std::uint64_t active_health_successes{};
  std::uint64_t active_health_failures{};
  std::uint64_t active_health_timeouts{};
  std::uint64_t active_health_state_changes{};
  std::uint64_t active_health_publish_failures{};
  std::uint64_t active_health_cycle_overruns{};
  std::uint64_t dns_refresh_attempts{};
  std::uint64_t dns_refresh_successes{};
  std::uint64_t dns_refresh_failures{};
  std::uint64_t dns_address_changes{};
  std::uint64_t dns_publish_failures{};
  std::uint64_t dns_refresh_cycle_overruns{};
  std::uint64_t upstream_framing_rejections{};
  std::uint64_t upstream_chunked_responses{};
  std::uint64_t upstream_response_trailers_dropped{};
  std::uint64_t request_timeouts{};
  std::uint64_t tls_handshakes{};
  std::uint64_t tls_handshake_failures{};
  std::uint64_t tls_handshake_timeouts{};
  std::uint64_t tls_sni_rejections{};
  std::uint64_t tls_alpn_rejections{};
  std::uint64_t upstream_tls_handshakes{};
  std::uint64_t upstream_tls_handshake_failures{};
  std::uint64_t upstream_tls_handshake_timeouts{};
  std::uint64_t upstream_http1_pool_waits{};
  std::uint64_t upstream_http1_pool_wait_nanoseconds{};
  std::uint64_t upstream_http1_pool_wait_max_nanoseconds{};
  std::uint64_t upstream_http2_connections{};
  std::uint64_t upstream_http2_connection_failures{};
  std::uint64_t upstream_http2_protocol_errors{};
  std::uint64_t upstream_http2_streams{};
  std::uint64_t upstream_http2_stream_resets{};
  std::uint64_t upstream_http2_goaways{};
  std::uint64_t upstream_http2_request_cancellations{};
  std::uint64_t upstream_http2_response_trailers{};
  std::uint64_t upstream_http2_pool_waits{};
  std::uint64_t upstream_http2_stream_delimited_responses{};
  std::uint64_t grpc_requests{};
  std::uint64_t grpc_successes{};
  std::uint64_t grpc_application_errors{};
  std::uint64_t grpc_local_errors{};
  std::uint64_t grpc_protocol_rejections{};
  std::uint64_t grpc_deadlines_propagated{};
  std::uint64_t grpc_response_trailers_forwarded{};
  std::uint64_t grpc_trailing_metadata_fields{};
  std::uint64_t websocket_handshake_attempts{};
  std::uint64_t websocket_handshake_successes{};
  std::uint64_t websocket_handshake_rejections{};
  std::uint64_t websocket_upstream_handshake_failures{};
  std::uint64_t websocket_connections{};
  std::uint64_t websocket_idle_timeouts{};
  std::uint64_t websocket_drain_terminations{};
  std::uint64_t websocket_downstream_bytes{};
  std::uint64_t websocket_upstream_bytes{};
  std::uint64_t http2_connections{};
  std::uint64_t http2_streams{};
  std::uint64_t http2_stream_resets{};
  std::uint64_t http2_request_cancellations{};
  std::uint64_t http2_protocol_errors{};
  std::uint64_t http2_goaways{};
  std::uint64_t http2_drain_timeouts{};
  std::uint64_t request_bytes{};
  std::uint64_t response_bytes{};
  std::uint64_t response_path_diagnostics_enabled{};
  std::uint64_t response_path_completed_responses{};
  std::uint64_t response_path_write_operations{};
  std::uint64_t response_path_write_bytes{};
  std::uint64_t response_path_flush_operations{};
  std::uint64_t response_path_flush_wait_operations{};
  std::uint64_t response_path_flush_wait_nanoseconds{};
  std::uint64_t response_path_handoff_observations{};
  std::uint64_t response_path_handoff_nanoseconds{};
  std::uint64_t active_requests{};
  std::uint64_t active_route_requests{};
  std::uint64_t active_connections{};
  std::uint64_t active_tls_handshakes{};
  std::uint64_t active_upstream_tls_handshakes{};
  std::uint64_t active_upstream_requests{};
  std::uint64_t active_upstream_http1_requests{};
  std::uint64_t configured_upstream_http1_connections{};
  std::uint64_t active_unhealthy_endpoints{};
  std::uint64_t open_endpoint_circuits{};
  std::uint64_t half_open_endpoint_circuits{};
  std::uint64_t active_retries{};
  std::uint64_t active_upstream_http2_connections{};
  std::uint64_t active_upstream_http2_streams{};
  std::uint64_t active_http2_connections{};
  std::uint64_t active_http2_streams{};
  std::uint64_t active_websocket_connections{};
  seastar::metrics::histogram request_latency_microseconds;
};

struct ErrorResponse final {
  std::uint16_t status{502U};
  std::string code{"request_failure"};
  std::string message{"The request failed"};
  bool close_connection{true};
  bool timeout{false};
  bool upstream_failure{false};
};

enum class CorsRequestKind { none, actual, preflight };

struct CorsRequestInspection final {
  CorsRequestKind kind{CorsRequestKind::none};
  std::string_view origin;
  std::string_view requested_method;
  std::string_view requested_headers;
  bool malformed{false};
};

struct CorsResponseContext final {
  const CorsPolicy* policy{};
  // Borrows the same immutable snapshot as policy, never request headers.
  std::string_view origin;
  bool preflight{false};
};

struct CorsApplication final {
  std::optional<ErrorResponse> rejection;
  std::optional<CorsResponseContext> response;
};

struct RequestContentApplication final {
  std::optional<ErrorResponse> rejection;
  std::optional<std::string_view> accept;
};

template <typename AddHeader>
void append_cors_response_headers(const CorsResponseContext& context,
                                  AddHeader&& add_header) {
  const auto& policy = *context.policy;
  add_header("access-control-allow-origin",
             policy.allow_any_origin() ? std::string_view{"*"}
                                       : context.origin);
  if (policy.allow_credentials()) {
    add_header("access-control-allow-credentials", "true");
  }
  if (context.preflight) {
    add_header("access-control-allow-methods",
               policy.allowed_methods_value());
    if (!policy.allowed_headers_value().empty()) {
      add_header("access-control-allow-headers",
                 policy.allowed_headers_value());
    }
    add_header("access-control-max-age", policy.max_age_value());
    add_header(
        "vary",
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
  } else {
    if (!policy.exposed_headers_value().empty()) {
      add_header("access-control-expose-headers",
                 policy.exposed_headers_value());
    }
    if (!policy.allow_any_origin()) {
      add_header("vary", "Origin");
    }
  }
}

struct PreparedApiKeyAuth final {
  std::string header_name;
  std::shared_ptr<const ApiKeyCredentialSet> credentials;
};

struct PreparedJwtAuth final {
  PreparedJwtAuth(std::unique_ptr<JwtValidator> prepared_validator,
                  RuntimeLocalRateLimit verification_rate_limit)
      : validator(std::move(prepared_validator)),
        verification_budget(RuntimeRouteAdmissionPolicy{
            0U, verification_rate_limit}) {}

  std::unique_ptr<JwtValidator> validator;
  ShardLocalRouteAdmission verification_budget;
};

std::optional<ErrorResponse> try_enforce_source_ip_policy(
    const SourceIpPolicy* policy, std::string_view client_address,
    GatewayStats& stats) {
  if (policy == nullptr) {
    return std::nullopt;
  }
  if (policy->allows(client_address)) {
    ++stats.source_ip_policy_allows;
    return std::nullopt;
  }
  ++stats.source_ip_policy_rejections;
  return ErrorResponse{403U, "source_ip_denied",
                       "The client address is not allowed for this route",
                       false, false, false};
}

std::optional<ErrorResponse> try_authenticate_api_key(
    const PreparedApiKeyAuth* policy, const void* header_context,
    RequestHeaderLookup header_lookup, GatewayStats& stats) {
  if (policy == nullptr) {
    return std::nullopt;
  }
  const auto credential =
      header_lookup(header_context, policy->header_name);
  if (credential.present && !credential.repeated &&
      policy->credentials->authorizes(credential.value)) {
    ++stats.api_key_auth_successes;
    return std::nullopt;
  }
  ++stats.api_key_auth_rejections;
  return ErrorResponse{401U, "unauthorized", "A valid API key is required",
                       false, false, false};
}

std::optional<ErrorResponse> try_authenticate_jwt(
    PreparedJwtAuth* policy, const void* header_context,
    RequestHeaderLookup header_lookup, GatewayStats& stats) {
  if (policy == nullptr) {
    return std::nullopt;
  }
  const auto authorization = header_lookup(header_context, "authorization");
  if (!authorization.present || authorization.repeated) {
    ++stats.jwt_auth_rejections;
    return ErrorResponse{401U, "unauthorized",
                         "A valid bearer token is required", false, false,
                         false};
  }
  if (policy->verification_budget.try_acquire(
          ShardLocalRouteAdmission::Clock::now()) !=
      RouteAdmission::admitted) {
    ++stats.overload_rejections;
    ++stats.jwt_verification_overload_rejections;
    return ErrorResponse{503U, "jwt_verification_overloaded",
                         "JWT verification capacity is temporarily exhausted",
                         false, false, false};
  }
  const auto result = policy->validator->authorize_bearer(authorization.value);
  policy->verification_budget.release();
  switch (result) {
    case JwtAuthorizationResult::authorized:
      ++stats.jwt_auth_successes;
      return std::nullopt;
    case JwtAuthorizationResult::invalid_token:
      ++stats.jwt_auth_rejections;
      return ErrorResponse{401U, "unauthorized",
                           "A valid bearer token is required", false, false,
                           false};
    case JwtAuthorizationResult::insufficient_scope:
      ++stats.jwt_authorization_rejections;
      return ErrorResponse{403U, "forbidden",
                           "The bearer token is not authorized for this route",
                           false, false, false};
  }
  throw std::logic_error("unknown JWT authorization result");
}

std::optional<ErrorResponse> try_admit_route(
    ShardLocalRouteAdmission* admission, GatewayStats& stats) {
  if (admission == nullptr) {
    return std::nullopt;
  }
  switch (admission->try_acquire(ShardLocalRouteAdmission::Clock::now())) {
    case RouteAdmission::admitted:
      ++stats.active_route_requests;
      return std::nullopt;
    case RouteAdmission::rate_limited:
      ++stats.route_rate_limit_rejections;
      return ErrorResponse{429U, "rate_limited",
                           "The route's local rate limit is exhausted", false,
                           false, false};
    case RouteAdmission::concurrency_limited:
      ++stats.overload_rejections;
      ++stats.route_overload_rejections;
      return ErrorResponse{503U, "route_overloaded",
                           "The route's per-shard concurrency limit is full",
                           false, false, false};
  }
  throw std::logic_error("unknown route admission result");
}

void release_route(ShardLocalRouteAdmission* admission,
                   GatewayStats& stats) {
  if (admission == nullptr) {
    return;
  }
  admission->release();
  --stats.active_route_requests;
}

ErrorResponse classify_error(std::exception_ptr error) {
  try {
    std::rethrow_exception(std::move(error));
  } catch (const bonvoyage::http::RequestError& request_error) {
    const auto timeout = request_error.code() == "request_timeout";
    return ErrorResponse{request_error.status_code(), request_error.code(),
                         request_error.what(),
                         request_error.close_connection(), timeout, false};
  } catch (const Overloaded& overloaded) {
    return ErrorResponse{503U, "upstream_overloaded", overloaded.what(), false,
                         false, false};
  } catch (const NoHealthyUpstream& unavailable) {
    return ErrorResponse{503U, "no_healthy_upstream", unavailable.what(),
                         false, false, false};
  } catch (const ConnectTimedOut& timeout) {
    return ErrorResponse{504U, "upstream_connect_timeout", timeout.what(),
                         true, true, true};
  } catch (const UpstreamAttemptTimedOut& timeout) {
    return ErrorResponse{504U, "upstream_attempt_timeout", timeout.what(),
                         true, true, true};
  } catch (const seastar::abort_requested_exception&) {
    return ErrorResponse{504U, "request_timeout",
                         "The upstream request timed out", true, true, false};
  } catch (seastar::nested_exception& nested) {
    try {
      nested.rethrow_nested();
    } catch (...) {
      return classify_error(std::current_exception());
    }
  } catch (const std::exception& exception) {
    gateway_log.debug("request failed: {}", exception.what());
    return ErrorResponse{502U, "upstream_failure",
                         "The upstream request failed", true, false, true};
  } catch (...) {
    return ErrorResponse{};
  }
}

std::string_view reason_phrase(std::uint16_t status) {
  switch (status) {
    case 101:
      return "Switching Protocols";
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 202:
      return "Accepted";
    case 204:
      return "No Content";
    case 206:
      return "Partial Content";
    case 301:
      return "Moved Permanently";
    case 302:
      return "Found";
    case 303:
      return "See Other";
    case 304:
      return "Not Modified";
    case 307:
      return "Temporary Redirect";
    case 308:
      return "Permanent Redirect";
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 408:
      return "Request Timeout";
    case 413:
      return "Payload Too Large";
    case 414:
      return "URI Too Long";
    case 417:
      return "Expectation Failed";
    case 421:
      return "Misdirected Request";
    case 426:
      return "Upgrade Required";
    case 429:
      return "Too Many Requests";
    case 431:
      return "Request Header Fields Too Large";
    case 500:
      return "Internal Server Error";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    case 504:
      return "Gateway Timeout";
    case 505:
      return "HTTP Version Not Supported";
    default:
      return "";
  }
}

[[nodiscard]] std::uint32_t grpc_status_for_http_error(
    std::uint16_t status) noexcept {
  switch (status) {
    case 400U:
    case 415U:
    case 431U:
      return 3U;
    case 401U:
      return 16U;
    case 403U:
      return 7U;
    case 404U:
    case 405U:
      return 12U;
    case 408U:
    case 504U:
      return 4U;
    case 409U:
      return 10U;
    case 413U:
    case 429U:
      return 8U;
    case 502U:
    case 503U:
      return 14U;
    default:
      return 13U;
  }
}

std::string json_escape(std::string_view value) {
  std::string escaped;
  escaped.reserve(value.size());
  for (const auto character : value) {
    switch (character) {
      case '\\':
        escaped += "\\\\";
        break;
      case '"':
        escaped += "\\\"";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(character) >= 0x20U) {
          escaped.push_back(character);
        }
    }
  }
  return escaped;
}

void record_response_status(GatewayStats& stats, std::uint16_t status) {
  if (status < 300U) {
    ++stats.responses_2xx;
  } else if (status < 400U) {
    ++stats.responses_3xx;
  } else if (status < 500U) {
    ++stats.responses_4xx;
  } else {
    ++stats.responses_5xx;
  }
}

bool safe_header_value(std::string_view value) {
  return std::none_of(value.begin(), value.end(), [](char character) {
    const auto byte = static_cast<unsigned char>(character);
    return (byte < 0x20U && byte != '\t') || byte == 0x7fU;
  });
}

bool apply_request_header_mutations(
    seastar::http::request& request,
    std::span<const HeaderMutation> mutations, std::size_t max_bytes) {
  std::vector<MutableHeader> headers;
  headers.reserve(request._headers.size() + mutations.size());
  for (const auto& [name, value] : request._headers) {
    headers.emplace_back(std::string(name), std::string(value));
  }
  if (!apply_header_mutations(headers, mutations, max_bytes)) {
    return false;
  }
  request._headers.clear();
  for (const auto& [name, value] : headers) {
    request._headers[seastar::sstring(name.data(), name.size())] =
        seastar::sstring(value.data(), value.size());
  }
  return true;
}

bool request_headers_within_limit(const seastar::http::request& request,
                                  std::size_t maximum) noexcept {
  std::size_t total = 0U;
  for (const auto& [name, value] : request._headers) {
    constexpr std::size_t delimiter_bytes = 4U;  // ": " and CRLF.
    if (name.size() > maximum || value.size() > maximum ||
        delimiter_bytes > maximum || total > maximum - delimiter_bytes ||
        name.size() > maximum - total - delimiter_bytes) {
      return false;
    }
    total += name.size() + delimiter_bytes;
    if (value.size() > maximum - total) {
      return false;
    }
    total += value.size();
  }
  return true;
}

bool apply_http2_response_header_mutations(
    std::vector<bonvoyage::http::Http2Header>& headers,
    std::span<const HeaderMutation> mutations, std::size_t max_bytes) {
  std::vector<MutableHeader> mutable_headers;
  mutable_headers.reserve(headers.size() + mutations.size());
  for (const auto& header : headers) {
    mutable_headers.emplace_back(header.name, header.value);
  }
  if (!apply_header_mutations(mutable_headers, mutations, max_bytes)) {
    return false;
  }
  headers.clear();
  headers.reserve(mutable_headers.size());
  for (auto& [name, value] : mutable_headers) {
    headers.push_back(
        {std::move(name), std::move(value), false});
  }
  return true;
}

void validate_and_record_upstream_trailers(
    GatewayStats& stats, const seastar::http::reply& reply) {
  if (reply.trailing_headers.empty()) {
    return;
  }
  for (const auto& [name, value] : reply.trailing_headers) {
    if (name.empty() || !safe_header_value(value)) {
      throw std::runtime_error(
          "upstream response contains an unsafe trailer field");
    }
  }
  ++stats.upstream_response_trailers_dropped;
}

std::vector<bonvoyage::http::Http2Header> grpc_status_headers(
    const seastar::http::reply& reply) {
  std::vector<bonvoyage::http::Http2Header> result;
  for (const auto& [raw_name, value] : reply._headers) {
    const auto name = bonvoyage::http::lowercase(raw_name);
    if (name == "grpc-status" || name == "grpc-message" ||
        name == "grpc-status-details-bin") {
      result.push_back({name, std::string(value),
                        name == "grpc-status-details-bin"});
    }
  }
  return result;
}

std::vector<bonvoyage::http::Http2Header> grpc_response_trailers(
    const seastar::http::reply& reply) {
  std::vector<bonvoyage::http::Http2Header> result;
  result.reserve(reply.trailing_headers.size());
  for (const auto& [raw_name, value] : reply.trailing_headers) {
    const auto name = bonvoyage::http::lowercase(raw_name);
    if (!safe_header_value(value)) {
      throw std::invalid_argument("unsafe gRPC response trailer value");
    }
    result.push_back({name, std::string(value),
                      name == "grpc-status-details-bin"});
  }
  return result;
}

void record_grpc_status(GatewayStats& stats,
                        const bonvoyage::http::GrpcTrailerInfo& info) {
  if (info.status == 0U) {
    ++stats.grpc_successes;
  } else {
    ++stats.grpc_application_errors;
  }
  stats.grpc_trailing_metadata_fields += info.custom_metadata_fields;
}

bool keep_alive(std::string_view version, std::string_view connection) {
  const auto has_close =
      bonvoyage::http::connection_has_token(connection, "close");
  const auto has_keep_alive =
      bonvoyage::http::connection_has_token(connection, "keep-alive");
  return version == "1.1" ? !has_close : has_keep_alive;
}

struct RequestTarget final {
  std::string_view path;
  std::string_view query;
};

RequestTarget split_request_target(std::string_view target) {
  const auto query = target.find('?');
  if (query == std::string_view::npos) {
    return RequestTarget{target, {}};
  }
  return RequestTarget{target.substr(0U, query), target.substr(query + 1U)};
}

RequestHeaderLookupResult find_http1_request_header(
    const void* context, std::string_view lowercase_name) noexcept {
  const auto& request = *static_cast<const seastar::http::request*>(context);
  RequestHeaderLookupResult result;
  for (const auto& [name, value] : request._headers) {
    if (!bonvoyage::http::ascii_case_equal(name, lowercase_name)) {
      continue;
    }
    if (result.present) {
      result.repeated = true;
      continue;
    }
    result.value = value;
    result.present = true;
  }
  return result;
}

RequestHeaderLookupResult find_http2_request_header(
    const void* context, std::string_view lowercase_name) noexcept {
  const auto& headers = *static_cast<
      const std::vector<bonvoyage::http::Http2Header>*>(context);
  RequestHeaderLookupResult result;
  for (const auto& header : headers) {
    if (header.name != lowercase_name) {
      continue;
    }
    if (result.present) {
      result.repeated = true;
      continue;
    }
    result.value = header.value;
    result.present = true;
  }
  return result;
}

struct GrpcRequestContract final {
  std::optional<std::chrono::nanoseconds> timeout;
  bool compression_allowed{false};
};

[[nodiscard]] bool grpc_call_definition_header(
    std::string_view name) noexcept {
  constexpr std::array<std::string_view, 8U> headers{
      "content-length", "content-type", "grpc-accept-encoding",
      "grpc-encoding", "grpc-message-type", "grpc-timeout", "te",
      "user-agent"};
  return std::find(headers.begin(), headers.end(), name) != headers.end();
}

GrpcRequestContract validate_grpc_request_contract(
    const bonvoyage::http::Http2RequestHead& request) {
  if (request.method != "POST") {
    throw bonvoyage::http::RequestError(
        400U, "invalid_grpc_method", "Native gRPC requires HTTP POST", false);
  }
  if (!bonvoyage::http::is_grpc_method_path(request.path)) {
    throw bonvoyage::http::RequestError(
        400U, "invalid_grpc_path",
        "Native gRPC requires a /service/method request path", false);
  }

  const auto content_type = find_http2_request_header(
      &request.headers, "content-type");
  if (!content_type.present || content_type.repeated ||
      !bonvoyage::http::is_grpc_content_type(content_type.value)) {
    throw bonvoyage::http::RequestError(
        415U, "invalid_grpc_content_type",
        "Native gRPC requires one application/grpc content type", false);
  }
  const auto te = find_http2_request_header(&request.headers, "te");
  if (!te.present || te.repeated || te.value != "trailers") {
    throw bonvoyage::http::RequestError(
        400U, "invalid_grpc_te",
        "Native gRPC requires exactly one TE: trailers field", false);
  }

  GrpcRequestContract result;
  const auto timeout = find_http2_request_header(
      &request.headers, "grpc-timeout");
  if (timeout.repeated) {
    throw bonvoyage::http::RequestError(
        400U, "invalid_grpc_timeout", "grpc-timeout must not be repeated",
        false);
  }
  if (timeout.present) {
    try {
      result.timeout = bonvoyage::http::parse_grpc_timeout(timeout.value);
    } catch (const std::invalid_argument&) {
      throw bonvoyage::http::RequestError(
          400U, "invalid_grpc_timeout", "grpc-timeout is malformed", false);
    }
  }

  const auto encoding = find_http2_request_header(
      &request.headers, "grpc-encoding");
  if (encoding.repeated || (encoding.present && encoding.value.empty())) {
    throw bonvoyage::http::RequestError(
        400U, "invalid_grpc_encoding", "grpc-encoding is malformed", false);
  }
  result.compression_allowed =
      encoding.present && encoding.value != "identity";

  try {
    for (const auto& header : request.headers) {
      if (grpc_call_definition_header(header.name)) {
        continue;
      }
      bonvoyage::http::validate_grpc_metadata(header.name, header.value);
    }
  } catch (const std::invalid_argument&) {
    throw bonvoyage::http::RequestError(
        400U, "invalid_grpc_metadata", "gRPC metadata is malformed", false);
  }
  return result;
}

CorsRequestInspection inspect_cors_request_fields(
    std::string_view method, RequestHeaderLookupResult origin,
    RequestHeaderLookupResult requested_method,
    RequestHeaderLookupResult requested_headers) noexcept {
  CorsRequestInspection result;
  result.origin = origin.value;
  result.requested_method = requested_method.value;
  result.requested_headers = requested_headers.value;
  const auto preflight_control_present =
      requested_method.present || requested_headers.present;
  if (preflight_control_present) {
    result.kind = CorsRequestKind::preflight;
    result.malformed =
        method != "OPTIONS" || !origin.present || origin.repeated ||
        !requested_method.present || requested_method.repeated ||
        requested_headers.repeated ||
        !is_canonical_cors_method(requested_method.value);
    return result;
  }
  if (origin.present) {
    result.kind = CorsRequestKind::actual;
    result.malformed = origin.repeated;
  }
  return result;
}

CorsRequestInspection inspect_cors_request(
    std::string_view method, const void* header_context,
    RequestHeaderLookup header_lookup) noexcept {
  return inspect_cors_request_fields(
      method, header_lookup(header_context, "origin"),
      header_lookup(header_context, "access-control-request-method"),
      header_lookup(header_context, "access-control-request-headers"));
}

CorsApplication apply_cors_policy(const CorsPolicy* policy,
                                  const CorsRequestInspection& request,
                                  std::string_view actual_method,
                                  GatewayStats& stats) {
  if (policy == nullptr || request.kind == CorsRequestKind::none) {
    return {};
  }
  const auto reject = [&stats](std::uint16_t status, std::string code,
                               std::string message) {
    ++stats.cors_rejections;
    CorsApplication result;
    result.rejection = ErrorResponse{status, std::move(code),
                                     std::move(message), false, false, false};
    return result;
  };
  if (request.malformed || !is_canonical_cors_origin(request.origin)) {
    return reject(400U, "invalid_cors_request",
                  "The CORS request fields are malformed");
  }
  const auto response_origin = policy->response_origin(request.origin);
  if (!response_origin.has_value()) {
    return reject(403U, "cors_origin_denied",
                  "The request origin is not allowed for this route");
  }
  const auto requested_method =
      request.kind == CorsRequestKind::preflight ? request.requested_method
                                                 : actual_method;
  if (!policy->allows_method(requested_method)) {
    return reject(403U, "cors_method_denied",
                  "The request method is not allowed by the CORS policy");
  }
  if (request.kind == CorsRequestKind::preflight) {
    switch (policy->allows_request_headers(request.requested_headers)) {
      case CorsHeaderDecision::malformed:
        return reject(400U, "invalid_cors_request",
                      "Access-Control-Request-Headers is malformed");
      case CorsHeaderDecision::denied:
        return reject(
            403U, "cors_headers_denied",
            "A requested field is not allowed by the CORS policy");
      case CorsHeaderDecision::allowed:
        break;
    }
    ++stats.cors_preflight_successes;
  } else {
    ++stats.cors_actual_allows;
  }
  CorsApplication result;
  result.response = CorsResponseContext{
      policy, *response_origin, request.kind == CorsRequestKind::preflight};
  return result;
}

RequestContentApplication apply_request_content_policy(
    const RequestContentPolicy* policy, const void* header_context,
    RequestHeaderLookup header_lookup, bool body_capable,
    std::optional<std::uint64_t> declared_body_bytes,
    std::uint64_t observed_body_bytes, GatewayStats& stats) {
  if (policy == nullptr) {
    return {};
  }
  const auto reject = [](std::uint16_t status, std::string code,
                         std::string message) {
    RequestContentApplication result;
    result.rejection = ErrorResponse{status, std::move(code),
                                     std::move(message), false, false, false};
    return result;
  };
  if (policy->maximum_body_bytes().has_value() &&
      (declared_body_bytes.value_or(0U) >
           *policy->maximum_body_bytes() ||
       observed_body_bytes > *policy->maximum_body_bytes())) {
    ++stats.request_body_limit_rejections;
    return reject(413U, "request_body_too_large",
                  "Request body exceeds the route limit");
  }
  if (policy->constrains_content_type()) {
    const auto content_type = header_lookup(header_context, "content-type");
    switch (policy->evaluate_content_type(
        content_type.value, content_type.present, content_type.repeated,
        body_capable)) {
      case RequestContentTypeDecision::allowed:
        break;
      case RequestContentTypeDecision::required: {
        ++stats.request_content_type_rejections;
        auto result = reject(415U, "content_type_required",
                             "Content-Type is required for this route");
        result.accept = policy->accept_header_value();
        return result;
      }
      case RequestContentTypeDecision::unsupported: {
        ++stats.request_content_type_rejections;
        auto result = reject(415U, "unsupported_media_type",
                             "Content-Type is not allowed for this route");
        result.accept = policy->accept_header_value();
        return result;
      }
      case RequestContentTypeDecision::malformed:
        ++stats.request_content_type_rejections;
        return reject(400U, "invalid_content_type",
                      "Content-Type is malformed or repeated");
      case RequestContentTypeDecision::too_large:
        ++stats.request_content_type_rejections;
        return reject(431U, "content_type_too_large",
                      "Content-Type exceeds the route policy limit");
    }
  }
  ++stats.request_content_policy_allows;
  return {};
}

struct ForwardedForHeaderFields final {
  std::array<std::string_view, kMaximumForwardedForHops + 1U> values{};
  std::size_t count{};

  [[nodiscard]] std::span<const std::string_view> view() const noexcept {
    return {values.data(), count};
  }
};

ForwardedForHeaderFields find_http2_forwarded_for_fields(
    const std::vector<bonvoyage::http::Http2Header>& headers) noexcept {
  ForwardedForHeaderFields result;
  for (const auto& header : headers) {
    if (header.name != "x-forwarded-for") {
      continue;
    }
    if (result.count == result.values.size()) {
      break;
    }
    result.values[result.count++] = header.value;
  }
  return result;
}

std::string format_peer_address(
    const seastar::socket_address& address) {
  const auto formatted = seastar::format("{}", address.addr());
  return {formatted.data(), formatted.size()};
}

std::string secret_path(std::string_view directory,
                        std::string_view secret_name) {
  const std::filesystem::path root(directory);
  if (!root.is_absolute() || root == root.root_path()) {
    throw std::invalid_argument(
        "secrets directory must be an absolute non-root path");
  }
  std::error_code error;
  const auto canonical_root = std::filesystem::canonical(root, error);
  if (error || canonical_root == canonical_root.root_path()) {
    throw std::invalid_argument("secrets directory cannot be resolved");
  }
  const auto resolved =
      std::filesystem::canonical(canonical_root / secret_name, error);
  if (error || !std::filesystem::is_regular_file(resolved, error) || error) {
    throw std::invalid_argument(
        "secret reference must resolve to a readable regular file");
  }
  const auto relative = resolved.lexically_relative(canonical_root);
  if (relative.empty() || relative.begin() == relative.end() ||
      *relative.begin() == "..") {
    throw std::invalid_argument("secret reference escapes the secrets directory");
  }
  return resolved.string();
}

seastar::future<std::string> read_api_key_secret(
    const std::string& path) {
  auto file = co_await seastar::open_file_dma(path, seastar::open_flags::ro);
  const auto size = co_await file.size();
  if (size == 0U || size > kMaximumApiKeySecretBytes) {
    co_await file.close();
    throw std::invalid_argument(
        "API-key secret must contain between 1 byte and 16 KiB");
  }
  auto input = seastar::make_file_input_stream(file, 0U, size);
  auto read = co_await seastar::coroutine::as_future(
      seastar::util::read_entire_stream_contiguous(input));
  co_await input.close().handle_exception([](const std::exception_ptr&) {});
  co_await file.close().handle_exception([](const std::exception_ptr&) {});
  if (read.failed()) {
    std::rethrow_exception(read.get_exception());
  }
  auto bytes = read.get();
  auto erase_bytes = seastar::defer([&bytes] {
    secure_erase(std::span<char>{bytes.data(), bytes.size()});
  });
  co_return std::string(bytes.data(), bytes.size());
}

seastar::future<std::string> read_jwt_jwks(const std::string& path) {
  auto file = co_await seastar::open_file_dma(path, seastar::open_flags::ro);
  const auto size = co_await file.size();
  if (size == 0U || size > kMaximumJwtJwksBytes) {
    co_await file.close();
    throw std::invalid_argument(
        "JWT JWKS must contain between 1 byte and 64 KiB");
  }
  auto input = seastar::make_file_input_stream(file, 0U, size);
  auto read = co_await seastar::coroutine::as_future(
      seastar::util::read_entire_stream_contiguous(input));
  co_await input.close().handle_exception([](const std::exception_ptr&) {});
  co_await file.close().handle_exception([](const std::exception_ptr&) {});
  if (read.failed()) {
    std::rethrow_exception(read.get_exception());
  }
  const auto bytes = read.get();
  co_return std::string(bytes.data(), bytes.size());
}

struct ResolvedEndpointAddress final {
  ResolvedEndpointAddress(seastar::socket_address socket_address,
                          std::string display_address)
      : socket_address(socket_address),
        display_address(std::move(display_address)) {}

  seastar::socket_address socket_address;
  std::string display_address;
};

class TimedConnectionFactory final
    : public seastar::http::experimental::connection_factory {
 public:
  TimedConnectionFactory(
      seastar::shared_ptr<ResolvedEndpointAddress> address,
      std::chrono::milliseconds timeout,
      seastar::shared_ptr<seastar::tls::certificate_credentials>
          tls_credentials,
      seastar::sstring tls_server_name, std::string_view alpn_protocol,
      bool require_alpn, GatewayStats& stats)
      : address_(std::move(address)),
        timeout_(timeout),
        tls_credentials_(std::move(tls_credentials)),
        tls_server_name_(std::move(tls_server_name)),
        alpn_protocol_(alpn_protocol),
        require_alpn_(require_alpn),
        stats_(stats) {}

  seastar::future<seastar::connected_socket> make(
      seastar::abort_source* abort) override {
    const auto address = address_->socket_address;
    return seastar::do_with(
        seastar::engine().net().socket(),
        std::optional<seastar::connected_socket>{}, seastar::timer<>{}, false,
        [this, abort, address](seastar::socket& socket,
                              std::optional<seastar::connected_socket>& connection,
                              seastar::timer<>& timer, bool& timed_out) {
          const auto shutdown = [this, &socket, &connection]() noexcept {
            if (connection.has_value()) {
              if (tls_credentials_ != nullptr) {
                try {
                  seastar::tls::abort(*connection);
                  return;
                } catch (...) {
                  // The transport may still be cleartext between TCP connect
                  // completion and TLS wrapping; use ordinary socket shutdown.
                }
              }
              connection->shutdown_input();
              connection->shutdown_output();
            } else {
              socket.shutdown();
            }
          };
          timer.set_callback([&timed_out, shutdown] {
            timed_out = true;
            shutdown();
          });
          seastar::optimized_optional<seastar::abort_source::subscription>
              subscription;
          if (abort != nullptr) {
            if (abort->abort_requested()) {
              return seastar::make_exception_future<
                  seastar::connected_socket>(
                  seastar::abort_requested_exception{});
            }
            subscription = abort->subscribe(shutdown);
          }
          gateway_log.debug("connecting to upstream {}", address);
          timer.arm(seastar::timer<>::clock::now() + timeout_);
          auto connecting = socket.connect(address);
          return seastar::do_with(
              std::move(subscription),
              [this, &connection, &timer, &timed_out,
               connecting = std::move(connecting)](auto&) mutable {
                return std::move(connecting).then_wrapped(
                    [this, &connection, &timer, &timed_out](
                        seastar::future<seastar::connected_socket> result) {
                      if (result.failed()) {
                        timer.cancel();
                        if (timed_out) {
                          result.ignore_ready_future();
                          return seastar::make_exception_future<
                              seastar::connected_socket>(ConnectTimedOut{});
                        }
                        return result;
                      }
                      connection.emplace(result.get());
                      if (!tls_credentials_) {
                        timer.cancel();
                        gateway_log.debug("upstream connect completed");
                        return seastar::make_ready_future<
                            seastar::connected_socket>(
                            std::move(*connection));
                      }

                      ++stats_.active_upstream_tls_handshakes;
                      seastar::tls::tls_options options;
                      options.server_name = tls_server_name_;
                      options.verify_certificate = true;
                      options.alpn_protocols.emplace_back(alpn_protocol_);
                      auto transport = std::move(*connection);
                      connection.reset();
                      auto negotiation = seastar::futurize_invoke(
                          [this, transport = std::move(transport),
                           options = std::move(options)]() mutable {
                            return seastar::tls::wrap_client(
                                tls_credentials_, std::move(transport),
                                std::move(options));
                          });
                      return std::move(negotiation)
                          .then([&connection](
                                    seastar::connected_socket secured) {
                            connection.emplace(std::move(secured));
                            return seastar::tls::get_negotiated_alpn(
                                *connection);
                          })
                          .then_wrapped(
                              [this, &connection, &timer,
                               &timed_out](auto negotiated) {
                                timer.cancel();
                                --stats_.active_upstream_tls_handshakes;
                                if (timed_out) {
                                  negotiated.ignore_ready_future();
                                  ++stats_.upstream_tls_handshake_timeouts;
                                  ++stats_.upstream_tls_handshake_failures;
                                  return seastar::make_exception_future<
                                      seastar::connected_socket>(
                                      ConnectTimedOut{});
                                }
                                if (negotiated.failed()) {
                                  ++stats_.upstream_tls_handshake_failures;
                                  return seastar::make_exception_future<
                                      seastar::connected_socket>(
                                      negotiated.get_exception());
                                }
                                const auto alpn = negotiated.get();
                                if ((require_alpn_ && !alpn.has_value()) ||
                                    (alpn.has_value() &&
                                     *alpn != alpn_protocol_)) {
                                  ++stats_.upstream_tls_handshake_failures;
                                  return seastar::make_exception_future<
                                      seastar::connected_socket>(
                                      std::runtime_error(
                                          "upstream TLS negotiated an unsupported ALPN protocol"));
                                }
                                ++stats_.upstream_tls_handshakes;
                                gateway_log.debug(
                                    "upstream TLS connect completed for {}",
                                    tls_server_name_);
                                return seastar::make_ready_future<
                                    seastar::connected_socket>(
                                    std::move(*connection));
                              });
                    });
              });
        });
  }

 private:
  seastar::shared_ptr<ResolvedEndpointAddress> address_;
  std::chrono::milliseconds timeout_;
  seastar::shared_ptr<seastar::tls::certificate_credentials>
      tls_credentials_;
  seastar::sstring tls_server_name_;
  seastar::sstring alpn_protocol_;
  bool require_alpn_;
  GatewayStats& stats_;
};

struct EndpointState final {
  seastar::shared_ptr<ResolvedEndpointAddress> resolved_address;
  std::unique_ptr<SelectedUpstreamHttp1Client> http1_client;
  std::unique_ptr<ShardLocalUpstreamHttp2Client> http2_client;
  std::string desired_dns_address;
  std::string published_dns_address;
  std::uint32_t consecutive_dns_failures{};
  bool desired_active_healthy{true};
  bool published_active_healthy{true};
  std::uint32_t active_http1_requests{};
};

UpstreamHttp2ClientMetrics upstream_http2_metrics(
    GatewayStats& stats) noexcept {
  return UpstreamHttp2ClientMetrics{
      .connections = &stats.upstream_http2_connections,
      .connection_failures = &stats.upstream_http2_connection_failures,
      .protocol_errors = &stats.upstream_http2_protocol_errors,
      .streams = &stats.upstream_http2_streams,
      .stream_resets = &stats.upstream_http2_stream_resets,
      .goaways = &stats.upstream_http2_goaways,
      .request_cancellations =
          &stats.upstream_http2_request_cancellations,
      .response_trailers = &stats.upstream_http2_response_trailers,
      .pool_waits = &stats.upstream_http2_pool_waits,
      .active_connections = &stats.active_upstream_http2_connections,
      .active_streams = &stats.active_upstream_http2_streams};
}

std::vector<std::uint32_t> endpoint_weights(const RuntimeCluster& cluster) {
  std::vector<std::uint32_t> weights;
  weights.reserve(cluster.endpoints.size());
  for (const auto& endpoint : cluster.endpoints) {
    weights.push_back(endpoint.weight);
  }
  return weights;
}

std::uint64_t endpoint_selector_seed(std::string_view cluster_name) noexcept {
  std::uint64_t hash = 1469598103934665603ULL;
  for (const auto character : cluster_name) {
    hash ^= static_cast<unsigned char>(character);
    hash *= 1099511628211ULL;
  }
  hash ^= static_cast<std::uint64_t>(seastar::this_shard_id()) +
          0x9e3779b97f4a7c15ULL;
  return hash;
}

bool neutral_endpoint_failure(const std::exception_ptr& error) {
  try {
    std::rethrow_exception(error);
  } catch (const seastar::abort_requested_exception&) {
    return true;
  } catch (const bonvoyage::http::RequestError&) {
    return true;
  } catch (...) {
    return false;
  }
}

class ClusterState final {
 public:
  /** One selected, admitted transport reserved for a WebSocket tunnel. */
  struct WebSocketTransport final {
    seastar::connected_socket socket;
    std::size_t endpoint_index{};
    seastar::semaphore_units<> admission;
  };

  ClusterState(const RuntimeCluster& config, GatewayStats& stats,
               std::string secrets_directory,
               std::size_t max_response_header_bytes,
               std::size_t max_chunk_metadata_bytes,
               bool trust_http1_connection_reuse)
      : config_(config),
        stats_(stats),
        secrets_directory_(std::move(secrets_directory)),
        max_response_header_bytes_(max_response_header_bytes),
        max_chunk_metadata_bytes_(max_chunk_metadata_bytes),
        trust_http1_connection_reuse_(trust_http1_connection_reuse),
        admission_(static_cast<std::size_t>(
            config.max_connections_per_shard +
            config.max_pending_requests_per_shard)),
        selector_(config.load_balancing_policy, endpoint_weights(config),
                  config.passive_health,
                  endpoint_selector_seed(config.name),
                  config.max_concurrent_requests_per_endpoint) {
    if (config_.active_health.has_value()) {
      active_health_tracker_.emplace(
          config_.endpoints.size(),
          config_.active_health->healthy_threshold,
          config_.active_health->unhealthy_threshold);
    }
    if (config_.retry.has_value()) {
      retry_budget_.emplace(config_.retry->budget);
    }
  }

  seastar::future<> start() {
    if (config_.upstream_tls.has_value()) {
      const auto& tls = *config_.upstream_tls;
      tls_credentials_ =
          seastar::make_shared<seastar::tls::certificate_credentials>();
      tls_credentials_->set_priority_string(seastar::sstring(kTlsPriority));
      co_await tls_credentials_->set_x509_trust_file(
          seastar::sstring(secret_path(secrets_directory_,
                                      tls.trust_bundle_secret)),
          seastar::tls::x509_crt_format::PEM);
      if (tls.certificate_chain_secret.has_value()) {
        co_await tls_credentials_->set_x509_key_file(
            seastar::sstring(secret_path(
                secrets_directory_, *tls.certificate_chain_secret)),
            seastar::sstring(
                secret_path(secrets_directory_, *tls.private_key_secret)),
            seastar::tls::x509_crt_format::PEM);
      }
      tls_server_name_ = seastar::sstring(tls.server_name);
    }
    if (config_.dns_refresh.has_value()) {
      seastar::net::dns_resolver::options options;
      options.timeout = std::chrono::milliseconds(
          config_.dns_refresh->resolve_timeout_ms);
      dns_resolver_ =
          std::make_unique<seastar::net::dns_resolver>(options);
    }
    endpoints_.reserve(config_.endpoints.size());
    endpoint_indices_.reserve(config_.endpoints.size());
    dns_endpoint_indices_.reserve(config_.endpoints.size());
    const auto endpoint_count = config_.endpoints.size();
    const auto base_connections =
        config_.max_connections_per_shard /
        static_cast<std::uint32_t>(endpoint_count);
    const auto extra_connections =
        config_.max_connections_per_shard %
        static_cast<std::uint32_t>(endpoint_count);
    for (std::size_t endpoint_index = 0U; endpoint_index < endpoint_count;
         ++endpoint_index) {
      const auto& endpoint = config_.endpoints[endpoint_index];
      seastar::net::inet_address address;
      if (endpoint.dns_hostname) {
        if (dns_resolver_ != nullptr) {
          address = co_await dns_resolver_->resolve_name(
              seastar::sstring(endpoint.address),
              seastar::net::inet_address::family::INET);
        } else {
          address = co_await seastar::net::dns::resolve_name(
              seastar::sstring(endpoint.address),
              seastar::net::inet_address::family::INET);
        }
      } else {
        address = seastar::net::inet_address(
            seastar::sstring(endpoint.address));
      }
      const auto display_address = fmt::format("{}", address);
      auto resolved_address =
          seastar::make_shared<ResolvedEndpointAddress>(
              seastar::socket_address{address, endpoint.port},
              display_address);
      const auto connections =
          base_connections + (endpoint_index < extra_connections ? 1U : 0U);
      auto factory = std::make_unique<TimedConnectionFactory>(
          resolved_address,
          std::chrono::milliseconds(config_.connect_timeout_ms),
          tls_credentials_, tls_server_name_,
          config_.protocol == RuntimeUpstreamProtocol::http2 ? kHttp2Alpn
                                                             : kHttp11Alpn,
          config_.protocol == RuntimeUpstreamProtocol::http2, stats_);
      EndpointState state;
      state.resolved_address = std::move(resolved_address);
      state.desired_dns_address = display_address;
      if (config_.protocol == RuntimeUpstreamProtocol::http2) {
        state.http2_client =
            std::make_unique<ShardLocalUpstreamHttp2Client>(
                std::move(factory), connections,
                config_.max_http2_streams_per_connection,
                max_response_header_bytes_, upstream_http2_metrics(stats_));
      } else {
        state.http1_client =
            std::make_unique<SelectedUpstreamHttp1Client>(
                std::move(factory), connections,
                max_response_header_bytes_, max_chunk_metadata_bytes_,
                [this](std::chrono::nanoseconds wait) noexcept {
                  ++stats_.upstream_http1_pool_waits;
                  if (wait.count() <= 0) {
                    return;
                  }
                  const auto elapsed = static_cast<std::uint64_t>(wait.count());
                  stats_.upstream_http1_pool_wait_nanoseconds += elapsed;
                  stats_.upstream_http1_pool_wait_max_nanoseconds = std::max(
                      stats_.upstream_http1_pool_wait_max_nanoseconds, elapsed);
                },
                trust_http1_connection_reuse_);
      }
      endpoints_.push_back(std::move(state));
      endpoint_indices_.push_back(endpoint_index);
      if (endpoint.dns_hostname) {
        dns_endpoint_indices_.push_back(endpoint_index);
      }
    }
  }

  seastar::future<> stop() {
    std::exception_ptr failure;
    auto preserve = [&failure](std::exception_ptr error) {
      if (failure == nullptr) {
        failure = std::move(error);
      }
    };
    co_await stop_maintenance().handle_exception(preserve);
    if (dns_resolver_ != nullptr && !dns_resolver_closed_) {
      co_await dns_resolver_->close().then([this] {
        dns_resolver_closed_ = true;
      }).handle_exception(preserve);
    }
    for (auto& endpoint : endpoints_) {
      if (endpoint.http2_client != nullptr) {
        co_await endpoint.http2_client->close().handle_exception(preserve);
      } else {
        co_await endpoint.http1_client->close().handle_exception(preserve);
      }
    }
    release_circuit_gauges();
    if (failure != nullptr) {
      std::rethrow_exception(failure);
    }
  }

  seastar::future<> start_maintenance(
      std::size_t cluster_index,
      GatewayShard::ActiveHealthPublisher active_health_publisher,
      GatewayShard::DnsAddressPublisher dns_address_publisher) {
    if (maintenance_started_) {
      throw std::logic_error("cluster maintenance was already started");
    }
    cluster_index_ = cluster_index;
    active_health_publisher_ = std::move(active_health_publisher);
    dns_address_publisher_ = std::move(dns_address_publisher);

    if (config_.dns_refresh.has_value()) {
      for (const auto endpoint_index : dns_endpoint_indices_) {
        auto& endpoint = endpoints_[endpoint_index];
        co_await dns_address_publisher_(cluster_index_, endpoint_index,
                                        endpoint.desired_dns_address);
        endpoint.published_dns_address = endpoint.desired_dns_address;
      }
    }

    maintenance_started_ = true;
    if (config_.active_health.has_value()) {
      active_health_loop_ = run_active_health_loop();
    }
    if (config_.dns_refresh.has_value()) {
      dns_refresh_loop_ = run_dns_refresh_loop();
    }
  }

  seastar::future<> stop_maintenance() {
    if (!maintenance_started_) {
      co_return;
    }
    maintenance_abort_.request_abort();
    std::exception_ptr failure;
    auto preserve = [&failure](std::exception_ptr error) {
      if (failure == nullptr) {
        failure = std::move(error);
      }
    };
    // Cancel pending DNS callbacks before waiting for maintenance to finish.
    // Resolver retries must not determine the gateway's shutdown duration.
    if (dns_resolver_ != nullptr && !dns_resolver_closed_) {
      co_await dns_resolver_->close().then([this] {
        dns_resolver_closed_ = true;
      }).handle_exception(preserve);
    }
    co_await std::move(active_health_loop_).handle_exception(preserve);
    co_await std::move(dns_refresh_loop_).handle_exception(preserve);
    maintenance_started_ = false;
    active_health_publisher_ = {};
    dns_address_publisher_ = {};
    if (failure != nullptr) {
      std::rethrow_exception(failure);
    }
  }

  void apply_active_health(std::size_t endpoint_index,
                           bool active_healthy) {
    if (!selector_.set_active_healthy(endpoint_index, active_healthy)) {
      return;
    }
    if (active_healthy) {
      if (stats_.active_unhealthy_endpoints == 0U) {
        throw std::logic_error("active unhealthy endpoint gauge underflow");
      }
      --stats_.active_unhealthy_endpoints;
    } else {
      ++stats_.active_unhealthy_endpoints;
    }
  }

  void apply_resolved_address(std::size_t endpoint_index,
                              const std::string& resolved_address) {
    if (endpoint_index >= endpoints_.size()) {
      throw std::out_of_range("resolved endpoint index is out of range");
    }
    auto& endpoint = endpoints_[endpoint_index];
    if (endpoint.resolved_address->display_address == resolved_address) {
      return;
    }
    const auto address =
        seastar::net::inet_address(seastar::sstring(resolved_address));
    endpoint.resolved_address->socket_address = seastar::socket_address{
        address, config_.endpoints[endpoint_index].port};
    endpoint.resolved_address->display_address = resolved_address;
  }

  using ReplyHandler = SelectedUpstreamHttp1Client::ReplyHandler;
  using RequestFactory = std::function<seastar::http::request()>;

  seastar::future<> make_endpoint_request(
      std::size_t endpoint_index, seastar::http::request request,
      ReplyHandler handler, seastar::abort_source* abort) {
    auto& endpoint = endpoints_[endpoint_index];
    if (endpoint.http2_client != nullptr) {
      return endpoint.http2_client->make_request(
          std::move(request), std::move(handler), abort);
    }
    ++endpoint.active_http1_requests;
    ++stats_.active_upstream_http1_requests;
    return endpoint.http1_client
        ->make_request(std::move(request), std::move(handler), abort)
        .finally([this, &endpoint] {
          if (endpoint.active_http1_requests == 0U ||
              stats_.active_upstream_http1_requests == 0U) {
            throw std::logic_error(
                "upstream HTTP/1 request gauge underflow");
          }
          --endpoint.active_http1_requests;
          --stats_.active_upstream_http1_requests;
        });
  }

  [[nodiscard]] bool retries_enabled_for(std::string_view method,
                                         bool request_replayable) const
      noexcept {
    return request_replayable && config_.retry.has_value() &&
           config_.retry->method_is_retryable(method);
  }

  /** Returns whether this cluster owns shard-local HTTP/2 transports. */
  [[nodiscard]] bool uses_http2() const noexcept {
    return config_.protocol == RuntimeUpstreamProtocol::http2;
  }

  seastar::future<WebSocketTransport> open_websocket_transport(
      seastar::abort_source* abort) {
    if (uses_http2()) {
      throw std::logic_error(
          "WebSocket transport requires an HTTP/1 upstream cluster");
    }
    auto admission = seastar::try_get_units(admission_, 1U);
    if (!admission.has_value()) {
      ++stats_.overload_rejections;
      ++stats_.cluster_overload_rejections;
      throw Overloaded();
    }
    const auto endpoint_index = select_endpoint_attempt();
    ++stats_.upstream_endpoint_selections;
    ++stats_.active_upstream_requests;
    try {
      TimedConnectionFactory factory(
          endpoints_[endpoint_index].resolved_address,
          std::chrono::milliseconds(config_.connect_timeout_ms),
          tls_credentials_, tls_server_name_, kHttp11Alpn, false, stats_);
      auto socket = co_await factory.make(abort);
      co_return WebSocketTransport{std::move(socket), endpoint_index,
                                std::move(*admission)};
    } catch (...) {
      const auto error = std::current_exception();
      const auto neutral =
          (abort != nullptr && abort->abort_requested()) ||
          neutral_endpoint_failure(error);
      if (!neutral) {
        ++stats_.upstream_passive_failures;
      }
      complete_endpoint_attempt(
          endpoint_index,
          neutral ? EndpointCompletion::neutral
                  : EndpointCompletion::passive_failure);
      std::rethrow_exception(error);
    }
  }

  /** Releases selector and admission state retained for one tunnel. */
  void complete_websocket_transport(std::size_t endpoint_index,
                                    EndpointCompletion outcome) {
    complete_endpoint_attempt(endpoint_index, outcome);
  }

  seastar::future<> make_request(seastar::http::request request,
                                 ReplyHandler handler,
                                 seastar::abort_source* abort,
                                 bool request_replayable,
                                 RequestFactory retry_request_factory = {}) {
    auto units = seastar::try_get_units(admission_, 1U);
    if (!units.has_value()) {
      ++stats_.overload_rejections;
      ++stats_.cluster_overload_rejections;
      throw Overloaded();
    }
    const auto method_retryable =
        config_.retry.has_value() &&
        config_.retry->method_is_retryable(request._method);
    if (method_retryable && !request_replayable) {
      ++stats_.retry_non_replayable_suppressions;
    }

    if (!method_retryable || !request_replayable) {
      const auto endpoint_index = select_endpoint_attempt();
      ++stats_.upstream_endpoint_selections;
      ++stats_.active_upstream_requests;
      gateway_log.debug("cluster={} endpoint={} handling request",
                        config_.name,
                        config_.endpoints[endpoint_index].name);
      bool response_head_received = false;
      auto tracked_handler =
          [handler = std::move(handler), &response_head_received](
              const seastar::http::reply& reply,
              seastar::input_stream<char>&& response_body) mutable {
            response_head_received = true;
            return handler(reply, std::move(response_body));
          };
      try {
        co_await make_endpoint_request(
            endpoint_index,
            std::move(request), std::move(tracked_handler), abort);
      } catch (const seastar::httpd::response_parsing_exception&) {
        ++stats_.upstream_framing_rejections;
        const auto outcome = response_head_received
                                 ? EndpointCompletion::success
                                 : EndpointCompletion::passive_failure;
        if (!response_head_received) {
          ++stats_.upstream_passive_failures;
        }
        complete_endpoint_attempt(endpoint_index, outcome);
        throw;
      } catch (const seastar::httpd::bad_request_exception&) {
        ++stats_.upstream_framing_rejections;
        const auto outcome = response_head_received
                                 ? EndpointCompletion::success
                                 : EndpointCompletion::passive_failure;
        if (!response_head_received) {
          ++stats_.upstream_passive_failures;
        }
        complete_endpoint_attempt(endpoint_index, outcome);
        throw;
      } catch (...) {
        const auto error = std::current_exception();
        auto outcome = EndpointCompletion::passive_failure;
        if (response_head_received) {
          outcome = EndpointCompletion::success;
        } else if (neutral_endpoint_failure(error)) {
          outcome = EndpointCompletion::neutral;
        } else {
          ++stats_.upstream_passive_failures;
        }
        complete_endpoint_attempt(endpoint_index, outcome);
        std::rethrow_exception(error);
      }
      complete_endpoint_attempt(endpoint_index, EndpointCompletion::success);
      co_return;
    }

    if (!retry_request_factory) {
      throw std::logic_error(
          "retryable request is missing its replay factory");
    }
    const auto& retry_policy = *config_.retry;
    const std::string request_method(request._method);
    auto downstream_handler = std::move(handler);
    std::uint32_t attempts_started = 0U;
    std::exception_ptr last_error;

    while (true) {
      if (abort != nullptr && abort->abort_requested()) {
        throw seastar::abort_requested_exception{};
      }
      const bool retry_attempt = attempts_started != 0U;
      if (retry_attempt) {
        const auto admission = retry_budget_->try_acquire(
            ShardLocalRetryBudget::Clock::now());
        if (admission != RetryAdmission::admitted) {
          if (admission == RetryAdmission::token_exhausted) {
            ++stats_.retry_token_rejections;
          } else {
            ++stats_.retry_concurrency_rejections;
          }
          std::rethrow_exception(last_error);
        }
        ++stats_.retry_attempts;
        ++stats_.active_retries;
      }
      auto release_retry = seastar::defer([this, retry_attempt] {
        if (!retry_attempt) {
          return;
        }
        retry_budget_->release();
        --stats_.active_retries;
      });

      auto attempt_request = retry_attempt ? retry_request_factory()
                                           : std::move(request);
      ++attempts_started;
      const auto endpoint_index = select_endpoint_attempt();
      ++stats_.upstream_endpoint_selections;
      ++stats_.active_upstream_requests;
      gateway_log.debug("cluster={} endpoint={} handling attempt={}",
                        config_.name,
                        config_.endpoints[endpoint_index].name,
                        attempts_started);

      auto commit_state = AttemptCommitState::not_started;
      bool attempt_timed_out = false;
      seastar::abort_source attempt_abort;
      seastar::optimized_optional<seastar::abort_source::subscription>
          request_subscription;
      if (abort != nullptr) {
        request_subscription = abort->subscribe(
            [&attempt_abort]() noexcept { attempt_abort.request_abort(); });
      }
      seastar::timer<> attempt_timer(
          [&attempt_timed_out, &attempt_abort]() noexcept {
            attempt_timed_out = true;
            attempt_abort.request_abort();
          });
      attempt_timer.arm(
          std::chrono::milliseconds(retry_policy.per_try_timeout_ms));
      auto tracked_handler =
          [&downstream_handler, &commit_state, &attempt_timer](
              const seastar::http::reply& reply,
              seastar::input_stream<char>&& response_body) mutable {
            commit_state = AttemptCommitState::response_head_received;
            attempt_timer.cancel();
            commit_state = AttemptCommitState::downstream_handoff;
            return downstream_handler(reply, std::move(response_body));
          };

      try {
        commit_state = AttemptCommitState::request_started;
        co_await make_endpoint_request(
            endpoint_index,
            std::move(attempt_request), std::move(tracked_handler),
            &attempt_abort);
      } catch (const seastar::httpd::response_parsing_exception&) {
        attempt_timer.cancel();
        ++stats_.upstream_framing_rejections;
        const auto committed =
            commit_state == AttemptCommitState::downstream_handoff;
        if (!committed) {
          ++stats_.upstream_passive_failures;
        }
        complete_endpoint_attempt(
            endpoint_index, committed ? EndpointCompletion::success
                                      : EndpointCompletion::passive_failure);
        throw;
      } catch (const seastar::httpd::bad_request_exception&) {
        attempt_timer.cancel();
        ++stats_.upstream_framing_rejections;
        const auto committed =
            commit_state == AttemptCommitState::downstream_handoff;
        if (!committed) {
          ++stats_.upstream_passive_failures;
        }
        complete_endpoint_attempt(
            endpoint_index, committed ? EndpointCompletion::success
                                      : EndpointCompletion::passive_failure);
        throw;
      } catch (...) {
        attempt_timer.cancel();
        const auto error = std::current_exception();
        const auto parent_aborted =
            abort != nullptr && abort->abort_requested();
        auto outcome = EndpointCompletion::passive_failure;
        if (commit_state == AttemptCommitState::downstream_handoff) {
          outcome = EndpointCompletion::success;
        } else if (parent_aborted ||
                   (!attempt_timed_out && neutral_endpoint_failure(error))) {
          outcome = EndpointCompletion::neutral;
        } else {
          ++stats_.upstream_passive_failures;
        }
        complete_endpoint_attempt(endpoint_index, outcome);

        if (attempt_timed_out && !parent_aborted) {
          ++stats_.retry_per_try_timeouts;
        }
        const auto failure =
            parent_aborted
                ? RetryFailureClass::cancelled
                : (attempt_timed_out
                       ? RetryFailureClass::per_try_timeout
                       : (neutral_endpoint_failure(error)
                              ? RetryFailureClass::cancelled
                              : RetryFailureClass::transport));
        const auto decision = evaluate_retry(
            retry_policy, request_method, true, attempts_started,
            commit_state, failure);
        if (decision == RetryDecision::retry) {
          last_error =
              attempt_timed_out && !parent_aborted
                  ? std::make_exception_ptr(UpstreamAttemptTimedOut{})
                  : error;
          continue;
        }
        if (decision == RetryDecision::attempts_exhausted) {
          ++stats_.retry_exhausted;
        } else if (decision == RetryDecision::response_committed) {
          ++stats_.retry_commit_suppressions;
        }
        if (attempt_timed_out && !parent_aborted) {
          throw UpstreamAttemptTimedOut();
        }
        std::rethrow_exception(error);
      }
      attempt_timer.cancel();
      complete_endpoint_attempt(endpoint_index, EndpointCompletion::success);
      if (attempts_started > 1U) {
        ++stats_.retry_successes;
      }
      co_return;
    }
  }

 private:
  [[nodiscard]] std::size_t select_endpoint_attempt() {
    const auto selection =
        selector_.select(ShardLocalEndpointSelector::Clock::now());
    if (selection.half_opened_endpoints != 0U) {
      if (stats_.open_endpoint_circuits <
          selection.half_opened_endpoints) {
        throw std::logic_error("open endpoint circuit gauge underflow");
      }
      stats_.upstream_passive_reactivations +=
          selection.half_opened_endpoints;
      stats_.endpoint_circuit_half_open_transitions +=
          selection.half_opened_endpoints;
      stats_.open_endpoint_circuits -= selection.half_opened_endpoints;
      stats_.half_open_endpoint_circuits +=
          selection.half_opened_endpoints;
    }
    if (selection.endpoint_index.has_value()) {
      return *selection.endpoint_index;
    }

    if (selection.rejection ==
        EndpointSelectionRejection::endpoint_concurrency_limit) {
      ++stats_.overload_rejections;
      ++stats_.endpoint_overload_rejections;
      throw Overloaded("every eligible endpoint reached its concurrency limit");
    }
    if (selection.rejection ==
        EndpointSelectionRejection::half_open_probe_limit) {
      ++stats_.overload_rejections;
      ++stats_.endpoint_circuit_probe_rejections;
      throw Overloaded("endpoint circuit recovery probe is already active");
    }
    ++stats_.upstream_no_eligible_endpoints;
    throw NoHealthyUpstream();
  }

  [[nodiscard]] std::string health_authority(
      std::size_t endpoint_index) const {
    const auto& health = *config_.active_health;
    if (health.host.has_value()) {
      return *health.host;
    }
    if (config_.upstream_tls.has_value()) {
      return config_.upstream_tls->server_name;
    }
    return config_.endpoints[endpoint_index].address;
  }

  [[nodiscard]] std::chrono::milliseconds maintenance_jitter(
      std::uint32_t interval_ms, std::uint64_t salt) const noexcept {
    const auto spread = std::max<std::uint32_t>(
        1U, std::min<std::uint32_t>(250U, interval_ms / 10U));
    const auto value = (endpoint_selector_seed(config_.name) ^ salt) % spread;
    return std::chrono::milliseconds(value + 1U);
  }

  seastar::future<> wait_for_next_cycle(
      std::chrono::steady_clock::time_point cycle_started,
      std::uint32_t interval_ms, std::uint64_t& overrun_counter) {
    const auto interval = std::chrono::milliseconds(interval_ms);
    const auto elapsed = std::chrono::steady_clock::now() - cycle_started;
    if (elapsed >= interval) {
      ++overrun_counter;
      co_return;
    }
    co_await seastar::sleep_abortable(interval - elapsed,
                                      maintenance_abort_);
  }

  seastar::future<std::optional<bool>> probe_endpoint(
      std::size_t endpoint_index) {
    if (maintenance_abort_.abort_requested()) {
      co_return std::nullopt;
    }
    const auto& health = *config_.active_health;
    std::unique_ptr<SelectedUpstreamHttp1Client> http1_client;
    if (config_.protocol == RuntimeUpstreamProtocol::http1) {
      auto factory = std::make_unique<TimedConnectionFactory>(
          endpoints_[endpoint_index].resolved_address,
          std::chrono::milliseconds(config_.connect_timeout_ms),
          tls_credentials_, tls_server_name_, kHttp11Alpn, false, stats_);
      http1_client = std::make_unique<SelectedUpstreamHttp1Client>(
          std::move(factory), 1U, max_response_header_bytes_,
          max_chunk_metadata_bytes_);
    }

    std::optional<std::uint16_t> response_status;
    seastar::abort_source probe_abort;
    seastar::optimized_optional<seastar::abort_source::subscription>
        maintenance_subscription;
    if (maintenance_abort_.abort_requested()) {
      if (http1_client != nullptr) {
        co_await http1_client->close().handle_exception(
            [](const std::exception_ptr&) {});
      }
      co_return std::nullopt;
    }
    maintenance_subscription = maintenance_abort_.subscribe(
        [&probe_abort]() noexcept { probe_abort.request_abort(); });
    bool timed_out = false;
    seastar::timer<> timer([&timed_out, &probe_abort] {
      timed_out = true;
      probe_abort.request_abort();
    });
    timer.arm(seastar::timer<>::clock::now() +
              std::chrono::milliseconds(health.timeout_ms));

    auto request = seastar::http::request::make(
        "GET", health_authority(endpoint_index), health.path);
    request._version = config_.protocol == RuntimeUpstreamProtocol::http2
                           ? "2"
                           : "1.1";
    if (config_.protocol == RuntimeUpstreamProtocol::http1) {
      request._headers["Connection"] = "close";
    }
    auto handler = [&response_status](
                       const seastar::http::reply& reply,
                       seastar::input_stream<char>&& response_body) {
      response_status = static_cast<std::uint16_t>(reply._status);
      return response_body.close().handle_exception(
          [](const std::exception_ptr&) {});
    };
    auto run_probe = [&]() -> seastar::future<> {
      if (config_.protocol == RuntimeUpstreamProtocol::http2) {
        return endpoints_[endpoint_index].http2_client->make_request(
            std::move(request), std::move(handler), &probe_abort);
      }
      return http1_client->make_request(
          std::move(request), std::move(handler), &probe_abort);
    };
    auto result = co_await seastar::coroutine::as_future(run_probe());
    timer.cancel();
    if (http1_client != nullptr) {
      co_await http1_client->close().handle_exception(
          [](const std::exception_ptr&) {});
    }

    if (maintenance_abort_.abort_requested()) {
      if (result.failed()) {
        result.ignore_ready_future();
      }
      co_return std::nullopt;
    }
    if (timed_out) {
      ++stats_.active_health_timeouts;
    }
    if (result.failed()) {
      result.ignore_ready_future();
    }
    if (!response_status.has_value()) {
      co_return false;
    }
    co_return *response_status >= health.expected_status_min &&
              *response_status <= health.expected_status_max;
  }

  seastar::future<> publish_pending_health() {
    for (const auto endpoint_index : endpoint_indices_) {
      auto& endpoint = endpoints_[endpoint_index];
      if (endpoint.desired_active_healthy ==
          endpoint.published_active_healthy) {
        continue;
      }
      try {
        co_await active_health_publisher_(
            cluster_index_, endpoint_index,
            endpoint.desired_active_healthy);
      } catch (...) {
        ++stats_.active_health_publish_failures;
        gateway_log.error(
            "event=active_health_publish_failed cluster={} endpoint={}",
            config_.name, config_.endpoints[endpoint_index].name);
        continue;
      }
      endpoint.published_active_healthy =
          endpoint.desired_active_healthy;
      ++stats_.active_health_state_changes;
      if (endpoint.published_active_healthy) {
        gateway_log.info(
            "event=active_health_recovered cluster={} endpoint={}",
            config_.name, config_.endpoints[endpoint_index].name);
      } else {
        gateway_log.warn(
            "event=active_health_excluded cluster={} endpoint={}",
            config_.name, config_.endpoints[endpoint_index].name);
      }
    }
  }

  seastar::future<> run_active_health_loop() {
    try {
      co_await seastar::sleep_abortable(
          maintenance_jitter(config_.active_health->interval_ms,
                             0x4845414c5448ULL),
          maintenance_abort_);
      while (!maintenance_abort_.abort_requested()) {
        const auto cycle_started = std::chrono::steady_clock::now();
        co_await seastar::max_concurrent_for_each(
            endpoint_indices_, kMaintenanceConcurrency,
            [this](std::size_t endpoint_index) -> seastar::future<> {
              const auto result = co_await probe_endpoint(endpoint_index);
              if (!result.has_value()) {
                co_return;
              }
              ++stats_.active_health_checks;
              if (*result) {
                ++stats_.active_health_successes;
              } else {
                ++stats_.active_health_failures;
              }
              const auto decision = active_health_tracker_->record_probe(
                  endpoint_index, *result);
              endpoints_[endpoint_index].desired_active_healthy =
                  decision.active_healthy;
            });
        if (maintenance_abort_.abort_requested()) {
          break;
        }
        co_await publish_pending_health();
        co_await wait_for_next_cycle(
            cycle_started, config_.active_health->interval_ms,
            stats_.active_health_cycle_overruns);
      }
    } catch (const seastar::sleep_aborted&) {
      // Expected during coordinated shutdown.
    }
  }

  seastar::future<> refresh_dns_endpoint(std::size_t endpoint_index) {
    if (maintenance_abort_.abort_requested()) {
      co_return;
    }
    auto& endpoint = endpoints_[endpoint_index];
    ++stats_.dns_refresh_attempts;
    try {
      const auto address = co_await dns_resolver_->resolve_name(
          seastar::sstring(config_.endpoints[endpoint_index].address),
          seastar::net::inet_address::family::INET);
      if (maintenance_abort_.abort_requested()) {
        co_return;
      }
      ++stats_.dns_refresh_successes;
      if (endpoint.consecutive_dns_failures != 0U) {
        gateway_log.info(
            "event=dns_refresh_recovered cluster={} endpoint={}",
            config_.name, config_.endpoints[endpoint_index].name);
      }
      endpoint.consecutive_dns_failures = 0U;
      endpoint.desired_dns_address = fmt::format("{}", address);
    } catch (...) {
      if (maintenance_abort_.abort_requested()) {
        co_return;
      }
      ++stats_.dns_refresh_failures;
      if (endpoint.consecutive_dns_failures !=
          std::numeric_limits<std::uint32_t>::max()) {
        ++endpoint.consecutive_dns_failures;
      }
      if (endpoint.consecutive_dns_failures == 1U) {
        gateway_log.warn(
            "event=dns_refresh_failed cluster={} endpoint={} action=retain_last_known_address",
            config_.name, config_.endpoints[endpoint_index].name);
      }
    }
  }

  seastar::future<> publish_pending_dns() {
    for (const auto endpoint_index : dns_endpoint_indices_) {
      auto& endpoint = endpoints_[endpoint_index];
      if (endpoint.desired_dns_address == endpoint.published_dns_address) {
        continue;
      }
      try {
        co_await dns_address_publisher_(
            cluster_index_, endpoint_index,
            endpoint.desired_dns_address);
      } catch (...) {
        ++stats_.dns_publish_failures;
        gateway_log.error(
            "event=dns_publish_failed cluster={} endpoint={}",
            config_.name, config_.endpoints[endpoint_index].name);
        continue;
      }
      endpoint.published_dns_address = endpoint.desired_dns_address;
      ++stats_.dns_address_changes;
      gateway_log.info(
          "event=dns_address_applied cluster={} endpoint={}",
          config_.name, config_.endpoints[endpoint_index].name);
    }
  }

  seastar::future<> run_dns_refresh_loop() {
    try {
      co_await seastar::sleep_abortable(
          std::chrono::milliseconds(
              config_.dns_refresh->refresh_interval_ms) +
              maintenance_jitter(config_.dns_refresh->refresh_interval_ms,
                                 0x444e53ULL),
          maintenance_abort_);
      while (!maintenance_abort_.abort_requested()) {
        const auto cycle_started = std::chrono::steady_clock::now();
        co_await seastar::max_concurrent_for_each(
            dns_endpoint_indices_, kMaintenanceConcurrency,
            [this](std::size_t endpoint_index) {
              return refresh_dns_endpoint(endpoint_index);
            });
        if (maintenance_abort_.abort_requested()) {
          break;
        }
        co_await publish_pending_dns();
        co_await wait_for_next_cycle(
            cycle_started, config_.dns_refresh->refresh_interval_ms,
            stats_.dns_refresh_cycle_overruns);
      }
    } catch (const seastar::sleep_aborted&) {
      // Expected during coordinated shutdown.
    }
  }

  void record_circuit_transition(
      std::size_t endpoint_index,
      const EndpointCompletionDecision& completion) {
    if (completion.opened) {
      ++stats_.upstream_passive_ejections;
      ++stats_.endpoint_circuit_opens;
      ++stats_.open_endpoint_circuits;
      gateway_log.warn("event=endpoint_circuit_opened cluster={} endpoint={}",
                       config_.name,
                       config_.endpoints[endpoint_index].name);
    }
    if (completion.reopened) {
      if (stats_.half_open_endpoint_circuits == 0U) {
        throw std::logic_error("half-open endpoint circuit gauge underflow");
      }
      ++stats_.upstream_passive_ejections;
      ++stats_.endpoint_circuit_reopens;
      --stats_.half_open_endpoint_circuits;
      ++stats_.open_endpoint_circuits;
      gateway_log.warn("event=endpoint_circuit_reopened cluster={} endpoint={}",
                       config_.name,
                       config_.endpoints[endpoint_index].name);
    }
    if (completion.closed) {
      if (stats_.half_open_endpoint_circuits == 0U) {
        throw std::logic_error("half-open endpoint circuit gauge underflow");
      }
      ++stats_.endpoint_circuit_closes;
      --stats_.half_open_endpoint_circuits;
      gateway_log.info("event=endpoint_circuit_closed cluster={} endpoint={}",
                       config_.name,
                       config_.endpoints[endpoint_index].name);
    }
  }

  void complete_endpoint_attempt(std::size_t endpoint_index,
                                 EndpointCompletion outcome) {
    const auto completion = selector_.complete(
        endpoint_index, outcome, ShardLocalEndpointSelector::Clock::now());
    --stats_.active_upstream_requests;
    record_circuit_transition(endpoint_index, completion);
  }

  void release_circuit_gauges() {
    if (circuit_gauges_released_) {
      return;
    }
    if (stats_.open_endpoint_circuits < selector_.open_circuits() ||
        stats_.half_open_endpoint_circuits <
            selector_.half_open_circuits()) {
      throw std::logic_error("endpoint circuit gauge cleanup underflow");
    }
    stats_.open_endpoint_circuits -= selector_.open_circuits();
    stats_.half_open_endpoint_circuits -= selector_.half_open_circuits();
    circuit_gauges_released_ = true;
  }

  const RuntimeCluster& config_;
  GatewayStats& stats_;
  std::string secrets_directory_;
  std::size_t max_response_header_bytes_;
  std::size_t max_chunk_metadata_bytes_;
  bool trust_http1_connection_reuse_;
  seastar::shared_ptr<seastar::tls::certificate_credentials>
      tls_credentials_;
  seastar::sstring tls_server_name_;
  std::unique_ptr<seastar::net::dns_resolver> dns_resolver_;
  seastar::semaphore admission_;
  ShardLocalEndpointSelector selector_;
  std::optional<ShardLocalRetryBudget> retry_budget_;
  std::optional<ActiveHealthTracker> active_health_tracker_;
  std::vector<EndpointState> endpoints_;
  std::vector<std::size_t> endpoint_indices_;
  std::vector<std::size_t> dns_endpoint_indices_;
  seastar::abort_source maintenance_abort_;
  seastar::future<> active_health_loop_{seastar::make_ready_future<>()};
  seastar::future<> dns_refresh_loop_{seastar::make_ready_future<>()};
  GatewayShard::ActiveHealthPublisher active_health_publisher_;
  GatewayShard::DnsAddressPublisher dns_address_publisher_;
  std::size_t cluster_index_{};
  bool maintenance_started_{false};
  bool dns_resolver_closed_{false};
  bool circuit_gauges_released_{false};
};

class WebSocketResponseHeadConsumer final {
 public:
  using Result = seastar::consumption_result<char>;

  WebSocketResponseHeadConsumer(
      std::size_t maximum_header_bytes,
      const bonvoyage::http::WebSocketRequestHandshake& request)
      : parser_(maximum_header_bytes, 128U), request_(request) {}

  seastar::future<Result> operator()(
      seastar::temporary_buffer<char> data) {
    if (data.empty()) {
      return seastar::make_exception_future<Result>(
          std::runtime_error(
              "upstream WebSocket response ended before its header block"));
    }
    try {
      const auto prior_size = buffered_.size();
      std::optional<bonvoyage::http::ParsedUpstreamResponseHead> parsed;
      if (buffered_.empty()) {
        parsed = parser_.parse({data.get(), data.size()});
      } else {
        buffered_.append(data.get(), data.size());
        parsed = parser_.parse(buffered_);
      }
      if (!parsed.has_value()) {
        if (buffered_.empty()) {
          buffered_.assign(data.get(), data.size());
        }
        return seastar::make_ready_future<Result>(
            seastar::continue_consuming{});
      }
      if (parsed->status == 101U) {
        bonvoyage::http::validate_websocket_response(
            parsed->status, parsed->http_major, parsed->http_minor,
            parsed->headers, request_);
      }
      populate_reply(*parsed);
      if (parsed->bytes_consumed < prior_size) {
        throw std::runtime_error(
            "upstream WebSocket header boundary precedes current input");
      }
      const auto consumed_from_current =
          parsed->bytes_consumed - prior_size;
      if (consumed_from_current > data.size()) {
        throw std::runtime_error(
            "upstream WebSocket header boundary exceeds current input");
      }
      auto remainder = data.share(consumed_from_current,
                                  data.size() - consumed_from_current);
      return seastar::make_ready_future<Result>(
          seastar::stop_consuming<char>(std::move(remainder)));
    } catch (...) {
      return seastar::make_exception_future<Result>(
          std::current_exception());
    }
  }

  [[nodiscard]] std::unique_ptr<seastar::http::reply> take_reply() {
    if (reply_ == nullptr) {
      throw std::runtime_error(
          "upstream WebSocket response parser produced no reply");
    }
    return std::move(reply_);
  }

 private:
  void populate_reply(
      const bonvoyage::http::ParsedUpstreamResponseHead& parsed) {
    reply_ = std::make_unique<seastar::http::reply>();
    reply_->_status =
        static_cast<seastar::http::reply::status_type>(parsed.status);
    const auto version = std::to_string(parsed.http_major) + "." +
                         std::to_string(parsed.http_minor);
    reply_->_version = seastar::sstring(version);
    reply_->_response_line =
        seastar::sstring(parsed.reason.data(), parsed.reason.size());
    reply_->_headers.reserve(parsed.headers.size());
    for (const auto& header : parsed.headers) {
      reply_->_headers.insert_or_assign(
          seastar::sstring(header.name.data(), header.name.size()),
          seastar::sstring(header.value.data(), header.value.size()));
    }
  }

  bonvoyage::http::UpstreamResponseHeadParser parser_;
  const bonvoyage::http::WebSocketRequestHandshake& request_;
  std::string buffered_;
  std::unique_ptr<seastar::http::reply> reply_;
};

class BoundedRequestParser final {
 public:
  explicit BoundedRequestParser(std::size_t limit) : limit_(limit) {
    parser_.init();
  }

  using Remainder =
      std::optional<seastar::temporary_buffer<char>>;

  seastar::future<Remainder> operator()(
      seastar::temporary_buffer<char> data) {
    const auto original_size = data.size();
    auto scan = data.share();
    return parser_(std::move(data)).then(
        [this, original_size, scan = std::move(scan)](
            Remainder remainder) mutable {
          const auto remainder_size =
              remainder.has_value() ? remainder->size() : 0U;
          const auto consumed = original_size - remainder_size;
          header_bytes_ += consumed;
          for (std::size_t index = 0U; index < consumed; ++index) {
            const auto character = scan.get()[index];
            if (previous_two_ == '\r' && previous_one_ == '\n' &&
                (character == ' ' || character == '\t')) {
              throw bonvoyage::http::RequestError(
                  400U, "obsolete_header_folding",
                  "Obsolete folded headers are not accepted");
            }
            inspect_header_byte(character);
            previous_two_ = previous_one_;
            previous_one_ = character;
          }
          if (header_bytes_ > limit_) {
            throw bonvoyage::http::RequestError(
                431U, "request_headers_too_large",
                "Request headers exceed the configured limit");
          }
          return seastar::make_ready_future<Remainder>(
              std::move(remainder));
        });
  }

  [[nodiscard]] bool failed() const noexcept { return parser_.failed(); }
  [[nodiscard]] bool eof() const noexcept { return parser_.eof(); }
  [[nodiscard]] std::size_t header_bytes() const noexcept {
    return header_bytes_;
  }
  [[nodiscard]] bool traceparent_repeated() const noexcept {
    return traceparent_repeated_;
  }
  [[nodiscard]] std::unique_ptr<seastar::http::request> request() {
    return parser_.get_parsed_request();
  }

 private:
  void inspect_header_byte(char character) {
    if (first_line_) {
      if (character == '\n') {
        first_line_ = false;
        line_start_ = true;
      }
      return;
    }
    if (character == '\n') {
      line_start_ = true;
      return;
    }
    if (line_start_) {
      line_start_ = false;
      name_size_ = 0U;
      name_overflow_ = false;
      name_complete_ = false;
    }
    if (name_complete_ || character == '\r') {
      return;
    }
    if (character == ':') {
      name_complete_ = true;
      if (!name_overflow_) {
        count_security_sensitive_header(
            std::string_view(header_name_.data(), name_size_));
      }
      return;
    }
    if (name_size_ == header_name_.size()) {
      name_overflow_ = true;
      return;
    }
    auto byte = static_cast<unsigned char>(character);
    if (byte >= 'A' && byte <= 'Z') {
      byte = static_cast<unsigned char>(byte + ('a' - 'A'));
    }
    header_name_[name_size_++] = static_cast<char>(byte);
  }

  void count_security_sensitive_header(std::string_view name) {
    auto increment = [](std::uint8_t& count, std::string_view field) {
      if (++count > 1U) {
        throw bonvoyage::http::RequestError(
            400U, "duplicate_framing_header",
            std::string("Multiple ") + std::string(field) +
                " headers are not accepted");
      }
    };
    auto increment_handshake = [](std::uint8_t& count,
                                  std::string_view field) {
      if (++count > 1U) {
        throw bonvoyage::http::RequestError(
            400U, "duplicate_websocket_header",
            std::string("Multiple ") + std::string(field) +
                " headers are not accepted");
      }
    };
    if (name == "host") {
      increment(host_count_, "Host");
    } else if (name == "content-length") {
      increment(content_length_count_, "Content-Length");
    } else if (name == "transfer-encoding") {
      increment(transfer_encoding_count_, "Transfer-Encoding");
    } else if (name == "content-type" && ++content_type_count_ > 1U) {
      throw bonvoyage::http::RequestError(
          400U, "invalid_content_type",
          "Multiple Content-Type headers are not accepted");
    } else if (name == "connection") {
      increment_handshake(connection_count_, "Connection");
    } else if (name == "upgrade") {
      increment_handshake(upgrade_count_, "Upgrade");
    } else if (name == "sec-websocket-key") {
      increment_handshake(websocket_key_count_, "Sec-WebSocket-Key");
    } else if (name == "sec-websocket-version") {
      increment_handshake(websocket_version_count_,
                          "Sec-WebSocket-Version");
    } else if (name == "sec-websocket-protocol") {
      increment_handshake(websocket_protocol_count_,
                          "Sec-WebSocket-Protocol");
    } else if (name == "sec-websocket-extensions") {
      increment_handshake(websocket_extensions_count_,
                          "Sec-WebSocket-Extensions");
    } else if (name == "traceparent") {
      traceparent_repeated_ = traceparent_seen_;
      traceparent_seen_ = true;
    }
  }

  seastar::http_request_parser parser_;
  std::size_t limit_;
  std::size_t header_bytes_{};
  std::array<char, 32U> header_name_{};
  std::size_t name_size_{};
  std::uint8_t host_count_{};
  std::uint8_t content_length_count_{};
  std::uint8_t transfer_encoding_count_{};
  std::uint8_t content_type_count_{};
  std::uint8_t connection_count_{};
  std::uint8_t upgrade_count_{};
  std::uint8_t websocket_key_count_{};
  std::uint8_t websocket_version_count_{};
  std::uint8_t websocket_protocol_count_{};
  std::uint8_t websocket_extensions_count_{};
  bool traceparent_seen_{false};
  bool traceparent_repeated_{false};
  bool first_line_{true};
  bool line_start_{true};
  bool name_overflow_{false};
  bool name_complete_{false};
  char previous_two_{};
  char previous_one_{};
};

class BoundedChunkedSourceImpl final : public seastar::data_source_impl {
 public:
  BoundedChunkedSourceImpl(seastar::input_stream<char>& input,
                           std::uint64_t max_body_bytes,
                           std::size_t max_metadata_bytes,
                           std::uint64_t* route_limit_rejections = nullptr)
      : input_(input),
        max_body_bytes_(max_body_bytes),
        max_metadata_bytes_(max_metadata_bytes),
        route_limit_rejections_(route_limit_rejections) {}

  seastar::future<seastar::temporary_buffer<char>> get() override {
    while (true) {
      switch (state_) {
        case State::size: {
          const auto line = co_await read_line();
          if (line.find(';') != std::string::npos) {
            throw bonvoyage::http::RequestError(
                400U, "chunk_extensions_not_supported",
                "Chunk extensions are not enabled in Phase 1");
          }
          if (line.empty() || line.size() > 16U) {
            throw bonvoyage::http::RequestError(
                400U, "invalid_chunk_size", "Chunk size is invalid");
          }
          std::uint64_t size = 0U;
          const auto [position, error] =
              std::from_chars(line.data(), line.data() + line.size(), size, 16);
          if (error != std::errc{} || position != line.data() + line.size()) {
            throw bonvoyage::http::RequestError(
                400U, "invalid_chunk_size", "Chunk size is invalid");
          }
          if (size > max_body_bytes_ - decoded_bytes_) {
            record_route_limit_rejection();
            throw bonvoyage::http::RequestError(
                413U, "request_body_too_large",
                "Request body exceeds the configured limit");
          }
          if (size == 0U) {
            state_ = State::trailers;
          } else {
            remaining_chunk_bytes_ = size;
            state_ = State::body;
          }
          break;
        }
        case State::body: {
          auto data = co_await input_.read_up_to(
              static_cast<std::size_t>(std::min<std::uint64_t>(
                  remaining_chunk_bytes_, 64U * 1024U)));
          if (data.empty()) {
            throw bonvoyage::http::RequestError(
                400U, "truncated_request_body",
                "Chunked request body ended before the chunk was complete");
          }
          const auto data_size = static_cast<std::uint64_t>(data.size());
          remaining_chunk_bytes_ -= data_size;
          decoded_bytes_ += data_size;
          if (remaining_chunk_bytes_ == 0U) {
            state_ = State::body_crlf;
          }
          co_return data;
        }
        case State::body_crlf: {
          auto delimiter = co_await input_.read_exactly(2U);
          account_metadata(delimiter.size());
          if (delimiter.size() != 2U || delimiter.get()[0] != '\r' ||
              delimiter.get()[1] != '\n') {
            throw bonvoyage::http::RequestError(
                400U, "invalid_chunk_delimiter",
                "Chunk data must end with CRLF");
          }
          state_ = State::size;
          break;
        }
        case State::trailers: {
          const auto line = co_await read_line();
          if (!line.empty()) {
            throw bonvoyage::http::RequestError(
                400U, "chunk_trailers_not_supported",
                "Chunk trailers are not enabled in Phase 1");
          }
          state_ = State::done;
          break;
        }
        case State::done:
          co_return seastar::temporary_buffer<char>{};
      }
    }
  }

  seastar::future<> close() override { return seastar::make_ready_future<>(); }

 private:
  enum class State : std::uint8_t { size, body, body_crlf, trailers, done };

  seastar::future<std::string> read_line() {
    std::string line;
    while (true) {
      auto byte = co_await input_.read_exactly(1U);
      account_metadata(byte.size());
      if (byte.empty()) {
        throw bonvoyage::http::RequestError(
            400U, "truncated_request_body",
            "Chunked request body ended before its framing was complete");
      }
      const auto character = byte.get()[0];
      if (character == '\n') {
        if (line.empty() || line.back() != '\r') {
          throw bonvoyage::http::RequestError(
              400U, "invalid_chunk_delimiter",
              "Chunk framing lines must end with CRLF");
        }
        line.pop_back();
        co_return line;
      }
      line.push_back(character);
    }
  }

  void account_metadata(std::size_t bytes) {
    metadata_bytes_ += bytes;
    if (metadata_bytes_ > max_metadata_bytes_) {
      throw bonvoyage::http::RequestError(
          431U, "chunk_metadata_too_large",
          "Chunk framing exceeds the configured header limit");
    }
  }

  void record_route_limit_rejection() noexcept {
    if (route_limit_rejections_ != nullptr &&
        !route_limit_rejection_recorded_) {
      ++*route_limit_rejections_;
      route_limit_rejection_recorded_ = true;
    }
  }

  seastar::input_stream<char>& input_;
  std::uint64_t max_body_bytes_;
  std::size_t max_metadata_bytes_;
  std::uint64_t* route_limit_rejections_{};
  std::uint64_t remaining_chunk_bytes_{};
  std::uint64_t decoded_bytes_{};
  std::size_t metadata_bytes_{};
  bool route_limit_rejection_recorded_{false};
  State state_{State::size};
};

enum class Http2BodyAppendResult {
  accepted,
  closed,
  content_length_mismatch,
  body_too_large
};

class Http2RequestBody final {
 public:
  Http2RequestBody(std::optional<std::uint64_t> content_length,
                   std::uint64_t maximum_bytes, bool end_stream)
      : content_length_(content_length),
        maximum_bytes_(maximum_bytes),
        finished_(end_stream) {}

  [[nodiscard]] Http2BodyAppendResult append(
      std::vector<std::uint8_t> data) {
    if (finished_ || failure_ != nullptr) {
      return Http2BodyAppendResult::closed;
    }
    if (data.size() >
        maximum_bytes_ -
            std::min<std::uint64_t>(received_bytes_, maximum_bytes_)) {
      return Http2BodyAppendResult::body_too_large;
    }
    const auto bytes = static_cast<std::uint64_t>(data.size());
    if (content_length_.has_value() &&
        bytes > *content_length_ -
                    std::min(received_bytes_, *content_length_)) {
      return Http2BodyAppendResult::content_length_mismatch;
    }
    received_bytes_ += bytes;
    if (buffer_.empty()) {
      buffer_ = std::move(data);
    } else {
      buffer_.insert(buffer_.end(), data.begin(), data.end());
    }
    available_.broadcast();
    return Http2BodyAppendResult::accepted;
  }

  /** Tightens the stream ceiling after immutable route selection. */
  void tighten_maximum_bytes(std::uint64_t maximum_bytes) noexcept {
    maximum_bytes_ = std::min(maximum_bytes_, maximum_bytes);
  }

  void finish() {
    if (finished_ || failure_ != nullptr) {
      return;
    }
    if (content_length_.has_value() && received_bytes_ != *content_length_) {
      abort(std::make_exception_ptr(bonvoyage::http::RequestError(
          400U, "content_length_mismatch",
          "HTTP/2 DATA does not match Content-Length", false)));
      return;
    }
    finished_ = true;
    available_.broadcast();
  }

  void abort(std::exception_ptr failure) noexcept {
    if (finished_ || failure_ != nullptr) {
      return;
    }
    failure_ = std::move(failure);
    buffer_.clear();
    available_.broadcast();
  }

  [[nodiscard]] std::uint64_t received_bytes() const noexcept {
    return received_bytes_;
  }

  [[nodiscard]] seastar::future<std::vector<std::uint8_t>> read() {
    co_await available_.wait([this] {
      return !buffer_.empty() || finished_ || failure_ != nullptr;
    });
    if (failure_ != nullptr) {
      std::rethrow_exception(failure_);
    }
    if (buffer_.empty()) {
      co_return std::vector<std::uint8_t>{};
    }
    auto result = std::move(buffer_);
    buffer_.clear();
    co_return result;
  }

 private:
  std::optional<std::uint64_t> content_length_;
  std::uint64_t maximum_bytes_;
  std::uint64_t received_bytes_{};
  std::vector<std::uint8_t> buffer_;
  seastar::condition_variable available_;
  std::exception_ptr failure_;
  bool finished_{false};
};

struct Http2StreamState final {
  std::int32_t stream_id{};
  bonvoyage::http::Http2RequestHead request;
  std::shared_ptr<Http2RequestBody> body;
  std::string forwarded_client_address;
  std::optional<CorsResponseContext> cors;
  std::optional<std::uint64_t> route_maximum_body_bytes;
  std::optional<std::chrono::steady_clock::time_point> grpc_deadline;
  AccessLogRecord access_log;
  std::optional<TraceSpanRecord> trace;
  seastar::abort_source abort;
  bool grpc{false};
  bool grpc_compression_allowed{false};
  bool response_started{false};
  bool response_complete{false};
  bool request_complete{false};
  bool peer_closed{false};
  bool cors_policy_configured{false};
  bool route_body_limit_rejection_recorded{false};
};

class GatewayRuntimeGeneration final {
 public:
  GatewayRuntimeGeneration(SnapshotReference reference,
                           RuntimeSnapshot snapshot,
                           bool trust_http1_connection_reuse)
      : reference_(std::move(reference)),
        snapshot_(std::move(snapshot)),
        trust_http1_connection_reuse_(trust_http1_connection_reuse) {
    if (reference_.snapshot_id != snapshot_.snapshot_id()) {
      throw std::invalid_argument(
          "live gateway snapshot identity does not match compiled bytes");
    }
  }

  GatewayRuntimeGeneration(const GatewayRuntimeGeneration&) = delete;
  GatewayRuntimeGeneration& operator=(const GatewayRuntimeGeneration&) =
      delete;

  seastar::future<> start(GatewayStats& stats,
                          const std::string& secrets_directory) {
    stats_ = &stats;
    std::exception_ptr failure;
    try {
      route_admissions_.reserve(
          snapshot_.route_admission_policies().size());
      for (const auto& policy : snapshot_.route_admission_policies()) {
        route_admissions_.push_back(
            policy.enabled()
                ? std::make_unique<ShardLocalRouteAdmission>(policy)
                : nullptr);
      }

      std::optional<ApiKeyPepper> pepper;
      if (std::any_of(snapshot_.route_api_key_policies().begin(),
                      snapshot_.route_api_key_policies().end(),
                      [](const auto& policy) { return policy.has_value(); })) {
        pepper = generate_api_key_pepper();
      }
      auto erase_pepper = seastar::defer([&pepper] {
        if (pepper.has_value()) {
          secure_erase(*pepper);
        }
      });
      std::unordered_map<std::string,
                         std::shared_ptr<const ApiKeyCredentialSet>>
          credential_sets;
      route_api_key_auth_.reserve(snapshot_.route_api_key_policies().size());
      for (const auto& policy : snapshot_.route_api_key_policies()) {
        if (!policy.has_value()) {
          route_api_key_auth_.push_back(std::nullopt);
          continue;
        }
        auto credentials = credential_sets.find(policy->credentials_secret);
        if (credentials == credential_sets.end()) {
          auto plaintext = co_await read_api_key_secret(secret_path(
              secrets_directory, policy->credentials_secret));
          auto erase_plaintext =
              seastar::defer([&plaintext] { secure_erase(plaintext); });
          auto prepared = std::make_shared<const ApiKeyCredentialSet>(
              ApiKeyCredentialSet::compile(plaintext, pepper.value()));
          credentials = credential_sets
                            .emplace(policy->credentials_secret,
                                     std::move(prepared))
                            .first;
        }
        route_api_key_auth_.push_back(PreparedApiKeyAuth{
            policy->header_name, credentials->second});
      }

      std::unordered_map<std::string, std::shared_ptr<const JwtKeySet>>
          jwt_keys;
      route_jwt_auth_.reserve(snapshot_.route_jwt_policies().size());
      for (const auto& policy : snapshot_.route_jwt_policies()) {
        if (!policy.has_value()) {
          route_jwt_auth_.push_back(nullptr);
          continue;
        }
        auto keys = jwt_keys.find(policy->jwks_secret);
        if (keys == jwt_keys.end()) {
          auto jwks = co_await read_jwt_jwks(
              secret_path(secrets_directory, policy->jwks_secret));
          keys = jwt_keys
                     .emplace(policy->jwks_secret, JwtKeySet::compile(jwks))
                     .first;
        }
        auto validator = std::make_unique<JwtValidator>(
            keys->second,
            JwtValidationPolicy{
                policy->issuer,
                policy->audience,
                policy->required_type,
                policy->algorithms,
                policy->clock_skew_seconds,
                policy->max_token_lifetime_seconds,
                policy->required_scopes,
                policy->required_claims});
        route_jwt_auth_.push_back(std::make_unique<PreparedJwtAuth>(
            std::move(validator), policy->verification_rate_limit));
      }

      route_weighted_cluster_selectors_.reserve(
          snapshot_.route_weighted_clusters().size());
      for (const auto& targets : snapshot_.route_weighted_clusters()) {
        route_weighted_cluster_selectors_.push_back(
            targets.empty()
                ? nullptr
                : std::make_unique<ShardLocalWeightedClusterSelector>(
                      targets));
      }

      clusters_.reserve(snapshot_.clusters().size());
      for (const auto& cluster : snapshot_.clusters()) {
        auto state = std::make_unique<ClusterState>(
            cluster, stats, secrets_directory,
            snapshot_.limits().max_upstream_response_header_bytes,
            snapshot_.limits().max_upstream_chunk_metadata_bytes,
            trust_http1_connection_reuse_);
        co_await state->start();
        clusters_.push_back(std::move(state));
      }
      started_ = true;
    } catch (...) {
      failure = std::current_exception();
    }
    if (failure != nullptr) {
      co_await stop().handle_exception([](const std::exception_ptr&) {});
      std::rethrow_exception(failure);
    }
  }

  seastar::future<> stop() {
    std::exception_ptr failure;
    auto preserve = [&failure](const std::exception_ptr& error) {
      if (failure == nullptr) {
        failure = error;
      }
    };
    co_await stop_maintenance().handle_exception(preserve);
    for (auto& cluster : clusters_) {
      co_await cluster->stop().handle_exception(preserve);
    }
    clusters_.clear();
    route_admissions_.clear();
    route_api_key_auth_.clear();
    route_jwt_auth_.clear();
    route_weighted_cluster_selectors_.clear();
    started_ = false;
    if (failure != nullptr) {
      std::rethrow_exception(failure);
    }
  }

  seastar::future<> start_maintenance(
      GatewayShard::ActiveHealthPublisher active_health_publisher,
      GatewayShard::DnsAddressPublisher dns_address_publisher) {
    if (maintenance_started_) {
      throw std::logic_error(
          "gateway generation maintenance was already started");
    }
    std::size_t started_clusters = 0U;
    std::exception_ptr failure;
    try {
      for (; started_clusters < clusters_.size(); ++started_clusters) {
        co_await clusters_[started_clusters]->start_maintenance(
            started_clusters, active_health_publisher,
            dns_address_publisher);
      }
      maintenance_started_ = true;
    } catch (...) {
      failure = std::current_exception();
    }
    if (failure != nullptr) {
      while (started_clusters != 0U) {
        --started_clusters;
        co_await clusters_[started_clusters]
            ->stop_maintenance()
            .handle_exception([](const std::exception_ptr&) {});
      }
      std::rethrow_exception(failure);
    }
  }

  seastar::future<> stop_maintenance() {
    if (!maintenance_started_) {
      co_return;
    }
    std::exception_ptr failure;
    for (auto& cluster : clusters_) {
      co_await cluster->stop_maintenance().handle_exception(
          [&failure](const std::exception_ptr& error) {
            if (failure == nullptr) {
              failure = error;
            }
          });
    }
    maintenance_started_ = false;
    if (failure != nullptr) {
      std::rethrow_exception(failure);
    }
  }

  void apply_active_health(std::size_t cluster_index,
                           std::size_t endpoint_index,
                           bool active_healthy) {
    if (cluster_index >= clusters_.size()) {
      throw std::out_of_range("active-health cluster index is out of range");
    }
    clusters_[cluster_index]->apply_active_health(endpoint_index,
                                                   active_healthy);
  }

  void apply_resolved_address(std::size_t cluster_index,
                              std::size_t endpoint_index,
                              const std::string& resolved_address) {
    if (cluster_index >= clusters_.size()) {
      throw std::out_of_range("DNS cluster index is out of range");
    }
    clusters_[cluster_index]->apply_resolved_address(endpoint_index,
                                                      resolved_address);
  }

  [[nodiscard]] const SnapshotReference& reference() const noexcept {
    return reference_;
  }
  [[nodiscard]] const RuntimeSnapshot& snapshot() const noexcept {
    return snapshot_;
  }
  [[nodiscard]] ClusterState& cluster(std::size_t index) noexcept {
    return *clusters_[index];
  }
  [[nodiscard]] ShardLocalRouteAdmission* route_admission(
      const RuntimeRoute& route) noexcept {
    return route_admissions_[route.runtime_index].get();
  }
  [[nodiscard]] const PreparedApiKeyAuth* api_key_auth(
      const RuntimeRoute& route) const noexcept {
    const auto& policy = route_api_key_auth_[route.runtime_index];
    return policy.has_value() ? &*policy : nullptr;
  }
  [[nodiscard]] PreparedJwtAuth* jwt_auth(
      const RuntimeRoute& route) noexcept {
    return route_jwt_auth_[route.runtime_index].get();
  }
  [[nodiscard]] std::size_t select_cluster(const RuntimeRoute& route) {
    if (route.cluster_index.has_value()) {
      return *route.cluster_index;
    }
    auto* selector =
        route_weighted_cluster_selectors_[route.runtime_index].get();
    if (selector == nullptr || stats_ == nullptr) {
      throw std::logic_error(
          "reverse-proxy route has no prepared cluster selector");
    }
    ++stats_->route_weighted_cluster_selections;
    return selector->select();
  }
  [[nodiscard]] bool maintenance_started() const noexcept {
    return maintenance_started_;
  }

 private:
  SnapshotReference reference_;
  RuntimeSnapshot snapshot_;
  bool trust_http1_connection_reuse_;
  GatewayStats* stats_{};
  std::vector<std::unique_ptr<ClusterState>> clusters_;
  std::vector<std::unique_ptr<ShardLocalRouteAdmission>> route_admissions_;
  std::vector<std::optional<PreparedApiKeyAuth>> route_api_key_auth_;
  std::vector<std::unique_ptr<PreparedJwtAuth>> route_jwt_auth_;
  std::vector<std::unique_ptr<ShardLocalWeightedClusterSelector>>
      route_weighted_cluster_selectors_;
  bool started_{false};
  bool maintenance_started_{false};
};

struct ConnectionRuntime final {
  GatewayRuntimeGeneration* generation{};
  SnapshotReadLease lease;
};

[[nodiscard]] bool same_downstream_tls(
    const std::optional<RuntimeDownstreamTls>& left,
    const std::optional<RuntimeDownstreamTls>& right) {
  if (left.has_value() != right.has_value()) {
    return false;
  }
  if (!left.has_value()) {
    return true;
  }
  return left->certificate_chain_secret == right->certificate_chain_secret &&
         left->private_key_secret == right->private_key_secret &&
         left->trust_bundle_secret == right->trust_bundle_secret &&
         left->require_client_certificate == right->require_client_certificate;
}

[[nodiscard]] bool compatible_listener_topology(
    const RuntimeSnapshot& active, const RuntimeSnapshot& candidate) {
  if (active.listeners().size() != candidate.listeners().size()) {
    return false;
  }
  for (std::size_t index = 0U; index < active.listeners().size(); ++index) {
    const auto& left = active.listeners()[index];
    const auto& right = candidate.listeners()[index];
    if (left.address != right.address || left.port != right.port ||
        left.protocol != right.protocol ||
        !same_downstream_tls(left.downstream_tls, right.downstream_tls)) {
      return false;
    }
  }
  return true;
}

class ListenerServer;

class DownstreamConnection final
    : public seastar::enable_lw_shared_from_this<DownstreamConnection> {
 public:
  DownstreamConnection(ListenerServer& server,
                       GatewayRuntimeGeneration& generation,
                       SnapshotReadLease lease,
                       seastar::connected_socket socket,
                       seastar::socket_address remote_address);

  seastar::future<> process();
  void begin_drain(bool terminate_websocket = true) noexcept;

 private:
  friend class ListenerServer;

  seastar::future<> process_http1();
  seastar::future<> process_http2();
  seastar::future<> initialize_security();
  seastar::future<> negotiate_tls();
  seastar::future<std::unique_ptr<seastar::http::request>> read_request();
  seastar::future<> handle_request(
      std::unique_ptr<seastar::http::request> request,
      seastar::abort_source& abort);
  seastar::future<> consume_body(
      const bonvoyage::http::BodyFraming& framing,
      std::optional<std::uint64_t> route_maximum_body_bytes = std::nullopt);
  seastar::future<seastar::temporary_buffer<char>> read_http1_body(
      seastar::input_stream<char>& body);
  [[nodiscard]] ClientAddressResolution resolve_client_address(
      std::span<const std::string_view> forwarded_for_fields,
      bool close_connection);
  seastar::future<> proxy_request(
      seastar::http::request& downstream,
      const bonvoyage::http::BodyFraming& framing,
      const RuntimeRoute& route, std::string_view connection,
      std::string_view authority, std::string_view client_address,
      bool downstream_keep_alive,
      seastar::abort_source& abort);
  seastar::future<> proxy_websocket(
      seastar::http::request& downstream, const RuntimeRoute& route,
      std::string_view connection, std::string_view authority,
      std::string_view client_address, bool downstream_keep_alive,
      const bonvoyage::http::WebSocketRequestHandshake& handshake,
      seastar::abort_source& abort);
  seastar::future<std::unique_ptr<seastar::http::reply>>
  read_websocket_response(
      seastar::input_stream<char>& input,
      const bonvoyage::http::WebSocketRequestHandshake& handshake);
  seastar::future<> write_websocket_response(
      const seastar::http::reply& reply,
      const HeaderTransformations* transformations);
  seastar::future<> tunnel_websocket(
      seastar::connected_socket& upstream_socket,
      seastar::input_stream<char>& upstream_input,
      seastar::output_stream<char>& upstream_output,
      std::chrono::milliseconds idle_timeout,
      seastar::abort_source& abort);
  seastar::future<> write_upstream_response(
      const seastar::http::reply& reply,
      seastar::input_stream<char>& body, std::string_view method,
      bool downstream_keep_alive,
      const HeaderTransformations* transformations,
      std::optional<std::chrono::steady_clock::time_point>
          handoff_started_at);
  seastar::future<> write_transferred_upstream_response(
      const seastar::http::reply& reply,
      seastar::input_stream<char>& body, std::uint16_t status,
      std::size_t response_length, bool downstream_keep_alive,
      const HeaderTransformations* transformations,
      std::optional<std::chrono::steady_clock::time_point>
          handoff_started_at);
  seastar::future<> write_response_head(
      std::uint16_t status,
      std::vector<std::pair<std::string, std::string>> headers,
      bool close_connection);
  seastar::future<> write_cors_preflight(bool close_connection);
  seastar::future<> write_fixed_response(
      const RuntimeFixedResponse& response, std::string_view method,
      bool close_connection);
  seastar::future<> write_redirect_response(
      const RuntimeRedirectResponse& response, bool close_connection);
  seastar::future<> write_error(std::uint16_t status, std::string_view code,
                                std::string_view message,
                                bool close_connection,
                                std::optional<std::uint32_t>
                                    retry_after_seconds = std::nullopt,
                                std::optional<std::string_view>
                                    www_authenticate = std::nullopt,
                                std::optional<std::string_view>
                                    accept = std::nullopt,
                                std::optional<std::string_view>
                                    websocket_version = std::nullopt);
  seastar::future<seastar::temporary_buffer<char>> read_http2_input();
  seastar::future<> receive_http2_input(
      std::span<const std::uint8_t> input);
  seastar::future<> dispatch_http2_events(
      std::vector<bonvoyage::http::Http2Event> events);
  seastar::future<> pump_http2_output();
  void abort_http2_transport() noexcept;
  seastar::future<> wait_http2_response_complete(
      std::shared_ptr<Http2StreamState> stream);
  seastar::future<> reset_http2_stream(std::int32_t stream_id,
                                       std::uint32_t error_code);
  seastar::future<> acknowledge_http2_data(std::int32_t stream_id,
                                           std::size_t bytes);
  seastar::future<> handle_http2_stream(
      std::shared_ptr<Http2StreamState> stream);
  seastar::future<> execute_http2_request(
      std::shared_ptr<Http2StreamState> stream);
  seastar::future<> consume_http2_body(
      std::shared_ptr<Http2StreamState> stream);
  seastar::future<> proxy_http2_request(
      std::shared_ptr<Http2StreamState> stream,
      const RuntimeRoute& route);
  seastar::future<> write_http2_upstream_response(
      std::shared_ptr<Http2StreamState> stream,
      const seastar::http::reply& reply,
      seastar::input_stream<char>& body,
      const HeaderTransformations* transformations);
  seastar::future<> submit_http2_headers(
      std::shared_ptr<Http2StreamState> stream, std::uint16_t status,
      std::vector<bonvoyage::http::Http2Header> headers, bool end_stream);
  seastar::future<> submit_http2_data(
      std::shared_ptr<Http2StreamState> stream,
      std::span<const std::uint8_t> data, bool end_stream,
      bool best_effort_error = false);
  seastar::future<> submit_http2_trailers(
      std::shared_ptr<Http2StreamState> stream,
      std::vector<bonvoyage::http::Http2Header> trailers);
  seastar::future<> write_http2_fixed_response(
      std::shared_ptr<Http2StreamState> stream,
      const RuntimeFixedResponse& response);
  seastar::future<> write_http2_redirect_response(
      std::shared_ptr<Http2StreamState> stream,
      const RuntimeRedirectResponse& response);
  seastar::future<> write_http2_cors_preflight(
      std::shared_ptr<Http2StreamState> stream);
  seastar::future<> write_http2_grpc_error(
      std::shared_ptr<Http2StreamState> stream, std::uint32_t grpc_status,
      std::string_view message);
  seastar::future<> write_http2_grpc_trailer_error(
      std::shared_ptr<Http2StreamState> stream, std::uint32_t grpc_status,
      std::string_view message);
  seastar::future<> write_http2_error(
      std::int32_t stream_id, std::uint16_t status, std::string_view code,
      std::string_view message,
      std::optional<std::uint32_t> retry_after_seconds = std::nullopt,
      std::optional<std::string_view> www_authenticate = std::nullopt,
      const CorsResponseContext* cors = nullptr,
      std::optional<std::string_view> accept = std::nullopt);
  seastar::future<> close_streams() noexcept;
  void record_http1_request_bytes(std::size_t bytes) noexcept;
  void record_http1_response_bytes(std::size_t bytes) noexcept;
  void record_http2_request_bytes(
      const std::shared_ptr<Http2StreamState>& stream,
      std::size_t bytes) noexcept;
  void record_http2_response_bytes(
      const std::shared_ptr<Http2StreamState>& stream,
      std::size_t bytes) noexcept;
  [[nodiscard]] std::optional<std::chrono::steady_clock::time_point>
  start_response_path_handoff() const noexcept;
  void record_response_path_handoff(
      std::optional<std::chrono::steady_clock::time_point>&
          handoff_started_at) noexcept;
  void record_response_path_write(std::size_t bytes) noexcept;
  [[nodiscard]] seastar::future<> flush_response_path();
  void record_response_path_completion() noexcept;

  [[nodiscard]] const RuntimeSnapshot& snapshot() const noexcept {
    return generation_->snapshot();
  }
  [[nodiscard]] ClusterState& cluster(std::size_t index) noexcept {
    return generation_->cluster(index);
  }
  [[nodiscard]] ShardLocalRouteAdmission* route_admission(
      const RuntimeRoute& route) noexcept {
    return generation_->route_admission(route);
  }
  [[nodiscard]] const PreparedApiKeyAuth* api_key_auth(
      const RuntimeRoute& route) const noexcept {
    return generation_->api_key_auth(route);
  }
  [[nodiscard]] PreparedJwtAuth* jwt_auth(
      const RuntimeRoute& route) noexcept {
    return generation_->jwt_auth(route);
  }
  [[nodiscard]] std::size_t select_cluster(const RuntimeRoute& route) {
    return generation_->select_cluster(route);
  }
  [[nodiscard]] GatewayRuntimeGeneration* generation() const noexcept {
    return generation_;
  }

  ListenerServer& server_;
  GatewayRuntimeGeneration* generation_{};
  SnapshotReadLease snapshot_lease_;
  seastar::connected_socket socket_;
  seastar::input_stream<char> input_;
  seastar::output_stream<char> output_;
  seastar::socket_address remote_address_;
  // Socket endpoints do not change during a downstream connection.
  seastar::socket_address local_address_;
  ClientAddressResolver client_address_resolver_;
  seastar::sstring forwarded_proto_;
  std::optional<std::string> server_name_;
  std::unique_ptr<bonvoyage::http::Http2ServerSession> http2_session_;
  std::unordered_map<std::int32_t, std::shared_ptr<Http2StreamState>>
      http2_streams_;
  std::unordered_set<std::int32_t> http2_rejected_streams_;
  seastar::semaphore http2_session_mutex_{1U};
  seastar::condition_variable http2_progress_;
  seastar::gate http2_stream_gate_;
  seastar::gate http2_background_gate_;
  seastar::timer<> http2_drain_timer_;
  seastar::timer<> http2_output_timer_;
  std::uint64_t http2_progress_epoch_{};
  bool draining_{false};
  bool in_request_{false};
  bool response_started_{false};
  bool http1_body_read_pending_{false};
  AccessLogRecord* http1_access_log_{nullptr};
  TraceSpanRecord* http1_trace_{nullptr};
  bool http1_traceparent_repeated_{false};
  std::optional<CorsResponseContext> http1_cors_;
  bool http1_cors_policy_configured_{false};
  bool http2_transport_closed_{false};
  bool output_closed_{false};
  seastar::abort_source* active_websocket_abort_{nullptr};
  bool websocket_established_{false};
  bool completed_websocket_tunnel_{false};
};

class ListenerServer final {
 public:
  using RuntimeAcquirer =
      std::function<std::optional<ConnectionRuntime>()>;

  ListenerServer(const RuntimeSnapshot& snapshot, std::size_t listener_index,
                 RuntimeAcquirer acquire_runtime,
                 GatewayStats& stats, AccessLogSink& access_log,
                 OtlpTraceExporter& traces,
                 std::string secrets_directory,
                 bool response_path_diagnostics_enabled)
      : listener_config_(snapshot.listeners()[listener_index]),
        listener_index_(listener_index),
        acquire_runtime_(std::move(acquire_runtime)),
        stats_(stats),
        access_log_(access_log),
        traces_(traces),
        secrets_directory_(std::move(secrets_directory)),
        response_path_diagnostics_enabled_(
            response_path_diagnostics_enabled) {}

  seastar::future<> start() {
    const auto& listener = listener_config_;
    const seastar::net::inet_address address{listener.address};
    seastar::listen_options options;
    options.reuse_address = true;
    options.listen_backlog = 1024;
    const auto bind_address =
        seastar::socket_address{address, listener.port};
    if (listener.downstream_tls.has_value()) {
      const auto& tls = *listener.downstream_tls;
      credentials_ = seastar::make_shared<seastar::tls::server_credentials>();
      credentials_->set_priority_string(seastar::sstring(kTlsPriority));
      co_await credentials_->set_x509_key_file(
          seastar::sstring(secret_path(secrets_directory_,
                                      tls.certificate_chain_secret)),
          seastar::sstring(
              secret_path(secrets_directory_, tls.private_key_secret)),
          seastar::tls::x509_crt_format::PEM);
      if (tls.require_client_certificate) {
        co_await credentials_->set_x509_trust_file(
            seastar::sstring(secret_path(
                secrets_directory_, *tls.trust_bundle_secret)),
            seastar::tls::x509_crt_format::PEM);
        credentials_->set_client_auth(seastar::tls::client_auth::REQUIRE);
      }
      seastar::tls::tls_options tls_options;
      tls_options.alpn_protocols.emplace_back(
          listener.protocol == RuntimeProtocol::http2 ? kHttp2Alpn
                                                       : kHttp11Alpn);
      listener_socket_ = seastar::tls::listen(
          credentials_, bind_address, options, std::move(tls_options));
    } else {
      listener_socket_ = seastar::listen(bind_address, options);
    }
    (void)seastar::with_gate(gate_, [this] { return accept_loop(); })
        .handle_exception([this](std::exception_ptr error) {
          if (!draining_) {
            gateway_log.error("listener accept loop failed: {}", error);
          }
        });
    co_return;
  }

  seastar::future<> stop() {
    if (draining_) {
      co_return;
    }
    draining_ = true;
    if (listener_socket_) {
      listener_socket_.abort_accept();
    }
    for (auto* connection : connections_) {
      connection->begin_drain();
    }
    co_await gate_.close();
  }

  [[nodiscard]] std::size_t listener_index() const noexcept {
    return listener_index_;
  }
  [[nodiscard]] bool draining() const noexcept { return draining_; }
  [[nodiscard]] bool tls_enabled() const noexcept {
    return listener_config_.downstream_tls.has_value();
  }
  [[nodiscard]] RuntimeProtocol protocol() const noexcept {
    return listener_config_.protocol;
  }
  [[nodiscard]] GatewayStats& stats() noexcept { return stats_; }
  [[nodiscard]] AccessLogSink& access_log() noexcept { return access_log_; }
  [[nodiscard]] OtlpTraceExporter& traces() noexcept { return traces_; }
  [[nodiscard]] bool response_path_diagnostics_enabled() const noexcept {
    return response_path_diagnostics_enabled_;
  }
  void remove(DownstreamConnection* connection) noexcept {
    connections_.erase(connection);
  }

  void drain_generation(GatewayRuntimeGeneration* generation) noexcept {
    for (auto* connection : connections_) {
      if (connection->generation() == generation) {
        connection->begin_drain(false);
      }
    }
  }

 private:
  seastar::future<> accept_loop() {
    bool resource_exhausted = false;
    while (!draining_) {
      bool retry_accept = false;
      try {
        auto accepted = co_await listener_socket_.accept();
        if (resource_exhausted) {
          gateway_log.info("listener accept recovered after resource exhaustion");
          resource_exhausted = false;
        }
        auto runtime = acquire_runtime_();
        if (!runtime.has_value() || runtime->generation == nullptr) {
          ++stats_.downstream_connection_rejections;
          accepted.connection.shutdown_input();
          accepted.connection.shutdown_output();
          continue;
        }
        if (stats_.active_connections >=
            runtime->generation->snapshot()
                .limits()
                .max_downstream_connections_per_shard) {
          ++stats_.downstream_connection_rejections;
          accepted.connection.shutdown_input();
          accepted.connection.shutdown_output();
          continue;
        }
        accepted.connection.set_nodelay(true);
        ++stats_.downstream_connections_accepted;
        auto connection = seastar::make_lw_shared<DownstreamConnection>(
            *this, *runtime->generation, std::move(runtime->lease),
            std::move(accepted.connection),
            accepted.remote_address);
        connections_.insert(connection.get());
        ++stats_.active_connections;
        (void)seastar::with_gate(
                  gate_, [connection] { return connection->process(); })
            .finally([this, connection] {
              remove(connection.get());
              --stats_.active_connections;
            });
      } catch (const std::system_error& error) {
        if (!draining_) {
          const auto code = error.code();
          if (code != std::errc::too_many_files_open &&
              code != std::errc::too_many_files_open_in_system &&
              code != std::errc::no_buffer_space &&
              code != std::errc::not_enough_memory) {
            throw;
          }
          if (!resource_exhausted) {
            gateway_log.warn("listener accept resource exhaustion: {}", error.what());
            resource_exhausted = true;
          }
          retry_accept = true;
        }
      } catch (...) {
        if (!draining_) {
          throw;
        }
      }
      if (retry_accept) {
        // Keep the listener alive without spinning or flooding logs under EMFILE.
        // Drain waits at most this bounded interval before the loop exits.
        co_await seastar::sleep(std::chrono::milliseconds(100));
      }
    }
  }

  RuntimeListener listener_config_;
  std::size_t listener_index_;
  RuntimeAcquirer acquire_runtime_;
  GatewayStats& stats_;
  AccessLogSink& access_log_;
  OtlpTraceExporter& traces_;
  std::string secrets_directory_;
  bool response_path_diagnostics_enabled_{false};
  seastar::shared_ptr<seastar::tls::server_credentials> credentials_;
  seastar::server_socket listener_socket_;
  seastar::gate gate_;
  std::unordered_set<DownstreamConnection*> connections_;
  bool draining_{false};
};

DownstreamConnection::DownstreamConnection(
    ListenerServer& server, GatewayRuntimeGeneration& generation,
    SnapshotReadLease lease, seastar::connected_socket socket,
    seastar::socket_address remote_address)
    : server_(server),
      generation_(&generation),
      snapshot_lease_(std::move(lease)),
      socket_(std::move(socket)),
      input_(socket_.input(seastar::connected_socket_input_stream_config{
          .buffer_size = 4096U,
          .min_buffer_size = 512U,
          .max_buffer_size = 4096U})),
      output_(socket_.output(kDownstreamOutputBufferBytes)),
      remote_address_(remote_address),
      local_address_(socket_.local_address()),
      client_address_resolver_(
          generation.snapshot().listeners()[server.listener_index()]
                  .trusted_proxy.has_value()
              ? &*generation.snapshot()
                      .listeners()[server.listener_index()]
                      .trusted_proxy
              : nullptr,
                               format_peer_address(remote_address_)),
      forwarded_proto_(server.tls_enabled() ? "https" : "http"),
      http2_drain_timer_([this] {
        ++server_.stats().http2_drain_timeouts;
        gateway_log.debug("HTTP/2 drain deadline expired");
        abort_http2_transport();
      }),
      http2_output_timer_([this] {
        gateway_log.warn("event=http2_output_timeout reason=write_idle_deadline");
        abort_http2_transport();
      }) {}

void DownstreamConnection::record_http1_request_bytes(
    std::size_t bytes) noexcept {
  server_.stats().request_bytes += bytes;
  if (http1_access_log_ != nullptr) {
    http1_access_log_->request_body_bytes += bytes;
  }
}

void DownstreamConnection::record_http1_response_bytes(
    std::size_t bytes) noexcept {
  server_.stats().response_bytes += bytes;
  if (http1_access_log_ != nullptr) {
    http1_access_log_->response_body_bytes += bytes;
  }
}

void DownstreamConnection::record_http2_request_bytes(
    const std::shared_ptr<Http2StreamState>& stream,
    std::size_t bytes) noexcept {
  server_.stats().request_bytes += bytes;
  stream->access_log.request_body_bytes += bytes;
}

void DownstreamConnection::record_http2_response_bytes(
    const std::shared_ptr<Http2StreamState>& stream,
    std::size_t bytes) noexcept {
  server_.stats().response_bytes += bytes;
  stream->access_log.response_body_bytes += bytes;
}

std::optional<std::chrono::steady_clock::time_point>
DownstreamConnection::start_response_path_handoff() const noexcept {
  if (!server_.response_path_diagnostics_enabled()) {
    return std::nullopt;
  }
  return std::chrono::steady_clock::now();
}

void DownstreamConnection::record_response_path_handoff(
    std::optional<std::chrono::steady_clock::time_point>&
        handoff_started_at) noexcept {
  if (!handoff_started_at.has_value()) {
    return;
  }
  auto& stats = server_.stats();
  ++stats.response_path_handoff_observations;
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           std::chrono::steady_clock::now() -
                           *handoff_started_at)
                           .count();
  if (elapsed > 0) {
    stats.response_path_handoff_nanoseconds +=
        static_cast<std::uint64_t>(elapsed);
  }
  handoff_started_at.reset();
}

void DownstreamConnection::record_response_path_write(
    std::size_t bytes) noexcept {
  if (!server_.response_path_diagnostics_enabled()) {
    return;
  }
  auto& stats = server_.stats();
  ++stats.response_path_write_operations;
  stats.response_path_write_bytes += bytes;
}

seastar::future<> DownstreamConnection::flush_response_path() {
  if (!server_.response_path_diagnostics_enabled()) {
    return output_.flush();
  }
  auto& stats = server_.stats();
  ++stats.response_path_flush_operations;
  auto pending = output_.flush();
  if (pending.available()) {
    return pending;
  }
  ++stats.response_path_flush_wait_operations;
  const auto started_at = std::chrono::steady_clock::now();
  return std::move(pending).then([this, started_at] {
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             std::chrono::steady_clock::now() - started_at)
                             .count();
    if (elapsed > 0) {
      server_.stats().response_path_flush_wait_nanoseconds +=
          static_cast<std::uint64_t>(elapsed);
    }
  });
}

void DownstreamConnection::record_response_path_completion() noexcept {
  if (server_.response_path_diagnostics_enabled()) {
    ++server_.stats().response_path_completed_responses;
  }
}

void DownstreamConnection::begin_drain(bool terminate_websocket) noexcept {
  draining_ = true;
  if (websocket_established_ && active_websocket_abort_ != nullptr) {
    if (!terminate_websocket) {
      return;
    }
    if (!active_websocket_abort_->abort_requested()) {
      ++server_.stats().websocket_drain_terminations;
      active_websocket_abort_->request_abort();
    }
    socket_.shutdown_input();
    return;
  }
  if (http2_session_ != nullptr) {
    try {
      if (!http2_drain_timer_.armed()) {
        http2_drain_timer_.arm(seastar::timer<>::clock::now() +
                               kHttp2DrainTimeout);
      }
      if (!http2_session_->is_draining()) {
        http2_session_->begin_graceful_shutdown();
        ++server_.stats().http2_goaways;
      }
      (void)seastar::with_gate(http2_background_gate_, [this] {
        return pump_http2_output();
      }).handle_exception([](const std::exception_ptr&) {
        gateway_log.debug("failed to flush HTTP/2 GOAWAY");
      });
    } catch (...) {
      socket_.shutdown_input();
    }
    return;
  }
  if (!in_request_) {
    socket_.shutdown_input();
  }
}

seastar::future<> DownstreamConnection::negotiate_tls() {
  const auto server_name = co_await seastar::tls::get_server_name(socket_);
  const auto alpn = co_await seastar::tls::get_negotiated_alpn(socket_);
  if (server_name.has_value()) {
    server_name_.emplace(server_name->data(), server_name->size());
    if (!snapshot().listener_accepts_server_name(
            server_.listener_index(), *server_name_)) {
      ++server_.stats().tls_sni_rejections;
      throw std::runtime_error("TLS SNI name is not configured on the listener");
    }
  }
  const auto expected_alpn = server_.protocol() == RuntimeProtocol::http2
                                 ? kHttp2Alpn
                                 : kHttp11Alpn;
  const auto alpn_valid = server_.protocol() == RuntimeProtocol::http2
                              ? alpn.has_value() && *alpn == expected_alpn
                              : !alpn.has_value() || *alpn == expected_alpn;
  if (!alpn_valid) {
    ++server_.stats().tls_alpn_rejections;
    throw std::runtime_error("TLS negotiated an unsupported ALPN protocol");
  }
}

seastar::future<> DownstreamConnection::initialize_security() {
  ++server_.stats().active_tls_handshakes;
  auto active = seastar::defer(
      [this] { --server_.stats().active_tls_handshakes; });
  bool timed_out = false;
  seastar::timer<> timer([this, &timed_out] {
    timed_out = true;
    seastar::tls::abort(socket_);
  });
  timer.arm(seastar::timer<>::clock::now() + kTlsHandshakeTimeout);
  auto negotiated =
      co_await seastar::coroutine::as_future(negotiate_tls());
  timer.cancel();
  if (timed_out) {
    negotiated.ignore_ready_future();
    ++server_.stats().tls_handshake_timeouts;
    ++server_.stats().tls_handshake_failures;
    throw std::runtime_error("TLS handshake timed out");
  }
  if (negotiated.failed()) {
    ++server_.stats().tls_handshake_failures;
    std::rethrow_exception(negotiated.get_exception());
  }
  negotiated.get();
  ++server_.stats().tls_handshakes;
}

seastar::future<std::unique_ptr<seastar::http::request>>
DownstreamConnection::read_request() {
  BoundedRequestParser parser(
      snapshot().limits().max_request_header_bytes);
  bool idle_timed_out = false;
  seastar::timer<> idle_timer([this, &idle_timed_out] {
    idle_timed_out = true;
    socket_.shutdown_input();
  });
  idle_timer.arm(seastar::timer<>::clock::now() + std::chrono::milliseconds(
      snapshot().limits().downstream_idle_timeout_ms));
  auto consumed = co_await seastar::coroutine::as_future(input_.consume(parser));
  idle_timer.cancel();
  if (idle_timed_out) {
    consumed.ignore_ready_future();
    throw bonvoyage::http::RequestError(
        408U, "downstream_idle_timeout",
        "Request headers were not received before the idle timeout");
  }
  if (consumed.failed()) {
    std::rethrow_exception(consumed.get_exception());
  }
  consumed.get();
  if (parser.eof()) {
    if (parser.header_bytes() == 0U) {
      co_return nullptr;
    }
    throw bonvoyage::http::RequestError(
        400U, "truncated_request", "The HTTP/1 request ended before its headers");
  }
  if (parser.failed()) {
    throw bonvoyage::http::RequestError(
        400U, "malformed_request", "The HTTP/1 request is malformed");
  }
  auto request = parser.request();
  http1_traceparent_repeated_ = parser.traceparent_repeated();
  request->_client_address = remote_address_;
  request->_server_address = local_address_;
  co_return request;
}

seastar::future<> DownstreamConnection::close_streams() noexcept {
  // TLS shutdown closes the whole session. Preserve any flushed response by
  // closing the output stream before releasing the input side.
  if (!output_closed_) {
    output_closed_ = true;
    co_await output_.close().handle_exception([](const std::exception_ptr&) {});
  }
  co_await input_.close().handle_exception([](const std::exception_ptr&) {});
}

seastar::future<> DownstreamConnection::process() {
  if (server_.tls_enabled()) {
    auto initialized =
        co_await seastar::coroutine::as_future(initialize_security());
    if (initialized.failed()) {
      gateway_log.debug("downstream TLS connection rejected: {}",
                        initialized.get_exception());
      co_await close_streams();
      co_return;
    }
    initialized.get();
  }
  if (server_.protocol() == RuntimeProtocol::http2) {
    co_await process_http2();
  } else {
    co_await process_http1();
  }
  co_await close_streams();
}

seastar::future<> DownstreamConnection::process_http1() {
  while (!draining_) {
    response_started_ = false;
    completed_websocket_tunnel_ = false;
    // Parsing can fail before handle_request; never reuse the previous policy.
    http1_cors_.reset();
    http1_cors_policy_configured_ = false;
    auto read = co_await seastar::coroutine::as_future(read_request());
    if (read.failed()) {
      const auto error = classify_error(read.get_exception());
      if (draining_ || error.upstream_failure) {
        break;
      }
      if (!response_started_) {
        co_await write_error(error.status, error.code, error.message, true)
            .handle_exception([](const std::exception_ptr&) {});
      }
      break;
    }
    auto request = read.get();
    if (request == nullptr) {
      break;
    }
    in_request_ = true;
    const auto request_started = std::chrono::steady_clock::now();
    AccessLogRecord access_log;
    access_log.snapshot_generation = snapshot().generation();
    access_log.shard = seastar::this_shard_id();
    access_log.listener =
        snapshot().listeners()[server_.listener_index()].name;
    access_log.method = classify_access_log_method(request->_method);
    http1_access_log_ = &access_log;
    auto clear_access_log =
        seastar::defer([this] { http1_access_log_ = nullptr; });
    std::optional<TraceSpanRecord> trace;
    if (server_.traces().enabled()) {
      const auto& incoming = request->get_header("traceparent");
      trace.emplace(server_.traces().begin_request(
          http1_traceparent_repeated_ ? std::string_view{"duplicate"}
                                      : std::string_view{incoming}));
      http1_trace_ = &*trace;
    }
    auto clear_trace = seastar::defer([this] { http1_trace_ = nullptr; });
    ++server_.stats().active_requests;
    ++server_.stats().requests_total;
    seastar::abort_source abort;
    bool request_timed_out = false;
    seastar::timer<> request_timer([this, &abort, &request_timed_out] {
      if (websocket_established_) {
        return;
      }
      request_timed_out = true;
      abort.request_abort();
      if (response_started_) {
        // A partially written response cannot be replaced with a 504. Abort
        // both directions so a slow reader cannot retain request resources.
        if (server_.tls_enabled()) {
          seastar::tls::abort(socket_);
        } else {
          socket_.shutdown_input();
          socket_.shutdown_output();
        }
      } else if (http1_body_read_pending_) {
        // TLS input shutdown does not interrupt a pending decrypted body read.
        // Abort that transport because an incomplete request cannot receive a
        // reliable 504; plaintext input shutdown is sufficient to wake its
        // pending read without closing the output side.
        if (server_.tls_enabled()) {
          seastar::tls::abort(socket_);
        } else {
          socket_.shutdown_input();
        }
      } else if (!server_.tls_enabled()) {
        // Upstream waits are cancelled through the request abort source. Keep
        // TLS open so the timeout response can be written to the client.
        socket_.shutdown_input();
      }
    });
    request_timer.arm(seastar::timer<>::clock::now() +
                      std::chrono::milliseconds(
                          snapshot().limits().request_timeout_ms));
    auto handled = co_await seastar::coroutine::as_future(
        handle_request(std::move(request), abort));
    request_timer.cancel();
    if (request_timed_out) {
      handled.ignore_ready_future();
      handled = seastar::make_exception_future<>(
          bonvoyage::http::RequestError(
              504U, "request_timeout", "The request timed out", true));
    }
    bool response_complete = false;
    if (handled.failed()) {
      const auto error = classify_error(handled.get_exception());
      if (error.timeout) {
        ++server_.stats().request_timeouts;
      }
      if (error.upstream_failure) {
        ++server_.stats().upstream_failures;
      }
      if (!response_started_) {
        co_await write_error(error.status, error.code, error.message,
                             error.close_connection)
            .then([&response_complete] { response_complete = true; })
            .handle_exception([](std::exception_ptr write_failure) {
              gateway_log.warn("failed to write downstream error response: {}",
                               write_failure);
            });
      }
      draining_ = draining_ || error.close_connection;
    } else {
      handled.get();
      response_complete = true;
    }
    --server_.stats().active_requests;
    if (!completed_websocket_tunnel_) {
      server_.stats().observe_request_latency(
          std::chrono::steady_clock::now() - request_started);
    }
    access_log.timestamp_unix_microseconds = unix_microseconds_now();
    access_log.duration_microseconds = elapsed_microseconds(request_started);
    access_log.completion =
        response_complete
            ? AccessLogCompletion::complete
            : (response_started_ ? AccessLogCompletion::partial
                                 : AccessLogCompletion::aborted);
    if (trace.has_value()) {
      complete_trace_from_access_log(*trace, access_log);
      server_.traces().enqueue(*trace);
    }
    server_.access_log().enqueue(access_log);
    in_request_ = false;
  }
}

seastar::future<seastar::temporary_buffer<char>>
DownstreamConnection::read_http2_input() {
  bool idle_timed_out = false;
  seastar::timer<> idle_timer([this, &idle_timed_out] {
    idle_timed_out = true;
    socket_.shutdown_input();
  });
  idle_timer.arm(seastar::timer<>::clock::now() + std::chrono::milliseconds(
      snapshot().limits().downstream_idle_timeout_ms));
  auto read = co_await seastar::coroutine::as_future(input_.read_up_to(64U *
                                                                      1024U));
  idle_timer.cancel();
  if (idle_timed_out) {
    read.ignore_ready_future();
    throw bonvoyage::http::RequestError(
        408U, "downstream_idle_timeout",
        "HTTP/2 input was not received before the idle timeout", false);
  }
  if (read.failed()) {
    std::rethrow_exception(read.get_exception());
  }
  co_return read.get();
}

seastar::future<> DownstreamConnection::process_http2() {
  http2_session_ =
      std::make_unique<bonvoyage::http::Http2ServerSession>();
  ++server_.stats().http2_connections;
  ++server_.stats().active_http2_connections;
  auto active_connection = seastar::defer(
      [this] { --server_.stats().active_http2_connections; });

  bool protocol_failed = false;
  try {
    co_await pump_http2_output();
    while (!http2_transport_closed_) {
      auto data = co_await read_http2_input();
      if (data.empty()) {
        break;
      }
      const auto* bytes =
          reinterpret_cast<const std::uint8_t*>(data.get());
      co_await receive_http2_input({bytes, data.size()});
    }
  } catch (const bonvoyage::http::Http2ProtocolError& error) {
    protocol_failed = true;
    ++server_.stats().http2_protocol_errors;
    gateway_log.debug("downstream HTTP/2 protocol failure: {}", error.what());
  } catch (const std::exception& error) {
    gateway_log.debug("downstream HTTP/2 connection ended: {}", error.what());
  }

  http2_drain_timer_.cancel();

  if (http2_session_ != nullptr && !http2_transport_closed_ &&
      !protocol_failed && !http2_session_->is_draining()) {
    try {
      http2_session_->begin_graceful_shutdown();
      ++server_.stats().http2_goaways;
      co_await pump_http2_output();
    } catch (const std::exception& error) {
      gateway_log.debug("failed to drain HTTP/2 session: {}", error.what());
    }
  }

  http2_transport_closed_ = true;
  ++http2_progress_epoch_;
  http2_progress_.broadcast();
  const auto closed = std::make_exception_ptr(
      seastar::abort_requested_exception{});
  for (auto& [stream_id, stream] : http2_streams_) {
    (void)stream_id;
    stream->peer_closed = true;
    stream->abort.request_abort();
    stream->body->abort(closed);
    --server_.stats().active_http2_streams;
  }
  co_await http2_background_gate_.close();
  co_await http2_stream_gate_.close();
  http2_streams_.clear();
  http2_rejected_streams_.clear();
}

seastar::future<> DownstreamConnection::receive_http2_input(
    std::span<const std::uint8_t> input) {
  std::size_t offset = 0U;
  while (offset < input.size()) {
    std::size_t consumed = 0U;
    std::vector<bonvoyage::http::Http2Event> events;
    {
      auto units = co_await seastar::get_units(http2_session_mutex_, 1U);
      if (http2_transport_closed_) {
        co_return;
      }
      consumed = http2_session_->receive(input.subspan(offset));
      events = http2_session_->take_events();
    }
    if (consumed == 0U) {
      throw bonvoyage::http::Http2ProtocolError(
          NGHTTP2_ERR_CALLBACK_FAILURE,
          "HTTP/2 parser made no progress on non-empty input");
    }
    offset += consumed;
    ++http2_progress_epoch_;
    http2_progress_.broadcast();
    co_await dispatch_http2_events(std::move(events));
    co_await pump_http2_output();
  }
}

void DownstreamConnection::abort_http2_transport() noexcept {
  http2_transport_closed_ = true;
  // TLS shutdown is graceful and can itself wait behind the blocked write.
  // The existing abort hook interrupts the underlying transport immediately.
  if (server_.tls_enabled()) {
    seastar::tls::abort(socket_);
  } else {
    socket_.shutdown_input();
    socket_.shutdown_output();
  }
  ++http2_progress_epoch_;
  http2_progress_.broadcast();
}

seastar::future<> DownstreamConnection::pump_http2_output() {
  if (http2_session_ == nullptr || http2_transport_closed_) {
    co_return;
  }
  // Arm a connection watchdog only for an actual pending socket operation.
  // Ready writes keep their existing fast path; never race and abandon I/O.
  const auto bounded_write = [this](seastar::future<> pending) {
    if (pending.available()) {
      return pending;
    }
    http2_output_timer_.arm(seastar::timer<>::clock::now() +
        std::chrono::milliseconds(
            snapshot().limits().downstream_idle_timeout_ms));
    return std::move(pending).finally([this] { http2_output_timer_.cancel(); });
  };
  while (!http2_transport_closed_) {
    std::vector<bonvoyage::http::Http2Event> events;
    bool should_close_transport = false;
    {
      auto units = co_await seastar::get_units(http2_session_mutex_, 1U);
      if (http2_transport_closed_) {
        co_return;
      }
      bool wrote = false;
      while (true) {
        auto chunk = http2_session_->take_output_chunk();
        if (chunk.empty()) {
          break;
        }
        wrote = true;
        co_await bounded_write(output_.write(
            reinterpret_cast<const char*>(chunk.data()), chunk.size()));
      }
      if (wrote) {
        co_await bounded_write(output_.flush());
      }
      events = http2_session_->take_events();
      should_close_transport =
          !http2_session_->is_draining() &&
          http2_session_->should_close_transport();
    }
    ++http2_progress_epoch_;
    http2_progress_.broadcast();
    if (events.empty()) {
      if (should_close_transport) {
        http2_transport_closed_ = true;
        output_closed_ = true;
        co_await output_.close().handle_exception(
            [](const std::exception_ptr&) {});
        socket_.shutdown_input();
      }
      break;
    }
    co_await dispatch_http2_events(std::move(events));
  }
}

seastar::future<> DownstreamConnection::reset_http2_stream(
    std::int32_t stream_id, std::uint32_t error_code) {
  if (http2_session_ == nullptr || http2_transport_closed_) {
    co_return;
  }
  {
    auto units = co_await seastar::get_units(http2_session_mutex_, 1U);
    if (http2_transport_closed_) {
      co_return;
    }
    http2_session_->reset_stream(stream_id, error_code);
  }
  co_await pump_http2_output();
}

seastar::future<> DownstreamConnection::acknowledge_http2_data(
    std::int32_t stream_id, std::size_t bytes) {
  if (bytes == 0U || http2_session_ == nullptr || http2_transport_closed_) {
    co_return;
  }
  {
    auto units = co_await seastar::get_units(http2_session_mutex_, 1U);
    if (http2_transport_closed_) {
      co_return;
    }
    http2_session_->acknowledge_data(stream_id, bytes);
  }
  co_await pump_http2_output();
}

seastar::future<> DownstreamConnection::dispatch_http2_events(
    std::vector<bonvoyage::http::Http2Event> events) {
  for (auto& event : events) {
    switch (event.kind) {
      case bonvoyage::http::Http2EventKind::request_headers: {
        if (draining_) {
          co_await reset_http2_stream(event.stream_id,
                                      NGHTTP2_REFUSED_STREAM);
          break;
        }
        try {
          auto request = bonvoyage::http::validate_http2_request_headers(
              event.headers, event.end_stream,
              snapshot().limits().max_request_body_bytes);
          if (server_name_.has_value() &&
              !RuntimeSnapshot::authority_matches_server_name(
                  request.authority, *server_name_)) {
            throw bonvoyage::http::RequestError(
                421U, "sni_authority_mismatch",
                "HTTP/2 authority does not match the TLS server name", false);
          }
          const auto forwarded_for =
              find_http2_forwarded_for_fields(request.headers);
          auto client_address =
              resolve_client_address(forwarded_for.view(), false);
          const auto content_type = find_http2_request_header(
              &request.headers, "content-type");
          auto stream = std::make_shared<Http2StreamState>();
          stream->stream_id = event.stream_id;
          stream->grpc =
              content_type.present &&
              bonvoyage::http::is_grpc_content_type(content_type.value);
          stream->request = std::move(request);
          stream->forwarded_client_address = std::move(client_address.address);
          stream->body = std::make_shared<Http2RequestBody>(
              stream->request.content_length,
              snapshot().limits().max_request_body_bytes,
              event.end_stream);
          stream->request_complete = event.end_stream;
          if (!http2_streams_.emplace(event.stream_id, stream).second) {
            co_await reset_http2_stream(event.stream_id,
                                        NGHTTP2_PROTOCOL_ERROR);
            break;
          }
          ++server_.stats().http2_streams;
          ++server_.stats().active_http2_streams;
          (void)seastar::with_gate(http2_stream_gate_, [this, stream] {
            return handle_http2_stream(stream);
          }).handle_exception([](const std::exception_ptr&) {
            gateway_log.debug("HTTP/2 stream task failed");
          });
        } catch (const bonvoyage::http::RequestError& error) {
          http2_rejected_streams_.insert(event.stream_id);
          const auto status = error.status_code();
          const auto& code = error.code();
          const auto message = std::string(error.what());
          (void)seastar::with_gate(
                    http2_background_gate_,
                    [this, stream_id = event.stream_id, status, code,
                     message] {
                      return write_http2_error(stream_id, status, code,
                                               message)
                          .then([this, stream_id] {
                            return reset_http2_stream(stream_id,
                                                      NGHTTP2_PROTOCOL_ERROR);
                          });
                    })
              .handle_exception([](const std::exception_ptr&) {
                gateway_log.debug("failed to reject HTTP/2 request");
              });
        }
        break;
      }
      case bonvoyage::http::Http2EventKind::request_trailers: {
        const auto found = http2_streams_.find(event.stream_id);
        if (found != http2_streams_.end()) {
          found->second->body->abort(std::make_exception_ptr(
              bonvoyage::http::RequestError(
                  400U, "request_trailers_not_supported",
                  "HTTP/2 request trailers are not enabled", false)));
        }
        break;
      }
      case bonvoyage::http::Http2EventKind::data: {
        const auto data_bytes = event.data.size();
        if (http2_rejected_streams_.contains(event.stream_id)) {
          co_await acknowledge_http2_data(event.stream_id, data_bytes);
          break;
        }
        const auto found = http2_streams_.find(event.stream_id);
        const auto append_result =
            found == http2_streams_.end()
                ? Http2BodyAppendResult::closed
                : found->second->body->append(std::move(event.data));
        if (append_result != Http2BodyAppendResult::accepted) {
          if (found != http2_streams_.end()) {
            if (append_result == Http2BodyAppendResult::body_too_large) {
              if (found->second->route_maximum_body_bytes.has_value() &&
                  !found->second->route_body_limit_rejection_recorded) {
                ++server_.stats().request_body_limit_rejections;
                found->second->route_body_limit_rejection_recorded = true;
              }
              found->second->body->abort(std::make_exception_ptr(
                  bonvoyage::http::RequestError(
                      413U, "request_body_too_large",
                      "HTTP/2 request body exceeds the configured limit",
                      false)));
            } else if (append_result ==
                       Http2BodyAppendResult::content_length_mismatch) {
              found->second->body->abort(std::make_exception_ptr(
                  bonvoyage::http::RequestError(
                      400U, "content_length_mismatch",
                      "HTTP/2 DATA exceeds Content-Length", false)));
            }
          }
          http2_rejected_streams_.insert(event.stream_id);
          co_await acknowledge_http2_data(event.stream_id, data_bytes);
        }
        break;
      }
      case bonvoyage::http::Http2EventKind::stream_end: {
        const auto found = http2_streams_.find(event.stream_id);
        if (found != http2_streams_.end()) {
          found->second->request_complete = true;
          found->second->body->finish();
        }
        break;
      }
      case bonvoyage::http::Http2EventKind::stream_closed: {
        http2_rejected_streams_.erase(event.stream_id);
        const auto found = http2_streams_.find(event.stream_id);
        if (found != http2_streams_.end()) {
          found->second->peer_closed = true;
          if (event.error_code != NGHTTP2_NO_ERROR) {
            ++server_.stats().http2_stream_resets;
            found->second->abort.request_abort();
            found->second->body->abort(std::make_exception_ptr(
                seastar::abort_requested_exception{}));
          }
          http2_streams_.erase(found);
          --server_.stats().active_http2_streams;
          ++http2_progress_epoch_;
          http2_progress_.broadcast();
        }
        break;
      }
    }
  }
}

seastar::future<> DownstreamConnection::submit_http2_headers(
    std::shared_ptr<Http2StreamState> stream, std::uint16_t status,
    std::vector<bonvoyage::http::Http2Header> headers, bool end_stream) {
  if (http2_transport_closed_ || stream->peer_closed) {
    throw seastar::abort_requested_exception{};
  }
  if (stream->cors.has_value()) {
    append_cors_response_headers(
        *stream->cors, [&headers](std::string_view name,
                                 std::string_view value) {
          headers.push_back(
              {std::string(name), std::string(value), false});
        });
  }
  {
    auto units = co_await seastar::get_units(http2_session_mutex_, 1U);
    if (http2_transport_closed_ || stream->peer_closed) {
      throw seastar::abort_requested_exception{};
    }
    http2_session_->submit_response_headers(stream->stream_id, status, headers,
                                            end_stream);
    stream->response_started = true;
    stream->access_log.status = status;
  }
  co_await pump_http2_output();
  if (end_stream) {
    stream->response_complete = stream->peer_closed &&
                                !stream->abort.abort_requested() &&
                                !http2_transport_closed_;
  }
}

seastar::future<> DownstreamConnection::wait_http2_response_complete(
    std::shared_ptr<Http2StreamState> stream) {
  if (stream->response_complete) {
    co_return;
  }
  // Queuing END_STREAM is not completion when the peer withholds window credit.
  co_await http2_progress_.wait([this, &stream] {
    return http2_transport_closed_ || stream->peer_closed ||
           stream->abort.abort_requested();
  });
  if (http2_transport_closed_ || stream->abort.abort_requested()) {
    throw seastar::abort_requested_exception{};
  }
  stream->response_complete = true;
}

seastar::future<> DownstreamConnection::submit_http2_data(
    std::shared_ptr<Http2StreamState> stream,
    std::span<const std::uint8_t> data, bool end_stream,
    bool best_effort_error) {
  if (data.empty() && !end_stream) {
    co_return;
  }
  std::size_t offset = 0U;
  bool submitted_empty_final = false;
  while (offset < data.size() ||
         (data.empty() && end_stream && !submitted_empty_final)) {
    const auto amount = data.empty()
                            ? 0U
                            : std::min(kHttp2ResponseChunkBytes,
                                       data.size() - offset);
    const auto final_fragment =
        end_stream && (data.empty() || offset + amount == data.size());
    bool accepted = false;
    bool pumped = false;
    while (!accepted) {
      std::uint64_t observed_epoch = 0U;
      {
        auto units = co_await seastar::get_units(http2_session_mutex_, 1U);
        if (http2_transport_closed_ || stream->peer_closed ||
            (!best_effort_error && stream->abort.abort_requested())) {
          throw seastar::abort_requested_exception{};
        }
        accepted = http2_session_->try_submit_data(
            stream->stream_id, data.subspan(offset, amount), final_fragment);
        observed_epoch = http2_progress_epoch_;
      }
      if (accepted) {
        break;
      }
      // A terminal error cannot wait on the already-expired request's budget.
      if (best_effort_error) {
        throw seastar::abort_requested_exception{};
      }
      if (!pumped) {
        pumped = true;
        co_await pump_http2_output();
        continue;
      }
      co_await http2_progress_.wait(
          [this, stream, observed_epoch] {
            return http2_transport_closed_ || stream->peer_closed ||
                   stream->abort.abort_requested() ||
                   http2_progress_epoch_ != observed_epoch;
          });
      pumped = false;
    }
    offset += amount;
    submitted_empty_final = data.empty();
    co_await pump_http2_output();
  }
  if (end_stream) {
    stream->response_complete = stream->peer_closed &&
                                !stream->abort.abort_requested() &&
                                !http2_transport_closed_;
  }
}

seastar::future<> DownstreamConnection::submit_http2_trailers(
    std::shared_ptr<Http2StreamState> stream,
    std::vector<bonvoyage::http::Http2Header> trailers) {
  if (http2_transport_closed_ || stream->peer_closed) {
    throw seastar::abort_requested_exception{};
  }
  {
    auto units = co_await seastar::get_units(http2_session_mutex_, 1U);
    if (http2_transport_closed_ || stream->peer_closed) {
      throw seastar::abort_requested_exception{};
    }
    http2_session_->submit_response_trailers(stream->stream_id, trailers);
  }
  co_await pump_http2_output();
  stream->response_complete = stream->peer_closed &&
                              !stream->abort.abort_requested() &&
                              !http2_transport_closed_;
}

seastar::future<> DownstreamConnection::consume_http2_body(
    std::shared_ptr<Http2StreamState> stream) {
  while (true) {
    auto data = co_await stream->body->read();
    if (data.empty()) {
      break;
    }
    record_http2_request_bytes(stream, data.size());
    co_await acknowledge_http2_data(stream->stream_id, data.size());
  }
}

ClientAddressResolution DownstreamConnection::resolve_client_address(
    std::span<const std::string_view> forwarded_for_fields,
    bool close_connection) {
  auto resolved = client_address_resolver_.resolve(forwarded_for_fields);
  if (resolved.source == ClientAddressSource::invalid_forwarded_for) {
    ++server_.stats().forwarded_header_rejections;
    throw bonvoyage::http::RequestError(
        400U, "invalid_forwarded_for",
        "A trusted proxy supplied an invalid X-Forwarded-For chain",
        close_connection);
  }
  if (resolved.source == ClientAddressSource::trusted_forwarded_for) {
    ++server_.stats().trusted_proxy_client_ip_resolutions;
  }
  return resolved;
}

seastar::future<> DownstreamConnection::execute_http2_request(
    std::shared_ptr<Http2StreamState> stream) {
  const auto target = split_request_target(stream->request.path);
  const auto cors_request = inspect_cors_request(
      stream->request.method, &stream->request.headers,
      find_http2_request_header);
  if (cors_request.kind == CorsRequestKind::preflight &&
      cors_request.malformed) {
    ++server_.stats().cors_rejections;
    co_await write_http2_error(stream->stream_id, 400U,
                               "invalid_cors_request",
                               "The CORS preflight fields are malformed");
    stream->response_started = true;
    co_await consume_http2_body(stream);
    co_return;
  }
  const auto request_view = RequestView{
      stream->request.authority, target.path,
      cors_request.kind == CorsRequestKind::preflight
          ? cors_request.requested_method
          : std::string_view(stream->request.method),
      target.query, &stream->request.headers, find_http2_request_header};
  const auto match = cors_request.kind == CorsRequestKind::preflight
                         ? snapshot().match_cors_preflight(
                               server_.listener_index(), request_view)
                         : snapshot().match(server_.listener_index(),
                                                    request_view);
  if (match.route == nullptr) {
    ++server_.stats().route_misses;
    stream->access_log.action = AccessLogAction::route_miss;
    co_await consume_http2_body(stream);
    co_await write_http2_error(stream->stream_id, 404U, "route_not_found",
                               "No route matched the request");
    stream->response_started = true;
    co_return;
  }
  stream->access_log.route = match.route->name;
  if (cors_request.kind == CorsRequestKind::preflight) {
    stream->access_log.action = AccessLogAction::cors_preflight;
  } else if (match.route->fixed_response.has_value()) {
    stream->access_log.action = AccessLogAction::fixed_response;
  } else if (match.route->redirect.has_value()) {
    stream->access_log.action = AccessLogAction::redirect;
  } else {
    stream->access_log.action = AccessLogAction::proxy;
  }
  stream->cors_policy_configured = match.route->cors.has_value();
  const auto client_address = stream->forwarded_client_address.empty()
                                  ? client_address_resolver_.direct_peer_address()
                                  : std::string_view(
                                        stream->forwarded_client_address);
  const auto source_ip_rejection = try_enforce_source_ip_policy(
      match.route->source_ip_policy.has_value()
          ? &*match.route->source_ip_policy
          : nullptr,
      client_address, server_.stats());
  if (source_ip_rejection.has_value()) {
    const auto& error = *source_ip_rejection;
    co_await write_http2_error(stream->stream_id, error.status, error.code,
                               error.message);
    stream->response_started = true;
    co_await consume_http2_body(stream);
    co_return;
  }
  if (cors_request.kind == CorsRequestKind::preflight &&
      (!stream->request_complete ||
       stream->request.content_length.value_or(0U) != 0U ||
       stream->body->received_bytes() != 0U)) {
    ++server_.stats().cors_rejections;
    co_await write_http2_error(
        stream->stream_id, 400U, "invalid_cors_request",
        "CORS preflight requests must not contain a body");
    stream->response_started = true;
    co_await consume_http2_body(stream);
    co_return;
  }
  auto cors = apply_cors_policy(
      match.route->cors.has_value() ? &*match.route->cors : nullptr,
      cors_request, stream->request.method, server_.stats());
  if (cors.rejection.has_value()) {
    const auto& error = *cors.rejection;
    co_await write_http2_error(stream->stream_id, error.status, error.code,
                               error.message);
    stream->response_started = true;
    co_await consume_http2_body(stream);
    co_return;
  }
  stream->cors = cors.response;
  if (cors_request.kind == CorsRequestKind::preflight) {
    co_await write_http2_cors_preflight(stream);
    co_return;
  }
  const auto* request_content_policy =
      match.route->request_content.has_value()
          ? &*match.route->request_content
          : nullptr;
  const auto body_capable =
      !stream->request_complete ||
      stream->request.content_length.value_or(0U) != 0U ||
      stream->body->received_bytes() != 0U;
  auto request_content = apply_request_content_policy(
      request_content_policy, &stream->request.headers,
      find_http2_request_header, body_capable,
      stream->request.content_length, stream->body->received_bytes(),
      server_.stats());
  if (request_content_policy != nullptr &&
      request_content_policy->maximum_body_bytes().has_value()) {
    stream->route_maximum_body_bytes =
        request_content_policy->maximum_body_bytes();
    stream->body->tighten_maximum_bytes(
        *stream->route_maximum_body_bytes);
  }
  if (request_content.rejection.has_value()) {
    const auto& error = *request_content.rejection;
    if (error.status == 413U) {
      stream->route_body_limit_rejection_recorded = true;
    }
    co_await write_http2_error(
        stream->stream_id, error.status, error.code, error.message,
        std::nullopt, std::nullopt,
        stream->cors.has_value() ? &*stream->cors : nullptr,
        request_content.accept);
    stream->response_started = true;
    if (!stream->request_complete) {
      http2_rejected_streams_.insert(stream->stream_id);
      co_await reset_http2_stream(stream->stream_id, NGHTTP2_NO_ERROR)
          .handle_exception([](const std::exception_ptr&) {});
    }
    co_return;
  }
  const auto auth_rejection = try_authenticate_api_key(
      api_key_auth(*match.route), &stream->request.headers,
      find_http2_request_header, server_.stats());
  if (auth_rejection.has_value()) {
    const auto& error = *auth_rejection;
    co_await write_http2_error(stream->stream_id, error.status, error.code,
                               error.message, std::nullopt, "ApiKey",
                               stream->cors.has_value() ? &*stream->cors
                                                        : nullptr);
    stream->response_started = true;
    co_await consume_http2_body(stream);
    co_return;
  }
  const auto jwt_rejection = try_authenticate_jwt(
      jwt_auth(*match.route), &stream->request.headers,
      find_http2_request_header, server_.stats());
  if (jwt_rejection.has_value()) {
    const auto& error = *jwt_rejection;
    const auto challenge =
        error.status == 401U
            ? std::optional<std::string_view>{"Bearer"}
            : (error.status == 403U
                   ? std::optional<std::string_view>{
                         "Bearer error=\"insufficient_scope\""}
                   : std::nullopt);
    co_await write_http2_error(stream->stream_id, error.status, error.code,
                               error.message, std::nullopt, challenge,
                               stream->cors.has_value() ? &*stream->cors
                                                        : nullptr);
    stream->response_started = true;
    co_await consume_http2_body(stream);
    co_return;
  }
  auto* admission = route_admission(*match.route);
  const auto rejection =
      try_admit_route(admission, server_.stats());
  if (rejection.has_value()) {
    const auto& error = *rejection;
    co_await write_http2_error(
        stream->stream_id, error.status, error.code, error.message,
        error.status == 429U ? std::optional<std::uint32_t>{1U}
                             : std::nullopt,
        std::nullopt,
        stream->cors.has_value() ? &*stream->cors : nullptr);
    stream->response_started = true;
    co_await consume_http2_body(stream);
    co_return;
  }
  auto admitted_route = seastar::defer([this, admission] {
    release_route(admission, server_.stats());
  });
  if (match.route->fixed_response.has_value()) {
    co_await consume_http2_body(stream);
    co_await write_http2_fixed_response(stream, *match.route->fixed_response);
    co_await wait_http2_response_complete(stream);
    co_return;
  }
  if (match.route->redirect.has_value()) {
    co_await consume_http2_body(stream);
    co_await write_http2_redirect_response(stream, *match.route->redirect);
    co_await wait_http2_response_complete(stream);
    co_return;
  }
  co_await proxy_http2_request(stream, *match.route);
  co_await wait_http2_response_complete(stream);
}

seastar::future<> DownstreamConnection::handle_http2_stream(
    std::shared_ptr<Http2StreamState> stream) {
  const auto request_started = std::chrono::steady_clock::now();
  stream->access_log.snapshot_generation =
      snapshot().generation();
  stream->access_log.shard = seastar::this_shard_id();
  stream->access_log.listener =
      snapshot().listeners()[server_.listener_index()].name;
  stream->access_log.protocol =
      stream->grpc ? AccessLogProtocol::grpc : AccessLogProtocol::http2;
  stream->access_log.method =
      classify_access_log_method(stream->request.method);
  if (server_.traces().enabled()) {
    const auto incoming = find_http2_request_header(
        &stream->request.headers, "traceparent");
    stream->trace.emplace(server_.traces().begin_request(
        incoming.repeated ? std::string_view{"duplicate"}
                          : incoming.value));
  }
  ++server_.stats().active_requests;
  ++server_.stats().requests_total;
  auto active_request = seastar::defer([this, stream, request_started] {
    --server_.stats().active_requests;
    server_.stats().observe_request_latency(std::chrono::steady_clock::now() -
                                            request_started);
    stream->access_log.timestamp_unix_microseconds = unix_microseconds_now();
    stream->access_log.duration_microseconds =
        elapsed_microseconds(request_started);
    stream->access_log.completion =
        stream->response_complete
            ? AccessLogCompletion::complete
            : (stream->response_started ? AccessLogCompletion::partial
                                        : AccessLogCompletion::aborted);
    if (stream->trace.has_value()) {
      complete_trace_from_access_log(*stream->trace, stream->access_log);
      server_.traces().enqueue(*stream->trace);
    }
    server_.access_log().enqueue(stream->access_log);
  });

  auto request_timeout = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::milliseconds(
          snapshot().limits().request_timeout_ms));
  std::optional<std::string> grpc_contract_error;
  if (stream->grpc) {
    ++server_.stats().grpc_requests;
    try {
      const auto contract = validate_grpc_request_contract(stream->request);
      stream->grpc_compression_allowed = contract.compression_allowed;
      if (contract.timeout.has_value()) {
        request_timeout = std::min(request_timeout, *contract.timeout);
      }
      stream->grpc_deadline =
          std::chrono::steady_clock::now() + request_timeout;
    } catch (const bonvoyage::http::RequestError& error) {
      ++server_.stats().grpc_protocol_rejections;
      grpc_contract_error = error.what();
    }
  }
  if (grpc_contract_error.has_value()) {
    co_await write_http2_grpc_error(stream, 3U, *grpc_contract_error);
    if (!stream->request_complete && !stream->peer_closed &&
        !http2_transport_closed_) {
      co_await reset_http2_stream(stream->stream_id, NGHTTP2_NO_ERROR)
          .handle_exception([](const std::exception_ptr&) {});
    }
    co_return;
  }

  bool request_timed_out = false;
  seastar::timer<> request_timer([this, stream, &request_timed_out] {
    request_timed_out = true;
    stream->abort.request_abort();
    stream->body->abort(std::make_exception_ptr(
        bonvoyage::http::RequestError(
            504U, "request_timeout", "The HTTP/2 request timed out", false)));
    ++http2_progress_epoch_;
    http2_progress_.broadcast();
    // A pending TCP write holds the session lock, so even RST_STREAM cannot
    // proceed. Close that shared transport, not an otherwise healthy H2 link.
    if (!http2_transport_closed_ && http2_output_timer_.armed()) {
      gateway_log.warn("event=http2_output_timeout reason=request_deadline");
      abort_http2_transport();
    }
  });
  request_timer.arm(seastar::timer<>::clock::now() +
                    request_timeout);

  auto handled = co_await seastar::coroutine::as_future(
      execute_http2_request(stream).then([this, stream] {
        return wait_http2_response_complete(stream);
      }));
  request_timer.cancel();

  if (request_timed_out) {
    handled.ignore_ready_future();
    handled = seastar::make_exception_future<>(
        bonvoyage::http::RequestError(
            504U, "request_timeout", "The HTTP/2 request timed out", false));
  }
  if (handled.failed()) {
    const auto error = classify_error(handled.get_exception());
    const auto peer_cancelled =
        !request_timed_out && error.timeout &&
        (stream->peer_closed || http2_transport_closed_);
    if (request_timed_out || (error.timeout && !peer_cancelled)) {
      ++server_.stats().request_timeouts;
    }
    if (peer_cancelled) {
      ++server_.stats().http2_request_cancellations;
    }
    if (error.upstream_failure) {
      ++server_.stats().upstream_failures;
    }
    if (!stream->response_started && !stream->peer_closed &&
        !http2_transport_closed_) {
      co_await write_http2_error(stream->stream_id, error.status, error.code,
                                 error.message, std::nullopt, std::nullopt,
                                 stream->cors.has_value() ? &*stream->cors
                                                          : nullptr)
          .handle_exception([](const std::exception_ptr&) {
            gateway_log.debug("failed to write HTTP/2 error response");
          });
      stream->response_started = true;
    } else if (stream->response_started && !stream->peer_closed &&
               !http2_transport_closed_) {
      if (stream->grpc) {
        co_await write_http2_grpc_trailer_error(
                     stream, grpc_status_for_http_error(error.status),
                     error.message)
            .handle_exception([this, stream](const std::exception_ptr&) {
              return reset_http2_stream(stream->stream_id,
                                        NGHTTP2_INTERNAL_ERROR)
                  .handle_exception([](const std::exception_ptr&) {});
            });
      } else {
        co_await reset_http2_stream(stream->stream_id,
                                    NGHTTP2_INTERNAL_ERROR)
            .handle_exception([](const std::exception_ptr&) {});
      }
    }
    if ((!stream->request_complete || !stream->response_complete) &&
        !stream->peer_closed &&
        !http2_transport_closed_) {
      const auto reset_code = error.code == "content_length_mismatch"
                                  ? NGHTTP2_PROTOCOL_ERROR
                                  : (stream->response_complete
                                         ? NGHTTP2_NO_ERROR
                                         : NGHTTP2_INTERNAL_ERROR);
      co_await reset_http2_stream(stream->stream_id, reset_code)
          .handle_exception([](const std::exception_ptr&) {});
    }
  } else {
    handled.get();
  }
}

seastar::future<> DownstreamConnection::proxy_http2_request(
    std::shared_ptr<Http2StreamState> stream,
    const RuntimeRoute& route) {
  auto make_upstream_request = [this, stream, &route] {
    std::optional<std::string> rewritten_target;
    if (route.rewrite.has_value() && route.rewrite->path.has_value()) {
      rewritten_target = rewrite_request_target(
          stream->request.path, route.path, *route.rewrite->path,
          snapshot().limits().max_request_header_bytes);
      if (!rewritten_target.has_value()) {
        ++server_.stats().request_rewrite_limit_rejections;
        throw bonvoyage::http::RequestError(
            414U, "rewritten_request_target_too_large",
            "Rewritten request target exceeds the configured limit");
      }
    }
    auto result = [&] {
      if (!route.rewrite.has_value()) {
        return seastar::http::request::make(
            stream->request.method, stream->request.authority,
            stream->request.path);
      }
      const std::string_view upstream_authority =
          route.rewrite->authority.has_value()
              ? std::string_view(*route.rewrite->authority)
              : std::string_view(stream->request.authority);
      const std::string_view upstream_target =
          rewritten_target.has_value()
              ? std::string_view(*rewritten_target)
              : std::string_view(stream->request.path);
      return seastar::http::request::make(
          stream->request.method,
          seastar::sstring(upstream_authority.data(),
                           upstream_authority.size()),
          seastar::sstring(upstream_target.data(), upstream_target.size()));
    }();
    result._version = "1.1";
    for (const auto& header : stream->request.headers) {
      if (header.name != "content-length" && header.name != "host" &&
          header.name != "te" &&
          (!stream->grpc || header.name != "grpc-timeout") &&
          (!route.api_key_auth.has_value() ||
           header.name != route.api_key_auth->header_name) &&
          (!route.jwt_auth.has_value() || header.name != "authorization") &&
          (!server_.traces().enabled() ||
           !is_trace_propagation_header(header.name)) &&
          !is_forwarded_identity_header(header.name)) {
        const auto existing = result._headers.find(header.name);
        if (existing != result._headers.end() &&
            (header.name == "cookie" || stream->grpc)) {
          // RFC 9113 section 8.2.3: split Cookie fields become one ordered
          // semicolon-separated value at the non-HTTP/2 request-map boundary.
          // Joining reduces the size of the already bounded header list.
          existing->second += header.name == "cookie" ? "; " : ",";
          existing->second += header.value;
        } else {
          result._headers[header.name] = header.value;
        }
      }
    }
    result._headers["Connection"] = "keep-alive";
    result._headers["X-Forwarded-Proto"] = forwarded_proto_;
    const auto client_address = stream->forwarded_client_address.empty()
                                    ? client_address_resolver_
                                          .direct_peer_address()
                                    : std::string_view(
                                          stream->forwarded_client_address);
    result._headers["X-Forwarded-For"] = seastar::sstring(
        client_address.data(), client_address.size());
    if (route.rewrite.has_value() && route.rewrite->authority.has_value()) {
      result._headers["X-Forwarded-Host"] = stream->request.authority;
    }
    if (route.header_transformations.has_value() &&
        !route.header_transformations->request.empty()) {
      if (!apply_request_header_mutations(
              result, route.header_transformations->request,
              snapshot().limits().max_request_header_bytes)) {
        ++server_.stats().header_transformation_limit_rejections;
        throw bonvoyage::http::RequestError(
            431U, "transformed_request_headers_too_large",
            "Transformed request headers exceed the configured limit");
      }
      ++server_.stats().request_header_transformation_applications;
    }
    if (stream->trace.has_value()) {
      result._headers["traceparent"] = format_traceparent(
          stream->trace->trace_id, stream->trace->span_id,
          stream->trace->trace_flags);
      if (!request_headers_within_limit(
              result,
              snapshot().limits().max_request_header_bytes)) {
        ++server_.traces().stats().propagation_limit_rejections;
        throw bonvoyage::http::RequestError(
            431U, "forwarded_request_headers_too_large",
            "Forwarded request headers exceed the configured limit");
      }
    }
    if (stream->grpc) {
      result._headers["TE"] = "trailers";
      if (stream->grpc_deadline.has_value()) {
        const auto remaining = *stream->grpc_deadline -
                               std::chrono::steady_clock::now();
        if (remaining <= std::chrono::steady_clock::duration::zero()) {
          throw bonvoyage::http::RequestError(
              504U, "grpc_deadline_exceeded",
              "The gRPC deadline expired before upstream dispatch", false);
        }
        result._headers["grpc-timeout"] =
            bonvoyage::http::format_grpc_timeout(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    remaining));
        ++server_.stats().grpc_deadlines_propagated;
      }
    }
    if (route.rewrite.has_value() && route.rewrite->authority.has_value()) {
      ++server_.stats().request_authority_rewrite_applications;
    }
    if (route.rewrite.has_value() && route.rewrite->path.has_value()) {
      ++server_.stats().request_path_rewrite_applications;
    }
    return result;
  };
  // Reject invalid rewrites and headers before advancing the shard's route schedule.
  auto upstream = make_upstream_request();
  const auto cluster_index = select_cluster(route);
  stream->access_log.cluster =
      snapshot().clusters()[cluster_index].name;
  auto& cluster = this->cluster(cluster_index);
  if (stream->grpc && !cluster.uses_http2()) {
    ++server_.stats().grpc_protocol_rejections;
    throw bonvoyage::http::RequestError(
        502U, "grpc_requires_http2_upstream",
        "Native gRPC requires an HTTP/2 upstream cluster", false);
  }

  const auto has_streaming_body =
      stream->request.content_length.value_or(0U) != 0U ||
      stream->body->received_bytes() != 0U ||
      (!stream->request_complete &&
       !stream->request.content_length.has_value());
  if (stream->grpc && !has_streaming_body) {
    ++server_.stats().grpc_protocol_rejections;
    throw bonvoyage::http::RequestError(
        400U, "grpc_message_missing",
        "A unary gRPC request must contain one length-prefixed message",
        false);
  }
  auto grpc_request_validator =
      stream->grpc
          ? std::make_shared<bonvoyage::http::GrpcUnaryMessageValidator>(
                stream->grpc_compression_allowed)
          : std::shared_ptr<bonvoyage::http::GrpcUnaryMessageValidator>{};
  if (has_streaming_body) {
    if (stream->request.content_length.has_value()) {
      upstream.content_length = static_cast<std::size_t>(
          *stream->request.content_length);
    } else {
      upstream._headers["Transfer-Encoding"] = "chunked";
    }
    upstream.body_writer =
        [this, stream, grpc_request_validator](
            seastar::output_stream<char>&& output) {
          return seastar::do_with(
              std::move(output),
              [this, stream, grpc_request_validator](auto& destination) {
                return seastar::repeat(
                    [this, stream, grpc_request_validator, &destination] {
                  return stream->body->read().then(
                      [this, stream, grpc_request_validator, &destination](
                          std::vector<std::uint8_t> data) {
                        if (data.empty()) {
                          if (grpc_request_validator != nullptr) {
                            try {
                              grpc_request_validator->finish(true);
                            } catch (const std::invalid_argument&) {
                              ++server_.stats().grpc_protocol_rejections;
                              throw bonvoyage::http::RequestError(
                                  400U, "invalid_grpc_message",
                                  "The unary gRPC request body is malformed",
                                  false);
                            }
                          }
                          return seastar::make_ready_future<
                              seastar::stop_iteration>(
                              seastar::stop_iteration::yes);
                        }
                        if (grpc_request_validator != nullptr) {
                          try {
                            grpc_request_validator->consume(data);
                          } catch (const std::invalid_argument&) {
                            ++server_.stats().grpc_protocol_rejections;
                            throw bonvoyage::http::RequestError(
                                400U, "invalid_grpc_message",
                                "The unary gRPC request body is malformed",
                                false);
                          }
                        }
                        const auto size = data.size();
                        seastar::temporary_buffer<char> buffer(size);
                        std::memcpy(buffer.get_write(), data.data(), size);
                        return destination.write(std::move(buffer))
                            .then([this, stream, size] {
                              record_http2_request_bytes(stream, size);
                              return acknowledge_http2_data(stream->stream_id,
                                                            size);
                            })
                            .then([] {
                              return seastar::stop_iteration::no;
                            });
                      });
                }).finally([&destination] { return destination.close(); });
              });
        };
  } else if (!stream->request_complete) {
    co_await consume_http2_body(stream);
  }

  const auto* transformations = route.header_transformations.has_value()
                                    ? &*route.header_transformations
                                    : nullptr;
  auto handler = [this, stream, transformations](
                     const seastar::http::reply& reply,
                     seastar::input_stream<char>&& response_body) {
    return seastar::do_with(
        std::move(response_body),
        [this, stream, transformations, &reply](auto& body) {
          return write_http2_upstream_response(stream, reply, body,
                                               transformations)
              .finally([&body] { return body.close(); });
        });
  };
  ClusterState::RequestFactory retry_request_factory;
  const bool request_replayable = !has_streaming_body;
  if (cluster.retries_enabled_for(stream->request.method,
                                  request_replayable)) {
    retry_request_factory = make_upstream_request;
  }
  co_await cluster.make_request(
      std::move(upstream), std::move(handler), &stream->abort,
      request_replayable, std::move(retry_request_factory));
}

seastar::future<> DownstreamConnection::write_http2_upstream_response(
    std::shared_ptr<Http2StreamState> stream,
    const seastar::http::reply& reply, seastar::input_stream<char>& body,
    const HeaderTransformations* transformations) {
  const auto status = static_cast<std::uint16_t>(reply._status);
  const bool upstream_http2 = reply._version == "2";
  const auto content_length_value = reply.get_header("Content-Length");
  const auto transfer_encoding_value = reply.get_header("Transfer-Encoding");
  bonvoyage::http::ResponseBodyFraming framing;
  try {
    framing = bonvoyage::http::validate_response_framing(
        stream->request.method, status, content_length_value,
        transfer_encoding_value);
  } catch (...) {
    ++server_.stats().upstream_framing_rejections;
    throw;
  }
  const bool stream_delimited =
      upstream_http2 &&
      framing.kind == bonvoyage::http::ResponseBodyKind::close_delimited;
  if (stream->grpc && !upstream_http2) {
    ++server_.stats().grpc_protocol_rejections;
    throw std::runtime_error("gRPC response did not use upstream HTTP/2");
  }
  const bool grpc_response = stream->grpc && status == 200U;
  if (grpc_response && !bonvoyage::http::is_grpc_content_type(
                           reply.get_header("Content-Type"))) {
    ++server_.stats().grpc_protocol_rejections;
    throw std::runtime_error("gRPC response has an invalid content type");
  }
  if (framing.kind ==
          bonvoyage::http::ResponseBodyKind::close_delimited &&
      !stream_delimited) {
    ++server_.stats().upstream_framing_rejections;
    throw std::runtime_error(
        "close-delimited upstream responses cannot be translated to HTTP/2");
  }

  std::vector<bonvoyage::http::Http2Header> headers;
  const auto connection = reply.get_header("Connection");
  const bonvoyage::http::ConnectionTokenSet connection_tokens(connection);
  for (const auto& [name, value] : reply._headers) {
    if (!bonvoyage::http::is_hop_by_hop_header(name, connection_tokens) &&
        !bonvoyage::http::ascii_case_equal(name, "content-length") &&
        (!stream->cors_policy_configured ||
         !is_cors_response_header(name))) {
      if (!safe_header_value(value)) {
        throw std::runtime_error(
            "upstream response contains an unsafe header value");
      }
      headers.push_back({bonvoyage::http::lowercase(name),
                         std::string(value), false});
    }
  }
  if (transformations != nullptr && !transformations->response.empty()) {
    if (!apply_http2_response_header_mutations(
            headers, transformations->response,
            snapshot().limits().max_upstream_response_header_bytes)) {
      ++server_.stats().header_transformation_limit_rejections;
      throw std::runtime_error(
          "transformed upstream response headers exceed the configured limit");
    }
    ++server_.stats().response_header_transformation_applications;
  }
  auto downstream_length = framing.content_length;
  if (framing.kind == bonvoyage::http::ResponseBodyKind::none &&
      (stream->request.method != "HEAD" ||
       !framing.content_length.has_value())) {
    downstream_length = 0U;
  }
  if (downstream_length.has_value()) {
    headers.push_back(
        {"content-length", std::to_string(*downstream_length), false});
  }

  if (grpc_response) {
    try {
      const auto initial_status_headers = grpc_status_headers(reply);
      if (!initial_status_headers.empty()) {
        if (!reply.trailing_headers.empty()) {
          throw std::invalid_argument(
              "gRPC trailers-only response also carried trailing headers");
        }
        auto unexpected = co_await body.read();
        if (!unexpected.empty()) {
          throw std::invalid_argument(
              "gRPC trailers-only response carried a message body");
        }
        const auto info =
            bonvoyage::http::validate_grpc_response_trailers(
                initial_status_headers);
        co_await submit_http2_headers(stream, status, std::move(headers),
                                      true);
        record_grpc_status(server_.stats(), info);
        record_response_status(server_.stats(), status);
        co_return;
      }

      const auto response_encoding = reply.get_header("grpc-encoding");
      bonvoyage::http::GrpcUnaryMessageValidator response_validator(
          !response_encoding.empty() && response_encoding != "identity");
      co_await submit_http2_headers(stream, status, std::move(headers), false);
      std::uint64_t copied = 0U;
      while (true) {
        auto data = co_await body.read();
        if (data.empty()) {
          break;
        }
        const auto* bytes =
            reinterpret_cast<const std::uint8_t*>(data.get());
        response_validator.consume({bytes, data.size()});
        copied += data.size();
        record_http2_response_bytes(stream, data.size());
        co_await submit_http2_data(stream, {bytes, data.size()}, false);
      }
      if (framing.kind ==
              bonvoyage::http::ResponseBodyKind::content_length &&
          copied != *framing.content_length) {
        throw std::invalid_argument("gRPC response body was truncated");
      }
      auto trailers = grpc_response_trailers(reply);
      const auto info =
          bonvoyage::http::validate_grpc_response_trailers(trailers);
      response_validator.finish(info.status == 0U);
      co_await submit_http2_trailers(stream, std::move(trailers));
      ++server_.stats().grpc_response_trailers_forwarded;
      if (stream_delimited) {
        ++server_.stats().upstream_http2_stream_delimited_responses;
      }
      record_grpc_status(server_.stats(), info);
      record_response_status(server_.stats(), status);
      co_return;
    } catch (const std::invalid_argument&) {
      ++server_.stats().grpc_protocol_rejections;
      throw;
    }
  }

  if (framing.kind == bonvoyage::http::ResponseBodyKind::none ||
      (framing.kind == bonvoyage::http::ResponseBodyKind::content_length &&
       framing.content_length.value_or(0U) == 0U)) {
    if (upstream_http2) {
      auto unexpected = co_await body.read();
      if (!unexpected.empty()) {
        ++server_.stats().upstream_framing_rejections;
        throw std::runtime_error(
            "upstream HTTP/2 sent a body where none was permitted");
      }
      validate_and_record_upstream_trailers(server_.stats(), reply);
    }
    co_await submit_http2_headers(stream, status, std::move(headers), true);
    record_response_status(server_.stats(), status);
    co_return;
  }

  co_await submit_http2_headers(stream, status, std::move(headers), false);
  std::uint64_t copied = 0U;
  while (true) {
    auto data = co_await body.read();
    if (data.empty()) {
      break;
    }
    copied += data.size();
    record_http2_response_bytes(stream, data.size());
    const auto* bytes =
        reinterpret_cast<const std::uint8_t*>(data.get());
    co_await submit_http2_data(stream, {bytes, data.size()}, false);
  }
  if (framing.kind == bonvoyage::http::ResponseBodyKind::content_length &&
      copied != *framing.content_length) {
    throw std::runtime_error("upstream response body was truncated");
  }
  if (upstream_http2) {
    validate_and_record_upstream_trailers(server_.stats(), reply);
    if (stream_delimited) {
      ++server_.stats().upstream_http2_stream_delimited_responses;
    }
  } else if (framing.kind == bonvoyage::http::ResponseBodyKind::chunked) {
    validate_and_record_upstream_trailers(server_.stats(), reply);
    ++server_.stats().upstream_chunked_responses;
  }
  co_await submit_http2_data(stream, {}, true);
  record_response_status(server_.stats(), status);
}

seastar::future<> DownstreamConnection::write_http2_fixed_response(
    std::shared_ptr<Http2StreamState> stream,
    const RuntimeFixedResponse& response) {
  const auto body_allowed = bonvoyage::http::response_allows_body(
      stream->request.method, response.status_code);
  const auto representation_allowed =
      bonvoyage::http::response_status_allows_content(response.status_code);
  const auto body_size = representation_allowed ? response.body.size() : 0U;
  std::vector<bonvoyage::http::Http2Header> headers{
      {"content-type", response.content_type, false},
      {"content-length", std::to_string(body_size), false}};
  const auto send_body = body_allowed && body_size != 0U;
  co_await submit_http2_headers(stream, response.status_code,
                                std::move(headers), !send_body);
  if (send_body) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(
        response.body.data());
    co_await submit_http2_data(stream, {bytes, body_size}, true);
    record_http2_response_bytes(stream, body_size);
  }
  record_response_status(server_.stats(), response.status_code);
}

seastar::future<> DownstreamConnection::write_http2_redirect_response(
    std::shared_ptr<Http2StreamState> stream,
    const RuntimeRedirectResponse& response) {
  std::vector<bonvoyage::http::Http2Header> headers{
      {"location", response.location, false},
      {"content-length", "0", false}};
  co_await submit_http2_headers(stream, response.status_code,
                                std::move(headers), true);
  ++server_.stats().route_redirects;
  record_response_status(server_.stats(), response.status_code);
}

seastar::future<> DownstreamConnection::write_http2_cors_preflight(
    std::shared_ptr<Http2StreamState> stream) {
  co_await submit_http2_headers(stream, 204U, {}, true);
  record_response_status(server_.stats(), 204U);
}

seastar::future<> DownstreamConnection::write_http2_grpc_error(
    std::shared_ptr<Http2StreamState> stream, std::uint32_t grpc_status,
    std::string_view message) {
  std::vector<bonvoyage::http::Http2Header> headers{
      {"content-type", "application/grpc", false},
      {"grpc-status", std::to_string(grpc_status), true},
      {"grpc-message", bonvoyage::http::encode_grpc_message(message), true}};
  co_await submit_http2_headers(stream, 200U, std::move(headers), true);
  ++server_.stats().grpc_local_errors;
  record_response_status(server_.stats(), 200U);
}

seastar::future<> DownstreamConnection::write_http2_grpc_trailer_error(
    std::shared_ptr<Http2StreamState> stream, std::uint32_t grpc_status,
    std::string_view message) {
  std::vector<bonvoyage::http::Http2Header> trailers{
      {"grpc-status", std::to_string(grpc_status), true},
      {"grpc-message", bonvoyage::http::encode_grpc_message(message), true}};
  co_await submit_http2_trailers(stream, std::move(trailers));
  ++server_.stats().grpc_local_errors;
  record_response_status(server_.stats(), 200U);
}

seastar::future<> DownstreamConnection::write_http2_error(
    std::int32_t stream_id, std::uint16_t status, std::string_view code,
    std::string_view message,
    std::optional<std::uint32_t> retry_after_seconds,
    std::optional<std::string_view> www_authenticate,
    const CorsResponseContext* cors,
    std::optional<std::string_view> accept) {
  const auto existing_stream = http2_streams_.find(stream_id);
  if (existing_stream != http2_streams_.end() &&
      existing_stream->second->grpc) {
    co_await write_http2_grpc_error(
        existing_stream->second, grpc_status_for_http_error(status), message);
    co_return;
  }
  auto stream = existing_stream != http2_streams_.end()
                    ? existing_stream->second
                    : std::make_shared<Http2StreamState>();
  stream->stream_id = stream_id;
  if (cors != nullptr) {
    stream->cors = *cors;
  }
  const auto body = std::string("{\"error\":{\"code\":\"") +
                    json_escape(code) + "\",\"message\":\"" +
                    json_escape(message) + "\"}}\n";
  std::vector<bonvoyage::http::Http2Header> headers{
      {"content-type", "application/json", false},
      {"content-length", std::to_string(body.size()), false}};
  if (retry_after_seconds.has_value()) {
    headers.push_back(
        {"retry-after", std::to_string(*retry_after_seconds), false});
  }
  if (www_authenticate.has_value()) {
    headers.push_back(
        {"www-authenticate", std::string(*www_authenticate), false});
  }
  if (accept.has_value()) {
    headers.push_back({"accept", std::string(*accept), false});
  }
  co_await submit_http2_headers(stream, status, std::move(headers), false);
  const auto* bytes =
      reinterpret_cast<const std::uint8_t*>(body.data());
  co_await submit_http2_data(stream, {bytes, body.size()}, true, true);
  record_http2_response_bytes(stream, body.size());
  record_response_status(server_.stats(), status);
}

seastar::future<seastar::temporary_buffer<char>>
DownstreamConnection::read_http1_body(seastar::input_stream<char>& body) {
  http1_body_read_pending_ = true;
  auto read = co_await seastar::coroutine::as_future(body.read());
  http1_body_read_pending_ = false;
  if (read.failed()) {
    std::rethrow_exception(read.get_exception());
  }
  co_return read.get();
}

seastar::future<> DownstreamConnection::consume_body(
    const bonvoyage::http::BodyFraming& framing,
    std::optional<std::uint64_t> route_maximum_body_bytes) {
  std::uint64_t total = 0U;
  const auto maximum_body_bytes = route_maximum_body_bytes.value_or(
      snapshot().limits().max_request_body_bytes);
  if (framing.kind == bonvoyage::http::BodyKind::none) {
    co_return;
  }
  if (framing.kind == bonvoyage::http::BodyKind::content_length) {
    seastar::input_stream<char> body(seastar::data_source(
        std::make_unique<seastar::httpd::internal::content_length_source_impl>(
            input_, static_cast<std::size_t>(framing.content_length))));
    while (true) {
      auto data = co_await read_http1_body(body);
      if (data.empty()) {
        break;
      }
      total += data.size();
      record_http1_request_bytes(data.size());
    }
    co_await body.close();
    if (total != framing.content_length) {
      throw bonvoyage::http::RequestError(
          400U, "truncated_request_body",
          "Request body ended before Content-Length bytes were received");
    }
    co_return;
  }
  seastar::input_stream<char> body(seastar::data_source(
      std::make_unique<BoundedChunkedSourceImpl>(
          input_, maximum_body_bytes,
          snapshot().limits().max_request_header_bytes,
          route_maximum_body_bytes.has_value()
              ? &server_.stats().request_body_limit_rejections
              : nullptr)));
  while (true) {
    auto data = co_await read_http1_body(body);
    if (data.empty()) {
      break;
    }
    total += data.size();
    if (total > maximum_body_bytes) {
      if (route_maximum_body_bytes.has_value()) {
        ++server_.stats().request_body_limit_rejections;
      }
      throw bonvoyage::http::RequestError(
          413U, "request_body_too_large",
          "Request body exceeds the configured limit");
    }
    record_http1_request_bytes(data.size());
  }
  co_await body.close();
}

seastar::future<> DownstreamConnection::handle_request(
    std::unique_ptr<seastar::http::request> request,
    seastar::abort_source& abort) {
  const auto selected_headers =
      bonvoyage::http::select_http1_headers(*request);
  const auto framing = bonvoyage::http::validate_request(
      *request,
      bonvoyage::http::RequestFramingHeaders{
          selected_headers.host.value, selected_headers.upgrade.value,
          selected_headers.expect.value,
          selected_headers.content_length.value,
          selected_headers.transfer_encoding.value},
      snapshot().limits().max_request_body_bytes);
  const auto connection_header = selected_headers.connection.value;
  const auto upgrade_header = selected_headers.upgrade.value;
  const auto websocket_version = selected_headers.websocket_version.value;
  const auto websocket_key = selected_headers.websocket_key.value;
  const auto websocket_protocol = selected_headers.websocket_protocol.value;
  const auto websocket_extensions =
      selected_headers.websocket_extensions.value;
  const auto websocket_attempt =
      bonvoyage::http::websocket_handshake_attempt(
          connection_header, upgrade_header, websocket_version,
          websocket_key, websocket_protocol, websocket_extensions);
  if (websocket_attempt) {
    ++server_.stats().websocket_handshake_attempts;
  }
  if (server_name_.has_value() &&
      !RuntimeSnapshot::authority_matches_server_name(
          selected_headers.host.value, *server_name_)) {
    throw bonvoyage::http::RequestError(
        421U, "sni_host_mismatch",
        "HTTP Host does not match the TLS server name", true);
  }
  ForwardedForHeaderFields forwarded_for;
  if (selected_headers.forwarded_for.present) {
    forwarded_for.values[0] = selected_headers.forwarded_for.value;
    forwarded_for.count = 1U;
  }
  const auto client_resolution =
      resolve_client_address(forwarded_for.view(), true);
  const auto client_address =
      client_resolution.address.empty()
          ? client_address_resolver_.direct_peer_address()
          : std::string_view(client_resolution.address);
  const auto target = split_request_target(request->_url);
  const auto wants_keep_alive =
      keep_alive(request->_version, connection_header) && !server_.draining();
  const auto cors_request = inspect_cors_request_fields(
      request->_method, selected_headers.origin, selected_headers.cors_method,
      selected_headers.cors_headers);
  if (cors_request.kind == CorsRequestKind::preflight &&
      cors_request.malformed) {
    ++server_.stats().cors_rejections;
    const auto body_is_empty =
        framing.kind == bonvoyage::http::BodyKind::none ||
        (framing.kind == bonvoyage::http::BodyKind::content_length &&
         framing.content_length == 0U);
    const auto keep_rejected_connection = wants_keep_alive && body_is_empty;
    co_await write_error(400U, "invalid_cors_request",
                         "The CORS preflight fields are malformed",
                         !keep_rejected_connection);
    draining_ = !keep_rejected_connection;
    co_return;
  }
  const auto authority = selected_headers.host.value;
  const auto request_view = RequestView{
      authority, target.path,
      cors_request.kind == CorsRequestKind::preflight
          ? cors_request.requested_method
          : std::string_view(request->_method),
      target.query, request.get(), find_http1_request_header};
  const auto match = cors_request.kind == CorsRequestKind::preflight
                         ? snapshot().match_cors_preflight(
                               server_.listener_index(), request_view)
                         : snapshot().match(server_.listener_index(),
                                                    request_view);
  if (match.route == nullptr) {
    ++server_.stats().route_misses;
    if (http1_access_log_ != nullptr) {
      http1_access_log_->action = AccessLogAction::route_miss;
    }
    co_await consume_body(framing);
    co_await write_error(404U, "route_not_found",
                         "No route matched the request", !wants_keep_alive);
    draining_ = !wants_keep_alive;
    co_return;
  }
  if (http1_access_log_ != nullptr) {
    http1_access_log_->route = match.route->name;
    if (cors_request.kind == CorsRequestKind::preflight) {
      http1_access_log_->action = AccessLogAction::cors_preflight;
    } else if (match.route->fixed_response.has_value()) {
      http1_access_log_->action = AccessLogAction::fixed_response;
    } else if (match.route->redirect.has_value()) {
      http1_access_log_->action = AccessLogAction::redirect;
    } else if (match.route->websocket.has_value()) {
      http1_access_log_->action = AccessLogAction::websocket;
      http1_access_log_->protocol = AccessLogProtocol::websocket;
    } else {
      http1_access_log_->action = AccessLogAction::proxy;
    }
  }
  std::optional<bonvoyage::http::WebSocketRequestHandshake>
      websocket_handshake;
  if (match.route->websocket.has_value()) {
    if (!websocket_attempt) {
      ++server_.stats().websocket_handshake_rejections;
      co_await write_error(
          426U, "websocket_upgrade_required",
          "This route requires an RFC 6455 WebSocket upgrade", true,
          std::nullopt, std::nullopt, std::nullopt, "13");
      draining_ = true;
      co_return;
    }
    const auto has_body =
        framing.kind == bonvoyage::http::BodyKind::chunked ||
        (framing.kind == bonvoyage::http::BodyKind::content_length &&
         framing.content_length != 0U);
    std::optional<bonvoyage::http::WebSocketHandshakeError>
        websocket_rejection;
    try {
      websocket_handshake = bonvoyage::http::validate_websocket_request(
          request->_method, request->_version, connection_header,
          upgrade_header, websocket_version, websocket_key,
          websocket_protocol, websocket_extensions, has_body);
    } catch (const bonvoyage::http::WebSocketHandshakeError& error) {
      websocket_rejection.emplace(error);
    }
    if (websocket_rejection.has_value()) {
      const auto& error = *websocket_rejection;
      ++server_.stats().websocket_handshake_rejections;
      co_await write_error(
          error.status_code(), error.code(), error.what(), true,
          std::nullopt, std::nullopt, std::nullopt,
          error.advertise_version()
              ? std::optional<std::string_view>{"13"}
              : std::nullopt);
      draining_ = true;
      co_return;
    }
  } else if (websocket_attempt) {
    ++server_.stats().websocket_handshake_rejections;
    co_await write_error(
        426U, "websocket_not_enabled",
        "WebSocket upgrade is not enabled on this route", true,
        std::nullopt, std::nullopt, std::nullopt, "13");
    draining_ = true;
    co_return;
  }
  http1_cors_policy_configured_ = match.route->cors.has_value();
  const auto source_ip_rejection = try_enforce_source_ip_policy(
      match.route->source_ip_policy.has_value()
          ? &*match.route->source_ip_policy
          : nullptr,
      client_address, server_.stats());
  if (source_ip_rejection.has_value()) {
    const auto& error = *source_ip_rejection;
    const auto body_is_empty =
        framing.kind == bonvoyage::http::BodyKind::none ||
        (framing.kind == bonvoyage::http::BodyKind::content_length &&
         framing.content_length == 0U);
    const auto keep_rejected_connection = wants_keep_alive && body_is_empty;
    co_await write_error(error.status, error.code, error.message,
                         !keep_rejected_connection);
    draining_ = !keep_rejected_connection;
    co_return;
  }
  const auto body_is_empty =
      framing.kind == bonvoyage::http::BodyKind::none ||
      (framing.kind == bonvoyage::http::BodyKind::content_length &&
       framing.content_length == 0U);
  if (cors_request.kind == CorsRequestKind::preflight && !body_is_empty) {
    ++server_.stats().cors_rejections;
    co_await write_error(400U, "invalid_cors_request",
                         "CORS preflight requests must not contain a body",
                         true);
    draining_ = true;
    co_return;
  }
  auto cors = apply_cors_policy(
      match.route->cors.has_value() ? &*match.route->cors : nullptr,
      cors_request, request->_method, server_.stats());
  if (cors.rejection.has_value()) {
    const auto& error = *cors.rejection;
    const auto keep_rejected_connection = wants_keep_alive && body_is_empty;
    co_await write_error(error.status, error.code, error.message,
                         !keep_rejected_connection);
    draining_ = !keep_rejected_connection;
    co_return;
  }
  http1_cors_ = cors.response;
  if (cors_request.kind == CorsRequestKind::preflight) {
    co_await write_cors_preflight(!wants_keep_alive);
    draining_ = !wants_keep_alive;
    co_return;
  }
  const auto declared_body_bytes =
      framing.kind == bonvoyage::http::BodyKind::content_length
          ? std::optional<std::uint64_t>{framing.content_length}
          : std::nullopt;
  auto request_content = apply_request_content_policy(
      match.route->request_content.has_value()
          ? &*match.route->request_content
          : nullptr,
      request.get(), find_http1_request_header, !body_is_empty,
      declared_body_bytes, 0U, server_.stats());
  if (request_content.rejection.has_value()) {
    const auto& error = *request_content.rejection;
    const auto keep_rejected_connection = wants_keep_alive && body_is_empty;
    co_await write_error(error.status, error.code, error.message,
                         !keep_rejected_connection, std::nullopt,
                         std::nullopt, request_content.accept);
    draining_ = !keep_rejected_connection;
    co_return;
  }
  const auto auth_rejection = try_authenticate_api_key(
      api_key_auth(*match.route), request.get(),
      find_http1_request_header, server_.stats());
  if (auth_rejection.has_value()) {
    const auto& error = *auth_rejection;
    const auto body_is_empty =
        framing.kind == bonvoyage::http::BodyKind::none ||
        (framing.kind == bonvoyage::http::BodyKind::content_length &&
         framing.content_length == 0U);
    const auto keep_rejected_connection = wants_keep_alive && body_is_empty;
    co_await write_error(error.status, error.code, error.message,
                         !keep_rejected_connection, std::nullopt, "ApiKey");
    draining_ = !keep_rejected_connection;
    co_return;
  }
  const auto jwt_rejection = try_authenticate_jwt(
      jwt_auth(*match.route), request.get(),
      find_http1_request_header, server_.stats());
  if (jwt_rejection.has_value()) {
    const auto& error = *jwt_rejection;
    const auto body_is_empty =
        framing.kind == bonvoyage::http::BodyKind::none ||
        (framing.kind == bonvoyage::http::BodyKind::content_length &&
         framing.content_length == 0U);
    const auto keep_rejected_connection = wants_keep_alive && body_is_empty;
    const auto challenge =
        error.status == 401U
            ? std::optional<std::string_view>{"Bearer"}
            : (error.status == 403U
                   ? std::optional<std::string_view>{
                         "Bearer error=\"insufficient_scope\""}
                   : std::nullopt);
    co_await write_error(error.status, error.code, error.message,
                         !keep_rejected_connection, std::nullopt, challenge);
    draining_ = !keep_rejected_connection;
    co_return;
  }
  auto* admission = route_admission(*match.route);
  const auto rejection =
      try_admit_route(admission, server_.stats());
  if (rejection.has_value()) {
    const auto& error = *rejection;
    const auto body_is_empty =
        framing.kind == bonvoyage::http::BodyKind::none ||
        (framing.kind == bonvoyage::http::BodyKind::content_length &&
         framing.content_length == 0U);
    const auto keep_rejected_connection = wants_keep_alive && body_is_empty;
    co_await write_error(
        error.status, error.code, error.message, !keep_rejected_connection,
        error.status == 429U ? std::optional<std::uint32_t>{1U}
                             : std::nullopt);
    draining_ = !keep_rejected_connection;
    co_return;
  }
  auto admitted_route = seastar::defer([this, admission] {
    release_route(admission, server_.stats());
  });
  if (match.route->fixed_response.has_value()) {
    co_await consume_body(
        framing,
        match.route->request_content.has_value()
            ? match.route->request_content->maximum_body_bytes()
            : std::nullopt);
    co_await write_fixed_response(*match.route->fixed_response,
                                  request->_method,
                                  !wants_keep_alive);
    draining_ = !wants_keep_alive;
    co_return;
  }
  if (match.route->redirect.has_value()) {
    co_await consume_body(
        framing,
        match.route->request_content.has_value()
            ? match.route->request_content->maximum_body_bytes()
            : std::nullopt);
    co_await write_redirect_response(*match.route->redirect,
                                     !wants_keep_alive);
    draining_ = !wants_keep_alive;
    co_return;
  }

  if (websocket_handshake.has_value()) {
    co_await proxy_websocket(*request, *match.route, connection_header,
                             authority, client_address, wants_keep_alive,
                             *websocket_handshake, abort);
    draining_ = completed_websocket_tunnel_ || !wants_keep_alive;
    co_return;
  }

  co_await proxy_request(*request, framing, *match.route, connection_header,
                         authority, client_address, wants_keep_alive, abort);
  draining_ = !wants_keep_alive;
}

seastar::future<std::unique_ptr<seastar::http::reply>>
DownstreamConnection::read_websocket_response(
    seastar::input_stream<char>& input,
    const bonvoyage::http::WebSocketRequestHandshake& handshake) {
  constexpr std::size_t maximum_informational_responses = 8U;
  for (std::size_t count = 0U;
       count <= maximum_informational_responses; ++count) {
    WebSocketResponseHeadConsumer consumer(
        snapshot().limits().max_upstream_response_header_bytes,
        handshake);
    co_await input.consume(consumer);
    auto reply = consumer.take_reply();
    const auto status = static_cast<std::uint16_t>(reply->_status);
    if (status == 101U || status >= 200U) {
      co_return reply;
    }
    if (count == maximum_informational_responses) {
      throw std::runtime_error(
          "upstream sent too many informational WebSocket responses");
    }
  }
  throw std::logic_error(
      "WebSocket informational response limit was not enforced");
}

seastar::future<> DownstreamConnection::write_websocket_response(
    const seastar::http::reply& reply,
    const HeaderTransformations* transformations) {
  std::vector<MutableHeader> headers;
  headers.reserve(reply._headers.size() + 4U);
  const auto connection = reply.get_header("Connection");
  const bonvoyage::http::ConnectionTokenSet connection_tokens(connection);
  for (const auto& [name, value] : reply._headers) {
    if (bonvoyage::http::is_hop_by_hop_header(name, connection_tokens) ||
        bonvoyage::http::ascii_case_equal(name, "content-length") ||
        bonvoyage::http::ascii_case_equal(name, "transfer-encoding") ||
        (http1_cors_policy_configured_ &&
         is_cors_response_header(name))) {
      continue;
    }
    if (!safe_header_value(value)) {
      throw std::runtime_error(
          "upstream WebSocket response contains an unsafe header value");
    }
    headers.emplace_back(std::string(name), std::string(value));
  }
  if (transformations != nullptr && !transformations->response.empty()) {
    if (!apply_header_mutations(
            headers, transformations->response,
            snapshot().limits().max_upstream_response_header_bytes)) {
      ++server_.stats().header_transformation_limit_rejections;
      throw std::runtime_error(
          "transformed WebSocket response headers exceed the configured limit");
    }
    ++server_.stats().response_header_transformation_applications;
  }
  if (http1_cors_.has_value()) {
    append_cors_response_headers(
        *http1_cors_, [&headers](std::string_view name,
                                std::string_view value) {
          headers.emplace_back(name, value);
        });
  }

  std::size_t size = std::string_view("HTTP/1.1 101 Switching Protocols\r\n")
                         .size() +
                     std::string_view(
                         "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                         .size();
  for (const auto& [name, value] : headers) {
    size += name.size() + value.size() + 4U;
  }
  if (size >
      snapshot().limits().max_upstream_response_header_bytes) {
    throw std::runtime_error(
        "WebSocket response headers exceed the configured limit");
  }
  std::string head;
  head.reserve(size);
  head.append("HTTP/1.1 101 Switching Protocols\r\n");
  for (const auto& [name, value] : headers) {
    head.append(name);
    head.append(": ");
    head.append(value);
    head.append("\r\n");
  }
  head.append("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
  response_started_ = true;
  if (http1_access_log_ != nullptr) {
    http1_access_log_->status = 101U;
  }
  co_await output_.write(head);
  co_await output_.flush();
  record_response_status(server_.stats(), 101U);
}

seastar::future<> DownstreamConnection::tunnel_websocket(
    seastar::connected_socket& upstream_socket,
    seastar::input_stream<char>& upstream_input,
    seastar::output_stream<char>& upstream_output,
    std::chrono::milliseconds idle_timeout,
    seastar::abort_source& abort) {
  bool idle_timed_out = false;
  const auto shutdown = [this, &upstream_socket]() noexcept {
    socket_.shutdown_input();
    upstream_socket.shutdown_input();
    upstream_socket.shutdown_output();
  };
  seastar::timer<> idle_timer([&abort, &idle_timed_out, shutdown] {
    idle_timed_out = true;
    abort.request_abort();
    shutdown();
  });
  const auto rearm_idle = [&idle_timer, idle_timeout] {
    idle_timer.cancel();
    idle_timer.arm(seastar::timer<>::clock::now() + idle_timeout);
  };
  if (abort.abort_requested()) {
    throw seastar::abort_requested_exception{};
  }
  [[maybe_unused]] auto subscription = abort.subscribe(shutdown);
  rearm_idle();

  const auto pump = [&rearm_idle](seastar::input_stream<char>& source,
                                  seastar::output_stream<char>& destination,
                                  std::uint64_t& counter,
                                  bool buffered_destination)
      -> seastar::future<> {
    while (true) {
      auto data = co_await source.read_up_to(64U * 1024U);
      if (data.empty()) {
        co_return;
      }
      counter += data.size();
      rearm_idle();
      if (buffered_destination) {
        // The downstream stream may already contain buffered HTTP responses.
        // Seastar does not permit switching that stream to zero-copy writes.
        co_await destination.write(data.get(), data.size());
      } else {
        co_await destination.write(std::move(data));
      }
      co_await destination.flush();
    }
  };

  auto downstream_to_upstream =
      pump(input_, upstream_output,
           server_.stats().websocket_downstream_bytes, false)
          .finally(shutdown);
  auto upstream_to_downstream =
      pump(upstream_input, output_,
           server_.stats().websocket_upstream_bytes, true)
          .finally(shutdown);
  auto results = co_await seastar::when_all(
      std::move(downstream_to_upstream),
      std::move(upstream_to_downstream));
  idle_timer.cancel();
  if (idle_timed_out) {
    ++server_.stats().websocket_idle_timeouts;
    std::get<0>(results).ignore_ready_future();
    std::get<1>(results).ignore_ready_future();
    co_return;
  }
  auto& downstream_result = std::get<0>(results);
  auto& upstream_result = std::get<1>(results);
  if (!downstream_result.failed() || !upstream_result.failed()) {
    if (downstream_result.failed()) {
      downstream_result.ignore_ready_future();
    } else {
      downstream_result.get();
    }
    if (upstream_result.failed()) {
      upstream_result.ignore_ready_future();
    } else {
      upstream_result.get();
    }
    co_return;
  }
  std::exception_ptr failure;
  auto collect = [&failure](seastar::future<>& result) {
    if (result.failed()) {
      if (failure == nullptr) {
        failure = result.get_exception();
      } else {
        result.ignore_ready_future();
      }
    } else {
      result.get();
    }
  };
  collect(downstream_result);
  collect(upstream_result);
  if (failure != nullptr) {
    std::rethrow_exception(failure);
  }
}

seastar::future<> DownstreamConnection::proxy_websocket(
    seastar::http::request& downstream, const RuntimeRoute& route,
    std::string_view connection, std::string_view authority,
    std::string_view client_address, bool downstream_keep_alive,
    const bonvoyage::http::WebSocketRequestHandshake& handshake,
    seastar::abort_source& abort) {
  const bonvoyage::http::ConnectionTokenSet connection_tokens(connection);
  std::optional<std::string> rewritten_target;
  if (route.rewrite.has_value() && route.rewrite->path.has_value()) {
    rewritten_target = rewrite_request_target(
        downstream._url, route.path, *route.rewrite->path,
        snapshot().limits().max_request_header_bytes);
    if (!rewritten_target.has_value()) {
      ++server_.stats().request_rewrite_limit_rejections;
      throw bonvoyage::http::RequestError(
          414U, "rewritten_request_target_too_large",
          "Rewritten request target exceeds the configured limit");
    }
  }
  const auto downstream_authority = authority;
  const std::string_view upstream_authority =
      route.rewrite.has_value() && route.rewrite->authority.has_value()
          ? std::string_view(*route.rewrite->authority)
          : std::string_view(downstream_authority);
  const std::string_view upstream_target =
      rewritten_target.has_value() ? std::string_view(*rewritten_target)
                                   : std::string_view(downstream._url);
  auto upstream = seastar::http::request::make(
      downstream._method,
      seastar::sstring(upstream_authority.data(), upstream_authority.size()),
      seastar::sstring(upstream_target.data(), upstream_target.size()));
  upstream._version = "1.1";
  upstream._headers.reserve(downstream._headers.size() + 5U);
  for (const auto& [name, value] : downstream._headers) {
    if (!bonvoyage::http::is_hop_by_hop_header(name, connection_tokens) &&
        !bonvoyage::http::ascii_case_equal(name, "content-length") &&
        !bonvoyage::http::ascii_case_equal(name, "host") &&
        (!route.api_key_auth.has_value() ||
         !bonvoyage::http::ascii_case_equal(
             name, route.api_key_auth->header_name)) &&
        (!route.jwt_auth.has_value() ||
         !bonvoyage::http::ascii_case_equal(name, "authorization")) &&
        (!server_.traces().enabled() ||
         !is_trace_propagation_header(name)) &&
        !is_forwarded_identity_header(name)) {
      upstream._headers[name] = value;
    }
  }
  upstream._headers["Connection"] = "Upgrade";
  upstream._headers["Upgrade"] = "websocket";
  upstream._headers["X-Forwarded-Proto"] = forwarded_proto_;
  upstream._headers["X-Forwarded-For"] =
      seastar::sstring(client_address.data(), client_address.size());
  if (route.rewrite.has_value() && route.rewrite->authority.has_value()) {
    upstream._headers["X-Forwarded-Host"] = seastar::sstring(
        downstream_authority.data(), downstream_authority.size());
  }
  if (route.header_transformations.has_value() &&
      !route.header_transformations->request.empty()) {
    if (!apply_request_header_mutations(
            upstream, route.header_transformations->request,
            snapshot().limits().max_request_header_bytes)) {
      ++server_.stats().header_transformation_limit_rejections;
      throw bonvoyage::http::RequestError(
          431U, "transformed_request_headers_too_large",
          "Transformed request headers exceed the configured limit");
    }
    ++server_.stats().request_header_transformation_applications;
  }
  if (http1_trace_ != nullptr) {
    upstream._headers["traceparent"] = format_traceparent(
        http1_trace_->trace_id, http1_trace_->span_id,
        http1_trace_->trace_flags);
    if (!request_headers_within_limit(
            upstream,
            snapshot().limits().max_request_header_bytes)) {
      ++server_.traces().stats().propagation_limit_rejections;
      throw bonvoyage::http::RequestError(
          431U, "forwarded_request_headers_too_large",
          "Forwarded request headers exceed the configured limit");
    }
  }
  if (route.rewrite.has_value() && route.rewrite->authority.has_value()) {
    ++server_.stats().request_authority_rewrite_applications;
  }
  if (route.rewrite.has_value() && route.rewrite->path.has_value()) {
    ++server_.stats().request_path_rewrite_applications;
  }

  const auto cluster_index = select_cluster(route);
  if (http1_access_log_ != nullptr) {
    http1_access_log_->cluster =
        snapshot().clusters()[cluster_index].name;
  }
  auto& cluster = this->cluster(cluster_index);
  auto transport = co_await cluster.open_websocket_transport(&abort);
  if (abort.abort_requested()) {
    transport.socket.shutdown_input();
    transport.socket.shutdown_output();
    throw seastar::abort_requested_exception{};
  }
  [[maybe_unused]] auto handshake_abort = abort.subscribe([&transport]() noexcept {
    transport.socket.shutdown_input();
    transport.socket.shutdown_output();
  });
  auto completion = EndpointCompletion::passive_failure;
  auto release_endpoint = seastar::defer([&cluster, &transport, &completion] {
    cluster.complete_websocket_transport(transport.endpoint_index,
                                         completion);
  });
  auto upstream_input = transport.socket.input(
      seastar::connected_socket_input_stream_config{
          .buffer_size = 4096U,
          .min_buffer_size = 512U,
          .max_buffer_size = 4096U});
  auto upstream_output = transport.socket.output(8U * 1024U);
  std::exception_ptr failure;
  bool valid_final_response = false;
  try {
    auto request_head =
        bonvoyage::http::serialize_upstream_request_head(upstream);
    co_await upstream_output.write(std::move(request_head));
    co_await upstream_output.flush();
    auto reply = co_await read_websocket_response(upstream_input, handshake);
    valid_final_response = true;
    completion = EndpointCompletion::success;
    const auto status = static_cast<std::uint16_t>(reply->_status);
    const auto* transformations = route.header_transformations.has_value()
                                      ? &*route.header_transformations
                                      : nullptr;
    if (status != 101U) {
      auto handoff_started_at = start_response_path_handoff();
      co_await write_upstream_response(
          *reply, upstream_input, downstream._method,
          downstream_keep_alive, transformations,
          handoff_started_at);
    } else {
      co_await write_websocket_response(*reply, transformations);
      ++server_.stats().websocket_handshake_successes;
      ++server_.stats().websocket_connections;
      ++server_.stats().active_websocket_connections;
      websocket_established_ = true;
      completed_websocket_tunnel_ = true;
      active_websocket_abort_ = &abort;
      auto active_tunnel = seastar::defer([this] {
        active_websocket_abort_ = nullptr;
        websocket_established_ = false;
        --server_.stats().active_websocket_connections;
      });
      try {
        co_await tunnel_websocket(
            transport.socket, upstream_input, upstream_output,
            std::chrono::milliseconds(route.websocket->idle_timeout_ms),
            abort);
      } catch (const seastar::abort_requested_exception&) {
        if (!abort.abort_requested()) {
          throw;
        }
      }
    }
  } catch (...) {
    failure = std::current_exception();
    gateway_log.debug(
        "WebSocket proxy failed final_response={} established={} abort_requested={}: {}",
        valid_final_response, completed_websocket_tunnel_,
        abort.abort_requested(), failure);
    if (!valid_final_response && !abort.abort_requested()) {
      ++server_.stats().websocket_upstream_handshake_failures;
      ++server_.stats().upstream_passive_failures;
    }
    if (abort.abort_requested() && !completed_websocket_tunnel_) {
      completion = EndpointCompletion::neutral;
    }
  }
  auto input_closed = upstream_input.close().handle_exception(
      [](const std::exception_ptr&) {});
  auto output_closed = upstream_output.close().handle_exception(
      [](const std::exception_ptr&) {});
  co_await seastar::when_all(std::move(input_closed),
                             std::move(output_closed))
      .discard_result();
  if (failure != nullptr) {
    std::rethrow_exception(failure);
  }
}

seastar::future<> DownstreamConnection::proxy_request(
    seastar::http::request& downstream,
    const bonvoyage::http::BodyFraming& framing,
    const RuntimeRoute& route, std::string_view connection,
    std::string_view authority, std::string_view client_address,
    bool downstream_keep_alive,
    seastar::abort_source& abort) {
  const bonvoyage::http::ConnectionTokenSet connection_tokens(connection);
  auto make_upstream_request =
      [this, &downstream, &connection_tokens, authority, client_address,
       &route] {
        std::optional<std::string> rewritten_target;
        if (route.rewrite.has_value() && route.rewrite->path.has_value()) {
          rewritten_target = rewrite_request_target(
              downstream._url, route.path, *route.rewrite->path,
              snapshot().limits().max_request_header_bytes);
          if (!rewritten_target.has_value()) {
            ++server_.stats().request_rewrite_limit_rejections;
            throw bonvoyage::http::RequestError(
                414U, "rewritten_request_target_too_large",
                "Rewritten request target exceeds the configured limit");
          }
        }
        const auto downstream_authority = authority;
        auto result = [&] {
          if (!route.rewrite.has_value()) {
            return seastar::http::request::make(
                downstream._method,
                seastar::sstring(downstream_authority.data(),
                                 downstream_authority.size()),
                downstream._url);
          }
          const std::string_view upstream_authority =
              route.rewrite->authority.has_value()
                  ? std::string_view(*route.rewrite->authority)
                  : std::string_view(downstream_authority);
          const std::string_view upstream_target =
              rewritten_target.has_value()
                  ? std::string_view(*rewritten_target)
                  : std::string_view(downstream._url);
          return seastar::http::request::make(
              downstream._method,
              seastar::sstring(upstream_authority.data(),
                               upstream_authority.size()),
              seastar::sstring(upstream_target.data(),
                               upstream_target.size()));
        }();
        result._version = "1.1";
        result._headers.reserve(downstream._headers.size() + 4U);
        for (const auto& [name, value] : downstream._headers) {
          if (!bonvoyage::http::is_hop_by_hop_header(
                  name, connection_tokens) &&
              !bonvoyage::http::ascii_case_equal(name, "content-length") &&
              !bonvoyage::http::ascii_case_equal(name, "host") &&
              (!route.api_key_auth.has_value() ||
               !bonvoyage::http::ascii_case_equal(
                   name, route.api_key_auth->header_name)) &&
              (!route.jwt_auth.has_value() ||
               !bonvoyage::http::ascii_case_equal(name, "authorization")) &&
              (!server_.traces().enabled() ||
               !is_trace_propagation_header(name)) &&
              !is_forwarded_identity_header(name)) {
            result._headers[name] = value;
          }
        }
        result._headers["Connection"] = "keep-alive";
        result._headers["X-Forwarded-Proto"] = forwarded_proto_;
        result._headers["X-Forwarded-For"] =
            seastar::sstring(client_address.data(), client_address.size());
        if (route.rewrite.has_value() && route.rewrite->authority.has_value()) {
          result._headers["X-Forwarded-Host"] = seastar::sstring(
              downstream_authority.data(), downstream_authority.size());
        }
        if (route.header_transformations.has_value() &&
            !route.header_transformations->request.empty()) {
          if (!apply_request_header_mutations(
                  result, route.header_transformations->request,
                  snapshot().limits().max_request_header_bytes)) {
            ++server_.stats().header_transformation_limit_rejections;
            throw bonvoyage::http::RequestError(
                431U, "transformed_request_headers_too_large",
                "Transformed request headers exceed the configured limit");
          }
          ++server_.stats().request_header_transformation_applications;
        }
        if (http1_trace_ != nullptr) {
          result._headers["traceparent"] = format_traceparent(
              http1_trace_->trace_id, http1_trace_->span_id,
              http1_trace_->trace_flags);
          if (!request_headers_within_limit(
                  result,
                  snapshot().limits().max_request_header_bytes)) {
            ++server_.traces().stats().propagation_limit_rejections;
            throw bonvoyage::http::RequestError(
                431U, "forwarded_request_headers_too_large",
                "Forwarded request headers exceed the configured limit");
          }
        }
        if (route.rewrite.has_value() && route.rewrite->authority.has_value()) {
          ++server_.stats().request_authority_rewrite_applications;
        }
        if (route.rewrite.has_value() && route.rewrite->path.has_value()) {
          ++server_.stats().request_path_rewrite_applications;
        }
        return result;
      };
  auto upstream = make_upstream_request();

  const auto route_maximum_body_bytes =
      route.request_content.has_value()
          ? route.request_content->maximum_body_bytes()
          : std::nullopt;
  const auto maximum_body_bytes = route_maximum_body_bytes.value_or(
      snapshot().limits().max_request_body_bytes);

  std::optional<seastar::input_stream<char>> body;
  if (framing.kind == bonvoyage::http::BodyKind::content_length) {
    body.emplace(seastar::data_source(
        std::make_unique<seastar::httpd::internal::content_length_source_impl>(
            input_, static_cast<std::size_t>(framing.content_length))));
    upstream.content_length = static_cast<std::size_t>(framing.content_length);
  } else if (framing.kind == bonvoyage::http::BodyKind::chunked) {
    body.emplace(seastar::data_source(
        std::make_unique<BoundedChunkedSourceImpl>(
            input_, maximum_body_bytes,
            snapshot().limits().max_request_header_bytes,
            route_maximum_body_bytes.has_value()
                ? &server_.stats().request_body_limit_rejections
                : nullptr)));
    upstream._headers["Transfer-Encoding"] = "chunked";
  }

  std::uint64_t body_bytes = 0U;
  if (body.has_value()) {
    upstream.body_writer =
        [this, &body, &body_bytes, maximum_body_bytes,
         route_limit_configured = route_maximum_body_bytes.has_value(),
         expected_length =
             framing.kind == bonvoyage::http::BodyKind::content_length
                 ? std::optional<std::uint64_t>(framing.content_length)
                 : std::nullopt](seastar::output_stream<char>&& output) {
          return seastar::do_with(
              std::move(output),
              [this, &body, &body_bytes, maximum_body_bytes,
               route_limit_configured, expected_length](auto& stream) {
                return seastar::repeat([this, &body, &body_bytes,
                                        maximum_body_bytes,
                                        route_limit_configured,
                                        expected_length, &stream] {
                  return read_http1_body(*body).then(
                      [this, &body_bytes, maximum_body_bytes,
                       route_limit_configured, expected_length, &stream](
                          seastar::temporary_buffer<char> data) {
                        if (data.empty()) {
                          if (expected_length.has_value() &&
                              body_bytes != *expected_length) {
                            throw bonvoyage::http::RequestError(
                                400U, "truncated_request_body",
                                "Request body ended before Content-Length bytes were received");
                          }
                          return seastar::make_ready_future<
                              seastar::stop_iteration>(
                              seastar::stop_iteration::yes);
                        }
                        body_bytes += data.size();
                        if (body_bytes > maximum_body_bytes) {
                          if (route_limit_configured) {
                            ++server_.stats()
                                  .request_body_limit_rejections;
                          }
                          throw bonvoyage::http::RequestError(
                              413U, "request_body_too_large",
                              "Request body exceeds the configured limit");
                        }
                        record_http1_request_bytes(data.size());
                        return stream.write(std::move(data)).then([] {
                          return seastar::stop_iteration::no;
                        });
                      });
                }).finally([&stream] { return stream.close(); });
              });
        };
  }

  const auto* transformations = route.header_transformations.has_value()
                                    ? &*route.header_transformations
                                    : nullptr;
  auto handler = [this, method = std::string(downstream._method),
                  downstream_keep_alive, transformations](
                     const seastar::http::reply& reply,
                     seastar::input_stream<char>&& response_body) {
    auto handoff_started_at = start_response_path_handoff();
    return seastar::do_with(
        std::move(response_body), handoff_started_at,
        [this, method, downstream_keep_alive, transformations,
         &reply](auto& stream, auto& handoff) {
          return write_upstream_response(reply, stream, method,
                                         downstream_keep_alive,
                                         transformations,
                                         std::move(handoff))
              .finally([&stream] { return stream.close(); });
        });
  };
  const auto cluster_index = select_cluster(route);
  if (http1_access_log_ != nullptr) {
    http1_access_log_->cluster =
        snapshot().clusters()[cluster_index].name;
  }
  auto& cluster = this->cluster(cluster_index);
  ClusterState::RequestFactory retry_request_factory;
  const bool request_replayable = !body.has_value();
  if (cluster.retries_enabled_for(downstream._method,
                                  request_replayable)) {
    retry_request_factory = make_upstream_request;
  }
  auto request_result = co_await seastar::coroutine::as_future(
      cluster.make_request(std::move(upstream), std::move(handler), &abort,
                           request_replayable,
                           std::move(retry_request_factory)));
  if (body.has_value()) {
    co_await body->close().handle_exception([](const std::exception_ptr&) {});
  }
  if (request_result.failed()) {
    std::rethrow_exception(request_result.get_exception());
  }
  request_result.get();
}

seastar::future<> DownstreamConnection::write_response_head(
    std::uint16_t status,
    std::vector<std::pair<std::string, std::string>> headers,
    bool close_connection) {
  response_started_ = true;
  if (http1_access_log_ != nullptr) {
    http1_access_log_->status = status;
  }
  if (http1_cors_.has_value()) {
    append_cors_response_headers(
        *http1_cors_, [&headers](std::string_view name,
                                std::string_view value) {
          headers.emplace_back(name, value);
        });
  }
  const auto head = bonvoyage::http::serialize_response_head(
      status, reason_phrase(status), headers, close_connection);
  co_await output_.write(head);
}

seastar::future<> DownstreamConnection::write_cors_preflight(
    bool close_connection) {
  co_await write_response_head(204U, {}, close_connection);
  co_await output_.flush();
  record_response_status(server_.stats(), 204U);
}

seastar::future<> DownstreamConnection::write_fixed_response(
    const RuntimeFixedResponse& response, std::string_view method,
    bool close_connection) {
  const auto body_allowed =
      bonvoyage::http::response_allows_body(method, response.status_code);
  const auto representation_allowed =
      bonvoyage::http::response_status_allows_content(response.status_code);
  const auto body_size = representation_allowed ? response.body.size() : 0U;
  std::vector<std::pair<std::string, std::string>> headers;
  headers.emplace_back("Content-Type", response.content_type);
  headers.emplace_back("Content-Length", std::to_string(body_size));
  co_await write_response_head(response.status_code, headers,
                               close_connection);
  if (body_allowed && body_size != 0U) {
    co_await output_.write(response.body);
    record_http1_response_bytes(body_size);
  }
  co_await output_.flush();
  record_response_status(server_.stats(), response.status_code);
}

seastar::future<> DownstreamConnection::write_redirect_response(
    const RuntimeRedirectResponse& response, bool close_connection) {
  std::vector<std::pair<std::string, std::string>> headers;
  headers.emplace_back("Location", response.location);
  headers.emplace_back("Content-Length", "0");
  co_await write_response_head(response.status_code, std::move(headers),
                               close_connection);
  co_await output_.flush();
  ++server_.stats().route_redirects;
  record_response_status(server_.stats(), response.status_code);
}

seastar::future<> DownstreamConnection::write_error(
    std::uint16_t status, std::string_view code, std::string_view message,
    bool close_connection,
    std::optional<std::uint32_t> retry_after_seconds,
    std::optional<std::string_view> www_authenticate,
    std::optional<std::string_view> accept,
    std::optional<std::string_view> websocket_version) {
  const auto body = std::string("{\"error\":{\"code\":\"") +
                    json_escape(code) + "\",\"message\":\"" +
                    json_escape(message) + "\"}}\n";
  std::vector<std::pair<std::string, std::string>> headers;
  headers.emplace_back("Content-Type", "application/json");
  headers.emplace_back("Content-Length", std::to_string(body.size()));
  if (retry_after_seconds.has_value()) {
    headers.emplace_back("Retry-After",
                         std::to_string(*retry_after_seconds));
  }
  if (www_authenticate.has_value()) {
    headers.emplace_back("WWW-Authenticate", *www_authenticate);
  }
  if (accept.has_value()) {
    headers.emplace_back("Accept", *accept);
  }
  if (websocket_version.has_value()) {
    headers.emplace_back("Sec-WebSocket-Version", *websocket_version);
  }
  co_await write_response_head(status, headers, close_connection);
  co_await output_.write(body);
  co_await output_.flush();
  record_http1_response_bytes(body.size());
  if (status < 500U) {
    ++server_.stats().responses_4xx;
  } else {
    ++server_.stats().responses_5xx;
  }
}

seastar::future<> DownstreamConnection::write_transferred_upstream_response(
    const seastar::http::reply& reply, seastar::input_stream<char>& body,
    std::uint16_t status, std::size_t response_length,
    bool downstream_keep_alive,
    const HeaderTransformations* transformations,
    std::optional<std::chrono::steady_clock::time_point>
        handoff_started_at) {
  const auto connection = reply.get_header("Connection");
  const bonvoyage::http::ConnectionTokenSet connection_tokens(connection);
  std::vector<MutableHeader> owned_headers;
  std::vector<bonvoyage::http::HeaderView> headers;
  headers.reserve(reply._headers.size() + 1U);
  if (transformations != nullptr && !transformations->response.empty()) {
    owned_headers.reserve(reply._headers.size() +
                          transformations->response.size());
    for (const auto& [name, value] : reply._headers) {
      if (!bonvoyage::http::is_hop_by_hop_header(name, connection_tokens) &&
          !bonvoyage::http::ascii_case_equal(name, "content-length") &&
          (!http1_cors_policy_configured_ ||
           !is_cors_response_header(name))) {
        if (!safe_header_value(value)) {
          throw std::runtime_error(
              "upstream response contains an unsafe header value");
        }
        owned_headers.emplace_back(std::string(name), std::string(value));
      }
    }
    if (!apply_header_mutations(
            owned_headers, transformations->response,
            snapshot().limits().max_upstream_response_header_bytes)) {
      ++server_.stats().header_transformation_limit_rejections;
      throw std::runtime_error(
          "transformed upstream response headers exceed the configured limit");
    }
    ++server_.stats().response_header_transformation_applications;
    for (const auto& [name, value] : owned_headers) {
      headers.push_back({name, value});
    }
  } else {
    for (const auto& [name, value] : reply._headers) {
      if (!bonvoyage::http::is_hop_by_hop_header(name, connection_tokens) &&
          !bonvoyage::http::ascii_case_equal(name, "content-length") &&
          (!http1_cors_policy_configured_ ||
           !is_cors_response_header(name))) {
        if (!safe_header_value(value)) {
          throw std::runtime_error(
              "upstream response contains an unsafe header value");
        }
        headers.push_back(bonvoyage::http::HeaderView{name, value});
      }
    }
  }
  const auto response_length_text = std::to_string(response_length);
  headers.push_back(
      bonvoyage::http::HeaderView{"Content-Length", response_length_text});
  if (http1_cors_.has_value()) {
    append_cors_response_headers(
        *http1_cors_, [&headers](std::string_view name,
                                std::string_view value) {
          headers.push_back(bonvoyage::http::HeaderView{name, value});
        });
  }
  response_started_ = true;
  if (http1_access_log_ != nullptr) {
    http1_access_log_->status = status;
  }
  auto response_head = bonvoyage::http::serialize_response_head_buffer(
      status, reason_phrase(status), headers, !downstream_keep_alive);
  record_response_path_handoff(handoff_started_at);
  record_response_path_write(response_head.size());
  co_await output_.write(std::move(response_head));

  std::size_t transferred = 0U;
  while (true) {
    auto data = co_await body.read();
    if (data.empty()) {
      break;
    }
    transferred += data.size();
    record_http1_response_bytes(data.size());
    record_response_path_write(data.size());
    co_await output_.write(std::move(data));
  }
  if (transferred != response_length) {
    throw std::runtime_error("upstream response body was truncated");
  }
  if (reply._version == "2") {
    validate_and_record_upstream_trailers(server_.stats(), reply);
  }
  co_await flush_response_path();
  record_response_path_completion();
  if (status < 300U) {
    ++server_.stats().responses_2xx;
  } else if (status < 500U) {
    ++server_.stats().responses_4xx;
  } else {
    ++server_.stats().responses_5xx;
  }
}

seastar::future<> DownstreamConnection::write_upstream_response(
    const seastar::http::reply& reply, seastar::input_stream<char>& body,
    std::string_view method, bool downstream_keep_alive,
    const HeaderTransformations* transformations,
    std::optional<std::chrono::steady_clock::time_point>
        handoff_started_at) {
  const auto status = static_cast<std::uint16_t>(reply._status);
  const bool upstream_http2 = reply._version == "2";
  const auto content_length_value = reply.get_header("Content-Length");
  const auto transfer_encoding_value = reply.get_header("Transfer-Encoding");
  bonvoyage::http::ResponseBodyFraming framing;
  try {
    framing = bonvoyage::http::validate_response_framing(
        method, status, content_length_value, transfer_encoding_value);
  } catch (...) {
    ++server_.stats().upstream_framing_rejections;
    throw;
  }
  const bool stream_delimited =
      upstream_http2 &&
      framing.kind == bonvoyage::http::ResponseBodyKind::close_delimited;
  if (framing.kind ==
          bonvoyage::http::ResponseBodyKind::close_delimited &&
      !stream_delimited) {
    ++server_.stats().upstream_framing_rejections;
    throw std::runtime_error(
        "close-delimited upstream responses are not accepted");
  }

  if (framing.content_length.value_or(0U) >
      std::numeric_limits<std::size_t>::max()) {
    ++server_.stats().upstream_framing_rejections;
    throw std::runtime_error(
        "upstream Content-Length exceeds the local address space");
  }
  if (framing.kind == bonvoyage::http::ResponseBodyKind::content_length &&
      *framing.content_length >= kOwnershipTransferBodyThreshold) {
    co_await write_transferred_upstream_response(
        reply, body, status,
        static_cast<std::size_t>(*framing.content_length),
        downstream_keep_alive, transformations,
        handoff_started_at);
    co_return;
  }

  const auto connection = reply.get_header("Connection");
  const bonvoyage::http::ConnectionTokenSet connection_tokens(connection);
  const bool transform_response =
      transformations != nullptr && !transformations->response.empty();
  std::vector<MutableHeader> owned_headers;
  std::vector<bonvoyage::http::HeaderView> header_views;
  if (transform_response) {
    owned_headers.reserve(reply._headers.size() +
                          transformations->response.size() + 1U);
  } else {
    header_views.reserve(reply._headers.size() + 5U);
  }
  for (const auto& [name, value] : reply._headers) {
    if (!bonvoyage::http::is_hop_by_hop_header(name, connection_tokens) &&
        !bonvoyage::http::ascii_case_equal(name, "content-length") &&
        (!http1_cors_policy_configured_ ||
         !is_cors_response_header(name))) {
      if (!safe_header_value(value)) {
        throw std::runtime_error(
            "upstream response contains an unsafe header value");
      }
      if (transform_response) {
        owned_headers.emplace_back(std::string(name), std::string(value));
      } else {
        header_views.push_back({name, value});
      }
    }
  }
  if (transform_response) {
    if (!apply_header_mutations(
            owned_headers, transformations->response,
            snapshot().limits().max_upstream_response_header_bytes)) {
      ++server_.stats().header_transformation_limit_rejections;
      throw std::runtime_error(
          "transformed upstream response headers exceed the configured limit");
    }
    ++server_.stats().response_header_transformation_applications;
  }
  auto downstream_length = framing.content_length;
  const bool downstream_chunked =
      framing.kind == bonvoyage::http::ResponseBodyKind::chunked ||
      stream_delimited;
  if (framing.kind == bonvoyage::http::ResponseBodyKind::none &&
      (method != "HEAD" || !framing.content_length.has_value())) {
    downstream_length = 0U;
  }
  std::string downstream_length_text;
  if (downstream_length.has_value()) {
    downstream_length_text = std::to_string(*downstream_length);
    if (transform_response) {
      owned_headers.emplace_back("Content-Length", downstream_length_text);
    } else {
      header_views.push_back(
          {"Content-Length", downstream_length_text});
    }
  } else if (downstream_chunked) {
    if (transform_response) {
      owned_headers.emplace_back("Transfer-Encoding", "chunked");
    } else {
      header_views.push_back({"Transfer-Encoding", "chunked"});
    }
  }
  if (transform_response) {
    header_views.reserve(owned_headers.size() + 4U);
    for (const auto& [name, value] : owned_headers) {
      header_views.push_back({name, value});
    }
  }
  if (http1_cors_.has_value()) {
    append_cors_response_headers(
        *http1_cors_, [&header_views](std::string_view name,
                                     std::string_view value) {
          header_views.push_back({name, value});
        });
  }
  const bool flush_event_stream =
      std::any_of(header_views.begin(), header_views.end(),
                  [](const bonvoyage::http::HeaderView& header) {
                    return bonvoyage::http::ascii_case_equal(
                               header.name, "content-type") &&
                           bonvoyage::http::is_event_stream_content_type(
                               header.value);
                  });

  if (downstream_chunked) {
    response_started_ = true;
    if (http1_access_log_ != nullptr) {
      http1_access_log_->status = status;
    }
    auto response_head = bonvoyage::http::serialize_response_head_buffer(
        status, reason_phrase(status), header_views,
        !downstream_keep_alive);
    record_response_path_handoff(handoff_started_at);
    record_response_path_write(response_head.size());
    co_await output_.write(std::move(response_head));

    bool wrote_body_chunk = false;
    while (true) {
      auto data = co_await body.read();
      if (data.empty()) {
        break;
      }

      std::array<char, 2U + 2U * sizeof(std::size_t) + 2U> prefix{};
      auto* cursor = prefix.data();
      if (wrote_body_chunk) {
        *cursor++ = '\r';
        *cursor++ = '\n';
      }
      const auto [end, error] =
          std::to_chars(cursor, prefix.data() + prefix.size(), data.size(), 16);
      if (error != std::errc{}) {
        throw std::logic_error("HTTP chunk-size serialization failed");
      }
      cursor = end;
      *cursor++ = '\r';
      *cursor++ = '\n';

      const auto body_bytes = data.size();
      seastar::temporary_buffer<char> framing_prefix(
          static_cast<std::size_t>(cursor - prefix.data()));
      std::memcpy(framing_prefix.get_write(), prefix.data(),
                  framing_prefix.size());
      seastar::net::packet chunk(std::move(framing_prefix));
      chunk = seastar::net::packet(std::move(chunk), std::move(data));
      record_http1_response_bytes(body_bytes);
      record_response_path_write(chunk.len());
      co_await output_.write(std::move(chunk));
      if (flush_event_stream) {
        co_await flush_response_path();
      }
      wrote_body_chunk = true;
    }

    validate_and_record_upstream_trailers(server_.stats(), reply);
    constexpr std::string_view terminal_after_body{"\r\n0\r\n\r\n"};
    constexpr std::string_view terminal_without_body{"0\r\n\r\n"};
    const auto terminal =
        wrote_body_chunk ? terminal_after_body : terminal_without_body;
    seastar::temporary_buffer<char> terminal_buffer(terminal.size());
    std::memcpy(terminal_buffer.get_write(), terminal.data(), terminal.size());
    record_response_path_write(terminal_buffer.size());
    co_await output_.write(std::move(terminal_buffer));
    if (stream_delimited) {
      ++server_.stats().upstream_http2_stream_delimited_responses;
    } else {
      ++server_.stats().upstream_chunked_responses;
    }
    co_await flush_response_path();
    record_response_path_completion();
    record_response_status(server_.stats(), status);
    co_return;
  }

  response_started_ = true;
  if (http1_access_log_ != nullptr) {
    http1_access_log_->status = status;
  }
  const auto response_head = bonvoyage::http::serialize_response_head_views(
      status, reason_phrase(status), header_views,
      !downstream_keep_alive);
  record_response_path_handoff(handoff_started_at);
  record_response_path_write(response_head.size());
  co_await output_.write(response_head);

  if (framing.kind == bonvoyage::http::ResponseBodyKind::content_length) {
    std::uint64_t copied = 0U;
    while (true) {
      auto data = co_await body.read();
      if (data.empty()) {
        break;
      }
      copied += data.size();
      record_http1_response_bytes(data.size());
      record_response_path_write(data.size());
      co_await output_.write(data.get(), data.size());
    }
    if (copied != *framing.content_length) {
      throw std::runtime_error("upstream response body was truncated");
    }
  } else if (upstream_http2) {
    auto unexpected = co_await body.read();
    if (!unexpected.empty()) {
      ++server_.stats().upstream_framing_rejections;
      throw std::runtime_error(
          "upstream HTTP/2 sent a body where none was permitted");
    }
  }
  if (upstream_http2) {
    validate_and_record_upstream_trailers(server_.stats(), reply);
  }
  co_await flush_response_path();
  record_response_path_completion();
  record_response_status(server_.stats(), status);
}

}  // namespace

class GatewayShard::Impl final {
 public:
  void bind_snapshot_lifecycle(SnapshotPreparationShard& lifecycle) {
    if (lifecycle_ != nullptr || ready_) {
      throw std::logic_error(
          "gateway snapshot lifecycle must be bound exactly once before start");
    }
    lifecycle_ = &lifecycle;
  }

  seastar::future<> start(std::string snapshot_bytes,
                          std::string secrets_directory,
                          AccessLogOptions access_log_options,
                          OtlpTraceOptions trace_options,
                          ResponsePathDiagnosticOptions
                              response_path_diagnostics,
                          UpstreamHttp1ConnectionOptions
                              upstream_http1_options) {
    if (lifecycle_ == nullptr) {
      throw std::logic_error(
          "gateway start requires a bound snapshot lifecycle");
    }
    secrets_directory_ = std::move(secrets_directory);
    upstream_http1_options_ = upstream_http1_options;
    auto snapshot = RuntimeSnapshot::decode(snapshot_bytes);
    snapshot.validate_live_gateway_capabilities();
    SnapshotReference reference{snapshot.snapshot_id(),
                                snapshot_sha256(snapshot_bytes)};
    const auto lifecycle_state = lifecycle_->state();
    if (lifecycle_state.active_snapshot != reference) {
      throw std::logic_error(
          "gateway bootstrap snapshot differs from lifecycle identity");
    }
    access_log_ =
        std::make_unique<AccessLogSink>(std::move(access_log_options));
    trace_exporter_ =
        std::make_unique<OtlpTraceExporter>(std::move(trace_options));
    stats_.response_path_diagnostics_enabled =
        response_path_diagnostics.enabled ? 1U : 0U;
    co_await access_log_->start(snapshot.snapshot_id(), snapshot.generation());
    co_await trace_exporter_->start(snapshot.snapshot_id(), snapshot.generation(),
                                    bonvoyage::kDataplaneVersion);
    active_ = std::make_unique<GatewayRuntimeGeneration>(
        reference, std::move(snapshot),
        upstream_http1_options_.trust_connection_reuse);
    co_await active_->start(stats_, secrets_directory_);
    update_config_gauges(active_->snapshot());
    setup_metrics();
    listeners_.reserve(active_->snapshot().listeners().size());
    for (std::size_t index = 0U;
         index < active_->snapshot().listeners().size();
         ++index) {
      auto listener = std::make_unique<ListenerServer>(
          active_->snapshot(), index, [this] { return acquire_runtime(); },
          stats_, *access_log_, *trace_exporter_, secrets_directory_,
          response_path_diagnostics.enabled);
      co_await listener->start();
      listeners_.push_back(std::move(listener));
    }
    ready_ = true;
    stats_.ready = 1U;
  }

  seastar::future<> stop() {
    std::exception_ptr failure;
    auto preserve = [&failure](std::exception_ptr error) {
      if (failure == nullptr) {
        failure = std::move(error);
      }
    };
    co_await stop_maintenance().handle_exception(preserve);
    ready_ = false;
    stats_.ready = 0U;
    for (auto& listener : listeners_) {
      co_await listener->stop().handle_exception(preserve);
    }
    listeners_.clear();
    if (prepared_ != nullptr) {
      co_await prepared_->stop().handle_exception(preserve);
    }
    if (retired_ != nullptr) {
      co_await retired_->stop().handle_exception(preserve);
    }
    if (active_ != nullptr) {
      co_await active_->stop().handle_exception(preserve);
    }
    if (access_log_ != nullptr) {
      co_await access_log_->stop().handle_exception(preserve);
    }
    if (trace_exporter_ != nullptr) {
      co_await trace_exporter_->stop().handle_exception(preserve);
    }
    prepared_.reset();
    retired_.reset();
    active_.reset();
    metrics_.clear();
    access_log_.reset();
    trace_exporter_.reset();
    if (failure != nullptr) {
      std::rethrow_exception(failure);
    }
  }

  seastar::future<> start_maintenance(
      GatewayShard::ActiveHealthPublisher active_health_publisher,
      GatewayShard::DnsAddressPublisher dns_address_publisher) {
    if (seastar::this_shard_id() != 0U) {
      throw std::logic_error(
          "gateway maintenance must be started on shard zero");
    }
    if (!ready_ || active_ == nullptr) {
      throw std::logic_error(
          "gateway maintenance requires an active snapshot");
    }
    co_await active_->start_maintenance(std::move(active_health_publisher),
                                        std::move(dns_address_publisher));
  }

  seastar::future<> stop_maintenance() {
    if (active_ == nullptr) {
      co_return;
    }
    co_await active_->stop_maintenance();
  }

  void apply_active_health(std::size_t cluster_index,
                           std::size_t endpoint_index,
                           bool active_healthy) {
    active_->apply_active_health(cluster_index, endpoint_index,
                                 active_healthy);
  }

  void apply_resolved_address(std::size_t cluster_index,
                              std::size_t endpoint_index,
                              const std::string& resolved_address) {
    active_->apply_resolved_address(cluster_index, endpoint_index,
                                    resolved_address);
  }

  seastar::future<ShardSnapshotPreparationResult> prepare_live_snapshot(
      SnapshotPrepareCommand command) {
    ShardSnapshotPreparationResult result;
    result.active_snapshot = active_reference();
    try {
      if (!ready_ || active_ == nullptr || lifecycle_ == nullptr) {
        throw std::logic_error("live gateway is not initialized");
      }
      if (activation_intent_.has_value() || cancel_intent_.has_value()) {
        result.issue = make_issue(
            "snapshot.operation.in_progress", "rollout_sequence",
            "another live gateway snapshot operation is in progress");
        co_return result;
      }
      if (command.expected_active_snapshot != active_->reference()) {
        result.issue = make_issue(
            "snapshot.active_mismatch", "expected_active_snapshot",
            "expected active snapshot does not match the live gateway");
        co_return result;
      }
      if (prepared_ != nullptr) {
        const bool replay =
            prepared_sequence_ == command.rollout_sequence &&
            prepared_->reference() == command.snapshot &&
            prepared_expected_active_ == command.expected_active_snapshot;
        if (!replay) {
          result.issue = make_issue(
              "snapshot.prepare.conflict", "rollout_sequence",
              "a different live gateway generation remains prepared");
          co_return result;
        }
        result.prepared = true;
        result.replayed = true;
        co_return result;
      }
      if (snapshot_sha256(command.snapshot_bytes) != command.snapshot.sha256) {
        result.issue = make_issue(
            "snapshot.digest.mismatch", "artifact.snapshot_sha256",
            "live gateway artifact bytes do not match their declared digest");
        co_return result;
      }
      auto snapshot = RuntimeSnapshot::decode(command.snapshot_bytes);
      snapshot.validate_live_gateway_capabilities();
      if (!compatible_listener_topology(active_->snapshot(), snapshot)) {
        result.issue = make_issue(
            "snapshot.listener_restart_required", "snapshot.listeners",
            "listener address, protocol, or TLS changes require a controlled process restart");
        co_return result;
      }
      auto candidate = std::make_unique<GatewayRuntimeGeneration>(
          command.snapshot, std::move(snapshot),
          upstream_http1_options_.trust_connection_reuse);
      co_await candidate->start(stats_, secrets_directory_);
      prepared_ = std::move(candidate);
      prepared_sequence_ = command.rollout_sequence;
      prepared_expected_active_ = command.expected_active_snapshot;
      result.prepared = true;
    } catch (const std::bad_alloc&) {
      result.issue = make_issue(
          "snapshot.prepare.resource_exhausted", "snapshot",
          "live gateway preparation exhausted memory");
    } catch (const std::exception& error) {
      result.issue = make_issue("snapshot.prepare.live_validation_failed",
                                "snapshot", error.what());
    }
    co_return result;
  }

  seastar::future<> start_prepared_maintenance(
      const SnapshotReference& snapshot,
      GatewayShard::ActiveHealthPublisher active_health_publisher,
      GatewayShard::DnsAddressPublisher dns_address_publisher) {
    if (seastar::this_shard_id() != 0U || prepared_ == nullptr ||
        prepared_->reference() != snapshot) {
      throw std::logic_error(
          "prepared maintenance requires the named private generation on shard zero");
    }
    co_await prepared_->start_maintenance(
        std::move(active_health_publisher),
        std::move(dns_address_publisher));
  }

  void apply_generation_active_health(const SnapshotReference& snapshot,
                                      std::size_t cluster_index,
                                      std::size_t endpoint_index,
                                      bool active_healthy) {
    generation(snapshot).apply_active_health(cluster_index, endpoint_index,
                                             active_healthy);
  }

  void apply_generation_resolved_address(
      const SnapshotReference& snapshot, std::size_t cluster_index,
      std::size_t endpoint_index, const std::string& resolved_address) {
    generation(snapshot).apply_resolved_address(
        cluster_index, endpoint_index, resolved_address);
  }

  ShardSnapshotActivationResult arm_live_activation(
      const SnapshotActivateCommand& command) {
    ShardSnapshotActivationResult result;
    result.active_snapshot = active_reference();
    if (last_activation_.has_value() &&
        last_activation_->rollout_sequence == command.rollout_sequence) {
      const bool replay =
          last_activation_->snapshot == command.prepared_snapshot &&
          last_activation_->expected_active == command.expected_active_snapshot &&
          active_reference() == command.prepared_snapshot;
      if (!replay) {
        result.issue = make_issue(
            "rollout.sequence.conflict", "rollout_sequence",
            "live activation sequence was reused with different metadata");
        return result;
      }
      result.accepted = true;
      result.replayed = true;
      return result;
    }
    if (retired_ != nullptr) {
      result.issue = make_issue(
          "snapshot.retirement.pending", "retired_snapshot",
          "the previous live gateway generation is still draining");
      return result;
    }
    if (prepared_ == nullptr ||
        prepared_sequence_ != command.rollout_sequence ||
        prepared_->reference() != command.prepared_snapshot ||
        prepared_expected_active_ != command.expected_active_snapshot ||
        active_reference() != command.expected_active_snapshot) {
      result.issue = make_issue(
          "snapshot.activate.not_prepared", "prepared_snapshot",
          "the exact live gateway generation is not prepared");
      return result;
    }
    activation_intent_ = ActivationIntent{
        command.rollout_sequence, command.prepared_snapshot,
        command.expected_active_snapshot};
    result.accepted = true;
    return result;
  }

  void abort_live_activation() noexcept { activation_intent_.reset(); }

  bool commit_live_activation() noexcept {
    if (!activation_intent_.has_value() || prepared_ == nullptr ||
        retired_ != nullptr ||
        activation_intent_->rollout_sequence != prepared_sequence_ ||
        activation_intent_->snapshot != prepared_->reference() ||
        activation_intent_->expected_active != active_reference()) {
      return false;
    }
    auto* old_generation = active_.get();
    retired_ = std::move(active_);
    active_ = std::move(prepared_);
    for (auto& listener : listeners_) {
      listener->drain_generation(old_generation);
    }
    last_activation_ = activation_intent_;
    activation_intent_.reset();
    prepared_sequence_ = 0U;
    prepared_expected_active_ = {};
    update_config_gauges(active_->snapshot());
    return true;
  }

  ShardSnapshotCancellationResult arm_live_cancel(
      const SnapshotCancelCommand& command) {
    ShardSnapshotCancellationResult result;
    result.active_snapshot = active_reference();
    if (last_cancel_.has_value() &&
        last_cancel_->rollout_sequence == command.rollout_sequence) {
      if (last_cancel_->snapshot != command.snapshot ||
          last_cancel_->reason != command.reason) {
        result.issue = make_issue(
            "rollout.sequence.conflict", "rollout_sequence",
            "live cancellation sequence was reused with different metadata");
        return result;
      }
      result.accepted = true;
      result.replayed = true;
      return result;
    }
    if (activation_intent_.has_value() || prepared_ == nullptr ||
        prepared_sequence_ != command.rollout_sequence ||
        prepared_->reference() != command.snapshot) {
      result.issue = make_issue(
          "snapshot.cancel.not_prepared", "snapshot",
          "the exact live gateway generation is not prepared");
      return result;
    }
    cancel_intent_ = CancelIntent{command.rollout_sequence, command.snapshot,
                                  command.reason};
    result.accepted = true;
    return result;
  }

  void abort_live_cancel() noexcept { cancel_intent_.reset(); }

  seastar::future<bool> commit_live_cancel() {
    if (!cancel_intent_.has_value() || prepared_ == nullptr ||
        cancel_intent_->rollout_sequence != prepared_sequence_ ||
        cancel_intent_->snapshot != prepared_->reference()) {
      co_return false;
    }
    auto cancelled = std::move(prepared_);
    last_cancel_ = cancel_intent_;
    cancel_intent_.reset();
    prepared_sequence_ = 0U;
    prepared_expected_active_ = {};
    co_await cancelled->stop().handle_exception(
        [](const std::exception_ptr& error) {
          gateway_log.warn(
              "private live generation cleanup failed during cancellation: {}",
              error);
        });
    co_return true;
  }

  seastar::future<> discard_live_prepared(
      std::uint64_t rollout_sequence, SnapshotReference snapshot) {
    if (prepared_ == nullptr || prepared_sequence_ != rollout_sequence ||
        prepared_->reference() != snapshot || activation_intent_.has_value() ||
        cancel_intent_.has_value()) {
      co_return;
    }
    auto discarded = std::move(prepared_);
    prepared_sequence_ = 0U;
    prepared_expected_active_ = {};
    co_await discarded->stop().handle_exception(
        [](const std::exception_ptr& error) {
          gateway_log.warn("private live generation cleanup failed: {}", error);
        });
  }

  seastar::future<ShardSnapshotRetirementResult> reap_live_retired(
      SnapshotReference snapshot, bool lifecycle_unpinned) {
    ShardSnapshotRetirementResult result;
    if (retired_ == nullptr) {
      result.complete = true;
      co_return result;
    }
    if (retired_->reference() != snapshot) {
      result.issue = make_issue(
          "snapshot.retirement.identity_mismatch", "retired_snapshot",
          "live gateway retained a different retired generation");
      co_return result;
    }
    if (!lifecycle_unpinned) {
      result.pinned_leases = 1U;
      co_return result;
    }
    auto retired = std::move(retired_);
    co_await retired->stop().handle_exception(
        [&result](const std::exception_ptr& error) {
          gateway_log.warn("retired live generation cleanup failed: {}", error);
          result.issue = make_issue(
              "snapshot.retirement.cleanup_failed", "retired_snapshot",
              "retired live gateway resources could not close cleanly");
        });
    result.complete = !result.issue.has_value();
    co_return result;
  }

  [[nodiscard]] bool ready() const noexcept { return ready_; }
  [[nodiscard]] const std::string& snapshot_id() const noexcept {
    return active_->snapshot().snapshot_id();
  }
  [[nodiscard]] std::uint64_t snapshot_generation() const noexcept {
    return active_->snapshot().generation();
  }

 private:
  struct ActivationIntent final {
    std::uint64_t rollout_sequence{};
    SnapshotReference snapshot;
    SnapshotReference expected_active;
  };

  struct CancelIntent final {
    std::uint64_t rollout_sequence{};
    SnapshotReference snapshot;
    std::string reason;
  };

  static SnapshotPreparationIssue make_issue(std::string code,
                                             std::string field_path,
                                             std::string message) {
    constexpr std::size_t kMaximumIssueText = 4096U;
    if (message.size() > kMaximumIssueText) {
      message.resize(kMaximumIssueText);
    }
    return SnapshotPreparationIssue{std::move(code), std::move(field_path),
                                    std::move(message)};
  }

  [[nodiscard]] SnapshotReference active_reference() const {
    return active_ == nullptr ? SnapshotReference{} : active_->reference();
  }

  [[nodiscard]] std::optional<ConnectionRuntime> acquire_runtime() noexcept {
    if (lifecycle_ == nullptr || active_ == nullptr) {
      return std::nullopt;
    }
    auto lease = lifecycle_->acquire_active_snapshot();
    if (!lease.has_value()) {
      return std::nullopt;
    }
    if (lease->snapshot() != active_->reference()) {
      std::terminate();
    }
    return ConnectionRuntime{active_.get(), std::move(*lease)};
  }

  GatewayRuntimeGeneration& generation(const SnapshotReference& reference) {
    for (auto* candidate : {active_.get(), prepared_.get(), retired_.get()}) {
      if (candidate != nullptr && candidate->reference() == reference) {
        return *candidate;
      }
    }
    throw std::out_of_range("snapshot generation is not retained");
  }

  void update_config_gauges(const RuntimeSnapshot& snapshot) noexcept {
    stats_.snapshot_generation = snapshot.generation();
    stats_.configured_listeners = snapshot.listeners().size();
    stats_.configured_routes = snapshot.route_admission_policies().size();
    stats_.configured_clusters = snapshot.clusters().size();
    stats_.configured_endpoints = 0U;
    stats_.configured_upstream_http1_connections = 0U;
    for (const auto& cluster : snapshot.clusters()) {
      stats_.configured_endpoints += cluster.endpoints.size();
      if (cluster.protocol == RuntimeUpstreamProtocol::http1) {
        stats_.configured_upstream_http1_connections +=
            cluster.max_connections_per_shard;
      }
    }
  }

  void setup_metrics() {
    namespace sm = seastar::metrics;
    auto& access_log_stats = access_log_->stats();
    auto& trace_stats = trace_exporter_->stats();
    metrics_.add_group(
        "bonvoyage_gateway",
        {sm::make_gauge(
             "telemetry_contract_version", stats_.telemetry_contract_version,
             sm::description("Stable BonVoyage telemetry contract version")),
         sm::make_gauge("ready", stats_.ready,
                        sm::description("Whether this shard serves the active snapshot")),
         sm::make_gauge("snapshot_generation", stats_.snapshot_generation,
                        sm::description("Active immutable snapshot generation")),
         sm::make_gauge("configured_listeners", stats_.configured_listeners,
                        sm::description("Listeners in the active snapshot")),
         sm::make_gauge("configured_routes", stats_.configured_routes,
                        sm::description("Routes in the active snapshot")),
         sm::make_gauge("configured_clusters", stats_.configured_clusters,
                        sm::description("Clusters in the active snapshot")),
         sm::make_gauge("configured_endpoints", stats_.configured_endpoints,
                        sm::description("Endpoints in the active snapshot")),
         sm::make_gauge(
             "access_log_enabled", access_log_stats.enabled,
             sm::description("Whether bounded shard-local access logging is enabled")),
         sm::make_gauge(
             "access_log_sink_healthy", access_log_stats.sink_healthy,
             sm::description("Whether the shard-local access-log sink can persist records")),
         sm::make_gauge(
             "access_log_queue_depth", access_log_stats.queue_depth,
             sm::description("Access records currently retained by the shard-local queue")),
         sm::make_gauge(
             "access_log_queue_capacity", access_log_stats.queue_capacity,
             sm::description("Maximum access records retained by the shard-local queue")),
         sm::make_counter(
             "access_log_records_enqueued_total",
             access_log_stats.records_enqueued,
             sm::description("Sampled access records admitted to the shard-local queue")),
         sm::make_counter(
             "access_log_records_written_total",
             access_log_stats.records_written,
             sm::description("Access records flushed to stable storage")),
         sm::make_counter(
             "access_log_records_dropped_total",
             access_log_stats.records_dropped,
             sm::description("Access records dropped without affecting request service")),
         sm::make_counter(
             "access_log_records_sampled_out_total",
             access_log_stats.records_sampled_out,
             sm::description("Access records intentionally omitted by deterministic sampling")),
         sm::make_counter(
             "access_log_queue_overflows_total",
             access_log_stats.queue_overflows,
             sm::description("Access records rejected by the drop-newest queue policy")),
         sm::make_counter(
             "access_log_write_failures_total",
             access_log_stats.write_failures,
             sm::description("Access-log segment open, write, flush, or close failures")),
         sm::make_counter(
             "access_log_capacity_exhaustions_total",
             access_log_stats.capacity_exhaustions,
             sm::description("Per-process access-log byte budgets exhausted on this shard")),
         sm::make_counter(
             "access_log_bytes_written_total", access_log_stats.bytes_written,
             sm::description("Logical JSONL bytes flushed to stable storage")),
         sm::make_counter(
             "access_log_segments_opened_total",
             access_log_stats.segments_opened,
             sm::description("Shard-local access-log segments opened successfully")),
         sm::make_gauge(
             "otlp_traces_enabled", trace_stats.enabled,
             sm::description("Whether bounded shard-local OTLP tracing is enabled")),
         sm::make_gauge(
             "otlp_trace_exporter_healthy", trace_stats.exporter_healthy,
             sm::description("Whether the shard-local OTLP exporter last completed a request successfully")),
         sm::make_gauge(
             "otlp_trace_queue_depth", trace_stats.queue_depth,
             sm::description("Completed spans currently retained by the shard-local trace queue")),
         sm::make_gauge(
             "otlp_trace_queue_capacity", trace_stats.queue_capacity,
             sm::description("Maximum completed spans retained by the shard-local trace queue")),
         sm::make_counter(
             "otlp_trace_spans_started_total", trace_stats.spans_started,
             sm::description("Requests assigned a BonVoyage trace context")),
         sm::make_counter(
             "otlp_trace_spans_sampled_total", trace_stats.spans_sampled,
             sm::description("Request spans selected by local bounded sampling")),
         sm::make_counter(
             "otlp_trace_spans_sampled_out_total",
             trace_stats.spans_sampled_out,
             sm::description("Request spans omitted by local bounded sampling")),
         sm::make_counter(
             "otlp_trace_invalid_traceparents_total",
             trace_stats.invalid_traceparents,
             sm::description("Invalid or repeated downstream traceparent fields ignored safely")),
         sm::make_counter(
             "otlp_trace_remote_parents_total", trace_stats.remote_parents,
             sm::description("Valid downstream trace parents continued by BonVoyage")),
         sm::make_counter(
             "otlp_trace_propagation_limit_rejections_total",
             trace_stats.propagation_limit_rejections,
             sm::description("Trace propagation rejected before exceeding the configured upstream header limit")),
         sm::make_counter(
             "otlp_trace_spans_enqueued_total", trace_stats.spans_enqueued,
             sm::description("Sampled spans admitted to the shard-local trace queue")),
         sm::make_counter(
             "otlp_trace_spans_exported_total", trace_stats.spans_exported,
             sm::description("Spans accepted by the configured OTLP collector")),
         sm::make_counter(
             "otlp_trace_spans_dropped_total", trace_stats.spans_dropped,
             sm::description("Spans observably dropped without affecting request service")),
         sm::make_counter(
             "otlp_trace_queue_overflows_total", trace_stats.queue_overflows,
             sm::description("Sampled spans rejected by the drop-newest queue policy")),
         sm::make_counter(
             "otlp_trace_batches_exported_total", trace_stats.batches_exported,
             sm::description("OTLP trace batches accepted without transport failure")),
         sm::make_counter(
             "otlp_trace_export_requests_total", trace_stats.export_requests,
             sm::description("OTLP trace export attempts including retries")),
         sm::make_counter(
             "otlp_trace_export_failures_total", trace_stats.export_failures,
             sm::description("Failed OTLP transport, protocol, or response attempts")),
         sm::make_counter(
             "otlp_trace_export_retries_total", trace_stats.export_retries,
             sm::description("Bounded OTLP retries after transient failures")),
         sm::make_counter(
             "otlp_trace_retry_exhaustions_total",
             trace_stats.retry_exhaustions,
             sm::description("OTLP batches dropped after their bounded retry budget")),
         sm::make_counter(
             "otlp_trace_partial_success_responses_total",
             trace_stats.partial_success_responses,
             sm::description("Collector responses reporting rejected spans or diagnostics")),
         sm::make_counter(
             "otlp_trace_exporter_recoveries_total",
             trace_stats.exporter_recoveries,
             sm::description("Exporter transitions from failed to healthy without a dataplane restart")),
         sm::make_counter(
             "otlp_trace_bytes_exported_total", trace_stats.bytes_exported,
             sm::description("Serialized OTLP protobuf bytes accepted by the collector")),
         sm::make_counter("requests_total", stats_.requests_total,
                          sm::description("Accepted HTTP requests")),
         sm::make_counter("responses_2xx_total", stats_.responses_2xx,
                          sm::description("2xx downstream responses")),
         sm::make_counter("responses_3xx_total", stats_.responses_3xx,
                          sm::description("3xx downstream responses")),
         sm::make_counter("responses_4xx_total", stats_.responses_4xx,
                          sm::description("4xx downstream responses")),
         sm::make_counter("responses_5xx_total", stats_.responses_5xx,
                          sm::description("5xx downstream responses")),
         sm::make_counter("route_misses_total", stats_.route_misses,
                          sm::description("Requests with no matching route")),
         sm::make_counter("route_redirects_total", stats_.route_redirects,
                          sm::description("Executed local route redirects")),
         sm::make_counter(
             "downstream_connections_accepted_total",
             stats_.downstream_connections_accepted,
             sm::description("Downstream connections admitted by this shard")),
         sm::make_counter(
             "downstream_connection_rejections_total",
             stats_.downstream_connection_rejections,
             sm::description("Connections rejected at the per-shard limit")),
         sm::make_counter("overload_rejections_total",
                          stats_.overload_rejections,
                          sm::description("Requests rejected by bounded route, cluster, endpoint, or probe admission")),
         sm::make_counter(
             "route_overload_rejections_total",
             stats_.route_overload_rejections,
             sm::description("Requests rejected by per-route shard-local concurrency limits")),
         sm::make_counter(
             "route_rate_limit_rejections_total",
             stats_.route_rate_limit_rejections,
             sm::description("Requests rejected by per-route shard-local token buckets")),
         sm::make_counter(
             "api_key_auth_successes_total", stats_.api_key_auth_successes,
             sm::description("Requests admitted by static shard-local API-key authentication")),
         sm::make_counter(
             "api_key_auth_rejections_total", stats_.api_key_auth_rejections,
             sm::description("Requests rejected by static shard-local API-key authentication")),
         sm::make_counter(
             "jwt_auth_successes_total", stats_.jwt_auth_successes,
             sm::description("Requests admitted by shard-local JWT authentication and authorization")),
         sm::make_counter(
             "jwt_auth_rejections_total", stats_.jwt_auth_rejections,
             sm::description("Requests rejected as invalid by shard-local JWT authentication")),
         sm::make_counter(
             "jwt_authorization_rejections_total",
             stats_.jwt_authorization_rejections,
             sm::description("Authenticated JWT requests rejected by route authorization")),
         sm::make_counter(
             "jwt_verification_overload_rejections_total",
             stats_.jwt_verification_overload_rejections,
             sm::description("JWT requests rejected before asymmetric verification by the shard-local CPU budget")),
         sm::make_counter(
             "source_ip_policy_allows_total",
             stats_.source_ip_policy_allows,
             sm::description("Requests admitted by static shard-local source IP policy")),
         sm::make_counter(
             "source_ip_policy_rejections_total",
             stats_.source_ip_policy_rejections,
             sm::description("Requests rejected by static shard-local source IP policy")),
         sm::make_counter(
             "cors_actual_allows_total", stats_.cors_actual_allows,
             sm::description("Actual cross-origin requests admitted by route CORS policy")),
         sm::make_counter(
             "cors_preflight_successes_total",
             stats_.cors_preflight_successes,
             sm::description("CORS preflight requests answered locally")),
         sm::make_counter(
             "cors_rejections_total", stats_.cors_rejections,
             sm::description("Malformed or disallowed CORS requests rejected by route policy")),
         sm::make_counter(
             "request_content_policy_allows_total",
             stats_.request_content_policy_allows,
             sm::description("Requests admitted by bounded route request-content policy")),
         sm::make_counter(
             "request_content_type_rejections_total",
             stats_.request_content_type_rejections,
             sm::description("Requests rejected by route Content-Type policy")),
         sm::make_counter(
             "request_body_limit_rejections_total",
             stats_.request_body_limit_rejections,
             sm::description("Requests rejected by explicit route body-size limits")),
         sm::make_counter(
             "request_header_transformation_applications_total",
             stats_.request_header_transformation_applications,
             sm::description("Sanitized upstream request attempts with configured header transformations")),
         sm::make_counter(
             "response_header_transformation_applications_total",
             stats_.response_header_transformation_applications,
             sm::description("Sanitized upstream responses with configured header transformations")),
         sm::make_counter(
             "header_transformation_limit_rejections_total",
             stats_.header_transformation_limit_rejections,
             sm::description("Request or response field blocks rejected after bounded transformation")),
         sm::make_counter(
             "request_authority_rewrite_applications_total",
             stats_.request_authority_rewrite_applications,
             sm::description("Sanitized upstream request attempts using a configured authority rewrite")),
         sm::make_counter(
             "request_path_rewrite_applications_total",
             stats_.request_path_rewrite_applications,
             sm::description("Sanitized upstream request attempts using a configured path rewrite")),
         sm::make_counter(
             "request_rewrite_limit_rejections_total",
             stats_.request_rewrite_limit_rejections,
             sm::description("Requests rejected before upstream selection when a rewritten target exceeded its bound")),
         sm::make_counter(
             "route_weighted_cluster_selections_total",
             stats_.route_weighted_cluster_selections,
             sm::description("Admitted proxy requests assigned by a shard-local weighted route schedule")),
         sm::make_counter(
             "trusted_proxy_client_ip_resolutions_total",
             stats_.trusted_proxy_client_ip_resolutions,
             sm::description("Requests whose client IP was resolved from a trusted X-Forwarded-For chain")),
         sm::make_counter(
             "forwarded_header_rejections_total",
             stats_.forwarded_header_rejections,
             sm::description("Malformed X-Forwarded-For chains rejected from trusted peers")),
         sm::make_counter(
             "cluster_overload_rejections_total",
             stats_.cluster_overload_rejections,
             sm::description("Requests rejected by the shard-local cluster admission limit")),
         sm::make_counter(
             "endpoint_overload_rejections_total",
             stats_.endpoint_overload_rejections,
             sm::description("Requests rejected by per-endpoint concurrency limits")),
         sm::make_counter("upstream_failures_total", stats_.upstream_failures,
                          sm::description("Failed upstream request attempts")),
         sm::make_counter(
             "upstream_endpoint_selections_total",
             stats_.upstream_endpoint_selections,
             sm::description("Shard-local endpoint selections")),
         sm::make_counter(
             "upstream_passive_failures_total",
             stats_.upstream_passive_failures,
             sm::description("Endpoint failures before a valid upstream response head")),
         sm::make_counter(
             "upstream_passive_ejections_total",
             stats_.upstream_passive_ejections,
             sm::description("Temporary shard-local passive-health ejections")),
         sm::make_counter(
             "upstream_passive_reactivations_total",
             stats_.upstream_passive_reactivations,
             sm::description("Endpoint circuits entering half-open after the open interval")),
         sm::make_counter(
             "upstream_no_eligible_endpoints_total",
             stats_.upstream_no_eligible_endpoints,
             sm::description("Requests rejected because every endpoint was open or actively unhealthy")),
         sm::make_counter(
             "endpoint_circuit_opens_total", stats_.endpoint_circuit_opens,
             sm::description("Closed endpoint circuits opened by passive failures")),
         sm::make_counter(
             "endpoint_circuit_half_open_transitions_total",
             stats_.endpoint_circuit_half_open_transitions,
             sm::description("Open endpoint circuits entering half-open recovery")),
         sm::make_counter(
             "endpoint_circuit_closes_total", stats_.endpoint_circuit_closes,
             sm::description("Half-open endpoint circuits closed by successful probes")),
         sm::make_counter(
             "endpoint_circuit_reopens_total", stats_.endpoint_circuit_reopens,
             sm::description("Half-open endpoint circuits reopened by failed probes")),
         sm::make_counter(
             "endpoint_circuit_probe_rejections_total",
             stats_.endpoint_circuit_probe_rejections,
             sm::description("Requests rejected while one half-open probe was active")),
         sm::make_counter(
             "retry_attempts_total", stats_.retry_attempts,
             sm::description("Additional upstream attempts admitted by retry policy")),
         sm::make_counter(
             "retry_successes_total", stats_.retry_successes,
             sm::description("Requests completed after at least one retry")),
         sm::make_counter(
             "retry_exhausted_total", stats_.retry_exhausted,
             sm::description("Retryable failures reaching the maximum total attempts")),
         sm::make_counter(
             "retry_token_rejections_total", stats_.retry_token_rejections,
             sm::description("Retries suppressed by an empty shard-local token bucket")),
         sm::make_counter(
             "retry_concurrency_rejections_total",
             stats_.retry_concurrency_rejections,
             sm::description("Retries suppressed by the shard-local concurrent retry circuit breaker")),
         sm::make_counter(
             "retry_per_try_timeouts_total", stats_.retry_per_try_timeouts,
             sm::description("Upstream attempts missing the configured response-head deadline")),
         sm::make_counter(
             "retry_commit_suppressions_total",
             stats_.retry_commit_suppressions,
             sm::description("Retries suppressed after downstream response handoff")),
         sm::make_counter(
             "retry_non_replayable_suppressions_total",
             stats_.retry_non_replayable_suppressions,
             sm::description("Retryable methods suppressed because the request body is not replayable")),
         sm::make_counter(
             "active_health_checks_total", stats_.active_health_checks,
             sm::description("Coordinator active-health probes completed")),
         sm::make_counter(
             "active_health_successes_total", stats_.active_health_successes,
             sm::description("Successful coordinator active-health probes")),
         sm::make_counter(
             "active_health_failures_total", stats_.active_health_failures,
             sm::description("Failed coordinator active-health probes")),
         sm::make_counter(
             "active_health_timeouts_total", stats_.active_health_timeouts,
             sm::description("Coordinator active-health probes that timed out")),
         sm::make_counter(
             "active_health_state_changes_total",
             stats_.active_health_state_changes,
             sm::description("Active-health transitions published to all shards")),
         sm::make_counter(
             "active_health_publish_failures_total",
             stats_.active_health_publish_failures,
             sm::description("Failed active-health cross-shard publications")),
         sm::make_counter(
             "active_health_cycle_overruns_total",
             stats_.active_health_cycle_overruns,
             sm::description("Active-health cycles exceeding their interval")),
         sm::make_counter(
             "dns_refresh_attempts_total", stats_.dns_refresh_attempts,
             sm::description("Coordinator DNS refresh attempts")),
         sm::make_counter(
             "dns_refresh_successes_total", stats_.dns_refresh_successes,
             sm::description("Successful coordinator DNS refreshes")),
         sm::make_counter(
             "dns_refresh_failures_total", stats_.dns_refresh_failures,
             sm::description("Failed coordinator DNS refreshes")),
         sm::make_counter(
             "dns_address_changes_total", stats_.dns_address_changes,
             sm::description("Resolved address changes published to all shards")),
         sm::make_counter(
             "dns_publish_failures_total", stats_.dns_publish_failures,
             sm::description("Failed DNS address cross-shard publications")),
         sm::make_counter(
             "dns_refresh_cycle_overruns_total",
             stats_.dns_refresh_cycle_overruns,
             sm::description("DNS refresh cycles exceeding their interval")),
         sm::make_counter(
             "upstream_framing_rejections_total",
             stats_.upstream_framing_rejections,
             sm::description("Rejected upstream HTTP/1 response framing")),
         sm::make_counter(
             "upstream_chunked_responses_total",
             stats_.upstream_chunked_responses,
             sm::description("Successfully translated chunked upstream responses")),
         sm::make_counter(
             "upstream_response_trailers_dropped_total",
             stats_.upstream_response_trailers_dropped,
             sm::description("Upstream responses whose trailers were validated and dropped")),
         sm::make_counter("request_timeouts_total", stats_.request_timeouts,
                          sm::description("Requests aborted by timeout")),
         sm::make_counter("tls_handshakes_total", stats_.tls_handshakes,
                          sm::description("Accepted downstream TLS handshakes")),
         sm::make_counter(
             "tls_handshake_failures_total", stats_.tls_handshake_failures,
             sm::description("Rejected or failed downstream TLS handshakes")),
         sm::make_counter(
             "tls_handshake_timeouts_total", stats_.tls_handshake_timeouts,
             sm::description("Downstream TLS handshakes exceeding 10 seconds")),
         sm::make_counter("tls_sni_rejections_total",
                          stats_.tls_sni_rejections,
                          sm::description("TLS connections rejected by SNI policy")),
         sm::make_counter(
             "tls_alpn_rejections_total", stats_.tls_alpn_rejections,
             sm::description("TLS connections selecting an unsupported protocol")),
         sm::make_counter(
             "upstream_tls_handshakes_total", stats_.upstream_tls_handshakes,
             sm::description("Verified upstream TLS handshakes")),
         sm::make_counter(
             "upstream_tls_handshake_failures_total",
             stats_.upstream_tls_handshake_failures,
             sm::description("Failed upstream TLS handshakes")),
         sm::make_counter(
             "upstream_tls_handshake_timeouts_total",
             stats_.upstream_tls_handshake_timeouts,
             sm::description("Upstream TLS handshakes exceeding the cluster connect timeout")),
         sm::make_counter(
             "upstream_http1_pool_waits_total",
             stats_.upstream_http1_pool_waits,
             sm::description("HTTP/1 requests that waited for selected endpoint pool capacity")),
         sm::make_counter(
             "upstream_http1_pool_wait_nanoseconds_total",
             stats_.upstream_http1_pool_wait_nanoseconds,
             sm::description("Nanoseconds spent awaiting selected endpoint HTTP/1 pool capacity")),
         sm::make_gauge(
             "upstream_http1_pool_wait_max_nanoseconds",
             stats_.upstream_http1_pool_wait_max_nanoseconds,
             sm::description("Longest completed or cancelled HTTP/1 pool-capacity wait in nanoseconds")),
         sm::make_counter(
             "upstream_http2_connections_total",
             stats_.upstream_http2_connections,
             sm::description("Established shard-local upstream HTTP/2 connections")),
         sm::make_counter(
             "upstream_http2_connection_failures_total",
             stats_.upstream_http2_connection_failures,
             sm::description("Failed upstream HTTP/2 connections")),
         sm::make_counter(
             "upstream_http2_protocol_errors_total",
             stats_.upstream_http2_protocol_errors,
             sm::description("Fatal upstream HTTP/2 protocol failures")),
         sm::make_counter(
             "upstream_http2_streams_total", stats_.upstream_http2_streams,
             sm::description("Admitted upstream HTTP/2 request streams")),
         sm::make_counter(
             "upstream_http2_stream_resets_total",
             stats_.upstream_http2_stream_resets,
             sm::description("Upstream HTTP/2 streams reset by peers")),
         sm::make_counter(
             "upstream_http2_goaways_total", stats_.upstream_http2_goaways,
             sm::description("GOAWAY frames received from upstream HTTP/2 peers")),
         sm::make_counter(
             "upstream_http2_request_cancellations_total",
             stats_.upstream_http2_request_cancellations,
             sm::description("Upstream HTTP/2 streams cancelled with downstream requests")),
         sm::make_counter(
             "upstream_http2_response_trailers_total",
             stats_.upstream_http2_response_trailers,
             sm::description("Upstream HTTP/2 responses carrying validated trailers")),
         sm::make_counter(
             "upstream_http2_pool_waits_total",
             stats_.upstream_http2_pool_waits,
             sm::description("Requests waiting for upstream HTTP/2 stream capacity")),
         sm::make_counter(
             "upstream_http2_stream_delimited_responses_total",
             stats_.upstream_http2_stream_delimited_responses,
             sm::description("HTTP/2 stream-delimited responses translated downstream")),
         sm::make_counter(
             "grpc_requests_total", stats_.grpc_requests,
             sm::description("Validated native gRPC requests")),
         sm::make_counter(
             "grpc_successes_total", stats_.grpc_successes,
             sm::description("Upstream gRPC responses with status zero")),
         sm::make_counter(
             "grpc_application_errors_total", stats_.grpc_application_errors,
             sm::description("Upstream gRPC responses with nonzero status")),
         sm::make_counter(
             "grpc_local_errors_total", stats_.grpc_local_errors,
             sm::description("Native gRPC errors generated by gateway policy or transport handling")),
         sm::make_counter(
             "grpc_protocol_rejections_total",
             stats_.grpc_protocol_rejections,
             sm::description("Malformed or unsupported gRPC requests and responses")),
         sm::make_counter(
             "grpc_deadlines_propagated_total",
             stats_.grpc_deadlines_propagated,
             sm::description("Adjusted grpc-timeout fields sent upstream")),
         sm::make_counter(
             "grpc_response_trailers_forwarded_total",
             stats_.grpc_response_trailers_forwarded,
             sm::description("gRPC response trailer blocks forwarded downstream")),
         sm::make_counter(
             "grpc_trailing_metadata_fields_total",
             stats_.grpc_trailing_metadata_fields,
             sm::description("Application-defined gRPC trailing metadata fields forwarded downstream")),
         sm::make_counter(
             "websocket_handshake_attempts_total",
             stats_.websocket_handshake_attempts,
             sm::description("HTTP/1 requests presenting WebSocket upgrade fields")),
         sm::make_counter(
             "websocket_handshake_successes_total",
             stats_.websocket_handshake_successes,
             sm::description("Validated end-to-end WebSocket upgrades")),
         sm::make_counter(
             "websocket_handshake_rejections_total",
             stats_.websocket_handshake_rejections,
             sm::description("WebSocket attempts rejected before upstream selection")),
         sm::make_counter(
             "websocket_upstream_handshake_failures_total",
             stats_.websocket_upstream_handshake_failures,
             sm::description("Malformed, incomplete, or unauthenticated upstream WebSocket handshakes")),
         sm::make_counter(
             "websocket_connections_total", stats_.websocket_connections,
             sm::description("Established shard-local WebSocket tunnels")),
         sm::make_counter(
             "websocket_idle_timeouts_total",
             stats_.websocket_idle_timeouts,
             sm::description("WebSocket tunnels closed after their route idle deadline")),
         sm::make_counter(
             "websocket_drain_terminations_total",
             stats_.websocket_drain_terminations,
             sm::description("WebSocket tunnels terminated by coordinated listener drain")),
         sm::make_counter(
             "websocket_downstream_bytes_total",
             stats_.websocket_downstream_bytes,
             sm::description("Opaque WebSocket bytes transferred from downstream to upstream")),
         sm::make_counter(
             "websocket_upstream_bytes_total",
             stats_.websocket_upstream_bytes,
             sm::description("Opaque WebSocket bytes transferred from upstream to downstream")),
         sm::make_counter(
             "http2_connections_total", stats_.http2_connections,
             sm::description("Accepted downstream HTTP/2 connections")),
         sm::make_counter(
             "http2_streams_total", stats_.http2_streams,
             sm::description("Validated downstream HTTP/2 request streams")),
         sm::make_counter(
             "http2_stream_resets_total", stats_.http2_stream_resets,
             sm::description("HTTP/2 streams closed with nonzero errors")),
         sm::make_counter(
             "http2_request_cancellations_total",
             stats_.http2_request_cancellations,
             sm::description("HTTP/2 requests cancelled by the downstream peer")),
         sm::make_counter(
             "http2_protocol_errors_total", stats_.http2_protocol_errors,
             sm::description("Fatal downstream HTTP/2 protocol failures")),
         sm::make_counter(
             "http2_goaways_total", stats_.http2_goaways,
             sm::description("Graceful downstream HTTP/2 GOAWAY frames")),
         sm::make_counter(
             "http2_drain_timeouts_total", stats_.http2_drain_timeouts,
             sm::description("HTTP/2 connections closed at the drain deadline")),
         sm::make_counter("request_bytes_total", stats_.request_bytes,
                          sm::description("Decoded request body bytes")),
         sm::make_counter("response_bytes_total", stats_.response_bytes,
                          sm::description("Decoded response body bytes")),
         sm::make_gauge(
             "response_path_diagnostics_enabled",
             stats_.response_path_diagnostics_enabled,
             sm::description("Whether opt-in HTTP/1 response-path diagnostics are enabled")),
         sm::make_counter(
             "response_path_completed_responses_total",
             stats_.response_path_completed_responses,
             sm::description("Proxied HTTP/1 responses completed while response-path diagnostics are enabled")),
         sm::make_counter(
             "response_path_write_operations_total",
             stats_.response_path_write_operations,
             sm::description("HTTP/1 proxy output-stream write submissions observed by response-path diagnostics")),
         sm::make_counter(
             "response_path_write_bytes_total",
             stats_.response_path_write_bytes,
             sm::description("Logical HTTP/1 proxy bytes submitted to the downstream output stream")),
         sm::make_counter(
             "response_path_flush_operations_total",
             stats_.response_path_flush_operations,
             sm::description("HTTP/1 proxy output-stream flush submissions observed by response-path diagnostics")),
         sm::make_counter(
             "response_path_flush_wait_operations_total",
             stats_.response_path_flush_wait_operations,
             sm::description("HTTP/1 proxy flushes that did not complete immediately")),
         sm::make_counter(
             "response_path_flush_wait_nanoseconds_total",
             stats_.response_path_flush_wait_nanoseconds,
             sm::description("Nanoseconds spent awaiting non-ready HTTP/1 proxy flushes")),
         sm::make_counter(
             "response_path_handoff_observations_total",
             stats_.response_path_handoff_observations,
             sm::description("HTTP/1 upstream-response handoffs observed before the first downstream write")),
         sm::make_counter(
             "response_path_handoff_nanoseconds_total",
             stats_.response_path_handoff_nanoseconds,
             sm::description("Nanoseconds from HTTP/1 upstream response handoff to first downstream write submission")),
         sm::make_gauge("active_requests", stats_.active_requests,
                        sm::description("Currently active requests")),
         sm::make_gauge(
             "active_route_requests", stats_.active_route_requests,
             sm::description("Currently active requests holding route admission")),
         sm::make_gauge("active_connections", stats_.active_connections,
                        sm::description("Currently open downstream connections")),
         sm::make_gauge("active_tls_handshakes",
                        stats_.active_tls_handshakes,
                        sm::description("Currently active TLS handshakes")),
         sm::make_gauge(
             "active_upstream_tls_handshakes",
             stats_.active_upstream_tls_handshakes,
             sm::description("Currently active upstream TLS handshakes")),
         sm::make_gauge(
             "active_upstream_requests", stats_.active_upstream_requests,
             sm::description("Currently active selected upstream requests")),
         sm::make_gauge(
             "active_upstream_http1_requests",
             stats_.active_upstream_http1_requests,
             sm::description("Currently active shard-local upstream HTTP/1 requests")),
         sm::make_gauge(
             "configured_upstream_http1_connections",
             stats_.configured_upstream_http1_connections,
             sm::description("Configured shard-local upstream HTTP/1 connection capacity")),
         sm::make_gauge(
             "active_unhealthy_endpoints", stats_.active_unhealthy_endpoints,
             sm::description("Endpoints excluded by active health")),
         sm::make_gauge(
             "open_endpoint_circuits", stats_.open_endpoint_circuits,
             sm::description("Shard-local endpoint circuits currently open")),
         sm::make_gauge(
             "half_open_endpoint_circuits",
             stats_.half_open_endpoint_circuits,
             sm::description("Shard-local endpoint circuits currently half-open")),
         sm::make_gauge(
             "active_retries", stats_.active_retries,
             sm::description("Currently active admitted retries")),
         sm::make_gauge(
             "active_upstream_http2_connections",
             stats_.active_upstream_http2_connections,
             sm::description("Currently active upstream HTTP/2 connections")),
         sm::make_gauge(
             "active_upstream_http2_streams",
             stats_.active_upstream_http2_streams,
             sm::description("Currently active upstream HTTP/2 streams")),
         sm::make_gauge(
             "active_http2_connections", stats_.active_http2_connections,
             sm::description("Currently active downstream HTTP/2 connections")),
         sm::make_gauge(
             "active_http2_streams", stats_.active_http2_streams,
             sm::description("Currently active downstream HTTP/2 streams")),
         sm::make_gauge(
             "active_websocket_connections",
             stats_.active_websocket_connections,
             sm::description("Currently established shard-local WebSocket tunnels")),
         sm::make_histogram(
             "request_latency_microseconds", stats_.request_latency_microseconds,
             sm::description("End-to-end request latency in microseconds"))});
  }

  SnapshotPreparationShard* lifecycle_{};
  GatewayStats stats_;
  std::unique_ptr<AccessLogSink> access_log_;
  std::unique_ptr<OtlpTraceExporter> trace_exporter_;
  seastar::metrics::metric_groups metrics_;
  std::unique_ptr<GatewayRuntimeGeneration> active_;
  std::unique_ptr<GatewayRuntimeGeneration> prepared_;
  std::unique_ptr<GatewayRuntimeGeneration> retired_;
  std::vector<std::unique_ptr<ListenerServer>> listeners_;
  std::string secrets_directory_;
  UpstreamHttp1ConnectionOptions upstream_http1_options_;
  std::uint64_t prepared_sequence_{};
  SnapshotReference prepared_expected_active_;
  std::optional<ActivationIntent> activation_intent_;
  std::optional<ActivationIntent> last_activation_;
  std::optional<CancelIntent> cancel_intent_;
  std::optional<CancelIntent> last_cancel_;
  bool ready_{false};
};

GatewayShard::GatewayShard() : impl_(std::make_unique<Impl>()) {}
GatewayShard::~GatewayShard() = default;

void GatewayShard::bind_snapshot_lifecycle(
    SnapshotPreparationShard& lifecycle) {
  impl_->bind_snapshot_lifecycle(lifecycle);
}

seastar::future<> GatewayShard::start(std::string snapshot_bytes,
                                     std::string secrets_directory,
                                     AccessLogOptions access_log_options,
                                     OtlpTraceOptions trace_options,
                                     ResponsePathDiagnosticOptions
                                         response_path_diagnostics,
                                     UpstreamHttp1ConnectionOptions
                                         upstream_http1_options) {
  return impl_->start(std::move(snapshot_bytes),
                      std::move(secrets_directory),
                      std::move(access_log_options),
                      std::move(trace_options),
                      response_path_diagnostics, upstream_http1_options);
}

seastar::future<ShardSnapshotPreparationResult>
GatewayShard::prepare_live_snapshot(SnapshotPrepareCommand command) {
  return impl_->prepare_live_snapshot(std::move(command));
}

seastar::future<> GatewayShard::start_prepared_maintenance(
    const SnapshotReference& snapshot,
    ActiveHealthPublisher active_health_publisher,
    DnsAddressPublisher dns_address_publisher) {
  return impl_->start_prepared_maintenance(
      snapshot, std::move(active_health_publisher),
      std::move(dns_address_publisher));
}

void GatewayShard::apply_generation_active_health(
    const SnapshotReference& snapshot, std::size_t cluster_index,
    std::size_t endpoint_index, bool active_healthy) {
  impl_->apply_generation_active_health(snapshot, cluster_index,
                                        endpoint_index, active_healthy);
}

void GatewayShard::apply_generation_resolved_address(
    const SnapshotReference& snapshot, std::size_t cluster_index,
    std::size_t endpoint_index, const std::string& resolved_address) {
  impl_->apply_generation_resolved_address(
      snapshot, cluster_index, endpoint_index, resolved_address);
}

ShardSnapshotActivationResult GatewayShard::arm_live_activation(
    const SnapshotActivateCommand& command) {
  return impl_->arm_live_activation(command);
}

void GatewayShard::abort_live_activation() noexcept {
  impl_->abort_live_activation();
}

bool GatewayShard::commit_live_activation() noexcept {
  return impl_->commit_live_activation();
}

ShardSnapshotCancellationResult GatewayShard::arm_live_cancel(
    const SnapshotCancelCommand& command) {
  return impl_->arm_live_cancel(command);
}

void GatewayShard::abort_live_cancel() noexcept { impl_->abort_live_cancel(); }

seastar::future<bool> GatewayShard::commit_live_cancel() {
  return impl_->commit_live_cancel();
}

seastar::future<> GatewayShard::discard_live_prepared(
    std::uint64_t rollout_sequence, SnapshotReference snapshot) {
  return impl_->discard_live_prepared(rollout_sequence, std::move(snapshot));
}

seastar::future<ShardSnapshotRetirementResult>
GatewayShard::reap_live_retired(SnapshotReference snapshot,
                               bool lifecycle_unpinned) {
  return impl_->reap_live_retired(std::move(snapshot), lifecycle_unpinned);
}

seastar::future<> GatewayShard::start_maintenance(
    ActiveHealthPublisher active_health_publisher,
    DnsAddressPublisher dns_address_publisher) {
  return impl_->start_maintenance(std::move(active_health_publisher),
                                  std::move(dns_address_publisher));
}

seastar::future<> GatewayShard::stop_maintenance() {
  return impl_->stop_maintenance();
}

void GatewayShard::apply_active_health(std::size_t cluster_index,
                                       std::size_t endpoint_index,
                                       bool active_healthy) {
  impl_->apply_active_health(cluster_index, endpoint_index, active_healthy);
}

void GatewayShard::apply_resolved_address(
    std::size_t cluster_index, std::size_t endpoint_index,
    const std::string& resolved_address) {
  impl_->apply_resolved_address(cluster_index, endpoint_index,
                                resolved_address);
}

seastar::future<> GatewayShard::stop() { return impl_->stop(); }

bool GatewayShard::ready() const noexcept { return impl_->ready(); }

const std::string& GatewayShard::snapshot_id() const noexcept {
  return impl_->snapshot_id();
}

std::uint64_t GatewayShard::snapshot_generation() const noexcept {
  return impl_->snapshot_generation();
}

}  // namespace bonvoyage::runtime
