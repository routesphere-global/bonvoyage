#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bonvoyage/runtime/runtime_snapshot.hh"
#include "bonvoyage/v1/config.pb.h"

namespace {

bonvoyage::v1::Snapshot valid_snapshot() {
  bonvoyage::v1::Snapshot snapshot;
  snapshot.set_schema_version(1U);
  snapshot.set_snapshot_id("runtime-test");
  snapshot.set_generation(7U);

  auto* cluster = snapshot.add_clusters();
  cluster->set_name("api");
  cluster->set_load_balancing_policy(
      bonvoyage::v1::LOAD_BALANCING_POLICY_ROUND_ROBIN);
  cluster->set_max_connections_per_shard(4U);
  auto* endpoint = cluster->add_endpoints();
  endpoint->set_name("api-1");
  endpoint->set_address("127.0.0.1");
  endpoint->set_port(8081U);
  endpoint->set_weight(2U);

  auto* host = snapshot.add_virtual_hosts();
  host->set_name("default");
  host->add_domains("*");

  auto* fallback = host->add_routes();
  fallback->set_name("fallback");
  fallback->mutable_match()->set_path_prefix("/");
  fallback->set_cluster_name("api");
  fallback->set_max_concurrent_requests_per_shard(3U);
  fallback->mutable_local_rate_limit()->set_capacity(8U);
  fallback->mutable_local_rate_limit()->set_refill_tokens_per_second(2U);
  fallback->mutable_api_key_auth()->set_header_name("x-api-key");
  fallback->mutable_api_key_auth()->set_credentials_secret(
      "runtime-api-keys.txt");
  fallback->mutable_source_ip_policy()->add_allow_cidrs("198.51.100.0/24");
  fallback->mutable_source_ip_policy()->add_deny_cidrs(
      "198.51.100.128/25");

  auto* version = host->add_routes();
  version->set_name("version");
  version->mutable_match()->set_path_prefix("/v1");
  version->set_cluster_name("api");
  auto* transformations = version->mutable_header_transformations();
  auto* request_set = transformations->add_request();
  request_set->set_operation(
      bonvoyage::v1::HEADER_MUTATION_OPERATION_SET);
  request_set->set_name("x-route-tier");
  request_set->set_value("gold");
  auto* request_remove = transformations->add_request();
  request_remove->set_operation(
      bonvoyage::v1::HEADER_MUTATION_OPERATION_REMOVE);
  request_remove->set_name("x-remove-me");
  auto* response_append = transformations->add_response();
  response_append->set_operation(
      bonvoyage::v1::HEADER_MUTATION_OPERATION_APPEND);
  response_append->set_name("cache-control");
  response_append->set_value("private");
  auto* rewrite = version->mutable_rewrite();
  rewrite->set_host("orders.internal.test");
  rewrite->set_port(9443U);
  rewrite->set_path_prefix("/v2");

  auto* exact = host->add_routes();
  exact->set_name("ready");
  exact->mutable_match()->set_path_exact("/v1/ready");
  auto* fixed = exact->mutable_fixed_response();
  fixed->set_status_code(200U);
  fixed->set_body("ready\n");
  fixed->set_content_type("text/plain");

  auto* selected = host->add_routes();
  selected->set_name("selected");
  selected->mutable_match()->set_path_exact("/select");
  selected->mutable_match()->add_methods("GET");
  auto* selected_header = selected->mutable_match()->add_headers();
  selected_header->set_name("x-release");
  selected_header->set_exact("beta");
  auto* selected_query = selected->mutable_match()->add_query_parameters();
  selected_query->set_name("tenant");
  selected_query->set_exact("acme");
  selected->mutable_fixed_response()->set_status_code(203U);

  auto* select_fallback = host->add_routes();
  select_fallback->set_name("select-fallback");
  select_fallback->mutable_match()->set_path_exact("/select");
  select_fallback->mutable_fixed_response()->set_status_code(204U);

  auto* absent = host->add_routes();
  absent->set_name("absence");
  absent->mutable_match()->set_path_exact("/absence");
  auto* absent_header = absent->mutable_match()->add_headers();
  absent_header->set_name("x-blocked");
  absent_header->set_present(false);
  auto* absent_query = absent->mutable_match()->add_query_parameters();
  absent_query->set_name("blocked");
  absent_query->set_present(false);
  absent->mutable_fixed_response()->set_status_code(205U);

  auto* regex = host->add_routes();
  regex->set_name("numeric-item");
  regex->mutable_match()->set_safe_regex(R"(/items/[0-9]+)");
  regex->mutable_fixed_response()->set_status_code(206U);

  auto* jwt = host->add_routes();
  jwt->set_name("jwt-protected");
  jwt->mutable_match()->set_path_exact("/jwt");
  jwt->mutable_fixed_response()->set_status_code(207U);
  auto* jwt_auth = jwt->mutable_jwt_auth();
  jwt_auth->set_jwks_secret("runtime-jwks.json");
  jwt_auth->set_issuer("https://issuer.example.test");
  jwt_auth->set_audience("payments-api");
  jwt_auth->set_required_type("at+jwt");
  jwt_auth->add_algorithms(bonvoyage::v1::JWT_ALGORITHM_RS256);
  jwt_auth->set_clock_skew_seconds(5U);
  jwt_auth->set_max_token_lifetime_seconds(300U);
  jwt_auth->add_required_scopes("payments:read");
  auto* jwt_claim = jwt_auth->add_required_claims();
  jwt_claim->set_name("tenant");
  jwt_claim->set_exact("tenant-a");
  jwt_auth->mutable_verification_rate_limit()->set_capacity(4096U);
  jwt_auth->mutable_verification_rate_limit()
      ->set_refill_tokens_per_second(2048U);

  auto* redirect_route = host->add_routes();
  redirect_route->set_name("legacy-redirect");
  redirect_route->mutable_match()->set_path_exact("/legacy");
  auto* redirect = redirect_route->mutable_redirect();
  redirect->set_status_code(308U);
  redirect->set_scheme("https");
  redirect->set_host("[2001:db8::10]");
  redirect->set_port(9443U);
  redirect->set_path("/v2/orders");
  redirect->set_query("source=legacy");

  auto* cors_route = host->add_routes();
  cors_route->set_name("cors-protected");
  cors_route->mutable_match()->set_path_exact("/cors");
  cors_route->mutable_match()->add_methods("POST");
  cors_route->mutable_fixed_response()->set_status_code(208U);
  auto* cors = cors_route->mutable_cors();
  cors->add_allowed_origins("https://app.example.com");
  cors->add_allowed_methods("POST");
  cors->add_allowed_headers("authorization");
  cors->add_exposed_headers("x-request-id");
  cors->set_allow_credentials(true);
  cors->set_max_age_seconds(600U);
  auto* request_content = cors_route->mutable_request_content();
  request_content->set_max_body_bytes(4096U);
  request_content->add_allowed_content_types("application/problem+json");
  request_content->add_allowed_content_types("application/json");

  auto* exact_host = snapshot.add_virtual_hosts();
  exact_host->set_name("api-host");
  exact_host->add_domains("api.example.com");
  auto* exact_host_route = exact_host->add_routes();
  exact_host_route->set_name("api-host-route");
  exact_host_route->mutable_match()->set_path_prefix("/");
  exact_host_route->mutable_fixed_response()->set_status_code(201U);

  auto* wildcard_host = snapshot.add_virtual_hosts();
  wildcard_host->set_name("wildcard-host");
  wildcard_host->add_domains("*.example.net");
  auto* wildcard_host_route = wildcard_host->add_routes();
  wildcard_host_route->set_name("wildcard-host-route");
  wildcard_host_route->mutable_match()->set_path_prefix("/");
  wildcard_host_route->mutable_fixed_response()->set_status_code(202U);

  auto* listener = snapshot.add_listeners();
  listener->set_name("http");
  listener->set_address("0.0.0.0");
  listener->set_port(8080U);
  listener->set_protocol(bonvoyage::v1::PROTOCOL_HTTP1);
  listener->add_virtual_host_names("default");
  listener->add_virtual_host_names("api-host");
  listener->add_virtual_host_names("wildcard-host");
  listener->mutable_trusted_proxy()->add_trusted_cidrs("10.0.0.0/8");
  return snapshot;
}

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

using TestHeaders =
    std::vector<std::pair<std::string_view, std::string_view>>;

bonvoyage::runtime::RequestHeaderLookupResult lookup_test_header(
    const void* context, std::string_view lowercase_name) noexcept {
  const auto& headers = *static_cast<const TestHeaders*>(context);
  bonvoyage::runtime::RequestHeaderLookupResult result;
  for (const auto& [name, value] : headers) {
    if (name != lowercase_name) {
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

bonvoyage::runtime::RequestView request_view(
    std::string_view host, std::string_view path, std::string_view method,
    std::string_view query = {}, const TestHeaders* headers = nullptr) {
  return bonvoyage::runtime::RequestView{
      host, path, method, query, headers,
      headers == nullptr ? nullptr : lookup_test_header};
}

template <typename Mutation>
void require_invalid(Mutation mutation, const char* message) {
  auto snapshot = valid_snapshot();
  mutation(snapshot);
  try {
    (void)bonvoyage::runtime::RuntimeSnapshot::compile(snapshot);
  } catch (const std::invalid_argument&) {
    return;
  }
  std::cerr << message << '\n';
  std::exit(1);
}

}  // namespace

int main() {
  auto snapshot = valid_snapshot();
  std::string wire;
  require(snapshot.SerializeToString(&wire), "snapshot serialization failed");
  const auto runtime = bonvoyage::runtime::RuntimeSnapshot::decode(wire);
  require(runtime.limits().max_downstream_connections_per_shard == 16384U,
          "default downstream connection limit is incorrect");
  require(runtime.limits().max_upstream_chunk_metadata_bytes == 32768U,
          "default upstream chunk metadata limit is incorrect");
  require(runtime.limits().max_upstream_response_header_bytes == 32768U,
          "default upstream response header limit is incorrect");
  require(runtime.clusters().front().load_balancing_policy ==
              bonvoyage::runtime::RuntimeLoadBalancingPolicy::round_robin,
          "round-robin policy was not compiled");
  require(runtime.clusters().front().max_concurrent_requests_per_endpoint ==
              260U,
          "default endpoint concurrency limit is incorrect");
  require(!runtime.clusters().front().passive_health.has_value(),
          "passive health unexpectedly enabled");
  require(!runtime.clusters().front().active_health.has_value(),
          "active health unexpectedly enabled");
  require(!runtime.clusters().front().dns_refresh.has_value(),
          "DNS refresh unexpectedly enabled");
  require(!runtime.clusters().front().retry.has_value(),
          "retry unexpectedly enabled");
  require(runtime.route_admission_policies().size() == 12U,
          "route admission policy index is incomplete");
  require(runtime.route_api_key_policies().size() == 12U &&
              runtime.route_api_key_policies().front().has_value() &&
              runtime.route_api_key_policies().front()->header_name ==
                  "x-api-key" &&
              runtime.route_api_key_policies().front()->credentials_secret ==
                  "runtime-api-keys.txt",
          "API-key policy index is incomplete");
  require(runtime.route_jwt_policies().size() == 12U &&
              runtime.route_jwt_policies()[7U].has_value() &&
              runtime.route_jwt_policies()[7U]->jwks_secret ==
                  "runtime-jwks.json" &&
              runtime.route_jwt_policies()[7U]->algorithms.size() == 1U &&
              runtime.route_jwt_policies()[7U]->algorithms.front() ==
                  bonvoyage::runtime::JwtAlgorithm::rs256 &&
              runtime.route_jwt_policies()[7U]
                      ->verification_rate_limit.capacity == 4096U &&
              runtime.route_jwt_policies()[7U]
                      ->verification_rate_limit
                      .refill_tokens_per_second == 2048U,
          "JWT policy index is incomplete");
  require(runtime.listeners().front().trusted_proxy.has_value() &&
              runtime.listeners().front().trusted_proxy->trusts("10.2.3.4") &&
              !runtime.listeners().front().trusted_proxy->trusts(
                  "198.51.100.1"),
          "trusted proxy policy was not prepared");
  const auto& fallback_admission = runtime.route_admission_policies().front();
  require(fallback_admission.max_concurrent_requests_per_shard == 3U &&
              fallback_admission.local_rate_limit.has_value() &&
              fallback_admission.local_rate_limit->capacity == 8U &&
              fallback_admission.local_rate_limit
                      ->refill_tokens_per_second == 2U,
          "route admission policy was not prepared");

  for (const auto policy : {
           bonvoyage::v1::LOAD_BALANCING_POLICY_LEAST_REQUEST,
           bonvoyage::v1::LOAD_BALANCING_POLICY_RANDOM}) {
    auto policy_snapshot = valid_snapshot();
    policy_snapshot.mutable_clusters(0)->set_load_balancing_policy(policy);
    const auto policy_runtime =
        bonvoyage::runtime::RuntimeSnapshot::compile(policy_snapshot);
    const auto expected =
        policy == bonvoyage::v1::LOAD_BALANCING_POLICY_LEAST_REQUEST
            ? bonvoyage::runtime::RuntimeLoadBalancingPolicy::least_request
            : bonvoyage::runtime::RuntimeLoadBalancingPolicy::random;
    require(policy_runtime.clusters().front().load_balancing_policy == expected,
            "load-balancing policy was not compiled");
  }

  auto health_snapshot = valid_snapshot();
  auto* health =
      health_snapshot.mutable_clusters(0)->mutable_passive_health();
  health->set_consecutive_failures(3U);
  health->set_ejection_time_ms(2500U);
  health->set_max_ejection_percent(75U);
  health->set_consecutive_successes(2U);
  const auto health_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(health_snapshot);
  require(health_runtime.clusters().front().passive_health.has_value(),
          "passive health policy was not compiled");
  require(health_runtime.clusters().front()
              .passive_health->consecutive_failures == 3U &&
              health_runtime.clusters().front()
                      .passive_health->ejection_time_ms == 2500U &&
              health_runtime.clusters().front()
                      .passive_health->max_ejection_percent == 75U &&
              health_runtime.clusters().front()
                      .passive_health->consecutive_successes == 2U,
          "passive health policy values are incorrect");

  auto maintenance_snapshot = valid_snapshot();
  maintenance_snapshot.mutable_clusters(0)->mutable_endpoints(0)->set_address(
      "upstream.example.test");
  auto* active =
      maintenance_snapshot.mutable_clusters(0)->mutable_active_health();
  active->set_path("/ready?source=bonvoyage");
  active->set_interval_ms(2500U);
  active->set_timeout_ms(750U);
  active->set_healthy_threshold(3U);
  active->set_unhealthy_threshold(4U);
  active->set_expected_status_min(204U);
  active->set_expected_status_max(299U);
  active->set_host("HEALTH.UPSTREAM.TEST");
  auto* dns = maintenance_snapshot.mutable_clusters(0)->mutable_dns_refresh();
  dns->set_refresh_interval_ms(15000U);
  dns->set_resolve_timeout_ms(800U);
  const auto maintenance_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(maintenance_snapshot);
  const auto& maintenance_cluster = maintenance_runtime.clusters().front();
  require(maintenance_cluster.active_health.has_value(),
          "active health policy was not compiled");
  require(maintenance_cluster.active_health->path ==
                  "/ready?source=bonvoyage" &&
              maintenance_cluster.active_health->interval_ms == 2500U &&
              maintenance_cluster.active_health->timeout_ms == 750U &&
              maintenance_cluster.active_health->healthy_threshold == 3U &&
              maintenance_cluster.active_health->unhealthy_threshold == 4U &&
              maintenance_cluster.active_health->expected_status_min == 204U &&
              maintenance_cluster.active_health->expected_status_max == 299U &&
              maintenance_cluster.active_health->host ==
                  std::optional<std::string>("health.upstream.test"),
          "active health policy values are incorrect");
  require(maintenance_cluster.dns_refresh.has_value() &&
              maintenance_cluster.dns_refresh->refresh_interval_ms == 15000U &&
              maintenance_cluster.dns_refresh->resolve_timeout_ms == 800U,
          "DNS refresh policy values are incorrect");

  auto retry_snapshot = valid_snapshot();
  auto* retry = retry_snapshot.mutable_clusters(0)->mutable_retry();
  retry->set_max_attempts(3U);
  retry->set_per_try_timeout_ms(250U);
  retry->add_retryable_methods("PUT");
  retry->add_retryable_methods("GET");
  auto* budget = retry->mutable_budget();
  budget->set_capacity(20U);
  budget->set_refill_tokens_per_second(4U);
  budget->set_max_concurrent_retries_per_shard(7U);
  const auto retry_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(retry_snapshot);
  const auto& runtime_retry = *retry_runtime.clusters().front().retry;
  require(runtime_retry.max_attempts == 3U &&
              runtime_retry.per_try_timeout_ms == 250U &&
              runtime_retry.retryable_methods ==
                  std::vector<std::string>({"GET", "PUT"}),
          "retry policy values were not prepared");
  require(runtime_retry.budget.capacity == 20U &&
              runtime_retry.budget.refill_tokens_per_second == 4U &&
              runtime_retry.budget.max_concurrent_retries_per_shard == 7U,
          "retry budget values were not prepared");

  auto custom_limits_snapshot = valid_snapshot();
  custom_limits_snapshot.mutable_runtime_limits()
      ->set_max_upstream_response_header_bytes(49152U);
  custom_limits_snapshot.mutable_runtime_limits()
      ->set_max_upstream_chunk_metadata_bytes(65536U);
  const auto custom_limits_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(custom_limits_snapshot);
  require(custom_limits_runtime.limits().max_upstream_chunk_metadata_bytes ==
              65536U,
          "configured upstream chunk metadata limit was not prepared");
  require(custom_limits_runtime.limits().max_upstream_response_header_bytes ==
              49152U,
          "configured upstream response header limit was not prepared");

  auto match =
      runtime.match(0U, request_view("example.test", "/v1/ready", "GET"));
  require(match.route != nullptr && match.route->name == "ready",
          "exact route did not win");
  require(match.route->fixed_response.has_value(),
          "fixed response action was not prepared");

  match =
      runtime.match(0U, request_view("example.test", "/v1/users", "GET"));
  require(match.route != nullptr && match.route->name == "version",
          "longest prefix route did not win");
  require(match.cluster != nullptr && match.cluster->name == "api",
          "cluster reference was not prepared");
  require(match.route->header_transformations.has_value() &&
              match.route->header_transformations->request.size() == 2U &&
              match.route->header_transformations->request.front().name ==
                  "x-remove-me" &&
              match.route->header_transformations->response.size() == 1U &&
              match.route->header_transformations->response.front().operation ==
                  bonvoyage::runtime::HeaderMutationOperation::append,
          "header transformations were not prepared deterministically");
  require(match.route->rewrite.has_value() &&
              match.route->rewrite->authority ==
                  std::optional<std::string>{"orders.internal.test:9443"} &&
              match.route->rewrite->path.has_value() &&
              match.route->rewrite->path->operation ==
                  bonvoyage::runtime::PathRewriteOperation::replace_prefix &&
              match.route->rewrite->path->value == "/v2",
          "route rewrite was not prepared deterministically");
  require(match.cluster->endpoints.size() == 1U &&
              match.cluster->endpoints.front().weight == 2U &&
              !match.cluster->endpoints.front().dns_hostname,
          "endpoint weight was not prepared");

  match = runtime.match(0U, request_view("example.test", "/other", "GET"));
  require(match.route != nullptr && match.route->name == "fallback",
          "fallback route did not match");
  require(match.route->runtime_index == 0U &&
              match.route->admission.max_concurrent_requests_per_shard == 3U,
          "matched route did not retain its admission-state index");
  require(match.route->source_ip_policy.has_value() &&
              match.route->source_ip_policy->allows("198.51.100.127") &&
              !match.route->source_ip_policy->allows("198.51.100.128"),
          "source IP policy was not prepared with deny precedence");

  auto websocket_snapshot = valid_snapshot();
  websocket_snapshot.mutable_virtual_hosts(0)
      ->mutable_routes(0)
      ->mutable_websocket()
      ->set_idle_timeout_ms(45000U);
  const auto websocket_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(websocket_snapshot);
  const auto websocket_match = websocket_runtime.match(
      0U, request_view("example.test", "/socket", "GET"));
  require(websocket_match.route != nullptr &&
              websocket_match.route->websocket.has_value() &&
              websocket_match.route->websocket->idle_timeout_ms == 45000U &&
              websocket_match.route->admission
                      .max_concurrent_requests_per_shard == 3U,
          "bounded WebSocket route policy was not prepared");

  auto weighted_snapshot = valid_snapshot();
  auto* canary_cluster = weighted_snapshot.add_clusters();
  canary_cluster->set_name("canary");
  canary_cluster->set_load_balancing_policy(
      bonvoyage::v1::LOAD_BALANCING_POLICY_ROUND_ROBIN);
  canary_cluster->set_max_connections_per_shard(4U);
  auto* canary_endpoint = canary_cluster->add_endpoints();
  canary_endpoint->set_name("canary-1");
  canary_endpoint->set_address("127.0.0.1");
  canary_endpoint->set_port(8082U);
  canary_endpoint->set_weight(1U);
  auto* weighted_route =
      weighted_snapshot.mutable_virtual_hosts(0)->add_routes();
  weighted_route->set_name("canary-split");
  weighted_route->mutable_match()->set_path_exact("/canary");
  auto* stable_target = weighted_route->add_weighted_clusters();
  stable_target->set_cluster_name("api");
  stable_target->set_weight(9U);
  auto* canary_target = weighted_route->add_weighted_clusters();
  canary_target->set_cluster_name("canary");
  canary_target->set_weight(1U);
  const auto weighted_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(weighted_snapshot);
  const auto weighted_match = weighted_runtime.match(
      0U, request_view("example.test", "/canary", "GET"));
  require(weighted_match.route != nullptr &&
              weighted_match.route->name == "canary-split" &&
              weighted_match.cluster == nullptr,
          "weighted route did not retain deferred cluster selection");
  const auto& weighted_targets =
      weighted_runtime.route_weighted_clusters()
          [weighted_match.route->runtime_index];
  require(weighted_targets.size() == 2U &&
              weighted_targets[0].cluster_index == 0U &&
              weighted_targets[0].weight == 9U &&
              weighted_targets[1].cluster_index == 1U &&
              weighted_targets[1].weight == 1U,
          "weighted route targets were not prepared deterministically");

  match = runtime.match(0U,
                        request_view("example.test", "/cors", "POST"));
  require(match.route != nullptr && match.route->cors.has_value() &&
              match.route->cors->allows_origin(
                  "https://app.example.com") &&
              match.route->cors->allows_method("POST"),
          "CORS policy was not prepared on the application route");
  require(match.route->request_content.has_value() &&
              match.route->request_content->maximum_body_bytes() ==
                  std::optional<std::uint64_t>{4096U} &&
              match.route->request_content->allowed_content_types() ==
                  std::vector<std::string>({"application/json",
                                            "application/problem+json"}),
          "request-content policy was not prepared on the application route");

  match = runtime.match(0U,
                        request_view("example.test", "/legacy", "POST"));
  require(match.route != nullptr && match.route->redirect.has_value() &&
              match.route->redirect->status_code == 308U &&
              match.route->redirect->location ==
                  "https://[2001:db8::10]:9443/v2/orders?source=legacy" &&
              !match.route->cluster_index.has_value() &&
              !match.route->fixed_response.has_value(),
          "redirect action was not prepared as one immutable Location");

  auto relative_redirect_snapshot = valid_snapshot();
  auto* relative_redirect = relative_redirect_snapshot.mutable_virtual_hosts(0)
                                ->mutable_routes(8)
                                ->mutable_redirect();
  relative_redirect->set_status_code(307U);
  relative_redirect->clear_scheme();
  relative_redirect->clear_host();
  relative_redirect->clear_port();
  relative_redirect->set_path("/relative/%7Eowner");
  relative_redirect->set_query("source=legacy&ok=true");
  const auto relative_redirect_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(relative_redirect_snapshot);
  const auto relative_match = relative_redirect_runtime.match(
      0U, request_view("example.test", "/legacy", "GET"));
  require(relative_match.route != nullptr &&
              relative_match.route->redirect.has_value() &&
              relative_match.route->redirect->status_code == 307U &&
              relative_match.route->redirect->location ==
                  "/relative/%7Eowner?source=legacy&ok=true",
          "relative redirect Location was not prepared");
  match = runtime.match(0U,
                        request_view("example.test", "/cors", "OPTIONS"));
  require(match.route != nullptr && match.route->name == "fallback",
          "ordinary OPTIONS unexpectedly bypassed normal route matching");
  match = runtime.match_cors_preflight(
      0U, request_view("example.test", "/cors", "POST"));
  require(match.route != nullptr && match.route->name == "cors-protected",
          "preflight did not resolve by its requested application method");
  match = runtime.match_cors_preflight(
      0U, request_view("example.test", "/cors", "GET"));
  require(match.route == nullptr,
          "preflight resolved a route that does not accept its method");

  match = runtime.match(
      0U, request_view("api.example.com:8080", "/", "GET"));
  require(match.route != nullptr && match.route->name == "api-host-route",
          "exact virtual host did not match");
  match =
      runtime.match(0U, request_view("edge.example.net", "/", "GET"));
  require(match.route != nullptr && match.route->name == "wildcard-host-route",
          "wildcard virtual host did not match");

  const TestHeaders selected_headers{{"x-release", "beta"}};
  match = runtime.match(
      0U, request_view("example.test", "/select", "GET", "tenant=ac%6de",
                       &selected_headers));
  require(match.route != nullptr && match.route->name == "selected",
          "method, header, and decoded query predicates did not match");
  match = runtime.match(
      0U, request_view("example.test", "/select", "POST", "tenant=acme",
                       &selected_headers));
  require(match.route != nullptr && match.route->name == "select-fallback",
          "same-path predicate fallback did not match");
  const TestHeaders repeated_headers{{"x-release", "beta"},
                                     {"x-release", "beta"}};
  match = runtime.match(
      0U, request_view("example.test", "/select", "GET", "tenant=acme",
                       &repeated_headers));
  require(match.route != nullptr && match.route->name == "select-fallback",
          "repeated exact-match header was not rejected conservatively");
  match = runtime.match(
      0U, request_view("example.test", "/select", "GET",
                       "tenant=wrong&tenant=acme", &selected_headers));
  require(match.route != nullptr && match.route->name == "selected",
          "a matching repeated query value was not selected");
  match = runtime.match(
      0U, request_view("example.test", "/select", "GET", "tenant=ac%",
                       &selected_headers));
  require(match.route != nullptr && match.route->name == "select-fallback",
          "malformed query escaping reached the exact predicate route");
  const TestHeaders no_headers;
  match = runtime.match(
      0U, request_view("example.test", "/absence", "GET", "other=1",
                       &no_headers));
  require(match.route != nullptr && match.route->name == "absence",
          "negative presence predicates did not match");
  const TestHeaders blocked_headers{{"x-blocked", "1"}};
  match = runtime.match(
      0U, request_view("example.test", "/absence", "GET", "other=1",
                       &blocked_headers));
  require(match.route != nullptr && match.route->name == "fallback",
          "negative header presence accepted a present field");
  match = runtime.match(
      0U, request_view("example.test", "/absence", "GET", "blocked=",
                       &no_headers));
  require(match.route != nullptr && match.route->name == "fallback",
          "negative query presence accepted a present parameter");
  match = runtime.match(
      0U, request_view("example.test", "/items/42", "GET"));
  require(match.route != nullptr && match.route->name == "numeric-item",
          "safe regular-expression route did not match before root fallback");
  match = runtime.match(
      0U, request_view("example.test", "/items/not-a-number", "GET"));
  require(match.route != nullptr && match.route->name == "fallback",
          "safe regular-expression route matched invalid input");

  auto tls_snapshot = valid_snapshot();
  auto* downstream_tls =
      tls_snapshot.mutable_listeners(0)->mutable_downstream_tls();
  downstream_tls->set_certificate_chain_secret("server-chain.pem");
  downstream_tls->set_private_key_secret("server-key.pem");
  const auto tls_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(tls_snapshot);
  require(tls_runtime.listeners().front().downstream_tls.has_value(),
          "downstream TLS was not prepared");
  require(tls_runtime.listener_accepts_server_name(0U, "api.example.com"),
          "exact SNI name was rejected");
  require(tls_runtime.listener_accepts_server_name(0U, "edge.example.net"),
          "wildcard SNI name was rejected");
  require(!tls_runtime.listener_accepts_server_name(0U, "bad/name"),
          "invalid SNI name was accepted");
  require(bonvoyage::runtime::RuntimeSnapshot::authority_matches_server_name(
              "API.EXAMPLE.COM:8443", "api.example.com"),
          "equivalent SNI and Host values did not match");
  require(!bonvoyage::runtime::RuntimeSnapshot::authority_matches_server_name(
              "other.example.com", "api.example.com"),
          "different SNI and Host values matched");

  tls_snapshot.mutable_listeners(0)->set_protocol(
      bonvoyage::v1::PROTOCOL_HTTP2);
  const auto http2_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(tls_snapshot);
  require(http2_runtime.listeners().front().protocol ==
              bonvoyage::runtime::RuntimeProtocol::http2,
          "TLS HTTP/2 listener protocol was not prepared");

  auto upstream_tls_snapshot = valid_snapshot();
  auto* upstream_tls =
      upstream_tls_snapshot.mutable_clusters(0)->mutable_upstream_tls();
  upstream_tls->set_server_name("API.UPSTREAM.EXAMPLE");
  upstream_tls->set_trust_bundle_secret("upstream-ca.pem");
  upstream_tls->set_certificate_chain_secret("gateway-client.pem");
  upstream_tls->set_private_key_secret("gateway-client-key.pem");
  const auto upstream_tls_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(upstream_tls_snapshot);
  require(upstream_tls_runtime.clusters().front().upstream_tls.has_value(),
          "upstream TLS was not prepared");
  require(upstream_tls_runtime.clusters().front().upstream_tls->server_name ==
              "api.upstream.example",
          "upstream TLS server name was not normalized");
  require(upstream_tls_runtime.clusters()
              .front()
              .upstream_tls->certificate_chain_secret.has_value(),
          "upstream mTLS certificate was not prepared");
  require(upstream_tls_runtime.clusters().front().protocol ==
              bonvoyage::runtime::RuntimeUpstreamProtocol::http1,
          "unspecified upstream protocol did not preserve HTTP/1");
  require(upstream_tls_runtime.clusters()
              .front()
              .max_http2_streams_per_connection == 100U,
          "default upstream HTTP/2 stream limit was not prepared");

  upstream_tls_snapshot.mutable_clusters(0)->set_protocol(
      bonvoyage::v1::PROTOCOL_HTTP2);
  const auto default_upstream_http2_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(upstream_tls_snapshot);
  require(default_upstream_http2_runtime.clusters()
              .front()
              .max_http2_streams_per_connection == 100U,
          "omitted upstream HTTP/2 stream limit did not use the default");
  upstream_tls_snapshot.mutable_clusters(0)
      ->set_max_http2_streams_per_connection(321U);
  const auto upstream_http2_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(upstream_tls_snapshot);
  require(upstream_http2_runtime.clusters().front().protocol ==
              bonvoyage::runtime::RuntimeUpstreamProtocol::http2,
          "TLS upstream HTTP/2 protocol was not prepared");
  require(upstream_http2_runtime.clusters()
              .front()
              .max_http2_streams_per_connection == 321U,
          "upstream HTTP/2 stream limit was not prepared");

  auto mixed_protocol_snapshot = valid_snapshot();
  auto* staged_http2_cluster = mixed_protocol_snapshot.add_clusters();
  staged_http2_cluster->set_name("staged-h2");
  staged_http2_cluster->set_protocol(bonvoyage::v1::PROTOCOL_HTTP2);
  staged_http2_cluster->set_load_balancing_policy(
      bonvoyage::v1::LOAD_BALANCING_POLICY_ROUND_ROBIN);
  staged_http2_cluster->set_max_connections_per_shard(1U);
  auto* staged_http2_tls = staged_http2_cluster->mutable_upstream_tls();
  staged_http2_tls->set_server_name("staged.example.test");
  staged_http2_tls->set_trust_bundle_secret("staged-ca.pem");
  auto* staged_http2_endpoint = staged_http2_cluster->add_endpoints();
  staged_http2_endpoint->set_name("staged-h2-1");
  staged_http2_endpoint->set_address("127.0.0.1");
  staged_http2_endpoint->set_port(8443U);
  staged_http2_endpoint->set_weight(1U);
  const auto mixed_protocol_runtime =
      bonvoyage::runtime::RuntimeSnapshot::compile(mixed_protocol_snapshot);
  mixed_protocol_runtime.validate_live_gateway_capabilities();
  upstream_tls_runtime.validate_live_gateway_capabilities();

  require_invalid(
      [](auto& value) { value.set_schema_version(2U); },
      "unsupported schema version was accepted");
  require_invalid(
      [](auto& value) { value.set_minimum_dataplane_version("99.0.0"); },
      "incompatible minimum dataplane version was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)->mutable_routes(0)->set_cluster_name(
            "missing");
      },
      "unknown cluster reference was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)->mutable_routes(0)->mutable_match()->
            set_safe_regex("(");
      },
      "invalid safe regex was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)->mutable_routes(0)->mutable_match()->
            set_safe_regex(std::string(1025U, 'a'));
      },
      "oversized safe regex was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)->mutable_routes(0)->
            mutable_fixed_response()->set_status_code(200U);
      },
      "route with two actions was accepted");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(0);
        route->clear_cluster_name();
        auto* target = route->add_weighted_clusters();
        target->set_cluster_name("api");
        target->set_weight(1U);
      },
      "weighted route with one target was accepted");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(0);
        route->clear_cluster_name();
        for (std::size_t index = 0U; index < 2U; ++index) {
          auto* target = route->add_weighted_clusters();
          target->set_cluster_name("api");
          target->set_weight(1U);
        }
      },
      "weighted route with duplicate targets was accepted");
  require_invalid(
      [](auto& value) {
        auto* second = value.add_clusters();
        second->CopyFrom(value.clusters(0));
        second->set_name("canary");
        second->mutable_endpoints(0)->set_name("canary-1");
        second->mutable_endpoints(0)->set_port(8082U);
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(0);
        route->clear_cluster_name();
        auto* stable = route->add_weighted_clusters();
        stable->set_cluster_name("api");
        stable->set_weight(4096U);
        auto* canary = route->add_weighted_clusters();
        canary->set_cluster_name("canary");
        canary->set_weight(1U);
      },
      "weighted route total above 4096 was accepted");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(0);
        auto* first = route->add_weighted_clusters();
        first->set_cluster_name("api");
        first->set_weight(1U);
        auto* second = route->add_weighted_clusters();
        second->set_cluster_name("api");
        second->set_weight(1U);
      },
      "route with single and weighted cluster actions was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)->mutable_routes(0)->
            mutable_redirect()->set_status_code(308U);
      },
      "route with a cluster and redirect action was accepted");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(0);
        route->clear_cluster_name();
      },
      "route without an action was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(8)
            ->mutable_redirect()
            ->set_status_code(300U);
      },
      "unsupported redirect status was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(8)
            ->mutable_redirect()
            ->set_scheme("HTTPS");
      },
      "non-canonical redirect scheme was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(8)
            ->mutable_redirect()
            ->clear_host();
      },
      "redirect scheme without a host was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(8)
            ->mutable_redirect()
            ->set_host("API.example.test");
      },
      "uppercase redirect host was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(8)
            ->mutable_redirect()
            ->set_host("2001:db8::10");
      },
      "unbracketed redirect IPv6 literal was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(8)
            ->mutable_redirect()
            ->set_port(65536U);
      },
      "redirect port overflow was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(8)
            ->mutable_redirect()
            ->set_path("//evil.example");
      },
      "network-path redirect was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(8)
            ->mutable_redirect()
            ->set_path("/bad%GG");
      },
      "invalid redirect path escape was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(8)
            ->mutable_redirect()
            ->set_query("?source=legacy");
      },
      "redirect query marker was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        auto* redirect = value.mutable_virtual_hosts(0)
                             ->mutable_routes(8)
                             ->mutable_redirect();
        redirect->set_path("/" + std::string(4095U, 'a'));
        redirect->set_query(std::string(4096U, 'b'));
      },
      "oversized prepared redirect Location was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)->mutable_routes(0)->mutable_rewrite();
      },
      "empty route rewrite was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(2)
            ->mutable_rewrite()
            ->set_host("fixed.internal.test");
      },
      "route rewrite on a fixed response was accepted");
  require_invalid(
      [](auto& value) {
        auto* rewrite = value.mutable_virtual_hosts(0)
                            ->mutable_routes(0)
                            ->mutable_rewrite();
        rewrite->set_port(8443U);
      },
      "route rewrite port without a host was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(1)
            ->mutable_rewrite()
            ->set_host("Orders.internal.test");
      },
      "uppercase route rewrite host was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(1)
            ->mutable_rewrite()
            ->set_host("2001:db8::10");
      },
      "unbracketed route rewrite IPv6 literal was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(1)
            ->mutable_rewrite()
            ->set_port(65536U);
      },
      "route rewrite port overflow was accepted");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(1);
        route->mutable_match()->set_path_exact("/v1");
      },
      "prefix rewrite on an exact route was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(1)
            ->mutable_rewrite()
            ->set_path_prefix("/v2/");
      },
      "ambiguous route rewrite slash boundary was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(1)
            ->mutable_rewrite()
            ->set_path("/bad?query");
      },
      "route rewrite path containing a query was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_runtime_limits()->set_max_request_header_bytes(1024U);
        value.mutable_virtual_hosts(0)
            ->mutable_routes(1)
            ->mutable_rewrite()
            ->set_path("/" + std::string(1024U, 'a'));
      },
      "route rewrite exceeding the runtime request-head limit was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_header_transformations();
      },
      "empty header transformations were accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        auto* mutation = value.mutable_virtual_hosts(0)
                             ->mutable_routes(2)
                             ->mutable_header_transformations()
                             ->add_response();
        mutation->set_operation(
            bonvoyage::v1::HEADER_MUTATION_OPERATION_REMOVE);
        mutation->set_name("server");
      },
      "header transformations on a fixed response were accepted");
  require_invalid(
      [](auto& value) {
        auto* mutation = value.mutable_virtual_hosts(0)
                             ->mutable_routes(0)
                             ->mutable_header_transformations()
                             ->add_request();
        mutation->set_operation(
            bonvoyage::v1::HEADER_MUTATION_OPERATION_SET);
        mutation->set_name("X-Route-Tier");
        mutation->set_value("gold");
      },
      "non-canonical mutation field name was accepted");
  require_invalid(
      [](auto& value) {
        auto* mutation = value.mutable_virtual_hosts(0)
                             ->mutable_routes(0)
                             ->mutable_header_transformations()
                             ->add_request();
        mutation->set_operation(
            bonvoyage::v1::HEADER_MUTATION_OPERATION_SET);
        mutation->set_name("content-length");
        mutation->set_value("1");
      },
      "framing-owned mutation field was accepted");
  require_invalid(
      [](auto& value) {
        auto* mutation = value.mutable_virtual_hosts(0)
                             ->mutable_routes(0)
                             ->mutable_header_transformations()
                             ->add_request();
        mutation->set_operation(
            bonvoyage::v1::HEADER_MUTATION_OPERATION_REMOVE);
        mutation->set_name("traceparent");
      },
      "trace propagation mutation field was accepted");
  require_invalid(
      [](auto& value) {
        auto* mutation = value.mutable_virtual_hosts(0)
                             ->mutable_routes(0)
                             ->mutable_header_transformations()
                             ->add_request();
        mutation->set_operation(
            bonvoyage::v1::HEADER_MUTATION_OPERATION_SET);
        mutation->set_name("sec-websocket-key");
        mutation->set_value("dGhlIHNhbXBsZSBub25jZQ==");
      },
      "WebSocket handshake mutation field was accepted");
  require_invalid(
      [](auto& value) {
        auto* mutation = value.mutable_virtual_hosts(0)
                             ->mutable_routes(0)
                             ->mutable_header_transformations()
                             ->add_response();
        mutation->set_operation(
            bonvoyage::v1::HEADER_MUTATION_OPERATION_SET);
        mutation->set_name("access-control-allow-origin");
        mutation->set_value("*");
      },
      "CORS-owned mutation field was accepted");
  require_invalid(
      [](auto& value) {
        auto* mutation = value.mutable_virtual_hosts(0)
                             ->mutable_routes(0)
                             ->mutable_header_transformations()
                             ->add_request();
        mutation->set_operation(
            bonvoyage::v1::HEADER_MUTATION_OPERATION_SET);
        mutation->set_name("x-api-key");
        mutation->set_value("embedded-secret");
      },
      "configured API-key field injection was accepted");
  require_invalid(
      [](auto& value) {
        auto* mutation = value.mutable_virtual_hosts(0)
                             ->mutable_routes(0)
                             ->mutable_header_transformations()
                             ->add_response();
        mutation->set_operation(
            bonvoyage::v1::HEADER_MUTATION_OPERATION_APPEND);
        mutation->set_name("set-cookie");
        mutation->set_value("session=secret");
      },
      "credential-bearing response append was accepted");
  require_invalid(
      [](auto& value) {
        auto* mutation = value.mutable_virtual_hosts(0)
                             ->mutable_routes(0)
                             ->mutable_header_transformations()
                             ->add_response();
        mutation->set_operation(
            bonvoyage::v1::HEADER_MUTATION_OPERATION_REMOVE);
        mutation->set_name("server");
        mutation->set_value("unexpected");
      },
      "remove mutation with a value was accepted");
  require_invalid(
      [](auto& value) {
        auto* mutations = value.mutable_virtual_hosts(0)
                              ->mutable_routes(0)
                              ->mutable_header_transformations();
        for (std::size_t index = 0U; index < 17U; ++index) {
          auto* mutation = mutations->add_request();
          mutation->set_operation(
              bonvoyage::v1::HEADER_MUTATION_OPERATION_REMOVE);
          mutation->set_name("x-remove-" + std::to_string(index));
        }
      },
      "more than 16 request mutations were accepted");
  require_invalid(
      [](auto& value) {
        auto* mutations = value.mutable_virtual_hosts(0)
                              ->mutable_routes(0)
                              ->mutable_header_transformations();
        for (std::size_t index = 0U; index < 5U; ++index) {
          auto* mutation = mutations->add_response();
          mutation->set_operation(
              bonvoyage::v1::HEADER_MUTATION_OPERATION_SET);
          mutation->set_name("x-large-" + std::to_string(index));
          mutation->set_value(std::string(4096U, 'a'));
        }
      },
      "header transformation configured-byte budget was not enforced");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->set_max_connections_per_shard(1U);
        auto* endpoint = value.mutable_clusters(0)->add_endpoints();
        endpoint->set_name("api-2");
        endpoint->set_address("127.0.0.2");
        endpoint->set_port(8082U);
      },
      "cluster capacity smaller than endpoint count was accepted");
  require_invalid(
      [](auto& value) {
        auto* cluster = value.mutable_clusters(0);
        cluster->set_max_connections_per_shard(4097U);
        for (std::size_t endpoint_number = 1U; endpoint_number < 4097U;
             ++endpoint_number) {
          auto* endpoint = cluster->add_endpoints();
          endpoint->set_name("endpoint-" + std::to_string(endpoint_number));
          endpoint->set_address("127.0.0.1");
          endpoint->set_port(8081U);
          endpoint->set_weight(1U);
        }
      },
      "unbounded endpoint count was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->set_max_connections_per_shard(1000001U);
      },
      "unbounded cluster connection capacity was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->set_protocol(
            bonvoyage::v1::PROTOCOL_HTTP2);
      },
      "upstream HTTP/2 without TLS was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->set_protocol(
            bonvoyage::v1::PROTOCOL_HTTP3);
      },
      "unsupported upstream protocol was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)
            ->set_max_http2_streams_per_connection(100U);
      },
      "HTTP/2 stream limit on HTTP/1 cluster was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)
            ->set_max_http2_streams_per_connection(1001U);
      },
      "unbounded upstream HTTP/2 stream limit was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->set_max_concurrent_requests_per_endpoint(
            261U);
      },
      "endpoint concurrency above cluster admission was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)
            ->mutable_passive_health()
            ->set_consecutive_successes(101U);
      },
      "passive recovery threshold above the bound was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_runtime_limits()
            ->set_max_upstream_response_header_bytes(1023U);
      },
      "undersized upstream response header limit was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_runtime_limits()
            ->set_max_downstream_connections_per_shard(1000001U);
      },
      "unbounded downstream connection capacity was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_runtime_limits()
            ->set_max_upstream_chunk_metadata_bytes(1023U);
      },
      "undersized upstream chunk metadata limit was accepted");
  require_invalid(
      [](auto& value) {
        auto* duplicate = value.mutable_virtual_hosts(0)->add_routes();
        duplicate->set_name("duplicate-fallback");
        duplicate->mutable_match()->set_path_prefix("/");
        duplicate->set_cluster_name("api");
      },
      "duplicate route binding was accepted");
  require_invalid(
      [](auto& value) {
        auto* shadowed = value.mutable_virtual_hosts(0)->add_routes();
        shadowed->set_name("shadowed-fallback");
        shadowed->mutable_match()->set_path_prefix("/");
        shadowed->mutable_match()->add_methods("GET");
        shadowed->set_cluster_name("api");
      },
      "unconditional route shadow was accepted");
  require_invalid(
      [](auto& value) {
        auto* match = value.mutable_virtual_hosts(0)
                          ->mutable_routes(0)
                          ->mutable_match();
        match->add_methods("GET");
        match->add_methods("GET");
      },
      "duplicate route method was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_match()
            ->add_methods("get");
      },
      "lowercase route method was accepted");
  require_invalid(
      [](auto& value) {
        auto* header = value.mutable_virtual_hosts(0)
                           ->mutable_routes(0)
                           ->mutable_match()
                           ->add_headers();
        header->set_name("bad header");
        header->set_present(true);
      },
      "invalid route header name was accepted");
  require_invalid(
      [](auto& value) {
        auto* match = value.mutable_virtual_hosts(0)
                          ->mutable_routes(0)
                          ->mutable_match();
        auto* first = match->add_headers();
        first->set_name("X-Release");
        first->set_present(true);
        auto* second = match->add_headers();
        second->set_name("x-release");
        second->set_exact("beta");
      },
      "duplicate normalized route header was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_api_key_auth()
            ->clear_credentials_secret();
      },
      "empty API-key credential secret was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_api_key_auth()
            ->set_credentials_secret("../api-keys.txt");
      },
      "API-key credential path traversal was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_api_key_auth()
            ->set_header_name("x-forwarded-for");
      },
      "forwarding identity API-key header was accepted");
  require_invalid(
      [](auto& value) {
        auto* header = value.mutable_virtual_hosts(0)
                           ->mutable_routes(0)
                           ->mutable_match()
                           ->add_headers();
        header->set_name("x-api-key");
        header->set_present(true);
      },
      "API-key header duplicated as a route predicate was accepted");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(0);
        auto* auth = route->mutable_jwt_auth();
        auth->set_jwks_secret("runtime-jwks.json");
        auth->set_issuer("https://issuer.example.test");
        auth->set_audience("payments-api");
        auth->set_required_type("at+jwt");
        auth->add_algorithms(bonvoyage::v1::JWT_ALGORITHM_RS256);
        auth->set_max_token_lifetime_seconds(300U);
        auth->mutable_verification_rate_limit()->set_capacity(10U);
        auth->mutable_verification_rate_limit()
            ->set_refill_tokens_per_second(10U);
      },
      "combined API-key and JWT policies were accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(7)
            ->mutable_jwt_auth()
            ->set_jwks_secret("../jwks.json");
      },
      "JWT key path traversal was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(7)
            ->mutable_jwt_auth()
            ->set_issuer("http://issuer.example.test");
      },
      "non-HTTPS JWT issuer was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(7)
            ->mutable_jwt_auth()
            ->set_issuer("https://user@issuer.example.test");
      },
      "JWT issuer userinfo was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(7)
            ->mutable_jwt_auth()
            ->clear_algorithms();
      },
      "empty JWT algorithm allowlist was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(7)
            ->mutable_jwt_auth()
            ->clear_verification_rate_limit();
      },
      "missing JWT verification budget was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(7)
            ->mutable_jwt_auth()
            ->mutable_required_claims(0)
            ->set_name("sub");
      },
      "reserved JWT claim override was accepted");
  require_invalid(
      [](auto& value) {
        auto* header = value.mutable_virtual_hosts(0)
                           ->mutable_routes(7)
                           ->mutable_match()
                           ->add_headers();
        header->set_name("Authorization");
        header->set_present(true);
      },
      "JWT Authorization header duplicated as a route predicate was accepted");
  require_invalid(
      [](auto& value) {
        auto* query = value.mutable_virtual_hosts(0)
                          ->mutable_routes(0)
                          ->mutable_match()
                          ->add_query_parameters();
        query->set_name("tenant");
      },
      "query predicate without a value match was accepted");
  require_invalid(
      [](auto& value) {
        auto* match = value.mutable_virtual_hosts(0)
                          ->mutable_routes(0)
                          ->mutable_match();
        auto* first = match->add_query_parameters();
        first->set_name("tenant");
        first->set_present(true);
        auto* second = match->add_query_parameters();
        second->set_name("tenant");
        second->set_exact("acme");
      },
      "duplicate route query parameter was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_listeners(0)->set_protocol(
            bonvoyage::v1::PROTOCOL_HTTP2);
      },
      "cleartext HTTP/2 listener was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_listeners(0)
            ->mutable_trusted_proxy()
            ->set_trusted_cidrs(0, "10.0.0.1/8");
      },
      "trusted proxy CIDR with host bits was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_listeners(0)->mutable_trusted_proxy()->clear_trusted_cidrs();
      },
      "empty trusted proxy policy was accepted");
  require_invalid(
      [](auto& value) {
        auto* listener = value.add_listeners();
        listener->set_name("duplicate-http");
        listener->set_address("0.0.0.0");
        listener->set_port(8080U);
        listener->set_protocol(bonvoyage::v1::PROTOCOL_HTTP1);
        listener->add_virtual_host_names("default");
      },
      "duplicate listener binding was accepted");
  require_invalid(
      [](auto& value) {
        auto* tls = value.mutable_listeners(0)->mutable_downstream_tls();
        tls->set_certificate_chain_secret("../server.pem");
        tls->set_private_key_secret("server-key.pem");
      },
      "TLS secret path traversal was accepted");
  require_invalid(
      [](auto& value) {
        auto* tls = value.mutable_listeners(0)->mutable_downstream_tls();
        tls->set_certificate_chain_secret("server-chain.pem");
        tls->set_private_key_secret("server-key.pem");
        tls->set_require_client_certificate(true);
      },
      "mTLS without a trust bundle was accepted");
  require_invalid(
      [](auto& value) {
        auto* tls = value.mutable_listeners(0)->mutable_downstream_tls();
        tls->set_certificate_chain_secret("server-chain.pem");
        tls->set_private_key_secret("server-key.pem");
        tls->set_trust_bundle_secret("clients.pem");
      },
      "unused downstream client trust bundle was accepted");
  require_invalid(
      [](auto& value) {
        auto* tls = value.mutable_clusters(0)->mutable_upstream_tls();
        tls->set_server_name("127.0.0.1");
        tls->set_trust_bundle_secret("upstream-ca.pem");
      },
      "upstream TLS IP server name was accepted");
  require_invalid(
      [](auto& value) {
        auto* tls = value.mutable_clusters(0)->mutable_upstream_tls();
        tls->set_server_name("upstream.example.test");
      },
      "upstream TLS without a trust bundle was accepted");
  require_invalid(
      [](auto& value) {
        auto* tls = value.mutable_clusters(0)->mutable_upstream_tls();
        tls->set_server_name("upstream.example.test");
        tls->set_trust_bundle_secret("../upstream-ca.pem");
      },
      "upstream TLS trust-bundle traversal was accepted");
  require_invalid(
      [](auto& value) {
        auto* tls = value.mutable_clusters(0)->mutable_upstream_tls();
        tls->set_server_name("upstream.example.test");
        tls->set_trust_bundle_secret("upstream-ca.pem");
        tls->set_certificate_chain_secret("gateway-client.pem");
      },
      "upstream mTLS without a private key was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->mutable_active_health()->set_path(
            "/healthz#fragment");
      },
      "active health fragment was accepted");
  require_invalid(
      [](auto& value) {
        auto* health =
            value.mutable_clusters(0)->mutable_active_health();
        health->set_interval_ms(1000U);
        health->set_timeout_ms(1001U);
      },
      "active health timeout above the interval was accepted");
  require_invalid(
      [](auto& value) {
        auto* health =
            value.mutable_clusters(0)->mutable_active_health();
        health->set_expected_status_min(500U);
        health->set_expected_status_max(299U);
      },
      "reversed active health status range was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->mutable_active_health()->set_host(
            "health.example.test:8080");
      },
      "active health host with a port was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->mutable_dns_refresh();
      },
      "DNS refresh without a hostname endpoint was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->mutable_endpoints(0)->set_address(
            "upstream.example.test");
        auto* dns = value.mutable_clusters(0)->mutable_dns_refresh();
        dns->set_refresh_interval_ms(1000U);
        dns->set_resolve_timeout_ms(1001U);
      },
      "DNS timeout above the refresh interval was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->mutable_retry()->set_max_attempts(6U);
      },
      "retry attempt count above the bound was accepted");
  require_invalid(
      [](auto& value) {
        auto* retry = value.mutable_clusters(0)->mutable_retry();
        retry->set_max_attempts(2U);
        retry->add_retryable_methods("POST");
      },
      "non-idempotent retry method was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_runtime_limits()->set_request_timeout_ms(100U);
        value.mutable_clusters(0)->mutable_retry()->set_per_try_timeout_ms(
            101U);
      },
      "retry deadline above the request deadline was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)
            ->mutable_retry()
            ->mutable_budget()
            ->set_capacity(1000001U);
      },
      "retry budget above the bound was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->set_max_concurrent_requests_per_shard(2000001U);
      },
      "route concurrency above the bound was accepted");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(0);
        route->set_max_concurrent_requests_per_shard(0U);
        route->mutable_websocket()->set_idle_timeout_ms(60000U);
      },
      "unbounded WebSocket route was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_websocket()
            ->set_idle_timeout_ms(999U);
      },
      "undersized WebSocket idle timeout was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_websocket()
            ->set_idle_timeout_ms(3600001U);
      },
      "unbounded WebSocket idle timeout was accepted");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(0);
        route->mutable_match()->add_methods("POST");
        route->mutable_websocket()->set_idle_timeout_ms(60000U);
      },
      "WebSocket route excluding GET was accepted");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(0);
        route->clear_cluster_name();
        route->mutable_fixed_response()->set_status_code(204U);
        route->mutable_websocket()->set_idle_timeout_ms(60000U);
      },
      "WebSocket local-response route was accepted");
  require_invalid(
      [](auto& value) {
        auto* cluster = value.mutable_clusters(0);
        cluster->set_protocol(bonvoyage::v1::PROTOCOL_HTTP2);
        auto* tls = cluster->mutable_upstream_tls();
        tls->set_server_name("upstream.example.test");
        tls->set_trust_bundle_secret("upstream-ca.pem");
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_websocket()
            ->set_idle_timeout_ms(60000U);
      },
      "WebSocket route selected an HTTP/2 upstream");
  require_invalid(
      [](auto& value) {
        auto* listener = value.mutable_listeners(0);
        listener->set_protocol(bonvoyage::v1::PROTOCOL_HTTP2);
        auto* tls = listener->mutable_downstream_tls();
        tls->set_certificate_chain_secret("server-chain.pem");
        tls->set_private_key_secret("server-key.pem");
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_websocket()
            ->set_idle_timeout_ms(60000U);
      },
      "WebSocket route was exposed by an HTTP/2 listener");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_local_rate_limit()
            ->set_capacity(0U);
      },
      "incomplete route rate limit was accepted");
  require_invalid(
      [](auto& value) {
        auto* limit = value.mutable_virtual_hosts(0)
                          ->mutable_routes(0)
                          ->mutable_local_rate_limit();
        limit->set_capacity(1000001U);
        limit->set_refill_tokens_per_second(1U);
      },
      "route rate limit above the bound was accepted");
  require_invalid(
      [](auto& value) {
        auto* policy = value.mutable_virtual_hosts(0)
                           ->mutable_routes(0)
                           ->mutable_source_ip_policy();
        policy->clear_allow_cidrs();
        policy->clear_deny_cidrs();
      },
      "empty source IP policy was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_source_ip_policy()
            ->set_allow_cidrs(0, "198.51.100.1/24");
      },
      "source IP CIDR host bits were accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        value.mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_source_ip_policy()
            ->set_allow_cidrs(0, "2001:0db8::/32");
      },
      "non-canonical source IP CIDR was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        auto* policy = value.mutable_virtual_hosts(0)
                           ->mutable_routes(0)
                           ->mutable_source_ip_policy();
        policy->add_allow_cidrs("198.51.100.0/24");
      },
      "duplicate source IP CIDR was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        auto* policy = value.mutable_virtual_hosts(0)
                           ->mutable_routes(0)
                           ->mutable_source_ip_policy();
        policy->clear_deny_cidrs();
        policy->add_deny_cidrs("198.51.100.0/24");
      },
      "source IP CIDR in both policy lists was accepted");
  require_invalid(
      [](auto& value) {
        auto* policy = value.mutable_virtual_hosts(0)
                           ->mutable_routes(0)
                           ->mutable_source_ip_policy();
        for (std::size_t index = 0U; index < 63U; ++index) {
          policy->add_allow_cidrs("203.0.113." + std::to_string(index) +
                                  "/32");
        }
      },
      "oversized source IP policy was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        auto* host = value.mutable_virtual_hosts(0);
        auto* cors = host->mutable_routes(host->routes_size() - 1)
                         ->mutable_cors();
        cors->set_allow_any_origin(true);
        cors->clear_allowed_origins();
        cors->set_allow_credentials(true);
      },
      "credential wildcard CORS policy was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        auto* host = value.mutable_virtual_hosts(0);
        host->mutable_routes(host->routes_size() - 1)
            ->mutable_cors()
            ->set_allowed_origins(0, "https://APP.example.com/");
      },
      "non-canonical CORS origin was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        auto* host = value.mutable_virtual_hosts(0);
        host->mutable_routes(host->routes_size() - 1)
            ->mutable_cors()
            ->set_allowed_methods(0, "GET");
      },
      "CORS method outside the route matcher was accepted");
  require_invalid(
      [](auto& value) {
        auto* host = value.mutable_virtual_hosts(0);
        auto* route = host->mutable_routes(host->routes_size() - 1);
        auto* header = route->mutable_match()->add_headers();
        header->set_name("x-tenant");
        header->set_present(true);
      },
      "CORS route header-predicate ambiguity was accepted");
  require_invalid(
      [](auto& value) {
        auto* host = value.mutable_virtual_hosts(0);
        host->mutable_routes(host->routes_size() - 1)
            ->mutable_request_content()
            ->set_max_body_bytes(20U * 1024U * 1024U);
      },
      "route request-body limit above the global limit was accepted");
  require_invalid(
      [](auto& value) {
        auto* host = value.mutable_virtual_hosts(0);
        auto* content = host->mutable_routes(host->routes_size() - 1)
                            ->mutable_request_content();
        content->set_max_body_bytes(0U);
        content->clear_allowed_content_types();
      },
      "empty request-content policy was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        auto* host = value.mutable_virtual_hosts(0);
        host->mutable_routes(host->routes_size() - 1)
            ->mutable_request_content()
            ->set_allowed_content_types(0, "Application/JSON");
      },
      "non-canonical request media type was accepted from the wire snapshot");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(1);
        route->mutable_request_content()->add_allowed_content_types(
            "application/json");
        auto* header = route->mutable_match()->add_headers();
        header->set_name("content-type");
        header->set_exact("application/json");
      },
      "request-content policy and Content-Type matcher conflict was accepted");
  require_invalid(
      [](auto& value) {
        auto* route = value.mutable_virtual_hosts(0)->mutable_routes(0);
        route->mutable_request_content()->add_allowed_content_types(
            "application/json");
        route->mutable_api_key_auth()->set_header_name("content-type");
      },
      "request-content policy and Content-Type API-key conflict was accepted");
  require_invalid(
      [](auto& value) {
        value.mutable_clusters(0)->mutable_endpoints(0)->set_address(
            "bad host/path");
      },
      "invalid endpoint address was accepted");

  return 0;
}
