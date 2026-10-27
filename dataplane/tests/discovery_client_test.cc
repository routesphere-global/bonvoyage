#include "bonvoyage/runtime/discovery_client.hh"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {

using namespace std::chrono_literals;
using bonvoyage::runtime::DiscoveryClientConfig;
using bonvoyage::runtime::DiscoveryCredentialReloadState;
using bonvoyage::runtime::DiscoveryNodeIdentity;
using bonvoyage::runtime::DiscoveryReconnectBackoff;

unsigned assertions{};

void require(bool condition, std::string_view message) {
  ++assertions;
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

template <typename Callback>
void require_invalid(Callback callback, std::string_view message) {
  ++assertions;
  try {
    callback();
  } catch (const std::invalid_argument&) {
    return;
  }
  throw std::runtime_error(std::string(message));
}

[[nodiscard]] DiscoveryClientConfig valid_config() {
  DiscoveryClientConfig config;
  config.endpoint_address = "control.internal.example";
  config.endpoint_port = 8443U;
  config.authority = "control.internal.example:8443";
  config.server_name = "control.internal.example";
  config.trust_bundle_file = "/run/bonvoyage/secrets/control-ca.pem";
  config.client_certificate_file =
      "/run/bonvoyage/secrets/dataplane-cert.pem";
  config.client_private_key_file =
      "/run/bonvoyage/secrets/dataplane-key.pem";
  config.credential_generation_file =
      "/run/bonvoyage/secrets/current-generation.json";
  config.heartbeat_interval = 5s;
  config.connect_timeout = 3s;
  config.request_timeout = 2s;
  config.reconnect_initial_backoff = 100ms;
  config.reconnect_max_backoff = 10s;
  return config;
}

template <typename Mutation>
void reject_config(Mutation mutation, std::string_view message) {
  auto config = valid_config();
  mutation(config);
  require_invalid(
      [&] { bonvoyage::runtime::validate_discovery_client_config(config); },
      message);
}

void test_config_validation() {
  auto config = valid_config();
  bonvoyage::runtime::validate_discovery_client_config(config);
  require(config.max_message_bytes ==
              bonvoyage::runtime::kMaximumDiscoveryMessageBytes,
          "valid configuration changed the protocol message ceiling");
  require(config.credential_reload_tolerance == 1s,
          "credential reload tolerance default changed");

  reject_config([](auto& value) { value.endpoint_address.clear(); },
                "empty endpoint address was accepted");
  reject_config([](auto& value) { value.endpoint_address = "https://host"; },
                "endpoint URI was accepted as a bare address");
  reject_config([](auto& value) { value.endpoint_port = 0U; },
                "zero endpoint port was accepted");
  reject_config([](auto& value) { value.authority = "host/path"; },
                "authority path was accepted");
  reject_config(
      [](auto& value) { value.authority = "control.internal.example:abc"; },
      "nonnumeric authority port was accepted");
  reject_config(
      [](auto& value) { value.authority = "other.internal.example:8443"; },
      "authority unrelated to the verified TLS name was accepted");
  reject_config([](auto& value) { value.server_name = "host:8443"; },
                "SNI containing a port was accepted");
  reject_config([](auto& value) { value.trust_bundle_file.clear(); },
                "empty trust bundle was accepted");
  reject_config(
      [](auto& value) { value.client_certificate_file = "cert\n.pem"; },
      "control character in certificate path was accepted");
  reject_config([](auto& value) { value.client_private_key_file.clear(); },
                "empty client key was accepted");
  reject_config(
      [](auto& value) {
        value.credential_generation_file = "generation\n.json";
      },
      "control character in credential generation path was accepted");
  reject_config([](auto& value) { value.heartbeat_interval = 99ms; },
                "sub-minimum heartbeat interval was accepted");
  reject_config([](auto& value) { value.heartbeat_interval = 301s; },
                "over-maximum heartbeat interval was accepted");
  reject_config([](auto& value) { value.connect_timeout = 99ms; },
                "sub-minimum connect timeout was accepted");
  reject_config([](auto& value) { value.request_timeout = 121s; },
                "over-maximum request timeout was accepted");
  reject_config(
      [](auto& value) { value.reconnect_initial_backoff = 9ms; },
      "sub-minimum reconnect delay was accepted");
  reject_config(
      [](auto& value) {
        value.reconnect_initial_backoff = 2s;
        value.reconnect_max_backoff = 1s;
      },
      "reversed reconnect bounds were accepted");
  reject_config([](auto& value) { value.max_message_bytes = 0U; },
                "zero message limit was accepted");
  reject_config(
      [](auto& value) {
        value.max_message_bytes =
            bonvoyage::runtime::kMaximumDiscoveryMessageBytes + 1U;
      },
      "message limit beyond the protocol ceiling was accepted");
  reject_config(
      [](auto& value) { value.credential_reload_tolerance = 99ms; },
      "sub-minimum credential reload tolerance was accepted");
  reject_config(
      [](auto& value) { value.credential_reload_tolerance = 30001ms; },
      "over-maximum credential reload tolerance was accepted");
  config.credential_reload_tolerance = 100ms;
  bonvoyage::runtime::validate_discovery_client_config(config);
  config.credential_reload_tolerance = 30s;
  bonvoyage::runtime::validate_discovery_client_config(config);
}

[[nodiscard]] DiscoveryNodeIdentity valid_identity() {
  return DiscoveryNodeIdentity{
      "edge-sin:node_01",
      "process:20260923_01",
      "1.0.0-rc.1",
      {1U, 2U},
      {
          {bonvoyage::v1::NODE_CAPABILITY_TYPE_TWO_PHASE_ROLLOUT, 1U},
          {bonvoyage::v1::NODE_CAPABILITY_TYPE_EXACT_ARTIFACT_ROLLBACK, 1U},
          {bonvoyage::v1::NODE_CAPABILITY_TYPE_HEARTBEAT_STATE_REPORT, 1U},
      }};
}

template <typename Mutation>
void reject_identity(Mutation mutation, std::string_view message) {
  auto identity = valid_identity();
  mutation(identity);
  require_invalid(
      [&] {
        bonvoyage::runtime::validate_discovery_node_identity(identity);
      },
      message);
}

void test_identity_validation() {
  bonvoyage::runtime::validate_discovery_node_identity(valid_identity());

  reject_identity([](auto& value) { value.node_id.clear(); },
                  "empty node identity was accepted");
  reject_identity([](auto& value) { value.node_id.assign(129U, 'n'); },
                  "overlong node identity was accepted");
  reject_identity([](auto& value) { value.node_id = "-node"; },
                  "unsupported node identity prefix was accepted");
  reject_identity([](auto& value) { value.node_id = "node/path"; },
                  "unsupported node identity byte was accepted");
  reject_identity([](auto& value) { value.process_instance_id.clear(); },
                  "empty process identity was accepted");
  reject_identity([](auto& value) { value.dataplane_version = "   "; },
                  "blank dataplane version was accepted");
  reject_identity(
      [](auto& value) { value.dataplane_version.assign(129U, 'v'); },
      "overlong dataplane version was accepted");
  reject_identity(
      [](auto& value) { value.dataplane_version = std::string("v1\0bad", 6U); },
      "control byte in dataplane version was accepted");
  reject_identity([](auto& value) { value.supported_schema_versions.clear(); },
                  "empty schema version set was accepted");
  reject_identity(
      [](auto& value) { value.supported_schema_versions = {0U, 1U}; },
      "zero schema version was accepted");
  reject_identity(
      [](auto& value) { value.supported_schema_versions = {1U, 1U}; },
      "duplicate schema version was accepted");
  reject_identity(
      [](auto& value) { value.supported_schema_versions = {2U, 3U}; },
      "schema set without version 1 was accepted");
  reject_identity([](auto& value) { value.capabilities.clear(); },
                  "empty capability set was accepted");
  reject_identity(
      [](auto& value) { value.capabilities.front().version = 2U; },
      "unsupported capability version was accepted");
  reject_identity(
      [](auto& value) {
        value.capabilities.push_back(value.capabilities.front());
      },
      "duplicate capability was accepted");
  reject_identity([](auto& value) { value.capabilities.pop_back(); },
                  "incomplete Phase 4 capability set was accepted");
  reject_identity(
      [](auto& value) {
        value.capabilities.front().capability =
            bonvoyage::v1::NODE_CAPABILITY_TYPE_UNSPECIFIED;
      },
      "unknown capability was accepted");
}

void test_deterministic_backoff() {
  DiscoveryReconnectBackoff deterministic(100ms, 450ms);
  require(deterministic.attempts() == 0U,
          "new reconnect policy has a non-zero attempt count");
  require(deterministic.next_delay() == 100ms,
          "first reconnect delay changed");
  require(deterministic.next_delay() == 200ms,
          "second reconnect delay changed");
  require(deterministic.next_delay() == 400ms,
          "third reconnect delay changed");
  require(deterministic.next_delay() == 450ms &&
              deterministic.next_delay() == 450ms,
          "reconnect delay did not saturate at its maximum");
  require(deterministic.attempts() == 5U,
          "reconnect attempt accounting changed");
  deterministic.reset();
  require(deterministic.attempts() == 0U &&
              deterministic.next_delay() == 100ms,
          "reconnect reset did not restore the initial delay");
}

void test_bounded_jitter() {
  std::uint64_t observed_upper = 0U;
  DiscoveryReconnectBackoff low_jitter(
      100ms, 400ms,
      [&observed_upper](std::uint64_t upper) {
        observed_upper = upper;
        return std::uint64_t{0U};
      });
  require(low_jitter.next_delay() == 75ms && observed_upper == 26U,
          "lower jitter boundary changed");
  require(low_jitter.next_delay() == 150ms && observed_upper == 51U,
          "second lower jitter boundary changed");

  DiscoveryReconnectBackoff high_jitter(
      100ms, 400ms, [](std::uint64_t upper) { return upper - 1U; });
  require(high_jitter.next_delay() == 100ms &&
              high_jitter.next_delay() == 200ms &&
              high_jitter.next_delay() == 400ms,
          "upper jitter boundary exceeded or reduced the base delay");

  DiscoveryReconnectBackoff reduced_sample(
      100ms, 100ms, [](std::uint64_t upper) { return upper * 3U; });
  const auto reduced = reduced_sample.next_delay();
  require(reduced >= 75ms && reduced <= 100ms,
          "out-of-range jitter source escaped the bounded interval");

  require_invalid(
      [] { DiscoveryReconnectBackoff invalid(0ms, 100ms); },
      "zero reconnect initial delay was accepted");
  require_invalid(
      [] { DiscoveryReconnectBackoff invalid(200ms, 100ms); },
      "reversed reconnect policy bounds were accepted");
}

void test_credential_reload_state() {
  DiscoveryCredentialReloadState state;
  auto status = state.status();
  require(status.generation_count == 0U &&
              status.successful_reload_count == 0U &&
              status.failed_reload_count == 0U &&
              status.last_outcome == "not_started" &&
              !status.reconnect_pending,
          "new credential reload state was not empty");

  state.record_initial_generation();
  state.record_initial_generation();
  status = state.status();
  require(status.generation_count == 1U &&
              status.last_outcome == "initial_load_succeeded" &&
              !status.reconnect_pending,
          "initial credential generation was not recorded idempotently");

  state.record_reload_failure();
  status = state.status();
  require(status.generation_count == 1U &&
              status.failed_reload_count == 1U &&
              status.last_outcome == "reload_failed" &&
              !status.reconnect_pending,
          "failed reload displaced the active credential generation");

  state.record_reload_success();
  status = state.status();
  require(status.generation_count == 2U &&
              status.successful_reload_count == 1U &&
              status.failed_reload_count == 1U &&
              status.last_outcome == "reload_succeeded" &&
              status.reconnect_pending,
          "successful reload did not request a generation reconnect");

  state.record_reload_failure();
  status = state.status();
  require(status.generation_count == 2U &&
              status.failed_reload_count == 2U &&
              status.last_outcome == "reload_failed" &&
              status.reconnect_pending,
          "later failed reload erased a pending successful reconnect");
  require(state.consume_reconnect_request(),
          "pending credential reconnect was not consumable");
  require(!state.consume_reconnect_request() &&
              !state.status().reconnect_pending,
          "credential reconnect was consumed more than once");
}

}  // namespace

int main() {
  try {
    test_config_validation();
    test_identity_validation();
    test_deterministic_backoff();
    test_bounded_jitter();
    test_credential_reload_state();
    std::cout << "discovery_client assertions=" << assertions << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "discovery_client failure: " << error.what() << '\n';
    return 1;
  }
}
