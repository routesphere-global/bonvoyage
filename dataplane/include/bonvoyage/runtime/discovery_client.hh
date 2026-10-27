#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <seastar/core/abort_source.hh>
#include <seastar/core/future.hh>

#include "bonvoyage/runtime/discovery_protocol.hh"

namespace bonvoyage::runtime {

/** Runtime limits and authenticated endpoint identity for discovery. */
struct DiscoveryClientConfig final {
  /** DNS name or IPv4 address used to establish the TCP connection. */
  std::string endpoint_address;
  /** TCP port of the discovery listener. */
  std::uint16_t endpoint_port{};
  /** HTTP/2 :authority value, including a port when deployment requires it. */
  std::string authority;
  /** Certificate name verified during the TLS handshake and sent as SNI. */
  std::string server_name;
  /** PEM trust bundle used exclusively for discovery-server verification. */
  std::string trust_bundle_file;
  /** PEM client certificate chain identifying this dataplane node. */
  std::string client_certificate_file;
  /** PEM private key paired with client_certificate_file. */
  std::string client_private_key_file;
  /**
   * Atomic node-credential generation commit marker.
   *
   * When nonempty, the client reloads the three TLS files only after this
   * bounded marker changes. This aligns reconnects with the node credential
   * store's final commit point instead of reacting to intermediate PEM writes.
   */
  std::string credential_generation_file;
  /** Interval between node-state heartbeats on an established stream. */
  std::chrono::milliseconds heartbeat_interval{5000};
  /** Bound for DNS, TCP, and TLS connection establishment. */
  std::chrono::milliseconds connect_timeout{5000};
  /** Bound from negotiated h2 transport to the flushed NodeHello frame. */
  std::chrono::milliseconds request_timeout{5000};
  /** First reconnect delay before bounded exponential growth and jitter. */
  std::chrono::milliseconds reconnect_initial_backoff{100};
  /** Maximum reconnect delay, including exponential growth and jitter. */
  std::chrono::milliseconds reconnect_max_backoff{10000};
  /** Maximum protobuf bytes accepted in one uncompressed gRPC message. */
  std::size_t max_message_bytes{kMaximumDiscoveryMessageBytes};
  /** Poll/debounce bound for validating one committed TLS generation. */
  std::chrono::milliseconds credential_reload_tolerance{1000};
};

/** Validates every discovery endpoint, TLS, timeout, and memory bound. */
void validate_discovery_client_config(const DiscoveryClientConfig& config);

/**
 * Validates the bounded node identity announced on every discovery stream.
 *
 * This startup check mirrors the discovery protocol codec's Phase 4 identity
 * contract so invalid configured identity cannot enter the reconnect loop.
 */
void validate_discovery_node_identity(const DiscoveryNodeIdentity& identity);

/**
 * Supplies a bounded jitter sample in the half-open range [0, upper_bound).
 *
 * Implementations may be deterministic for tests. Values outside the range
 * are reduced modulo upper_bound, keeping an injected source fail-safe.
 */
using DiscoveryJitterSource =
    std::function<std::uint64_t(std::uint64_t upper_bound)>;

/** Bounded exponential reconnect policy with optional 25-percent jitter. */
class DiscoveryReconnectBackoff final {
 public:
  /** Creates a policy after validating non-zero ordered delay bounds. */
  DiscoveryReconnectBackoff(std::chrono::milliseconds initial,
                            std::chrono::milliseconds maximum,
                            DiscoveryJitterSource jitter = {});

  /** Returns the next delay and advances the saturating attempt counter. */
  [[nodiscard]] std::chrono::milliseconds next_delay();

  /** Restores the next delay to the initial attempt. */
  void reset() noexcept;

  /** Returns the number of delays emitted since the last reset. */
  [[nodiscard]] std::uint32_t attempts() const noexcept;

 private:
  std::chrono::milliseconds initial_;
  std::chrono::milliseconds maximum_;
  DiscoveryJitterSource jitter_;
  std::uint32_t attempts_{};
};

/** Secret-free operator projection of discovery credential reload state. */
struct DiscoveryCredentialStatus final {
  /** Complete credential generations accepted since client startup. */
  std::uint64_t generation_count{};
  /** Successful post-start credential reloads. */
  std::uint64_t successful_reload_count{};
  /** Rejected post-start credential reloads. */
  std::uint64_t failed_reload_count{};
  /** Stable, operator-readable outcome name with no credential material. */
  std::string_view last_outcome{"not_started"};
  /** True while a successful generation awaits a replacement stream. */
  bool reconnect_pending{};
};

/**
 * Tracks credential generations and the controlled reconnect decision.
 *
 * The state machine owns no certificate, key, path, or exception text. Its
 * fixed outcome names are safe to expose through bounded operator telemetry.
 */
class DiscoveryCredentialReloadState final {
 public:
  /** Records the complete credential generation accepted during startup. */
  void record_initial_generation() noexcept;

  /** Accepts a complete reload and requests one break-before-make reconnect. */
  void record_reload_success() noexcept;

  /** Records a rejected reload without changing reconnect intent. */
  void record_reload_failure() noexcept;

  /** Consumes one pending controlled reconnect request. */
  [[nodiscard]] bool consume_reconnect_request() noexcept;

  /** Returns the current secret-free operator projection. */
  [[nodiscard]] DiscoveryCredentialStatus status() const noexcept;

 private:
  std::uint64_t generation_count_{};
  std::uint64_t successful_reload_count_{};
  std::uint64_t failed_reload_count_{};
  std::string_view last_outcome_{"not_started"};
  bool reconnect_pending_{};
};

/** Supplies the authoritative node-local snapshot state for hello/heartbeat. */
using DiscoveryStateProvider = std::function<SnapshotPreparationState()>;

/**
 * Applies one strictly decoded rollout command and returns its wire report.
 *
 * The abort source fires when the stream fails or the client stops. A live
 * coordinator may use it to abandon work that has not crossed a no-fail
 * publication boundary. The callback executes serially on shard zero.
 */
using DiscoveryCommandHandler = std::function<
    seastar::future<bonvoyage::v1::NodeRolloutReport>(
        SnapshotLifecycleCommand command, seastar::abort_source& abort)>;

/**
 * Owns the shard-zero authenticated snapshot-discovery stream.
 *
 * The client uses BonVoyage's transport-neutral HTTP/2 session indirectly
 * through the shard-local HTTP/2 transport, never grpc++. It sends NodeHello
 * first, serializes command handling, coalesces heartbeats, validates terminal
 * gRPC metadata, and reconnects until stop() is requested. Call stop() before
 * destruction.
 */
class DiscoveryClient final {
 public:
  /** Creates an inactive client; no files or sockets are opened yet. */
  DiscoveryClient(DiscoveryClientConfig config,
                  DiscoveryNodeIdentity identity,
                  std::uint32_t shard_count,
                  DiscoveryStateProvider state_provider,
                  DiscoveryCommandHandler command_handler,
                  DiscoveryJitterSource jitter = {});

  /** Stops and releases any remaining inactive resources. */
  ~DiscoveryClient();

  DiscoveryClient(const DiscoveryClient&) = delete;
  DiscoveryClient& operator=(const DiscoveryClient&) = delete;
  DiscoveryClient(DiscoveryClient&&) = delete;
  DiscoveryClient& operator=(DiscoveryClient&&) = delete;

  /** Loads credentials and starts this single-use reconnecting client. */
  seastar::future<> start();

  /** Aborts transport work and joins every owned background fiber. */
  seastar::future<> stop() noexcept;

  /** Returns true after start() and before stop() finishes. */
  [[nodiscard]] bool running() const noexcept;

  /**
   * Returns the shard-zero credential reload projection without secrets.
   *
   * The client is shard owned; callers must read this projection on the same
   * shard that owns start(), stop(), and the discovery transport.
   */
  [[nodiscard]] DiscoveryCredentialStatus credential_status() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace bonvoyage::runtime
