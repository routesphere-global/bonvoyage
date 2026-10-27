#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "bonvoyage/runtime/snapshot_preparation.hh"
#include "bonvoyage/v1/discovery.pb.h"

namespace bonvoyage::runtime {

struct NodeSnapshotPreparationReport;
struct NodeSnapshotActivationReport;
struct NodeSnapshotCancellationReport;

/** Standard uncompressed gRPC message-prefix size. */
inline constexpr std::size_t kGrpcMessagePrefixBytes = 5U;

/**
 * Maximum discovery protobuf accepted after the five-byte gRPC prefix.
 *
 * A rollout can carry one maximum-sized snapshot artifact. The additional MiB
 * is a strict allowance for bounded protobuf metadata and future compatible
 * envelope fields; it is not available to the snapshot artifact itself.
 */
inline constexpr std::size_t kMaximumDiscoveryMessageBytes =
    kMaximumSnapshotArtifactBytes + (1U << 20U);

/** Stable fail-closed protocol failure reported by the discovery codec. */
class DiscoveryProtocolError final : public std::runtime_error {
 public:
  /** Creates a structured failure with a stable code and field location. */
  DiscoveryProtocolError(std::string code, std::string field_path,
                         const std::string& message);

  /** Returns the stable machine-readable failure code. */
  [[nodiscard]] const std::string& code() const noexcept;
  /** Returns the protobuf, framing, or lifecycle field that failed. */
  [[nodiscard]] const std::string& field_path() const noexcept;

 private:
  std::string code_;
  std::string field_path_;
};

/** Result of consuming bytes until one frame completes or input is exhausted. */
struct GrpcDeframeResult final {
  /** Number of input bytes consumed by this call. */
  std::size_t consumed{};
  /** Complete protobuf payload, including a valid zero-length message. */
  std::optional<std::string> message;
};

/**
 * Incremental decoder for standard, uncompressed five-byte gRPC messages.
 *
 * The decoder retains at most one bounded in-progress payload and emits at
 * most one message per call. Callers can therefore loop over a transport
 * fragment without the codec accumulating an unbounded message queue.
 */
class GrpcMessageDeframer final {
 public:
  /** Creates a decoder with a non-zero per-message byte ceiling. */
  explicit GrpcMessageDeframer(
      std::size_t maximum_message_bytes = kMaximumDiscoveryMessageBytes);

  /** Consumes bytes until one message completes or the fragment is exhausted. */
  [[nodiscard]] GrpcDeframeResult consume(
      std::span<const std::uint8_t> fragment);

  /** Rejects a stream that ends in a partial prefix or payload. */
  void finish() const;

  /** Clears a complete or abandoned stream before reconnect. */
  void reset() noexcept;

 private:
  std::size_t maximum_message_bytes_{};
  std::uint8_t prefix_[kGrpcMessagePrefixBytes]{};
  std::size_t prefix_bytes_{};
  std::uint32_t declared_length_{};
  bool prefix_complete_{false};
  std::string payload_;
};

/** Adds the standard uncompressed gRPC prefix to one protobuf payload. */
[[nodiscard]] std::string frame_grpc_message(
    std::string_view protobuf_bytes,
    std::size_t maximum_message_bytes = kMaximumDiscoveryMessageBytes);

/** One validated command accepted by the shard-local snapshot lifecycle. */
using SnapshotLifecycleCommand =
    std::variant<SnapshotPrepareCommand, SnapshotActivateCommand,
                 SnapshotCancelCommand>;

/** Strictly maps a parsed rollout command into one lifecycle command. */
[[nodiscard]] SnapshotLifecycleCommand map_rollout_command(
    const bonvoyage::v1::RolloutCommand& command);

/** Parses and strictly maps one bounded serialized RolloutCommand protobuf. */
[[nodiscard]] SnapshotLifecycleCommand decode_rollout_command(
    std::string_view protobuf_bytes);

/** Parses a discovery response and requires exactly one rollout command. */
[[nodiscard]] SnapshotLifecycleCommand decode_discovery_response(
    std::string_view protobuf_bytes);

/** Immutable identity and capabilities announced by one dataplane process. */
struct DiscoveryNodeIdentity final {
  /** Stable node identity bound to the client certificate by the server. */
  std::string node_id;
  /** Unique identity for this process lifetime. */
  std::string process_instance_id;
  /** Human-readable dataplane semantic version. */
  std::string dataplane_version;
  /** Configuration schema versions this process accepts. */
  std::vector<std::uint32_t> supported_schema_versions{1U};
  /** Exact versioned lifecycle behaviors implemented by this process. */
  std::vector<SnapshotCapability> capabilities{
      default_snapshot_capabilities()};
};

/** Builds the first discovery-stream message from authoritative local state. */
[[nodiscard]] bonvoyage::v1::NodeHello build_node_hello(
    const DiscoveryNodeIdentity& identity,
    const SnapshotPreparationState& state, std::uint32_t shard_count);

/** Builds one timestamped liveness and reconciliation observation. */
[[nodiscard]] bonvoyage::v1::NodeHeartbeat build_node_heartbeat(
    const DiscoveryNodeIdentity& identity,
    const SnapshotPreparationState& state, std::uint32_t shard_count,
    std::chrono::system_clock::time_point observed_at);

/** Maps an all-shard PREPARE result to a structured wire ACK or NACK. */
[[nodiscard]] bonvoyage::v1::NodeRolloutReport build_node_rollout_report(
    const DiscoveryNodeIdentity& identity,
    const NodeSnapshotPreparationReport& report,
    std::chrono::system_clock::time_point completed_at);

/** Maps an all-shard ACTIVATE result to a structured wire ACK or NACK. */
[[nodiscard]] bonvoyage::v1::NodeRolloutReport build_node_rollout_report(
    const DiscoveryNodeIdentity& identity,
    const NodeSnapshotActivationReport& report,
    std::chrono::system_clock::time_point completed_at);

/** Maps an all-shard CANCEL result to a structured wire ACK or NACK. */
[[nodiscard]] bonvoyage::v1::NodeRolloutReport build_node_rollout_report(
    const DiscoveryNodeIdentity& identity,
    const NodeSnapshotCancellationReport& report,
    std::chrono::system_clock::time_point completed_at);

}  // namespace bonvoyage::runtime
