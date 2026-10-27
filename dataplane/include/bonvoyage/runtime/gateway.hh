#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include <seastar/core/future.hh>

#include "bonvoyage/runtime/access_log.hh"
#include "bonvoyage/runtime/snapshot_preparation.hh"
#include "bonvoyage/runtime/trace_exporter.hh"

namespace bonvoyage::runtime {

/** Opt-in response delivery counters used by bounded performance diagnostics. */
struct ResponsePathDiagnosticOptions final {
  /** Enables the additional response-path diagnostic counters. */
  bool enabled{false};
};

/** Process-level trust policy for upstream HTTP/1 connection reuse. */
struct UpstreamHttp1ConnectionOptions final {
  /** Allows reuse only when every process-reachable HTTP/1 peer is trusted. */
  bool trust_connection_reuse{false};
};

/** One fully shard-local BonVoyage listener, router, and upstream runtime. */
class GatewayShard final {
 public:
  /** Publishes one coordinator health state to every shard-local selector. */
  using ActiveHealthPublisher = std::function<seastar::future<>(
      std::size_t, std::size_t, bool)>;

  /** Publishes one resolved endpoint address to every shard-local pool. */
  using DnsAddressPublisher = std::function<seastar::future<>(
      std::size_t, std::size_t, std::string)>;

  /** Constructs an inactive shard-local runtime. */
  GatewayShard();

  /** Releases the hidden shard-local implementation. */
  ~GatewayShard();

  /** A gateway shard exclusively owns its listeners and pools. */
  GatewayShard(const GatewayShard&) = delete;

  /** A gateway shard exclusively owns its listeners and pools. */
  GatewayShard& operator=(const GatewayShard&) = delete;

  /** Binds the shard-local lifecycle owner before listeners start. */
  void bind_snapshot_lifecycle(SnapshotPreparationShard& lifecycle);

  /** Decodes a static snapshot and starts this shard's listeners. */
  seastar::future<> start(std::string snapshot_bytes,
                          std::string secrets_directory,
                          AccessLogOptions access_log_options = {},
                          OtlpTraceOptions trace_options = {},
                          ResponsePathDiagnosticOptions
                              response_path_diagnostics = {},
                          UpstreamHttp1ConnectionOptions
                              upstream_http1_options = {});

  /** Builds private live gateway resources for an already validated artifact. */
  seastar::future<ShardSnapshotPreparationResult> prepare_live_snapshot(
      SnapshotPrepareCommand command);

  /** Starts private maintenance loops after every shard has prepared. */
  seastar::future<> start_prepared_maintenance(
      const SnapshotReference& snapshot,
      ActiveHealthPublisher active_health_publisher,
      DnsAddressPublisher dns_address_publisher);

  /** Applies a health transition to the named active or prepared generation. */
  void apply_generation_active_health(const SnapshotReference& snapshot,
                                      std::size_t cluster_index,
                                      std::size_t endpoint_index,
                                      bool active_healthy);

  /** Applies a DNS result to the named active or prepared generation. */
  void apply_generation_resolved_address(
      const SnapshotReference& snapshot, std::size_t cluster_index,
      std::size_t endpoint_index, const std::string& resolved_address);

  /** Validates a live activation and closes no resources. */
  [[nodiscard]] ShardSnapshotActivationResult arm_live_activation(
      const SnapshotActivateCommand& command);

  /** Clears a failed live activation arm without changing active traffic. */
  void abort_live_activation() noexcept;

  /** Publishes prepared live resources using no-fail ownership moves. */
  [[nodiscard]] bool commit_live_activation() noexcept;

  /** Validates a live cancellation without clearing private resources. */
  [[nodiscard]] ShardSnapshotCancellationResult arm_live_cancel(
      const SnapshotCancelCommand& command);

  /** Clears a failed live cancellation arm. */
  void abort_live_cancel() noexcept;

  /** Stops and clears an armed private live generation. */
  seastar::future<bool> commit_live_cancel();

  /** Stops and clears a matching private generation after PREPARE failure. */
  seastar::future<> discard_live_prepared(
      std::uint64_t rollout_sequence, SnapshotReference snapshot);

  /** Stops and removes a matching retired generation after leases drain. */
  seastar::future<ShardSnapshotRetirementResult> reap_live_retired(
      SnapshotReference snapshot, bool lifecycle_unpinned);

  /** Starts centralized maintenance after every shard has activated. */
  seastar::future<> start_maintenance(
      ActiveHealthPublisher active_health_publisher,
      DnsAddressPublisher dns_address_publisher);

  /** Stops centralized probes and DNS queries before shard destruction. */
  seastar::future<> stop_maintenance();

  /** Applies one active-health transition on this shard. */
  void apply_active_health(std::size_t cluster_index,
                           std::size_t endpoint_index,
                           bool active_healthy);

  /** Applies one coordinator-resolved address on this shard. */
  void apply_resolved_address(std::size_t cluster_index,
                              std::size_t endpoint_index,
                              const std::string& resolved_address);

  /** Stops admission, drains active requests, and closes upstream pools. */
  seastar::future<> stop();

  /** Returns whether this shard has activated all configured listeners. */
  [[nodiscard]] bool ready() const noexcept;

  /** Returns the identity of the active immutable snapshot. */
  [[nodiscard]] const std::string& snapshot_id() const noexcept;

  /** Returns the generation of the active immutable snapshot. */
  [[nodiscard]] std::uint64_t snapshot_generation() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace bonvoyage::runtime
