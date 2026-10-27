#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <seastar/core/future.hh>

#include "bonvoyage/runtime/access_log.hh"
#include "bonvoyage/runtime/trace_context.hh"

namespace bonvoyage::runtime {

/** Node-local options for bounded shard-local OTLP/HTTP trace export. */
struct OtlpTraceOptions final {
  /** Full HTTP(S) endpoint; an empty value disables tracing. */
  std::string endpoint;

  /** PEM trust bundle used for HTTPS collector authentication. */
  std::string tls_ca_file{"/etc/ssl/certs/ca-certificates.crt"};

  /** Explicitly permits cleartext export to a non-loopback collector. */
  bool allow_insecure{false};

  /** Explicitly trusts the collector for persistent HTTP/1 reuse. */
  bool trust_upstream_http1_connection_reuse{false};

  /** Maximum completed spans retained in memory on each shard. */
  std::size_t queue_capacity{8192U};

  /** Maximum spans encoded into one OTLP request. */
  std::size_t max_batch_spans{256U};

  /** Maximum serialized OTLP request bytes. */
  std::size_t max_batch_bytes{1024U * 1024U};

  /** Maximum interval before a nonempty queue is exported. */
  std::uint32_t flush_interval_ms{1000U};

  /** DNS, connect, TLS, request, and response timeout per attempt. */
  std::uint32_t request_timeout_ms{10000U};

  /** Locally retain one request out of this many; remote flags cannot bypass it. */
  std::uint32_t sample_every{100U};

  /** Maximum retries after the first OTLP attempt. */
  std::uint32_t max_retries{3U};

  /** Initial transient-failure retry delay. */
  std::uint32_t retry_initial_backoff_ms{100U};

  /** Maximum transient-failure retry delay. */
  std::uint32_t retry_max_backoff_ms{5000U};

  /** Returns whether the optional exporter is configured. */
  [[nodiscard]] bool enabled() const noexcept { return !endpoint.empty(); }
};

/** Validates the complete OTLP bootstrap boundary or throws. */
void validate_otlp_trace_options(const OtlpTraceOptions& options);

/** Fixed request-lifecycle record retained only when local sampling selects it. */
struct TraceSpanRecord final {
  TraceId trace_id{};          ///< End-to-end trace identifier.
  SpanId span_id{};            ///< BonVoyage SERVER span identifier.
  SpanId parent_span_id{};     ///< Immediate remote parent when present.
  std::uint64_t start_unix_nanoseconds{};  ///< Wall-clock span start.
  std::uint64_t end_unix_nanoseconds{};    ///< Wall-clock span end.
  std::uint64_t snapshot_generation{};     ///< Serving snapshot generation.
  std::uint64_t request_body_bytes{};      ///< Consumed downstream body bytes.
  std::uint64_t response_body_bytes{};     ///< Emitted downstream body bytes.
  std::uint32_t shard{};                   ///< Owning Seastar shard.
  std::uint16_t status{};                  ///< Final downstream HTTP status.
  std::uint8_t trace_flags{};              ///< Canonical W3C v00 flags.
  std::string_view listener;               ///< Configured listener identity.
  std::string_view route;                  ///< Configured route identity.
  std::string_view cluster;                ///< Configured cluster identity.
  AccessLogProtocol protocol{AccessLogProtocol::http1};  ///< Request protocol.
  AccessLogMethod method{AccessLogMethod::other};        ///< Bounded method.
  AccessLogAction action{AccessLogAction::unresolved};   ///< Gateway action.
  AccessLogCompletion completion{AccessLogCompletion::aborted};  ///< Outcome.
  bool has_parent{false};       ///< Whether parent_span_id is meaningful.
  bool sampled{false};          ///< Local bounded head-sampling decision.
};

/** Preallocated, allocation-free-on-push ring used by one trace exporter. */
class BoundedTraceQueue final {
 public:
  /** Allocates the fixed ring used for completed sampled spans. */
  explicit BoundedTraceQueue(std::size_t capacity);
  BoundedTraceQueue(const BoundedTraceQueue&) = delete;
  BoundedTraceQueue& operator=(const BoundedTraceQueue&) = delete;

  /** Adds one record or returns false when the fixed ring is full. */
  [[nodiscard]] bool push(TraceSpanRecord record) noexcept;
  /** Removes and returns the oldest record from a nonempty ring. */
  [[nodiscard]] TraceSpanRecord pop() noexcept;
  /** Drops every retained record and returns the number removed. */
  [[nodiscard]] std::size_t clear() noexcept;
  /** Returns whether the ring contains no retained records. */
  [[nodiscard]] bool empty() const noexcept { return size_ == 0U; }
  /** Returns the number of retained records. */
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  /** Returns the immutable ring capacity. */
  [[nodiscard]] std::size_t capacity() const noexcept {
    return entries_.size();
  }

 private:
  std::vector<TraceSpanRecord> entries_;
  std::size_t head_{};
  std::size_t size_{};
};

/** Result returned by the isolated OTLP/HTTP transport. */
struct OtlpHttpResult final {
  std::uint16_t status{};               ///< HTTP response status.
  std::uint32_t retry_after_ms{};       ///< Bounded Retry-After delay.
  std::string response_body;            ///< Bounded Protobuf response body.
};

/** Fixed-cardinality metrics owned by one shard-local exporter. */
struct OtlpTraceStats final {
  std::uint64_t enabled{};               ///< Whether tracing is configured.
  std::uint64_t exporter_healthy{1U};    ///< Last export attempt health.
  std::uint64_t queue_depth{};           ///< Currently retained spans.
  std::uint64_t queue_capacity{};        ///< Fixed per-shard span capacity.
  std::uint64_t spans_started{};         ///< Requests assigned a context.
  std::uint64_t spans_sampled{};         ///< Requests selected locally.
  std::uint64_t spans_sampled_out{};     ///< Requests omitted locally.
  std::uint64_t invalid_traceparents{};  ///< Invalid remote parents ignored.
  std::uint64_t remote_parents{};        ///< Valid remote parents continued.
  std::uint64_t propagation_limit_rejections{};  ///< Header-limit rejections.
  std::uint64_t spans_enqueued{};        ///< Completed spans admitted.
  std::uint64_t spans_exported{};        ///< Spans accepted by collector.
  std::uint64_t spans_dropped{};         ///< Spans lost observably.
  std::uint64_t queue_overflows{};       ///< Drop-newest queue overflows.
  std::uint64_t batches_exported{};      ///< Accepted OTLP batches.
  std::uint64_t export_requests{};       ///< Attempts including retries.
  std::uint64_t export_failures{};       ///< Failed export attempts.
  std::uint64_t export_retries{};        ///< Transient retries started.
  std::uint64_t retry_exhaustions{};     ///< Batches exhausting retries.
  std::uint64_t partial_success_responses{};  ///< Collector partial success.
  std::uint64_t exporter_recoveries{};   ///< Failed-to-healthy transitions.
  std::uint64_t bytes_exported{};        ///< Protobuf bytes accepted.
};

/**
 * Bounded nonblocking producer and asynchronous shard-local OTLP/HTTP exporter.
 *
 * The request path only creates a fixed-size context and copies a sampled span
 * into a preallocated ring. Protobuf encoding, DNS, TLS, HTTP, response parsing,
 * retry delay, and failure handling are owned by the worker.
 */
class OtlpTraceExporter final {
 public:
  /** Test/transport seam; production construction supplies no callback. */
  using ExportFunction =
      std::function<seastar::future<OtlpHttpResult>(std::string)>;

  /** Creates one exporter from validated node-local bootstrap options. */
  explicit OtlpTraceExporter(OtlpTraceOptions options,
                             ExportFunction export_function = {});
  /** Releases the stopped exporter implementation. */
  ~OtlpTraceExporter();

  OtlpTraceExporter(const OtlpTraceExporter&) = delete;
  OtlpTraceExporter& operator=(const OtlpTraceExporter&) = delete;

  /** Starts the optional exporter after the immutable snapshot is prepared. */
  seastar::future<> start(std::string snapshot_id,
                          std::uint64_t snapshot_generation,
                          std::string service_version);

  /** Drains or observably drops the bounded queue, then closes transport. */
  seastar::future<> stop();

  /** Creates one canonical request context without performing I/O. */
  [[nodiscard]] TraceSpanRecord begin_request(
      std::string_view incoming_traceparent);

  /** Enqueues one completed sampled span without waiting for export. */
  void enqueue(TraceSpanRecord record) noexcept;

  /** Returns whether tracing is configured. */
  [[nodiscard]] bool enabled() const noexcept;

  /** Returns immutable bootstrap options. */
  [[nodiscard]] const OtlpTraceOptions& options() const noexcept;

  /** Returns immutable shard-local counters. */
  [[nodiscard]] const OtlpTraceStats& stats() const noexcept;

  /** Returns mutable shard-local counters for metric registration. */
  [[nodiscard]] OtlpTraceStats& stats() noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace bonvoyage::runtime
