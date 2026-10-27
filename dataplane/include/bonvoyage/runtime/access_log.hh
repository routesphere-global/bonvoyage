#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <seastar/core/future.hh>

namespace bonvoyage::runtime {

/** Node-local options for the bounded shard-local access-log sink. */
struct AccessLogOptions final {
  /** Existing writable directory; an empty value disables access logging. */
  std::string directory;

  /** Maximum records retained in memory on each shard. */
  std::size_t queue_capacity{8192U};

  /** Maximum logical JSONL bytes emitted by each shard for this process. */
  std::uint64_t max_file_bytes{1024U * 1024U * 1024U};

  /** Maximum interval before queued records are made durable. */
  std::uint32_t flush_interval_ms{1000U};

  /** Deterministically retain one out of this many completed requests. */
  std::uint32_t sample_every{1U};

  /** Returns whether the optional sink is configured. */
  [[nodiscard]] bool enabled() const noexcept { return !directory.empty(); }
};

/** Validates bounded access-log bootstrap options or throws. */
void validate_access_log_options(const AccessLogOptions& options);

/** Protocol classification carried by one privacy-safe access record. */
enum class AccessLogProtocol {
  http1,      ///< HTTP/1.1 request/response exchange.
  http2,      ///< HTTP/2 stream without a gRPC media contract.
  grpc,       ///< Native gRPC exchange over HTTP/2.
  websocket,  ///< Upgraded HTTP/1.1 WebSocket tunnel.
};

/** Bounded request-method classification; arbitrary tokens become other. */
enum class AccessLogMethod {
  get,      ///< GET request.
  head,     ///< HEAD request.
  post,     ///< POST request.
  put,      ///< PUT request.
  patch,    ///< PATCH request.
  delete_,  ///< DELETE request.
  options,  ///< OPTIONS request.
  connect,  ///< CONNECT request.
  other,    ///< Any method outside the bounded known set.
};

/** Snapshot-owned action selected for one request. */
enum class AccessLogAction {
  unresolved,      ///< Request ended before a route action was selected.
  route_miss,      ///< No route matched the request.
  proxy,           ///< Request used a configured upstream cluster.
  fixed_response,  ///< Route returned its configured fixed response.
  redirect,        ///< Route returned its configured redirect.
  cors_preflight,  ///< Gateway answered a CORS preflight locally.
  websocket,       ///< Request established a WebSocket tunnel.
};

/** Final downstream completion state. */
enum class AccessLogCompletion {
  complete,  ///< Downstream response completed successfully.
  partial,   ///< Response started but did not complete.
  aborted,   ///< No downstream response was completed.
};

/** Returns a fixed method class without retaining request-controlled text. */
[[nodiscard]] AccessLogMethod classify_access_log_method(
    std::string_view method) noexcept;

/**
 * One fixed-size record copied into a preallocated shard-local ring.
 *
 * Listener, route, and cluster views point into the active immutable snapshot.
 * The sink must therefore drain before the snapshot is destroyed.
 */
struct AccessLogRecord final {
  /** Wall-clock completion timestamp in Unix microseconds. */
  std::uint64_t timestamp_unix_microseconds{};
  /** Immutable snapshot generation serving the request. */
  std::uint64_t snapshot_generation{};
  /** Monotonic request duration in microseconds. */
  std::uint64_t duration_microseconds{};
  /** Downstream request payload bytes consumed by the gateway. */
  std::uint64_t request_body_bytes{};
  /** Downstream response payload bytes emitted by the gateway. */
  std::uint64_t response_body_bytes{};
  /** Seastar shard that retained request ownership. */
  std::uint32_t shard{};
  /** Final downstream HTTP status, or zero before response selection. */
  std::uint16_t status{};
  /** Configured listener name from the immutable snapshot. */
  std::string_view listener;
  /** Matched configured route name, or an empty view on a route miss. */
  std::string_view route;
  /** Selected configured cluster name, or an empty view when unused. */
  std::string_view cluster;
  /** Bounded downstream protocol classification. */
  AccessLogProtocol protocol{AccessLogProtocol::http1};
  /** Bounded request-method classification. */
  AccessLogMethod method{AccessLogMethod::other};
  /** Snapshot action selected for the request. */
  AccessLogAction action{AccessLogAction::unresolved};
  /** Final downstream completion classification. */
  AccessLogCompletion completion{AccessLogCompletion::aborted};
};

/** Formats one bounded JSON Lines record outside the request path. */
[[nodiscard]] std::string format_access_log_record(
    const AccessLogRecord& record);

/** Preallocated, allocation-free-on-push ring used by one shard. */
class BoundedAccessLogQueue final {
 public:
  /** Allocates a fixed-capacity shard-local ring. */
  explicit BoundedAccessLogQueue(std::size_t capacity);

  /** Queue ownership is shard-local and cannot be copied. */
  BoundedAccessLogQueue(const BoundedAccessLogQueue&) = delete;
  /** Queue ownership is shard-local and cannot be copied. */
  BoundedAccessLogQueue& operator=(const BoundedAccessLogQueue&) = delete;

  /** Pushes a record or returns false under drop-newest overflow policy. */
  [[nodiscard]] bool push(AccessLogRecord record) noexcept;

  /** Pops the oldest record; calling on an empty queue is invalid. */
  [[nodiscard]] AccessLogRecord pop() noexcept;

  /** Removes all retained records and returns the number discarded. */
  [[nodiscard]] std::size_t clear() noexcept;

  /** Returns whether no records are retained. */
  [[nodiscard]] bool empty() const noexcept { return size_ == 0U; }
  /** Returns the number of retained records. */
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  /** Returns the immutable ring capacity. */
  [[nodiscard]] std::size_t capacity() const noexcept {
    return entries_.size();
  }

 private:
  std::vector<AccessLogRecord> entries_;
  std::size_t head_{};
  std::size_t size_{};
};

/** Fixed-cardinality metrics owned by one shard-local sink. */
struct AccessLogStats final {
  /** Whether the optional sink is configured. */
  std::uint64_t enabled{};
  /** Whether the sink can currently persist records. */
  std::uint64_t sink_healthy{1U};
  /** Records currently retained in the shard-local queue. */
  std::uint64_t queue_depth{};
  /** Configured shard-local queue capacity. */
  std::uint64_t queue_capacity{};
  /** Sampled records admitted to the queue. */
  std::uint64_t records_enqueued{};
  /** Records flushed to stable storage. */
  std::uint64_t records_written{};
  /** Records discarded by any bounded failure policy. */
  std::uint64_t records_dropped{};
  /** Records intentionally omitted by deterministic sampling. */
  std::uint64_t records_sampled_out{};
  /** Records rejected by the drop-newest overflow policy. */
  std::uint64_t queue_overflows{};
  /** Segment open, write, flush, or close failures. */
  std::uint64_t write_failures{};
  /** Process-lifetime byte ceilings reached by this shard. */
  std::uint64_t capacity_exhaustions{};
  /** Logical JSONL bytes flushed to stable storage. */
  std::uint64_t bytes_written{};
  /** Shard-local segments opened successfully. */
  std::uint64_t segments_opened{};
};

/**
 * Bounded nonblocking producer and asynchronous shard-local file sink.
 *
 * enqueue() never waits for storage. The worker owns serialization, DMA, flush,
 * retry, and lifecycle work. Sink failure is fail-open for gateway traffic.
 */
class AccessLogSink final {
 public:
  /** Creates a stopped sink with validated node-local options. */
  explicit AccessLogSink(AccessLogOptions options);
  /** Releases the stopped sink implementation. */
  ~AccessLogSink();

  /** Sink ownership is shard-local and cannot be copied. */
  AccessLogSink(const AccessLogSink&) = delete;
  /** Sink ownership is shard-local and cannot be copied. */
  AccessLogSink& operator=(const AccessLogSink&) = delete;

  /** Starts the optional worker after the immutable snapshot is prepared. */
  seastar::future<> start(std::string snapshot_id,
                          std::uint64_t snapshot_generation);

  /** Drains bounded records, flushes stable storage, and stops the worker. */
  seastar::future<> stop();

  /** Samples and enqueues one completed request without waiting for the sink. */
  void enqueue(AccessLogRecord record) noexcept;

  /** Returns immutable bootstrap options. */
  [[nodiscard]] const AccessLogOptions& options() const noexcept;
  /** Returns immutable shard-local counters. */
  [[nodiscard]] const AccessLogStats& stats() const noexcept;
  /** Returns mutable shard-local counters for metric registration. */
  [[nodiscard]] AccessLogStats& stats() noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace bonvoyage::runtime
