#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bonvoyage::runtime {

/** Typed syslog severities; trace uses debug rather than emergency. */
enum class RuntimeLogSeverity : std::uint8_t {
  error = 3,    ///< Error diagnostic.
  warning = 4,  ///< Warning diagnostic.
  info = 6,     ///< Informational diagnostic.
  debug = 7,    ///< Debug or trace diagnostic.
};

/** One finite, nonblocking transport attempt; sent does not imply durability. */
enum class RuntimeLogSendResult {
  sent,         ///< Kernel accepted the entire datagram.
  would_block,  ///< Retry on a later scheduled drain, never in a busy loop.
  unavailable,  ///< Receiver is absent; retain bounded queued records.
  failed,       ///< Permanent error; drop this record and account for it.
};

/** A sender must not throw, wait, retain the view, or mutate/reenter its sink. */
using RuntimeLogSender = RuntimeLogSendResult (*)(void*, std::string_view) noexcept;

/** Validated once before allocating a fixed, owner-thread queue. */
struct RuntimeLogOptions final {
  /** Maximum retained records; 1 through 4096. */
  std::size_t queue_capacity{256U};
  /** Maximum complete datagram bytes, including framing/escaping; 128 to 2048. */
  std::size_t max_record_bytes{2048U};
  /** Maximum send attempts per drain or shutdown; 1 through 256. */
  std::size_t drain_batch{64U};
};

/** Throws for unbounded or invalid options, before any queue allocation. */
void validate_runtime_log_options(const RuntimeLogOptions& options);

/** Owner-thread counters ready for later shard-local metric registration. */
struct RuntimeLogStats final {
  std::uint64_t records_attempted{};       ///< All enqueue calls, including rejects.
  std::uint64_t records_enqueued{};        ///< Records admitted to the ring.
  std::uint64_t records_sent{};            ///< Datagrams accepted by the kernel.
  std::uint64_t records_dropped{};         ///< All record-level loss reasons below.
  std::uint64_t queue_overflows{};         ///< Drop-newest overflow rejects.
  std::uint64_t oversized_records{};       ///< Oversized input or escaped framing.
  std::uint64_t invalid_severities{};      ///< Invalid typed severity rejected.
  std::uint64_t send_failure_drops{};      ///< Permanent failure discarded a head.
  std::uint64_t shutdown_drops{};          ///< Pending records discarded on stop.
  std::uint64_t stopped_drops{};           ///< Calls arriving after stop.
  std::uint64_t send_attempts{};           ///< Attempts, including retries.
  std::uint64_t would_block_events{};      ///< Backpressure/interruption observations.
  std::uint64_t unavailable_events{};      ///< Missing/unavailable receiver observations.
  std::uint64_t bytes_sent{};              ///< Queued payload bytes accepted; excludes pipe-added LF.
  std::uint64_t queue_depth{};             ///< Current records retained.
  std::uint64_t queue_high_water{};        ///< Peak queue depth.
  std::uint64_t queue_capacity{};          ///< Fixed allocated record capacity.
  std::uint64_t sink_healthy{};            ///< Last attempt succeeded; initially unknown/0.
  std::uint64_t active{1U};                ///< Accepting enqueue calls.
};

/**
 * Preallocated owner-thread runtime-log core, without a Seastar hook or timer.
 *
 * enqueue copies bounded bytes and never performs I/O. drain makes at most a
 * fixed batch of nonblocking attempts. No cross-thread calls are supported.
 * attempted = sent + dropped + depth after every public operation.
 * Objects are process-owned: do not reuse inherited queues after fork. Call
 * stop and collect final stats before destruction, including exception paths;
 * the destructor performs no transport work or externally visible accounting.
 */
class RuntimeLogSink final {
 public:
  /** Validate, allocate once, and capture this process's framing identity. */
  explicit RuntimeLogSink(RuntimeLogOptions options = {});
  /** Owner-thread queues cannot be copied. */
  RuntimeLogSink(const RuntimeLogSink&) = delete;
  /** Owner-thread queues cannot be assigned. */
  RuntimeLogSink& operator=(const RuntimeLogSink&) = delete;

  /** Copy a complete record or drop it; views never escape this call. */
  [[nodiscard]] bool enqueue(RuntimeLogSeverity severity,
                            std::string_view message) noexcept;
  /** At most drain_batch attempts; stop on backpressure/absence; nested calls are ignored. */
  void drain(RuntimeLogSender sender, void* context) noexcept;
  /** Bounded final drain then count/discard leftovers; idempotent, nested calls ignored. */
  void stop(RuntimeLogSender sender, void* context) noexcept;
  /** Current owner-thread counters; reading concurrently is not supported. */
  [[nodiscard]] const RuntimeLogStats& stats() const noexcept { return stats_; }

 private:
  struct Record final {
    std::array<char, 2048U> bytes{};
    std::size_t size{};
  };
  RuntimeLogOptions options_;
  std::vector<Record> records_;
  RuntimeLogStats stats_;
  std::size_t head_{};
  std::size_t size_{};
  std::uint64_t process_id_{};
  bool draining_{};
};

/**
 * Linux owner-thread Unix datagram sender. No libc syslog/global mutex, waiting,
 * file output, background thread or blocking fallback. Destination is resolved
 * on each sendto, so replacement sockets can recover without a stale connect.
 * Requires a trusted destination namespace; a pathname does not authenticate a
 * receiver. Not fork-safe: construct fresh objects rather than reusing inherited
 * state. Sends/close preserve caller errno; no hard wall-time bound is promised.
 */
class UnixRuntimeLogTransport final {
 public:
  /** A bounded absolute local socket path; no abstract address or controls. */
  explicit UnixRuntimeLogTransport(std::string path = "/dev/log");
  /** Close the owned descriptor, without flushing or waiting for delivery. */
  ~UnixRuntimeLogTransport();
  /** Descriptor ownership cannot be copied. */
  UnixRuntimeLogTransport(const UnixRuntimeLogTransport&) = delete;
  /** Descriptor ownership cannot be assigned. */
  UnixRuntimeLogTransport& operator=(const UnixRuntimeLogTransport&) = delete;

  /** Single nonblocking sendto attempt; lazily creates a nonblocking socket. */
  [[nodiscard]] RuntimeLogSendResult try_send(std::string_view record) noexcept;
  /** Function-pointer adapter for RuntimeLogSink. */
  static RuntimeLogSendResult send(void* context, std::string_view record) noexcept;
  /** Last operation error, or zero following a complete accepted datagram. */
  [[nodiscard]] int last_error() const noexcept { return last_error_; }
  /** Borrowed diagnostic descriptor; never close or mutate it externally. */
  [[nodiscard]] int native_handle() const noexcept { return fd_; }

 private:
  std::string path_;
  int fd_{-1};
  int last_error_{};
};

/**
 * Linux Docker stderr-pipe sender. Kernel acceptance is not durable delivery.
 * The supplied descriptor must be a pipe/FIFO; it is duplicated and owned.
 * O_NONBLOCK is an open-file-description flag: setting it on the duplicate also
 * changes fd 2 (or any other aliases of the supplied descriptor). Construct
 * only where that shared effect is acceptable. Each send fails closed if the
 * flag was cleared. Concurrent mutation after that check still violates the
 * deployment ownership contract; no hard wall-time bound is promised.
 * One LF terminates each accepted record; trailing input LF bytes are replaced
 * by that terminator. Sink bytes_sent counts payload, not the pipe-added LF.
 * No waiting or retry is done.
 */
class PipeRuntimeLogTransport final {
 public:
  /** Duplicate and own a pipe descriptor, then require nonblocking writes. */
  explicit PipeRuntimeLogTransport(int fd = 2);
  /** Close the owned duplicate without waiting for a downstream reader. */
  ~PipeRuntimeLogTransport();
  /** Descriptor ownership cannot be copied. */
  PipeRuntimeLogTransport(const PipeRuntimeLogTransport&) = delete;
  /** Descriptor ownership cannot be assigned. */
  PipeRuntimeLogTransport& operator=(const PipeRuntimeLogTransport&) = delete;

  /** Make one atomic nonblocking write of a bounded LF-framed record. */
  [[nodiscard]] RuntimeLogSendResult try_send(std::string_view record) noexcept;
  /** Function-pointer adapter for RuntimeLogSink. */
  static RuntimeLogSendResult send(void* context, std::string_view record) noexcept;
  /** Last operation error, or zero following a complete accepted write. */
  [[nodiscard]] int last_error() const noexcept { return last_error_; }
  /** Borrowed owned duplicate; never close or mutate it externally. */
  [[nodiscard]] int native_handle() const noexcept { return fd_; }

 private:
  int fd_{-1};
  int last_error_{};
};

}  // namespace bonvoyage::runtime
