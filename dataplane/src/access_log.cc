#include "bonvoyage/runtime/access_log.hh"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <exception>
#include <limits>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <utility>

#include <unistd.h>

#include <seastar/core/condition-variable.hh>
#include <seastar/core/file.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/smp.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/core/timer.hh>
#include <seastar/util/log.hh>

namespace bonvoyage::runtime {
namespace {

constexpr std::size_t kMaximumAccessLogDirectoryBytes = 4096U;
constexpr std::size_t kMaximumQueueCapacity = 65536U;
constexpr std::uint64_t kMinimumFileBytes = 1024U * 1024U;
constexpr std::uint64_t kMaximumFileBytes = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr std::uint32_t kMinimumFlushIntervalMs = 10U;
constexpr std::uint32_t kMaximumFlushIntervalMs = 60000U;
constexpr std::uint32_t kMaximumSampleEvery = 1000000U;
constexpr std::size_t kMaximumDrainBatch = 256U;
constexpr std::uint32_t kMaximumSegments = 16U;

seastar::logger access_log_internal_log{"bonvoyage-access-log"};

template <typename Integer>
void append_integer(std::string& output, Integer value) {
  static_assert(std::is_integral_v<Integer>);
  std::array<char, std::numeric_limits<Integer>::digits10 + 4U> buffer{};
  const auto [end, error] =
      std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  if (error != std::errc{}) {
    throw std::logic_error("access-log integer formatting failed");
  }
  output.append(buffer.data(), end);
}

void append_json_string(std::string& output, std::string_view value) {
  constexpr char hex[] = "0123456789abcdef";
  output.push_back('"');
  for (const auto character : value) {
    const auto byte = static_cast<unsigned char>(character);
    switch (character) {
      case '"':
        output.append("\\\"");
        break;
      case '\\':
        output.append("\\\\");
        break;
      case '\b':
        output.append("\\b");
        break;
      case '\f':
        output.append("\\f");
        break;
      case '\n':
        output.append("\\n");
        break;
      case '\r':
        output.append("\\r");
        break;
      case '\t':
        output.append("\\t");
        break;
      default:
        if (byte < 0x20U) {
          output.append("\\u00");
          output.push_back(hex[(byte >> 4U) & 0x0fU]);
          output.push_back(hex[byte & 0x0fU]);
        } else {
          output.push_back(character);
        }
    }
  }
  output.push_back('"');
}

std::string_view protocol_name(AccessLogProtocol protocol) noexcept {
  switch (protocol) {
    case AccessLogProtocol::http1:
      return "http1";
    case AccessLogProtocol::http2:
      return "http2";
    case AccessLogProtocol::grpc:
      return "grpc";
    case AccessLogProtocol::websocket:
      return "websocket";
  }
  return "unknown";
}

std::string_view method_name(AccessLogMethod method) noexcept {
  switch (method) {
    case AccessLogMethod::get:
      return "GET";
    case AccessLogMethod::head:
      return "HEAD";
    case AccessLogMethod::post:
      return "POST";
    case AccessLogMethod::put:
      return "PUT";
    case AccessLogMethod::patch:
      return "PATCH";
    case AccessLogMethod::delete_:
      return "DELETE";
    case AccessLogMethod::options:
      return "OPTIONS";
    case AccessLogMethod::connect:
      return "CONNECT";
    case AccessLogMethod::other:
      return "OTHER";
  }
  return "OTHER";
}

std::string_view action_name(AccessLogAction action) noexcept {
  switch (action) {
    case AccessLogAction::unresolved:
      return "unresolved";
    case AccessLogAction::route_miss:
      return "route_miss";
    case AccessLogAction::proxy:
      return "proxy";
    case AccessLogAction::fixed_response:
      return "fixed_response";
    case AccessLogAction::redirect:
      return "redirect";
    case AccessLogAction::cors_preflight:
      return "cors_preflight";
    case AccessLogAction::websocket:
      return "websocket";
  }
  return "unresolved";
}

std::string_view completion_name(AccessLogCompletion completion) noexcept {
  switch (completion) {
    case AccessLogCompletion::complete:
      return "complete";
    case AccessLogCompletion::partial:
      return "partial";
    case AccessLogCompletion::aborted:
      return "aborted";
  }
  return "aborted";
}

bool unsafe_directory_character(char character) noexcept {
  const auto byte = static_cast<unsigned char>(character);
  return byte < 0x20U || byte == 0x7fU;
}

std::string segment_path(std::string_view directory,
                         std::string_view snapshot_id,
                         std::uint64_t boot_token, std::uint32_t shard,
                         std::uint32_t segment) {
  std::string path(directory);
  if (path.back() != '/') {
    path.push_back('/');
  }
  path.append("access-");
  path.append(snapshot_id);
  path.push_back('-');
  append_integer(path, boot_token);
  path.append("-shard-");
  append_integer(path, shard);
  path.append("-segment-");
  append_integer(path, segment);
  path.append(".jsonl");
  return path;
}

}  // namespace

void validate_access_log_options(const AccessLogOptions& options) {
  if (options.directory.size() > kMaximumAccessLogDirectoryBytes ||
      std::any_of(options.directory.begin(), options.directory.end(),
                  unsafe_directory_character)) {
    throw std::invalid_argument(
        "access-log directory must be at most 4096 bytes without control characters");
  }
  if (options.queue_capacity == 0U ||
      options.queue_capacity > kMaximumQueueCapacity) {
    throw std::invalid_argument(
        "access-log queue capacity must be between 1 and 65536 records");
  }
  if (options.max_file_bytes < kMinimumFileBytes ||
      options.max_file_bytes > kMaximumFileBytes ||
      options.max_file_bytes % 4096U != 0U) {
    throw std::invalid_argument(
        "access-log file budget must be 1 MiB through 1 TiB and 4096-byte aligned");
  }
  if (options.flush_interval_ms < kMinimumFlushIntervalMs ||
      options.flush_interval_ms > kMaximumFlushIntervalMs) {
    throw std::invalid_argument(
        "access-log flush interval must be between 10 and 60000 milliseconds");
  }
  if (options.sample_every == 0U ||
      options.sample_every > kMaximumSampleEvery) {
    throw std::invalid_argument(
        "access-log sample interval must be between 1 and 1000000 requests");
  }
}

AccessLogMethod classify_access_log_method(std::string_view method) noexcept {
  if (method == "GET") {
    return AccessLogMethod::get;
  }
  if (method == "HEAD") {
    return AccessLogMethod::head;
  }
  if (method == "POST") {
    return AccessLogMethod::post;
  }
  if (method == "PUT") {
    return AccessLogMethod::put;
  }
  if (method == "PATCH") {
    return AccessLogMethod::patch;
  }
  if (method == "DELETE") {
    return AccessLogMethod::delete_;
  }
  if (method == "OPTIONS") {
    return AccessLogMethod::options;
  }
  if (method == "CONNECT") {
    return AccessLogMethod::connect;
  }
  return AccessLogMethod::other;
}

std::string format_access_log_record(const AccessLogRecord& record) {
  std::string output;
  output.reserve(768U);
  output.append("{\"schema\":\"bonvoyage.access.v1\",\"timestamp_unix_us\":");
  append_integer(output, record.timestamp_unix_microseconds);
  output.append(",\"snapshot_generation\":");
  append_integer(output, record.snapshot_generation);
  output.append(",\"shard\":");
  append_integer(output, record.shard);
  output.append(",\"listener\":");
  append_json_string(output, record.listener);
  output.append(",\"route\":");
  if (record.route.empty()) {
    output.append("null");
  } else {
    append_json_string(output, record.route);
  }
  output.append(",\"cluster\":");
  if (record.cluster.empty()) {
    output.append("null");
  } else {
    append_json_string(output, record.cluster);
  }
  output.append(",\"protocol\":");
  append_json_string(output, protocol_name(record.protocol));
  output.append(",\"method\":");
  append_json_string(output, method_name(record.method));
  output.append(",\"action\":");
  append_json_string(output, action_name(record.action));
  output.append(",\"status\":");
  append_integer(output, record.status);
  output.append(",\"completion\":");
  append_json_string(output, completion_name(record.completion));
  output.append(",\"duration_us\":");
  append_integer(output, record.duration_microseconds);
  output.append(",\"request_body_bytes\":");
  append_integer(output, record.request_body_bytes);
  output.append(",\"response_body_bytes\":");
  append_integer(output, record.response_body_bytes);
  output.append("}\n");
  return output;
}

BoundedAccessLogQueue::BoundedAccessLogQueue(std::size_t capacity)
    : entries_(capacity) {
  if (capacity == 0U) {
    throw std::invalid_argument(
        "bounded access-log queue requires positive capacity");
  }
}

bool BoundedAccessLogQueue::push(AccessLogRecord record) noexcept {
  if (size_ == entries_.size()) {
    return false;
  }
  const auto tail = (head_ + size_) % entries_.size();
  entries_[tail] = record;
  ++size_;
  return true;
}

AccessLogRecord BoundedAccessLogQueue::pop() noexcept {
  const auto result = entries_[head_];
  head_ = (head_ + 1U) % entries_.size();
  --size_;
  return result;
}

std::size_t BoundedAccessLogQueue::clear() noexcept {
  const auto discarded = size_;
  head_ = 0U;
  size_ = 0U;
  return discarded;
}

class AccessLogSink::Impl final {
 public:
  explicit Impl(AccessLogOptions options)
      : options_(std::move(options)), queue_(options_.queue_capacity) {
    validate_access_log_options(options_);
    stats_.enabled = options_.enabled() ? 1U : 0U;
    stats_.sink_healthy = options_.enabled() ? 0U : 1U;
    stats_.queue_capacity = options_.enabled() ? options_.queue_capacity : 0U;
  }

  seastar::future<> start(std::string snapshot_id,
                          std::uint64_t snapshot_generation) {
    if (started_) {
      throw std::logic_error("access-log sink was already started");
    }
    started_ = true;
    snapshot_id_ = std::move(snapshot_id);
    snapshot_generation_ = snapshot_generation;
    boot_token_ = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    if (!options_.enabled()) {
      co_return;
    }
    flush_timer_.set_callback([this] {
      flush_due_ = true;
      wake_.broadcast();
    });
    flush_timer_.arm_periodic(
        std::chrono::milliseconds(options_.flush_interval_ms));
    worker_ = run();
  }

  seastar::future<> stop() {
    if (!started_ || stopped_) {
      co_return;
    }
    stopped_ = true;
    flush_timer_.cancel();
    wake_.broadcast();
    if (options_.enabled()) {
      co_await std::move(worker_);
    }
  }

  void enqueue(AccessLogRecord record) noexcept {
    if (!started_ || stopped_ || !options_.enabled()) {
      return;
    }
    ++sample_cursor_;
    if ((sample_cursor_ - 1U) % options_.sample_every != 0U) {
      ++stats_.records_sampled_out;
      return;
    }
    if (capacity_exhausted_) {
      ++stats_.records_dropped;
      return;
    }
    if (!queue_.push(record)) {
      ++stats_.records_dropped;
      ++stats_.queue_overflows;
      return;
    }
    ++stats_.records_enqueued;
    stats_.queue_depth = queue_.size();
    wake_.signal();
  }

  [[nodiscard]] const AccessLogOptions& options() const noexcept {
    return options_;
  }
  [[nodiscard]] const AccessLogStats& stats() const noexcept { return stats_; }
  [[nodiscard]] AccessLogStats& stats() noexcept { return stats_; }

 private:
  seastar::future<bool> open_segment() {
    if (segment_index_ >= kMaximumSegments || capacity_exhausted_) {
      co_return false;
    }
    try {
      seastar::file_open_options file_options;
      file_options.create_permissions =
          seastar::file_permissions::user_read |
          seastar::file_permissions::user_write |
          seastar::file_permissions::group_read;
      auto opened = co_await seastar::open_file_dma(
          segment_path(options_.directory, snapshot_id_, boot_token_,
                       seastar::this_shard_id(), segment_index_),
          seastar::open_flags::wo | seastar::open_flags::create |
              seastar::open_flags::truncate,
          file_options);
      const auto disk_alignment = opened.disk_write_dma_alignment();
      const auto memory_alignment = opened.memory_dma_alignment();
      alignment_ = static_cast<std::size_t>(
          std::max(disk_alignment, memory_alignment));
      if (alignment_ == 0U || options_.max_file_bytes % alignment_ != 0U) {
        co_await opened.close();
        throw std::runtime_error(
            "access-log file alignment exceeds the configured budget alignment");
      }
      block_ = seastar::temporary_buffer<char>::aligned(alignment_, alignment_);
      std::memset(block_.get_write(), 0, block_.size());
      file_.emplace(std::move(opened));
      file_offset_ = 0U;
      block_used_ = 0U;
      stats_.sink_healthy = 1U;
      ++stats_.segments_opened;
      open_failure_announced_ = false;
      access_log_internal_log.info(
          "event=access_log_sink_healthy shard={} segment={} snapshot_generation={}",
          seastar::this_shard_id(), segment_index_, snapshot_generation_);
      co_return true;
    } catch (...) {
      ++stats_.write_failures;
      stats_.sink_healthy = 0U;
      if (!open_failure_announced_) {
        open_failure_announced_ = true;
        access_log_internal_log.warn(
            "event=access_log_sink_unavailable shard={} reason=open_failed snapshot_generation={}",
            seastar::this_shard_id(), snapshot_generation_);
      }
      co_return false;
    }
  }

  seastar::future<> write_current_block() {
    if (!file_.has_value() || block_.empty()) {
      throw std::logic_error("access-log block write requires an open sink");
    }
    const auto written = co_await file_->dma_write(
        file_offset_, block_.get(), block_.size());
    if (written != block_.size()) {
      throw std::runtime_error("access-log sink returned a short DMA write");
    }
  }

  seastar::future<> append_line(std::string_view line) {
    std::size_t offset = 0U;
    while (offset < line.size()) {
      const auto available = alignment_ - block_used_;
      const auto amount = std::min(available, line.size() - offset);
      std::memcpy(block_.get_write() + block_used_, line.data() + offset,
                  amount);
      block_used_ += amount;
      offset += amount;
      if (block_used_ == alignment_) {
        co_await write_current_block();
        file_offset_ += alignment_;
        block_used_ = 0U;
        std::memset(block_.get_write(), 0, block_.size());
      }
    }
  }

  seastar::future<> flush_pending() {
    if (!file_.has_value() || pending_records_ == 0U) {
      co_return;
    }
    if (block_used_ != 0U) {
      std::memset(block_.get_write() + block_used_, 0,
                  alignment_ - block_used_);
      co_await write_current_block();
    }
    co_await file_->truncate(file_offset_ + block_used_);
    co_await file_->flush();
    stats_.records_written += pending_records_;
    stats_.bytes_written += pending_bytes_;
    pending_records_ = 0U;
    pending_bytes_ = 0U;
    stats_.sink_healthy = 1U;
  }

  seastar::future<> close_file() noexcept {
    std::exception_ptr close_failure;
    if (file_.has_value()) {
      try {
        co_await file_->close();
      } catch (...) {
        close_failure = std::current_exception();
      }
      file_.reset();
    }
    block_ = {};
    alignment_ = 0U;
    file_offset_ = 0U;
    block_used_ = 0U;
    if (close_failure != nullptr) {
      std::rethrow_exception(close_failure);
    }
  }

  seastar::future<> handle_write_failure() noexcept {
    ++stats_.write_failures;
    stats_.sink_healthy = 0U;
    stats_.records_dropped += pending_records_;
    pending_records_ = 0U;
    pending_bytes_ = 0U;
    access_log_internal_log.warn(
        "event=access_log_sink_unavailable shard={} reason=write_failed snapshot_generation={}",
        seastar::this_shard_id(), snapshot_generation_);
    co_await close_file();
    ++segment_index_;
  }

  void exhaust_capacity() noexcept {
    if (capacity_exhausted_) {
      return;
    }
    capacity_exhausted_ = true;
    stats_.sink_healthy = 0U;
    ++stats_.capacity_exhaustions;
    stats_.records_dropped += queue_.clear();
    stats_.queue_depth = 0U;
    access_log_internal_log.warn(
        "event=access_log_capacity_exhausted shard={} snapshot_generation={}",
        seastar::this_shard_id(), snapshot_generation_);
  }

  void drop_queue() noexcept {
    stats_.records_dropped += queue_.clear();
    stats_.queue_depth = 0U;
  }

  seastar::future<> run() noexcept {
    bool worker_failed = false;
    try {
      while (true) {
        if (queue_.empty() && !flush_due_ && !stopped_) {
          co_await wake_.wait([this] {
            return stopped_ || flush_due_ || !queue_.empty();
          });
        }

        const bool timer_fired = std::exchange(flush_due_, false);
        if (!file_.has_value() && !capacity_exhausted_ &&
            (!queue_.empty() || !stopped_)) {
          const auto opened = co_await open_segment();
          if (!opened && !stopped_) {
            co_await wake_.wait(
                [this] { return stopped_ || flush_due_; });
            continue;
          }
        }

        std::size_t drained = 0U;
        bool storage_failure = false;
        while (file_.has_value() && !queue_.empty() &&
               drained < kMaximumDrainBatch && !capacity_exhausted_) {
          auto record = queue_.pop();
          stats_.queue_depth = queue_.size();
          ++drained;
          bool append_failed = false;
          try {
            auto line = format_access_log_record(record);
            if (logical_bytes_accepted_ + line.size() >
                options_.max_file_bytes) {
              ++stats_.records_dropped;
              exhaust_capacity();
              break;
            }
            logical_bytes_accepted_ += line.size();
            ++pending_records_;
            pending_bytes_ += line.size();
            co_await append_line(line);
          } catch (...) {
            append_failed = true;
          }
          if (append_failed) {
            co_await handle_write_failure();
            storage_failure = true;
            break;
          }
        }

        if (file_.has_value() && pending_records_ != 0U &&
            (timer_fired || stopped_ || queue_.empty())) {
          bool flush_failed = false;
          try {
            co_await flush_pending();
          } catch (...) {
            flush_failed = true;
          }
          if (flush_failed) {
            co_await handle_write_failure();
            storage_failure = true;
          }
        }

        if (storage_failure && !stopped_) {
          co_await wake_.wait(
              [this] { return stopped_ || flush_due_; });
          continue;
        }

        if (capacity_exhausted_) {
          drop_queue();
        }
        if (stopped_) {
          if (!file_.has_value() && !queue_.empty()) {
            drop_queue();
          }
          if (queue_.empty()) {
            break;
          }
        }
      }
      if (file_.has_value() && pending_records_ != 0U) {
        bool flush_failed = false;
        try {
          co_await flush_pending();
        } catch (...) {
          flush_failed = true;
        }
        if (flush_failed) {
          co_await handle_write_failure();
        }
      }
      co_await close_file();
    } catch (...) {
      worker_failed = true;
    }

    if (worker_failed) {
      ++stats_.write_failures;
      stats_.sink_healthy = 0U;
      stats_.records_dropped += pending_records_;
      pending_records_ = 0U;
      pending_bytes_ = 0U;
      drop_queue();
      co_await close_file();
      access_log_internal_log.error(
          "event=access_log_sink_stopped shard={} reason=worker_failed snapshot_generation={}",
          seastar::this_shard_id(), snapshot_generation_);
    }
  }

  AccessLogOptions options_;
  BoundedAccessLogQueue queue_;
  AccessLogStats stats_;
  seastar::condition_variable wake_;
  seastar::timer<> flush_timer_;
  seastar::future<> worker_{seastar::make_ready_future<>()};
  std::optional<seastar::file> file_;
  seastar::temporary_buffer<char> block_;
  std::string snapshot_id_;
  std::uint64_t snapshot_generation_{};
  std::uint64_t boot_token_{};
  std::uint64_t sample_cursor_{};
  std::uint64_t logical_bytes_accepted_{};
  std::uint64_t pending_records_{};
  std::uint64_t pending_bytes_{};
  std::uint64_t file_offset_{};
  std::size_t alignment_{};
  std::size_t block_used_{};
  std::uint32_t segment_index_{};
  bool started_{false};
  bool stopped_{false};
  bool flush_due_{false};
  bool capacity_exhausted_{false};
  bool open_failure_announced_{false};
};

AccessLogSink::AccessLogSink(AccessLogOptions options)
    : impl_(std::make_unique<Impl>(std::move(options))) {}

AccessLogSink::~AccessLogSink() = default;

seastar::future<> AccessLogSink::start(
    std::string snapshot_id, std::uint64_t snapshot_generation) {
  return impl_->start(std::move(snapshot_id), snapshot_generation);
}

seastar::future<> AccessLogSink::stop() { return impl_->stop(); }

void AccessLogSink::enqueue(AccessLogRecord record) noexcept {
  impl_->enqueue(record);
}

const AccessLogOptions& AccessLogSink::options() const noexcept {
  return impl_->options();
}

const AccessLogStats& AccessLogSink::stats() const noexcept {
  return impl_->stats();
}

AccessLogStats& AccessLogSink::stats() noexcept { return impl_->stats(); }

}  // namespace bonvoyage::runtime
