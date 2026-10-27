#include "bonvoyage/runtime/runtime_log_service.hh"

#include <array>
#include <chrono>
#include <cstdio>
#include <exception>
#include <stdexcept>

#include <seastar/core/metrics.hh>
#include <seastar/core/reactor.hh>
#include <unistd.h>

namespace bonvoyage::runtime {
namespace {

using namespace std::chrono_literals;

}  // namespace

RuntimeLogService::~RuntimeLogService() { finish(); }

void RuntimeLogService::start(const std::string& transport,
                              const std::string& socket_path) {
  if (sink_ != nullptr) {
    throw std::logic_error("runtime logger service was already started");
  }
  if (transport == "unix") {
    unix_transport_ = std::make_unique<UnixRuntimeLogTransport>(socket_path);
  } else if (transport == "stderr-pipe") {
    pipe_transport_ = std::make_unique<PipeRuntimeLogTransport>(2);
  } else {
    throw std::invalid_argument("runtime logger transport must be unix or stderr-pipe");
  }
  sink_ = std::make_unique<RuntimeLogSink>();
  metrics_ = std::make_unique<seastar::metrics::metric_groups>();
  register_metrics();
  binding_ = std::make_unique<RuntimeLogBinding>(*sink_);
  drain_timer_.set_callback([this] { drain_once(); });
  drain_timer_.arm(50ms);
}

RuntimeLogSender RuntimeLogService::sender() const noexcept {
  return pipe_transport_ != nullptr ? &PipeRuntimeLogTransport::send
                                    : &UnixRuntimeLogTransport::send;
}

void* RuntimeLogService::sender_context() const noexcept {
  return pipe_transport_ != nullptr
             ? static_cast<void*>(pipe_transport_.get())
             : static_cast<void*>(unix_transport_.get());
}

void RuntimeLogService::drain_once() noexcept {
  if (sink_ == nullptr) {
    return;
  }
  sink_->drain(sender(), sender_context());
  const auto& stats = sink_->stats();
  const auto delay = stats.queue_depth == 0U ? 250ms
                     : stats.sink_healthy != 0U ? 10ms
                                                : 500ms;
  drain_timer_.arm(delay);
}

void RuntimeLogService::finish() noexcept {
  drain_timer_.cancel();
  metrics_.reset();
  if (binding_ != nullptr && sink_ != nullptr) {
    if (!binding_->detach()) {
      std::terminate();
    }
    binding_.reset();
  }
  if (sink_ != nullptr) {
    sink_->stop(sender(), sender_context());
    final_stats_ = sink_->stats();
    std::array<char, 512U> report{};
    const int size = std::snprintf(
        report.data(), report.size(),
        "<14>bonvoyage[%d]: event=runtime_log_final shard=%u attempted=%llu sent=%llu dropped=%llu shutdown_drops=%llu queued=%llu",
        static_cast<int>(::getpid()),
        static_cast<unsigned>(seastar::this_shard_id()),
        static_cast<unsigned long long>(final_stats_.records_attempted),
        static_cast<unsigned long long>(final_stats_.records_sent),
        static_cast<unsigned long long>(final_stats_.records_dropped),
        static_cast<unsigned long long>(final_stats_.shutdown_drops),
        static_cast<unsigned long long>(final_stats_.queue_depth));
    if (size > 0 && static_cast<std::size_t>(size) < report.size()) {
      final_report_sent_ =
          sender()(sender_context(), {report.data(), static_cast<std::size_t>(size)}) ==
          RuntimeLogSendResult::sent;
    }
    sink_.reset();
  }
  unix_transport_.reset();
  pipe_transport_.reset();
}

seastar::future<> RuntimeLogService::stop() {
  finish();
  return seastar::make_ready_future<>();
}

void RuntimeLogService::register_metrics() {
  namespace sm = seastar::metrics;
  metrics_->add_group(
      "bonvoyage_runtime_log",
      {sm::make_counter("records_attempted_total",
                        [this] { return sink_->stats().records_attempted; },
                        sm::description("Runtime log records offered to the owner queue")),
       sm::make_counter("records_sent_total",
                        [this] { return sink_->stats().records_sent; },
                        sm::description("Runtime log records accepted by the local transport")),
       sm::make_counter("records_dropped_total",
                        [this] { return sink_->stats().records_dropped; },
                        sm::description("Runtime log records dropped without affecting requests")),
       sm::make_counter("queue_overflows_total",
                        [this] { return sink_->stats().queue_overflows; },
                        sm::description("Runtime log records rejected by the full owner queue")),
       sm::make_counter("would_block_events_total",
                        [this] { return sink_->stats().would_block_events; },
                        sm::description("Nonblocking runtime log transport backpressure")),
       sm::make_counter("unavailable_events_total",
                        [this] { return sink_->stats().unavailable_events; },
                        sm::description("Runtime log receiver unavailable observations")),
       sm::make_counter("format_overflow_drops_total",
                        [this] { return binding_->stats().format_overflow_drops; },
                        sm::description("Seastar runtime records rejected by bounded formatting")),
       sm::make_counter("format_error_drops_total",
                        [this] { return binding_->stats().format_error_drops; },
                        sm::description("Seastar runtime records rejected after formatter failure")),
       sm::make_gauge("queue_depth",
                      [this] { return sink_->stats().queue_depth; },
                      sm::description("Runtime records currently retained by this owner")),
       sm::make_gauge("queue_capacity",
                      [this] { return sink_->stats().queue_capacity; },
                      sm::description("Fixed runtime log queue capacity per shard")),
       sm::make_gauge("sink_healthy",
                      [this] { return sink_->stats().sink_healthy; },
                      sm::description("Last local transport attempt accepted a record"))});
  if (seastar::this_shard_id() == 0U) {
    metrics_->add_group(
        "bonvoyage_runtime_log_process",
        {sm::make_counter("unbound_drops_total",
                          [] { return runtime_log_unbound_drops(); },
                          sm::description("Seastar callbacks without an attached owner"))});
  }
}

}  // namespace bonvoyage::runtime
