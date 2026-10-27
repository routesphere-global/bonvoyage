#pragma once

#include "bonvoyage/runtime/runtime_log.hh"
#include "bonvoyage/runtime/runtime_log_binding.hh"

#include <memory>
#include <string>

#include <seastar/core/future.hh>
#include <seastar/core/metrics_registration.hh>
#include <seastar/core/timer.hh>

namespace bonvoyage::runtime {

/** Owner-local Seastar logger service; never moves records between shards. */
class RuntimeLogService final {
 public:
  RuntimeLogService() = default;
  ~RuntimeLogService();
  RuntimeLogService(const RuntimeLogService&) = delete;
  RuntimeLogService& operator=(const RuntimeLogService&) = delete;

  /** Bind only after transport, queue and metrics are ready on this shard. */
  void start(const std::string& transport, const std::string& socket_path);
  /** Cancel the timer, detach, make one bounded final drain and retain counters. */
  seastar::future<> stop();
  /** Owner-thread final counters, including records dropped at shutdown. */
  [[nodiscard]] const RuntimeLogStats& final_stats() const noexcept {
    return final_stats_;
  }
  /** One out-of-band final summary was accepted by the kernel, not persisted. */
  [[nodiscard]] bool final_report_sent() const noexcept {
    return final_report_sent_;
  }

 private:
  RuntimeLogSender sender() const noexcept;
  void* sender_context() const noexcept;
  void drain_once() noexcept;
  void finish() noexcept;
  void register_metrics();

  std::unique_ptr<RuntimeLogSink> sink_;
  std::unique_ptr<UnixRuntimeLogTransport> unix_transport_;
  std::unique_ptr<PipeRuntimeLogTransport> pipe_transport_;
  std::unique_ptr<RuntimeLogBinding> binding_;
  seastar::timer<> drain_timer_;
  std::unique_ptr<seastar::metrics::metric_groups> metrics_;
  RuntimeLogStats final_stats_{};
  bool final_report_sent_{};
};

}  // namespace bonvoyage::runtime
