#pragma once

#include "bonvoyage/runtime/runtime_log.hh"

#include <seastar/util/log.hh>
#include <thread>

namespace bonvoyage::runtime {

/** Fixed formatter-storage ceiling, before syslog framing/control escaping. */
inline constexpr std::size_t kRuntimeLogFormatLimit = 1792U;

/** Owner-local pre-enqueue losses; transport counters remain independent. */
struct RuntimeLogBindingStats final {
  std::uint64_t received{};               ///< Callbacks received while attached.
  std::uint64_t format_overflow_drops{};  ///< Complete formatting exceeded storage.
  std::uint64_t format_error_drops{};     ///< Formatter threw or status was invalid.
  std::uint64_t invalid_severity_drops{}; ///< Unknown Seastar severity was rejected.
};

/**
 * Install once before workers; static dispatch survives all owner bindings.
 * No fallback is permitted after installation. Requires the candidate Seastar
 * hook; not called by the production gateway yet. Does not activate a timer.
 */
[[nodiscard]] bool install_runtime_log_dispatcher() noexcept;

/** Process-wide count of callbacks without an attached owner, including teardown. */
[[nodiscard]] std::uint64_t runtime_log_unbound_drops() noexcept;

/**
 * Synchronous owner-thread binding. Queue and binding cannot move or cross
 * threads. The sink must outlive this binding. Detach before stopping/destroying
 * the sink; destruction also detaches, including exception unwinding. No I/O,
 * timer, metrics registration or borrowed view survives a callback.
 */
class RuntimeLogBinding final {
 public:
  /** Attach one active sink; reject an existing owner or an already-stopped sink. */
  explicit RuntimeLogBinding(RuntimeLogSink& sink);
  /** Detach only; never flush or destroy the external sink. */
  ~RuntimeLogBinding();
  /** Owner bindings cannot be copied. */
  RuntimeLogBinding(const RuntimeLogBinding&) = delete;
  /** Owner bindings cannot be assigned. */
  RuntimeLogBinding& operator=(const RuntimeLogBinding&) = delete;
  /** Idempotent detach; false on a wrong thread without mutating either owner. */
  bool detach() noexcept;
  /** Owner-thread counters remain readable after detach until destruction. */
  [[nodiscard]] const RuntimeLogBindingStats& stats() const noexcept { return stats_; }

 private:
  friend bool install_runtime_log_dispatcher() noexcept;
  static void consume(void*, seastar::log_level, std::string_view,
                      seastar::log_record_status) noexcept;
  RuntimeLogSink& sink_;
  const std::thread::id owner_thread_{std::this_thread::get_id()};
  RuntimeLogBindingStats stats_;
};

}  // namespace bonvoyage::runtime
